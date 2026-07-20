from __future__ import annotations

import json
import os
import re
import time
import traceback
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from src.utils import read_json_file, dump_json_file, is_error_record
from src.config import CVE_DIR, PATCH_DIR, WHEN_DIR, GITHUB_DATES_CACHE_FILE

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

_GITHUB_COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{5,})")
_GITHUB_PR_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)")
_GITHUB_TAG_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/releases/tag/([^/?#]+)")
_GITHUB_RESOLVABLE_RE = re.compile(
    r"github\.com/[^/]+/[^/]+/(?:commit/[0-9a-f]{5,}|pull/\d+|releases/tag/[^/?#]+)"
)
_WAYBACK_RE = re.compile(r"web\.archive\.org/web/\d+/(.+)")


def _cve_path(cve_id: str) -> Path:
    _, year, num_str = cve_id.split("-", 2)
    bucket = f"{int(num_str) // 1000}xxx"
    return CVE_DIR / year / bucket / f"{cve_id}.json"

# Per-process read-only cache snapshot, populated by the Pool initializer.
# Each worker process has its own copy — no IPC locking needed during processing.
_WORKER_CACHE: dict[str, str | None] = {}


def _init_worker(cache_snapshot: dict[str, str | None]) -> None:
    global _WORKER_CACHE
    _WORKER_CACHE = dict(cache_snapshot)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _unwrap_url(url: str) -> str:
    m = _WAYBACK_RE.search(url)
    return m.group(1) if m else url


def has_resolvable_github_link(patches: list[dict]) -> bool:
    return any(
        _GITHUB_RESOLVABLE_RE.search(_unwrap_url(p.get("url", "")))
        for p in patches
    )


def _parse_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(date_str.rstrip("Z").split("+")[0], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------

def _github_get(url: str) -> dict | None:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cves-and-fixes"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=15) as resp:
            remaining = int(resp.headers.get("X-RateLimit-Remaining", 1))
            if remaining < 5:
                reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(0, reset - time.time()) + 2
                print(f"  [pid={os.getpid()}] rate limit low — sleeping {wait:.0f}s")
                time.sleep(wait)
            return json.loads(resp.read())
    except HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code in (403, 429):
            reset = int(exc.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(0, reset - time.time()) + 2
            print(f"  [pid={os.getpid()}] rate limited — sleeping {wait:.0f}s")
            time.sleep(wait)
            try:
                with urlopen(req, timeout=15) as resp:
                    return json.loads(resp.read())
            except Exception:
                return None
        return None
    except Exception:
        return None


def _resolve_single_url(url: str) -> str | None:
    """Hit the GitHub API for one canonical URL. No cache — caller deduplicates."""
    date: str | None = None

    m = _GITHUB_COMMIT_RE.search(url)
    if m:
        owner, repo, sha = m.groups()
        data = _github_get(f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}")
        if data:
            date = data.get("commit", {}).get("author", {}).get("date")

    if date is None:
        m = _GITHUB_PR_RE.search(url)
        if m:
            owner, repo, number = m.groups()
            data = _github_get(f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}")
            if data:
                # prefer merged_at (when the fix landed) over created_at
                date = data.get("merged_at") or data.get("created_at")

    if date is None:
        m = _GITHUB_TAG_RE.search(url)
        if m:
            owner, repo, tag = m.groups()
            data = _github_get(
                f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
            )
            if data:
                date = data.get("published_at")

    return date


# ---------------------------------------------------------------------------
# Per-CVE enrichment with inner ThreadPoolExecutor
# ---------------------------------------------------------------------------

def _enrich_patches(
    patches: list[dict],
    delay: float,
    thread_workers: int,
) -> tuple[list[dict], dict[str, str | None]]:
    """
    Resolve dates for all patch URLs using a ThreadPoolExecutor.

    Thread-safety guarantee: each unique canonical URL is fetched by exactly
    one thread (pre-deduplicated), so multiple threads never write to the same
    key in `resolved`. The worker-level cache (_WORKER_CACHE) is read-only here.

    Returns:
        enriched  — patches list with 'date' key added
        new_found — url→date entries not previously in _WORKER_CACHE (returned
                    to main process for persistent cache update)
    """
    # Map raw URL → canonical (Wayback-unwrapped) URL
    url_to_canonical = {p.get("url", ""): _unwrap_url(p.get("url", "")) for p in patches}

    # Unique canonicals, partitioned into cached vs to-fetch
    seen_canonicals: dict[str, str | None] = {}
    to_fetch: list[str] = []
    for canonical in dict.fromkeys(url_to_canonical.values()):
        if canonical in _WORKER_CACHE:
            seen_canonicals[canonical] = _WORKER_CACHE[canonical]
        else:
            to_fetch.append(canonical)

    # Fetch uncached URLs in parallel threads
    if to_fetch:
        def _fetch_one(url: str) -> tuple[str, str | None]:
            try:
                result = _resolve_single_url(url)
            except Exception:
                result = None
            time.sleep(delay)
            return url, result

        with ThreadPoolExecutor(max_workers=min(len(to_fetch), thread_workers)) as executor:
            future_map = {executor.submit(_fetch_one, url): url for url in to_fetch}
            for future in as_completed(future_map):
                url, date = future.result()
                seen_canonicals[url] = date

    # Discoveries not in the pre-loaded cache snapshot
    new_found = {u: d for u, d in seen_canonicals.items() if u not in _WORKER_CACHE}

    enriched = [
        {**p, "date": seen_canonicals.get(url_to_canonical.get(p.get("url", ""), ""))}
        for p in patches
    ]
    return enriched, new_found


# ---------------------------------------------------------------------------
# CVE processing
# ---------------------------------------------------------------------------

def _process_cve(
    cve_id: str,
    delay: float,
    thread_workers: int,
) -> tuple[dict | None, dict[str, str | None]]:
    """
    Returns (result_record | None, new_url_date_discoveries).
    None means the CVE has no resolvable GitHub patch link and should be skipped.
    """
    cve_path = _cve_path(cve_id)
    patch_path = PATCH_DIR / f"{cve_id}.json"

    if not cve_path.exists() or not patch_path.exists():
        return None, {}

    cve_data = read_json_file(cve_path)
    patch_data = read_json_file(patch_path)
    patches = patch_data.get("patches", [])

    if not has_resolvable_github_link(patches):
        return None, {}

    cve_published_raw: str | None = cve_data.get("cveMetadata", {}).get("datePublished")
    cve_published_dt = _parse_date(cve_published_raw)

    enriched, new_found = _enrich_patches(patches, delay, thread_workers)

    patch_dates = [dt for p in enriched if (dt := _parse_date(p.get("date")))]
    soonest_dt = min(patch_dates) if patch_dates else None
    soonest_raw = soonest_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if soonest_dt else None

    cve_first: bool | None = None
    delta_days: float | None = None
    if cve_published_dt and soonest_dt:
        cve_first = cve_published_dt < soonest_dt
        delta_days = round((soonest_dt - cve_published_dt).total_seconds() / 86400, 2)

    record = {
        "id": cve_id,
        "cve_published_date": cve_published_raw,
        "soonest_patched_date": soonest_raw,
        "delta_days": delta_days,
        "cve_first": cve_first,
        "patches": enriched,
    }
    return record, new_found


# ---------------------------------------------------------------------------
# Pool worker — must be module-level for pickling
# ---------------------------------------------------------------------------

def _worker(args: tuple) -> tuple[str, str, dict[str, str | None]]:
    """
    Outer process-pool worker. Returns (cve_id, status, new_url_discoveries).
    On unexpected failure writes an error record with full traceback so the
    problem can be diagnosed without re-running from scratch.
    """
    cve_id, delay, thread_workers = args
    out_path = WHEN_DIR / f"{cve_id}.json"

    if out_path.exists() and not is_error_record(out_path):
        return cve_id, "skipped", {}

    try:
        result, new_found = _process_cve(cve_id, delay, thread_workers)
        if result is None:
            return cve_id, "no_github", {}
        dump_json_file(out_path, result)
        return cve_id, "processed", new_found
    except Exception:
        dump_json_file(out_path, {
            "id": cve_id,
            "error": True,
            "traceback": traceback.format_exc(),
        })
        return cve_id, "error", {}


# ---------------------------------------------------------------------------
# Persistent URL-date cache (lives in outputs/cache/github_dates.json)
# ---------------------------------------------------------------------------

def _load_url_cache() -> dict[str, str | None]:
    if GITHUB_DATES_CACHE_FILE.exists():
        try:
            return json.loads(GITHUB_DATES_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            print(f"Warning: could not load URL cache from {GITHUB_DATES_CACHE_FILE}")
    return {}


def _save_url_cache(cache: dict[str, str | None]) -> None:
    GITHUB_DATES_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    dump_json_file(GITHUB_DATES_CACHE_FILE, cache)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correlate CVE publish dates with GitHub patch dates."
    )
    parser.add_argument("--cve-id", help="Process a single CVE ID instead of all.")
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Seconds to sleep after each GitHub API call per thread (default: 1.0).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Parallel CVE processes (default: 4).",
    )
    parser.add_argument(
        "--thread-workers",
        type=int,
        default=4,
        help="Threads per process for parallel URL resolution (default: 4).",
    )
    args = parser.parse_args()

    if not GITHUB_TOKEN:
        print(
            "Warning: GITHUB_TOKEN not set. "
            "Unauthenticated rate limit is 60 req/hour. "
            "Use --workers 1 --thread-workers 1 --delay 60 without a token."
        )

    WHEN_DIR.mkdir(parents=True, exist_ok=True)

    # Load persistent URL→date cache and pass a read-only snapshot to each worker
    # process via the Pool initializer. Workers return newly discovered entries;
    # only the main process writes back to the cache file (no race condition).
    url_cache = _load_url_cache()
    print(f"URL cache: {len(url_cache)} pre-loaded entries from {GITHUB_DATES_CACHE_FILE}")

    ids = (
        [args.cve_id]
        if args.cve_id
        else [p.stem for p in sorted(PATCH_DIR.glob("*.json"))]
    )
    total = len(ids)
    worker_args = [
        (cve_id, args.delay, args.thread_workers)
        for cve_id in ids
    ]

    counts: Counter = Counter()
    done = 0
    cache_dirty = False

    try:
        with Pool(
            processes=args.workers,
            initializer=_init_worker,
            initargs=(url_cache,),
        ) as pool:
            for _, status, new_found in pool.imap_unordered(_worker, worker_args):
                counts[status] += 1
                done += 1

                if new_found:
                    url_cache.update(new_found)
                    cache_dirty = True

                if done % 50 == 0 or done == total:
                    print(
                        f"[{done}/{total}] "
                        f"processed={counts['processed']} "
                        f"skipped={counts['skipped']} "
                        f"no_github={counts['no_github']} "
                        f"errors={counts['error']} "
                        f"cache={len(url_cache)}"
                    )
                    if cache_dirty:
                        _save_url_cache(url_cache)
                        cache_dirty = False

    finally:
        # Always persist the cache, even on Ctrl-C or pool worker crash
        if cache_dirty:
            _save_url_cache(url_cache)

    print(
        f"Done — processed={counts['processed']}, skipped={counts['skipped']}, "
        f"no_github_link={counts['no_github']}, errors={counts['error']}"
    )
    print(f"URL cache: {len(url_cache)} total entries saved to {GITHUB_DATES_CACHE_FILE}")


if __name__ == "__main__":
    main()
