from __future__ import annotations

import json
import os
import re
import time
import traceback
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import Pool
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from src.utils import read_json_file, dump_json_file, is_error_record
from src.config import PATCH_DIR, CODE_CHANGES_DIR, GITHUB_TOKEN

_GITHUB_COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{5,})")
_GITHUB_PR_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)")
_GITHUB_TAG_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/releases/tag/([^/?#]+)")
_GITHUB_RESOLVABLE_RE = re.compile(
    r"github\.com/[^/]+/[^/]+/(?:commit/[0-9a-f]{5,}|pull/\d+|releases/tag/[^/?#]+)"
)
_WAYBACK_RE = re.compile(r"web\.archive\.org/web/\d+/(.+)")

MAX_DIFF_BYTES = 500_000


def _canonical_url(url: str) -> str:
    m = _WAYBACK_RE.search(url)
    url = m.group(1) if m else url
    return url.split("#")[0]


def _is_resolvable(url: str) -> bool:
    return bool(_GITHUB_RESOLVABLE_RE.search(_canonical_url(url)))


# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------

def _github_get(url: str, accept: str = "application/vnd.github+json") -> bytes | None:
    headers = {"Accept": accept, "User-Agent": "cves-and-fixes"}
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
            return resp.read()
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
                    return resp.read()
            except Exception:
                return None
        return None
    except Exception:
        return None


def _fetch_diff(canonical_url: str) -> str | None:
    """Return unified diff text for a commit, PR, or release tag URL."""
    DIFF_ACCEPT = "application/vnd.github.diff"

    m = _GITHUB_COMMIT_RE.search(canonical_url)
    if m:
        owner, repo, sha = m.groups()
        data = _github_get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}",
            accept=DIFF_ACCEPT,
        )
        return data.decode("utf-8", errors="replace")[:MAX_DIFF_BYTES] if data else None

    m = _GITHUB_PR_RE.search(canonical_url)
    if m:
        owner, repo, number = m.groups()
        data = _github_get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}",
            accept=DIFF_ACCEPT,
        )
        return data.decode("utf-8", errors="replace")[:MAX_DIFF_BYTES] if data else None

    m = _GITHUB_TAG_RE.search(canonical_url)
    if m:
        owner, repo, tag = m.groups()
        # Resolve the tag ref to a commit SHA
        ref_data = _github_get(
            f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{tag}"
        )
        if not ref_data:
            return None
        ref_json = json.loads(ref_data)
        sha = ref_json.get("object", {}).get("sha")
        if not sha:
            return None
        # Annotated tags point to a tag object — dereference to the commit
        if ref_json.get("object", {}).get("type") == "tag":
            tag_obj = _github_get(
                f"https://api.github.com/repos/{owner}/{repo}/git/tags/{sha}"
            )
            if tag_obj:
                sha = json.loads(tag_obj).get("object", {}).get("sha", sha)
        data = _github_get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}",
            accept=DIFF_ACCEPT,
        )
        return data.decode("utf-8", errors="replace")[:MAX_DIFF_BYTES] if data else None

    return None


_DIFF_FILE_RE = re.compile(r"^diff --git a/.+ b/(.+)$", re.MULTILINE)


def _extract_changed_files(diff: str) -> list[str]:
    return _DIFF_FILE_RE.findall(diff)


# ---------------------------------------------------------------------------
# Per-CVE enrichment
# ---------------------------------------------------------------------------

def _enrich_patches(
    patches: list[dict],
    delay: float,
    thread_workers: int,
) -> list[dict]:
    resolvable = [p for p in patches if _is_resolvable(p.get("url", ""))]
    if not resolvable:
        return []

    url_to_canonical = {p.get("url", ""): _canonical_url(p.get("url", "")) for p in resolvable}
    unique_canonicals = list(dict.fromkeys(url_to_canonical.values()))

    fetched: dict[str, str | None] = {}

    def _fetch_one(url: str) -> tuple[str, str | None]:
        try:
            diff = _fetch_diff(url)
        except Exception:
            diff = None
        time.sleep(delay)
        return url, diff

    with ThreadPoolExecutor(max_workers=min(len(unique_canonicals), thread_workers)) as executor:
        futures = {executor.submit(_fetch_one, url): url for url in unique_canonicals}
        for future in as_completed(futures):
            url, diff = future.result()
            fetched[url] = diff

    result = []
    for p in resolvable:
        diff = fetched.get(url_to_canonical.get(p.get("url", ""), ""))
        result.append({
            **p,
            "files": _extract_changed_files(diff) if diff else [],
            "diff": diff,
        })
    return result


# ---------------------------------------------------------------------------
# Pool worker
# ---------------------------------------------------------------------------

def _worker(args: tuple) -> tuple[str, str]:
    cve_id, delay, thread_workers = args
    out_path = CODE_CHANGES_DIR / f"{cve_id}.json"

    if out_path.exists() and not is_error_record(out_path):
        return cve_id, "skipped"

    try:
        patch_path = PATCH_DIR / f"{cve_id}.json"
        if not patch_path.exists():
            return cve_id, "no_patch_file"

        patch_data = read_json_file(patch_path)
        patches = patch_data.get("patches", [])

        enriched = _enrich_patches(patches, delay, thread_workers)
        if not enriched:
            return cve_id, "no_github"

        dump_json_file(out_path, {"cve_id": cve_id, "patches": enriched})
        return cve_id, "processed"
    except Exception:
        dump_json_file(out_path, {
            "cve_id": cve_id,
            "error": True,
            "traceback": traceback.format_exc(),
        })
        return cve_id, "error"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch code diffs for CVE patch references from GitHub."
    )
    parser.add_argument("--cve-id", help="Process a single CVE ID instead of all.")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Seconds to sleep after each GitHub API call per thread (default: 0.5).",
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

    CODE_CHANGES_DIR.mkdir(parents=True, exist_ok=True)

    ids = (
        [args.cve_id]
        if args.cve_id
        else [p.stem for p in sorted(PATCH_DIR.glob("*.json"))]
    )
    total = len(ids)

    ids = [
        cve_id for cve_id in ids
        if not (CODE_CHANGES_DIR / f"{cve_id}.json").exists()
        or is_error_record(CODE_CHANGES_DIR / f"{cve_id}.json")
    ]
    skipped_upfront = total - len(ids)

    worker_args = [(cve_id, args.delay, args.thread_workers) for cve_id in ids]
    counts: Counter = Counter(skipped=skipped_upfront)
    done = skipped_upfront

    with Pool(processes=args.workers) as pool:
        for _, status in pool.imap_unordered(_worker, worker_args, chunksize=10):
            counts[status] += 1
            done += 1
            if done % 100 == 0 or done == total:
                print(
                    f"[{done}/{total}] "
                    f"processed={counts['processed']} "
                    f"skipped={counts['skipped']} "
                    f"no_github={counts['no_github']} "
                    f"errors={counts['error']}"
                )

    print(
        f"Done — processed={counts['processed']}, skipped={counts['skipped']}, "
        f"no_github={counts['no_github']}, errors={counts['error']}"
    )


if __name__ == "__main__":
    main()
