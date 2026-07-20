from __future__ import annotations

import re
import traceback
import argparse
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

from src.utils import read_json_file, dump_json_file, is_error_record
from src.config import CVE_DIR, PATCH_DIR

_GITHUB_PATCH_RE = re.compile(
    r"https?://github\.com/[^/]+/[^/]+/"
    r"(?:commit/[0-9a-f]{5,}|pull/\d+|releases/tag/[^/?#]+)"
)


def is_patch_reference(ref: dict) -> bool:
    url = ref.get("url", "")
    tags = ref.get("tags", [])
    return bool(_GITHUB_PATCH_RE.search(url)) or "patch" in tags


def extract_patches(cve_data: dict) -> list[dict]:
    refs = cve_data.get("containers", {}).get("cna", {}).get("references", [])
    return [r for r in refs if is_patch_reference(r)]


def _process_worker(args: tuple) -> tuple[str, str, int]:
    """
    Process one CVE file and write its patch record.
    Returns (cve_id, status, patch_count).
    status: 'processed' | 'skipped' | 'no_patches' | 'error'
    On error the output file contains the traceback for later debugging.
    """
    cve_path, patch_dir = args
    cve_id = cve_path.stem
    out_path = Path(patch_dir) / f"{cve_id}.json"

    if out_path.exists() and not is_error_record(out_path):
        return cve_id, "skipped", 0

    try:
        data = read_json_file(cve_path)
        cve_id = data.get("cveMetadata", {}).get("cveId", cve_id)
        patches = extract_patches(data)
        if not patches:
            return cve_id, "no_patches", 0
        dump_json_file(out_path, {"cve_id": cve_id, "patches": patches})
        return cve_id, "processed", len(patches)
    except Exception:
        dump_json_file(out_path, {
            "cve_id": cve_id,
            "error": True,
            "traceback": traceback.format_exc(),
        })
        return cve_id, "error", 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract patch references from CVE records.")
    parser.add_argument("--cve-dir", type=Path, default=CVE_DIR)
    parser.add_argument("--patch-dir", type=Path, default=PATCH_DIR)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    args.patch_dir.mkdir(parents=True, exist_ok=True)

    cve_files = sorted(args.cve_dir.glob("*/*/CVE-*.json"))
    total = len(cve_files)

    # Pre-filter in the main process: skip valid existing records, keep missing
    # and error records so they are (re)processed by the pool.
    cve_files = [
        p for p in cve_files
        if not (args.patch_dir / f"{p.stem}.json").exists()
        or is_error_record(args.patch_dir / f"{p.stem}.json")
    ]
    skipped_upfront = total - len(cve_files)

    worker_args = [(p, args.patch_dir) for p in cve_files]
    counts: Counter = Counter(skipped=skipped_upfront)
    total_patches = 0
    done = skipped_upfront

    with Pool(processes=args.workers) as pool:
        for cve_id, status, n in pool.imap_unordered(
            _process_worker, worker_args, chunksize=50
        ):
            counts[status] += 1
            total_patches += n
            done += 1
            if done % 500 == 0 or done == total:
                print(
                    f"[{done}/{total}] "
                    f"processed={counts['processed']} "
                    f"skipped={counts['skipped']} "
                    f"no_patches={counts['no_patches']} "
                    f"errors={counts['error']}"
                )

    print(
        f"Done — processed={counts['processed']}, skipped={counts['skipped']}, "
        f"no_patches={counts['no_patches']}, errors={counts['error']}, "
        f"total_patches={total_patches}"
    )


if __name__ == "__main__":
    main()
