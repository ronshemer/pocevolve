"""Load CVE fix diffs from VFC (Vulnerability Fix Component) filtered JSON.

The VFC data source is a single JSON file containing entries for real CVEs, each with
testbed metadata and ``source_code_changes[].patch`` — the actual unified diff text
from the vulnerability-fixing commit.

This module builds in-memory lookup indexes by all available keys (CVE IDs, testbed
directory names, fix_commit URLs) so that callers can retrieve a diff by whichever
identifier they have at hand.

## Data source layout

Each entry has:

    {
        "testbed_dir": "SNYK-JS-ISMYJSONVALID-597167",
        "ids": ["SNYK-JS-ISMYJSONVALID-597167", "GHSA-f522-ffg8-j8r6"],
        "vulnerability_fix_commit": "https://github.com/.../commit/abc123...",
        "source_code_changes": [{
            "filename": "index.js",
            "patch": "@@ -45,13 +45,6 @@ ..."
        }]
    }

## Usage

    from src.graph_analysis.vfc_loader import get_diff

    # By testbed directory (exact match)
    diff_text = get_diff(testbed_dir="SNYK-JS-ISMYJSONVALID-597167")

    # By CVE / SNYK ID
    diff_text = get_diff(cve_id="CVE-2024-XXXX")  # if an alias maps to this entry

    # By fix commit URL (prefix match)
    diff_text = get_diff(fix_commit_url="https://github.com/.../commit/abc123")
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Indexing structures
# ---------------------------------------------------------------------------

class _VfcEntry:
    """Lightweight wrapper around a single VFC entry."""
    __slots__ = ("testbed_dir", "ids", "fix_commit_url", "diff_text")

    def __init__(
        self,
        testbed_dir: str,
        ids: List[str],
        fix_commit_url: str,
        diff_text: str,
    ):
        self.testbed_dir = testbed_dir
        self.ids = ids
        self.fix_commit_url = fix_commit_url
        self.diff_text = diff_text


# ---------------------------------------------------------------------------
# Index builder
# ---------------------------------------------------------------------------

class _VfcIndex:
    """In-memory indexes keyed by all available identifiers."""

    def __init__(self):
        # testbed_dir -> VfcEntry
        self._by_testbed: Dict[str, _VfcEntry] = {}
        # CVE/snyk/ghsa id -> VfcEntry  (first entry wins on collision)
        self._by_id: Dict[str, _VfcEntry] = {}
        # fix_commit URL prefix (last 8 hex chars of commit hash) -> VfcEntry
        self._by_commit_prefix: Dict[str, _VfcEntry] = {}

    def add(self, entry: _VfcEntry):
        self._by_testbed[entry.testbed_dir] = entry
        for ident in entry.ids:
            key = ident.strip().lower()
            if key not in self._by_id:
                self._by_id[key] = entry
        # Extract the short commit hash from URLs like ...commit/abc123...
        url = entry.fix_commit_url
        m = re.search(r"/commit/([0-9a-f]{8,})", url)
        if m:
            short = m.group(1).lower()
            # Try progressively shorter prefixes (4 → 8 chars) to avoid collisions
            for length in range(4, min(len(short), 8) + 1):
                prefix = short[:length]
                if prefix not in self._by_commit_prefix:
                    self._by_commit_prefix[prefix] = entry

    def by_testbed(self, testbed_dir: str) -> Optional[_VfcEntry]:
        return self._by_testbed.get(testbed_dir)

    def by_id(self, ident: str) -> Optional[_VfcEntry]:
        return self._by_id.get(ident.strip().lower())

    def by_commit_prefix(self, url_or_hash: str) -> Optional[_VfcEntry]:
        """Match by any prefix (4-8 chars) of the hex commit hash in a URL."""
        m = re.search(r"/commit/([0-9a-f]{8,})", url_or_hash)
        if not m:
            # Treat it as a raw hash
            raw = url_or_hash.strip().lower()
        else:
            raw = m.group(1).lower()
        for length in range(min(len(raw), 8), 3, -1):
            prefix = raw[:length]
            if prefix in self._by_commit_prefix:
                return self._by_commit_prefix[prefix]
        return None


_INDEX: Optional[_VfcIndex] = None

# ---------------------------------------------------------------------------
# Load on demand (singleton)
# ---------------------------------------------------------------------------

def _locate_vfc_json() -> Optional[Path]:
    """Search for vfcs.filtered.json relative to this module."""
    candidates: List[Path] = [
        # Direct path
        Path(__file__).resolve().parent.parent.parent / "secbenchjs" / "vfcs.filtered.json",
        # One level up from graph_analysis (PoCEvolve/)
        Path(__file__).resolve().parent.parent.parent / "vfcs.filtered.json",
        # Current working directory
        Path.cwd() / "secbenchjs" / "vfcs.filtered.json",
        Path.cwd() / "vfcs.filtered.json",
    ]
    for p in candidates:
        if p.is_file():
            return p
    # Try known absolute paths
    for p in [
        Path("/home/ron/Projects/cve_pocs/pocevolve/PoCEvolve/secbenchjs/vfcs.filtered.json"),
    ]:
        if p.is_file():
            return p
    logger.warning("vfcs.filtered.json not found — VFC diffs unavailable")
    return None


def _load_index() -> _VfcIndex:
    """Load and index vfcs.filtered.json."""
    path = _locate_vfc_json()
    if path is None:
        idx = _VfcIndex()  # empty
        logger.info("VFC: no data file — returning empty index")
        return idx

    with open(path, "r", encoding="utf-8") as fh:
        entries = json.load(fh)

    if not isinstance(entries, list):
        raise ValueError("vfcs.filtered.json expected a JSON array at top level")

    idx = _VfcIndex()
    for raw in entries:
        testbed_dir = raw.get("testbed_dir", "")
        ids = raw.get("ids", [])
        fix_commit_url = raw.get("vulnerability_fix_commit", "")

        # Collect all patch text into one diff (may have multiple changed files)
        patches: List[str] = []
        filenames: List[str] = []
        for sc in raw.get("source_code_changes", []):
            patch = sc.get("patch", "")
            if patch.strip():
                # Prepend a --git header so parse_diff can handle multi-file diffs
                fname = sc.get("filename", "unknown")
                patches.append(f"diff --git a/{fname} b/{fname}\n{patch}")
                filenames.append(fname)

        if not patches:
            continue  # skip entries without patch text

        diff_text = "\n".join(patches)
        entry = _VfcEntry(
            testbed_dir=testbed_dir,
            ids=ids,
            fix_commit_url=fix_commit_url,
            diff_text=diff_text,
        )
        idx.add(entry)

    logger.info("VFC: loaded %d CVE fix diffs from %s", len(idx._by_testbed), path)
    return idx


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _ensure_index() -> _VfcIndex:
    global _INDEX
    if _INDEX is None:
        _INDEX = _load_index()
    return _INDEX


def get_diff(
    testbed_dir: Optional[str] = None,
    cve_id: Optional[str] = None,
    fix_commit_url: Optional[str] = None,
) -> Optional[str]:
    """Look up a CVE fix diff by any available identifier.

    Parameters are tried in order: *testbed_dir* (exact), then *cve_id*,
    then *fix_commit_url* (prefix match on commit hash).

    Returns the unified diff text or **None** if no matching entry is found.
    """
    idx = _ensure_index()

    # 1. By testbed directory (exact match)
    if testbed_dir:
        entry = idx.by_testbed(testbed_dir)
        if entry:
            return entry.diff_text

    # 2. By CVE / SNYK / GHSA ID
    if cve_id:
        entry = idx.by_id(cve_id)
        if entry:
            return entry.diff_text

    # 3. By fix commit URL (prefix match)
    if fix_commit_url:
        entry = idx.by_commit_prefix(fix_commit_url)
        if entry:
            return entry.diff_text

    return None


def has_diff(testbed_dir: Optional[str] = None, cve_id: Optional[str] = None) -> bool:
    """Return True if a diff is available for the given identifiers."""
    return get_diff(testbed_dir=testbed_dir, cve_id=cve_id) is not None


def list_available() -> Dict[str, List[str]]:
    """Return {'testbed_dir': [ids...], ...} for all loaded entries."""
    idx = _ensure_index()
    return {td: entry.ids for td, entry in idx._by_testbed.items()}


# Module-level auto-load so callers never need to call _load_index manually.
# The index is created at import time on-demand via get_diff().
_ensure_index()  # prime the cache
