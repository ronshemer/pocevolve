"""Batch analysis: use VFC filtered diffs to run PoCEvolve Phase 2a analyzer on local testbeds."""

import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Ensure PoCEvolve/ is on sys.path so `from src.* import ...` works
_base_dir = Path(__file__).resolve().parent.parent  # PoCEvolve/
if str(_base_dir) not in sys.path:
    sys.path.insert(0, str(_base_dir))

logger = logging.getLogger(__name__)


def _load_vfc_diffs(vfc_path: Path) -> dict[str, str]:
    """Load CVE diffs from vfcs.filtered.json and index by testbed_dir + all IDs.

    Returns a dict mapping {cve_id: full_patch_text} for every entry in the VFC file.
    """
    if not vfc_path.exists():
        logger.warning("VFC file not found: %s", vfc_path)
        return {}

    with open(vfc_path) as f:
        entries = json.load(f)

    # Build lookup by every ID-like key for maximum flexibility
    by_id: dict[str, str] = {}
    for entry in entries:
        # Collect all identifiers for this CVE
        ids = entry.get("ids", [])
        testbed_dir = entry.get("testbed_dir")
        if testbed_dir:
            ids.append(testbed_dir)

        # Assemble the full diff text from source_code_changes
        patches = []
        for change in entry.get("source_code_changes", []):
            patch_text = change.get("patch", "")
            if patch_text and len(patch_text.strip()) > 10:
                patches.append(patch_text)

        if not patches:
            continue

        # Use the first (or concatenated) patch as the diff for this CVE
        full_diff = "\n".join(patches)

        # Index under every known ID so we can look up by SNYK id, GHSA id, or testbed_dir
        for ident in ids:
            if not by_id.get(ident):  # prefer first (most specific) mapping
                by_id[ident] = full_diff

    logger.info("Loaded %d CVE diffs from VFC (%s entries)", len(by_id), len(entries))
    return by_id


def _find_local_testbed(cve_id: str, info: dict, local_base: Path) -> str | None:
    """Map a CVE entry to a local testbed directory.

    Strategy 1: exact match on testbed_dir (e.g. SNYK-JS-ARPPING-1060047).
    Strategy 2: extract repo + commit from fix_commit URL, match {repo}@{commit}.
    """
    testbed_dir = info.get("testbed_dir", "")
    fix_commit_url = info.get("vulnerability_fix_commit", "")

    # Strategy 1: exact testbed_dir name
    candidate = local_base / testbed_dir
    if candidate.exists():
        return str(candidate)

    # Strategy 2: repo@commit from vulnerability_fix_commit URL
    if not fix_commit_url or "github.com" not in fix_commit_url:
        return None

    parts = fix_commit_url.rstrip("/").split("/")
    if len(parts) < 6:
        return None

    repo_name = parts[-4]
    commit_hash = parts[-1]
    candidate2 = local_base / f"{repo_name}@{commit_hash}"
    if candidate2.exists():
        return str(candidate2)

    # Strategy 3: try matching the package name from cve_id against directory base names
    # SNYK-JS-ISMYJSONVALID-597167 → ismyjsonvalid or is-my-json-valid
    td_nodash = "".join(c for c in testbed_dir.lower() if c not in "-_")
    for d in local_base.iterdir():
        if not d.is_dir():
            continue
        name_nodash = "".join(c for c in d.name.lower() if c not in "-_@")
        # Check if the package name portion (6+ chars) appears in the dir name or vice versa
        pkg_name = testbed_dir.split("-")[2] if len(testbed_dir.split("-")) > 2 else ""
        if pkg_name and (pkg_name in name_nodash or name_nodash[:8] in td_nodash):
            return str(d)

    return None


@dataclass
class AnalysisResultItem:
    cve_id: str
    testbed_dir: str
    local_path: str | None
    diff_source: str  # "vfc", "github", or "none"
    diff_bytes: int
    analysis_available: bool
    matched_methods: int
    taint_flows: int
    indexer_available: bool
    error: str | None = None


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    base_dir = Path(__file__).resolve().parent.parent
    map_path = base_dir / "src" / "graph_analysis" / "cve_testbed_map.json"
    local_base = base_dir / "src" / "git_testbeds"

    if not map_path.exists():
        print(f"FATAL: {map_path} not found", file=sys.stderr)
        sys.exit(1)

    # Load CVE testbed mapping
    cve_map = json.loads(map_path.read_text())
    print(f"Loaded {len(cve_map)} CVE entries from cve_testbed_map.json")

    # Build unique testbed list, collecting associated CVEs
    seen = set()
    unique_testbeds = {}
    for cve_id, info in cve_map.items():
        td = info.get("testbed_dir", "")
        if not td or not isinstance(info, dict):
            continue
        if td in seen:
            continue
        seen.add(td)
        unique_testbeds[td] = {
            "cves": [cve_id],
            "fix_url": info.get("vulnerability_fix_commit", ""),
            "testbed_dir": td,
            "info": info,
        }
    print(f"Unique testbeds: {len(unique_testbeds)}")

    # Load VFC diffs
    vfc_candidates = [
        base_dir / "secbenchjs" / "vfcs.filtered.json",
        base_dir.parent / "PoCEvole" / "datasets" / "SecBench.js.PoCGen.vfc.173",
    ]
    vfc_path = None
    for candidate in vfc_candidates:
        if candidate.exists() and candidate.suffix == ".json":
            vfc_path = candidate
            break

    if not vfc_path or not vfc_path.exists():
        print(f"ERROR: VFC file not found. Checked:", file=sys.stderr)
        for c in vfc_candidates:
            print(f"  - {c}", file=sys.stderr)
        sys.exit(1)

    diff_by_id = _load_vfc_diffs(vfc_path)
    if not diff_by_id:
        print("ERROR: No VFC diffs loaded", file=sys.stderr)
        sys.exit(1)

    # Map each unique testbed to a local directory and find its diff
    local_paths = {}
    for td, info in unique_testbeds.items():
        match_path = _find_local_testbed(td, info["info"], local_base)
        if not match_path:
            continue

        scip = Path(match_path) / ".scip" / "index.scip"
        cg = Path(match_path) / "node_modules" / ".index" / "call_graph.json"
        local_paths[td] = {
            "path": match_path,
            "has_scip": scip.exists() and scip.stat().st_size > 0,
            "scip_size": scip.stat().st_size if scip.exists() else 0,
            "has_callgraph": cg.exists(),
        }

    # Determine which testbeds have VFC diffs available (by any of their IDs)
    testbeds_with_diff = {}
    for td, info in unique_testbeds.items():
        # Check by testbed_dir first, then collect all potential IDs
        if td in diff_by_id:
            testbeds_with_diff[td] = diff_by_id[td]
            continue
        # Check by the first associated CVE ID
        for cve_id in info["cves"]:
            if cve_id in diff_by_id:
                testbeds_with_diff[td] = diff_by_id[cve_id]
                break

    has_data = sum(1 for v in local_paths.values() if v["has_scip"] or v["has_callgraph"])
    no_data = len(local_paths) - has_data
    print(f"\nLocal testbeds: {len(local_paths)} (SCIP/callgraph: {has_data}, none: {no_data})")
    print(f"Testbeds with VFC diffs: {len(testbeds_with_diff)}")

    # Phase 1: Index all local testbeds (do this once, then reuse)
    print("\n--- PHASE 1: Indexing local testbeds ---")
    from src.indexer import scan as index_package
    from src.indexer.config import default_config

    indexed = {}
    for td in sorted(local_paths.keys()):
        path = local_paths[td]["path"]
        logger.info("Indexing %s ...", path)
        idx = index_package(path, default_config())
        indexed[td] = {
            "result": idx,
            "available": idx.available,
            "error": idx.error if not idx.available else None,
        }
        status = "OK" if idx.available else f"FAIL: {idx.error}"
        print(f"  {td[:40]:40s} → {status}")

    # Phase 2: Run analysis on testbeds with both indexer data and VFC diffs
    print("\n--- PHASE 2: Running analysis ---\n")
    results = []

    for td in sorted(local_paths.keys()):
        info = unique_testbeds[td]
        cve_id = info["cves"][0]
        local = local_paths[td]
        path = local["path"]

        # Get diff from VFC
        diff_text = testbeds_with_diff.get(td)
        has_vfc_diff = bool(diff_text)

        # Check indexer availability
        idx_data = indexed.get(td)
        has_indexer = idx_data and idx_data["available"] if idx_data else False
        idx_result = idx_data["result"] if has_indexer else None

        if not has_vfc_diff:
            results.append(AnalysisResultItem(
                cve_id=cve_id, testbed_dir=td, local_path=path,
                diff_source="none", diff_bytes=0, analysis_available=False,
                matched_methods=0, taint_flows=0, indexer_available=has_indexer,
                error="no VFC diff available for this CVE",
            ))
            print(f"  SKIP {td:45s} - no VFC diff")
            continue

        if not has_indexer:
            err = idx_data.get("error", "unknown") if idx_data else "not indexed"
            results.append(AnalysisResultItem(
                cve_id=cve_id, testbed_dir=td, local_path=path,
                diff_source="vfc", diff_bytes=len(diff_text),
                analysis_available=False, matched_methods=0, taint_flows=0,
                indexer_available=False, error=f"indexer failed: {err}",
            ))
            print(f"  SKIP {td:45s} - indexer unavailable")
            continue

        # Run analysis with VFC diff
        from src.graph_analysis.analyzer import run_analysis

        try:
            result = run_analysis(
                cve_id=cve_id,
                package_root=path,
                index_result=idx_result,
                diff_text=diff_text,
            )
            matched = len(result.matched_methods) if result else 0
            flows = len(result.taint_flows) if result else 0

            results.append(AnalysisResultItem(
                cve_id=cve_id, testbed_dir=td, local_path=path,
                diff_source="vfc", diff_bytes=len(diff_text),
                analysis_available=True, matched_methods=matched,
                taint_flows=flows, indexer_available=True,
            ))
            print(f"  OK   {td:45s} | nodes={len(idx_result.nodes):>4d} edges={len(idx_result.edges):>5d} | "
                  f"matched={matched:>3d} flows={flows}")

        except Exception as e:
            logger.warning("Analysis failed for %s: %s", td, e, exc_info=True)
            results.append(AnalysisResultItem(
                cve_id=cve_id, testbed_dir=td, local_path=path,
                diff_source="vfc", diff_bytes=len(diff_text),
                analysis_available=False, matched_methods=0, taint_flows=0,
                indexer_available=True, error=str(e),
            ))
            print(f"  ERR  {td:45s} - {e}")

    # Summary
    total = len(results)
    with_analysis = sum(1 for r in results if r.analysis_available)
    with_matched = sum(1 for r in results if r.matched_methods > 0)
    with_flows = sum(1 for r in results if r.taint_flows > 0)
    no_diff = sum(1 for r in results if not r.diff_source or r.diff_source == "none")
    index_fail = sum(1 for r in results if not r.indexer_available and not r.analysis_available)

    print(f"\n{'='*70}")
    print(f"RESULTS: {total} testbeds analyzed")
    print(f"  With analysis complete: {with_analysis}")
    print(f"  With matched methods:   {with_matched}")
    print(f"  With taint flows:       {with_flows}")
    print(f"  No VFC diff available:  {no_diff}")
    print(f"  Indexer failed:         {index_fail}")

    # Show sample results with findings
    results_with_findings = [r for r in results if r.analysis_available and (r.matched_methods > 0 or r.taint_flows > 0)]
    if results_with_findings:
        print(f"\nSample results ({len(results_with_findings)} testbeds with findings):")
        for r in sorted(results_with_findings, key=lambda x: x.matched_methods + x.taint_flows, reverse=True)[:10]:
            print(f"  {r.cve_id}: matched={r.matched_methods} flows={r.taint_flows} "
                  f"path={r.local_path.split('/')[-1]}")

    # Save results
    output = {
        "stats": {
            "total_testbeds": total,
            "with_analysis": with_analysis,
            "with_matched_methods": with_matched,
            "with_taint_flows": with_flows,
            "vfc_diffs_loaded": len(diff_by_id),
            "no_vfc_diff": no_diff,
        },
        "results": [r.__dict__ for r in results],
    }

    out_path = base_dir / "scripts" / "batch_results_analysis.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
