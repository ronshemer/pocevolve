#!/usr/bin/env python3
"""Batch graph analysis for SecBench.js VFC-filtered CVEs.

Reads all CVE IDs from datasets/SecBench.js.PoCGen.vfc.173, maps each to its
testbed directory under PoCEvolve/testbed/, runs graph analysis (scan mode), and
collects per-CVE results plus aggregate statistics.

Usage:
    python3 -B scripts/batch_analyze.py [--output results.json] [--max-cves N]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure the project root is on PYTHONPATH so `src.*` imports work.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent  # PoCEvolve/
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.indexer import scan as index_package, IndexerConfig  # noqa: E402
from src.graph_analysis._types import MatchedMethod, TaintFlow, TaintSink, TaintSource  # noqa: E402
from src.graph_analysis.taint_flow import _SHELL_SINK_PATTERNS  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

VFC_DATASET = Path(__file__).resolve().parent.parent / "datasets" / "SecBench.js.PoCGen.vfc.173"
TESTBED_ROOT = Path(__file__).resolve().parent.parent / "testbed"

# Source-level sink detection patterns (copy from __main__.py, needed standalone)
_QUOTE = r"""['"]"""
_DIRECT_SINK_RE = re.compile(
    rf"(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*{_QUOTE}child_process{_QUOTE}\s*\)"
)
_DESTRUCT_RE = re.compile(
    rf"(?:const|let|var)\s+\{{\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*)\}}\s*=\s*require\s*\(\s*{_QUOTE}child_process{_QUOTE}\s*\)"
)
_SINK_MEMBER_RE = re.compile(
    r"""(\w+)\.(exec|execFileSync|execSync|spawn|spawnSync|fork|execArgv)\s*\("""
)

# ---------------------------------------------------------------------------
# Dataset helpers
# ---------------------------------------------------------------------------

def load_vfc_ids(path: Path | None = None) -> List[str]:
    """Return all non-empty lines from the VFC dataset."""
    p = path or VFC_DATASET
    return [line.strip() for line in p.read_text(errors="replace").splitlines() if line.strip()]


def find_testbed_dir(cve_id: str, root: Path | None = None) -> Path | None:
    """Map a CVE ID to its testbed directory.

    Direct match under `root`.  Falls back to matching npm:package:version → npm_package_version dirs.
    """
    r = root or TESTBED_ROOT
    candidate = r / cve_id
    if candidate.is_dir():
        return candidate

    # Handle npm:package:version → look for npm_pkg_version
    if cve_id.startswith("npm:"):
        parts = cve_id.split(":")
        if len(parts) == 3:
            pkg_name = parts[1]
            # Try with underscores replacing hyphens/dots too
            for variant in [pkg_name, pkg_name.replace("-", "_"), pkg_name.replace(".", "_")]:
                alt = f"npm_{variant}_{parts[2].replace('-', '_').replace('.', '_')}"
                alt_candidate = r / alt
                if alt_candidate.is_dir():
                    return alt_candidate
            # Last resort: partial match on package name
            for entry in r.iterdir():
                if entry.is_dir() and pkg_name.lower().replace("-", "_") in entry.name.lower():
                    return entry
    return None


# ---------------------------------------------------------------------------
# Result data classes
# ---------------------------------------------------------------------------

@dataclass
class CVEStats:
    """Per-CVE analysis results."""
    cve_id: str
    testbed_path: str = ""
    status: str = "unknown"          # success | failed_index | no_testbed | error
    graph_nodes: int = 0
    graph_edges: int = 0
    entry_points_count: int = 0
    matched_methods_count: int = 0
    sinks_count: int = 0
    source_sinks_count: int = 0
    taint_flows_count: int = 0
    mode: str = "unknown"            # paths_found | entry_points_only | no_data
    error_msg: str = ""
    duration_sec: float = 0.0
    entry_point_details: list = field(default_factory=list)
    taint_flow_details: list = field(default_factory=list)


@dataclass
class BatchStats:
    """Aggregate statistics across all CVEs."""
    total_cves: int = 0
    has_testbed: int = 0
    no_testbed_count: int = 0
    failed_index: int = 0
    succeeded_analysis: int = 0
    paths_found: int = 0
    entry_points_only: int = 0
    no_data: int = 0
    total_graph_nodes: int = 0
    total_graph_edges: int = 0
    total_entry_points: int = 0
    total_sinks: int = 0
    total_source_sinks: int = 0
    total_taint_flows: int = 0
    avg_graph_nodes: float = 0.0
    avg_graph_edges: float = 0.0
    avg_entry_points: float = 0.0
    avg_sinks: float = 0.0
    avg_taint_flows: float = 0.0
    total_time_sec: float = 0.0


# ---------------------------------------------------------------------------
# Source-level sink detection (for when SCIP call graph is too sparse)
# ---------------------------------------------------------------------------

def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")


def _parse_source_sinks(testbed_root: str) -> List[Dict[str, Any]]:
    """Scan JS/TS source files for dangerous sink calls that SCIP misses.

    Handles:
      1. Direct binding:     `const cp = require('child_process')` → `cp.execFile(`
      2. Destructuring:      `const { execFile } = require('child_process')` → `execFile(`
      3. Inline require:     `require('child_process').execFile(`

    Returns list of dicts with: symbol, file_path, line_no, callee, variable, is_real_sink
    """
    found: List[Dict[str, Any]] = []
    src_exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    file_bindings: Dict[str, set] = {}
    direct_aliases: Dict[str, str] = {}

    for root_dir, _dirs, files in os.walk(testbed_root):
        if "__scip_bootstrap_stub__" in root_dir:
            continue
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in src_exts:
                continue
            fpath = str(Path(root_dir) / fname)
            try:
                text = Path(fpath).read_text(errors="replace")
            except Exception:
                continue

            for m in _DIRECT_SINK_RE.finditer(text):
                direct_aliases[m.group(1)] = "child_process"

            names: set = set()
            for dm in _DESTRUCT_RE.finditer(text):
                raw_names = dm.group(1)
                for name_part in raw_names.split(","):
                    name_part = name_part.strip()
                    if name_part in ("exec", "execFile", "execFileSync", "execSync",
                                     "spawn", "spawnSync", "fork"):
                        names.add(name_part)
            if names:
                file_bindings[fpath] = names

    for fpath, destruct_names in file_bindings.items():
        try:
            text = Path(fpath).read_text(errors="replace")
        except Exception:
            continue

        lines = text.split("\n")
        binding_aliases: Dict[str, str] = {}
        for m in _DIRECT_SINK_RE.finditer(text):
            binding_aliases[m.group(1)] = "child_process"

        # A) Calls from destructured names
        for name in destruct_names:
            for line_no, line in enumerate(lines, start=1):
                call_re = re.compile(rf"\b{name}\s*\(")
                if call_re.search(line) and not _is_comment_line(line):
                    found.append({
                        "symbol": f"external/{name}",
                        "file_path": fpath,
                        "line_no": line_no,
                        "callee": name,
                        "variable": name,
                        "is_real_sink": True,
                    })

        # B) Calls through direct bindings (cp.execFile( etc.)
        for m in _SINK_MEMBER_RE.finditer(text):
            var_name = m.group(1)
            callee = m.group(2)
            if var_name not in binding_aliases:
                continue
            sink_fqn = f"{var_name}.{callee}"
            found.append({
                "symbol": f"external/{sink_fqn}",
                "file_path": fpath,
                "line_no": m.start(),
                "callee": callee,
                "variable": var_name,
                "is_real_sink": True,
            })

        # C) Inline require: require('child_process').execFile(
        for line_no, line in enumerate(lines, start=1):
            if re.search(rf"require\s*\(\s*{_QUOTE}child_process{_QUOTE}\s*\)\."
                         rf"(?:exec|execFileSync|execSync|spawn|spawnSync|fork|execArgv)\s*\(", line):
                sink_match = _SINK_MEMBER_RE.search(line)
                if sink_match:
                    callee = sink_match.group(2)
                    found.append({
                        "symbol": f"external/child_process.{callee}",
                        "file_path": fpath,
                        "line_no": line_no,
                        "callee": callee,
                        "variable": "child_process",
                        "is_real_sink": True,
                    })

    return found


# ---------------------------------------------------------------------------
# Entry point / sink detection heuristics
# ---------------------------------------------------------------------------

_ENTRY_KEYWORDS = frozenset([
    "execute", "run", "exec", "spawn", "launch", "start", "go",
    "ping", "traceroute", "curl", "wget", "fetch", "request",
    "arpping", "command", "shell", "system", "scan", "lookup",
])


def _is_entry_point(symbol: str, display_name: str) -> bool:
    dn = (display_name or "").lower()
    sym_lower = (symbol or "").lower().replace("`", "")
    parts = sym_lower.split("/")
    last_seg = parts[-1] if parts else ""

    # Skip test files and stubs
    if "test" in (getattr(symbol, "__module__", "") or "").lower():
        pass  # handled by caller on file_path
    return any(kw in last_seg or kw in dn for kw in _ENTRY_KEYWORDS)


def _is_sink_via_patterns(symbol: str, display_name: str) -> bool:
    """Check if a symbol matches dangerous sink patterns."""
    sym_lower = (symbol or "").lower().replace("`", "")
    dn = (display_name or "").lower()
    return any(pat in sym_lower or pat in dn for pat in _SHELL_SINK_PATTERNS)


# ---------------------------------------------------------------------------
# BFS-based taint flow tracing (standalone version of scan_package's intent)
# ---------------------------------------------------------------------------

def _bfs_taint_path(
    entry_symbol: str,
    entry_file: str,
    edges: list,
    adj: Dict[str, List[str]],
    visited_limit: int = 200,
) -> list[TaintFlow]:
    """BFS from *entry_symbol* through the call graph to find sink reaches."""
    def _normalize(sym: str) -> str:
        return sym.split("::")[-1].split("/")[-1].lower() if sym else ""

    def _is_sink(s: str) -> bool:
        sl = s.lower()
        for pat in _SHELL_SINK_PATTERNS:
            if pat in sl:
                return True
            if "." in pat:
                leaf = pat.split(".")[-1].replace("(", "").rstrip()
                if leaf and leaf.lower() == sl:
                    return True
        return False

    def _sink_details(s: str) -> TaintSink:
        if "exec" in s.lower():
            sink_type = "shell_exec"
        elif "spawn" in s.lower():
            sink_type = "shell_spawn"
        elif "system" in s.lower():
            sink_type = "shell_system"
        else:
            sink_type = "shell_unknown"
        return TaintSink(symbol=s, call_site_file="", call_site_line=0, sink_type=sink_type)

    def _symbol_name(sym: str) -> str:
        if not sym:
            return ""
        parts = sym.replace("\\", "/").split("/")
        return parts[-1]

    normalized_visited: set = set()
    queue: deque = deque([(entry_symbol, [])])  # (current_node, path_so_far)
    flows: list[TaintFlow] = []

    while queue and len(normalized_visited) < visited_limit:
        current, path = queue.popleft()
        nc = _normalize(current)
        if nc in normalized_visited:
            continue
        normalized_visited.add(nc)

        callees = adj.get(current)
        if not callees:
            # Fallback: look by stripped name for js_call_graph edges
            fallback_key = current.split("::")[0] if "::" in current else None
            if fallback_key:
                callees = adj.get(fallback_key)

        if not callees:
            continue

        for callee in callees:
            if _normalize(callee) in normalized_visited:
                continue
            if _is_sink(_symbol_name(callee)):
                sink_info = _sink_details(callee)
                flows.append(TaintFlow(
                    source=TaintSource(
                        symbol=entry_symbol,
                        parameter_index=0,
                        parameter_name="...",
                        file_path=entry_file,
                        line_number=0,
                    ),
                    sinks=[sink_info],
                    intermediate_calls=list(path),
                ))
            else:
                queue.append((callee, path + [_symbol_name(callee)]))

    return flows


# ---------------------------------------------------------------------------
# Scan driver (per-CVE)
# ---------------------------------------------------------------------------

def run_scan(testbed_path: Path) -> dict:
    """Run the full Phase 2a scan pipeline for a single CVE testbed.

    Returns a dict with keys: nodes, edges, entry_points, sinks, source_sinks,
    taint_flows, mode.
    """
    config = IndexerConfig(prefer_text_fallback=True)
    idx_result = index_package(str(testbed_path), opts=config)

    if not idx_result.available:
        return {"status": "failed_index", "error": idx_result.error or "no nodes"}

    nodes = idx_result.nodes
    edges = idx_result.edges

    # Build adjacency list for traversal (caller → callees)
    adj: Dict[str, List[str]] = {}
    for edge in edges:
        caller_sym = getattr(edge, "caller_symbol", None) or ""
        callee_sym = getattr(edge, "callee_symbol", None) or ""
        if caller_sym not in adj:
            adj[caller_sym] = []
        adj[caller_sym].append(callee_sym)

    # Identify entry points among all nodes
    entry_nodes = []
    for node in nodes:
        sym = getattr(node, "symbol", "") or ""
        dn = getattr(node, "display_name", "") or ""
        fp = getattr(node, "file_path", "") or ""

        if "test" in fp.lower() or "__scip_bootstrap_stub__" in fp:
            continue
        if _is_entry_point(sym, dn):
            entry_nodes.append(node)

    # Identify sinks among indexed nodes
    sink_nodes = []
    for node in nodes:
        sym = getattr(node, "symbol", "") or ""
        dn = getattr(node, "display_name", "") or ""
        if _is_sink_via_patterns(sym, dn):
            sink_nodes.append(node)

    # Source-level sink fallback (handles require('child_process') patterns)
    source_sinks = []
    if not sink_nodes:
        source_sinks = _parse_source_sinks(str(testbed_path))

    return {
        "status": "success",
        "nodes": len(nodes),
        "edges": len(edges),
        "entry_points": entry_nodes,
        "sinks": sink_nodes,
        "source_sinks": source_sinks,
        "adj": adj,
    }


def trace_flows_from_scan(scan_result: dict) -> list[TaintFlow]:
    """Trace taint flows from entry points found by scan_package.

    Combines indexed sinks and source-level sinks for BFS traversal.
    """
    entry_nodes = scan_result.get("entry_points", [])
    sink_nodes = scan_result.get("sinks", [])
    source_sinks = scan_result.get("source_sinks", [])
    adj = scan_result["adj"]

    if not entry_nodes:
        return []

    # Build set of sink symbols (from both indexed and source-level sinks)
    sink_symbols: set[str] = set()
    for n in sink_nodes:
        sym = getattr(n, "symbol", "") or ""
        if sym:
            sink_symbols.add(sym)
    for ss in source_sinks:
        sink_symbols.add(ss["symbol"])

    flows = []
    for ep in entry_nodes:
        ep_sym = getattr(ep, "symbol", "") or ""
        ep_file = getattr(ep, "file_path", "") or ""

        if not ep_sym:
            continue

        # BFS from entry point
        bfs_flows = _bfs_taint_path(
            entry_symbol=ep_sym,
            entry_file=ep_file,
            edges=[],  # adj list already computed above; BFS will use it directly
            adj=adj,
        )
        flows.extend(bfs_flows)

    return flows


def determine_mode(taint_flows: list[TaintFlow], entry_nodes, source_sinks) -> str:
    """Determine the analysis mode based on findings."""
    if len(taint_flows) > 0:
        return "paths_found"
    if entry_nodes:
        return "entry_points_only"
    # If we found nothing via SCIP but have source-level sinks, note that
    if source_sinks:
        return "entry_points_only"
    return "no_data"


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def run_single_cve(cve_id: str, testbed_path: Path) -> CVEStats:
    """Run the full scan pipeline for one CVE."""
    stats = CVEStats(cve_id=cve_id, testbed_path=str(testbed_path))

    t0 = time.time()

    try:
        scan_result = run_scan(testbed_path)
    except Exception as e:
        stats.status = "error"
        stats.error_msg = str(e)
        stats.duration_sec = time.time() - t0
        return stats

    if scan_result.get("status") == "failed_index":
        stats.status = "failed_index"
        stats.error_msg = scan_result.get("error", "indexing failed")
        stats.duration_sec = time.time() - t0
        return stats

    # Collect stats
    stats.graph_nodes = scan_result["nodes"]
    stats.graph_edges = scan_result["edges"]
    stats.sinks_count = len(scan_result.get("sinks", []))
    stats.source_sinks_count = len(scan_result.get("source_sinks", []))

    entry_nodes = scan_result["entry_points"]
    stats.entry_points_count = len(entry_nodes)
    stats.entry_point_details = [
        {"symbol": getattr(n, "symbol", ""), "display_name": getattr(n, "display_name", "")}
        for n in entry_nodes
    ]

    # Trace flows combining indexed + source-level sinks
    taint_flows = trace_flows_from_scan(scan_result)
    stats.taint_flows_count = len(taint_flows)

    if taint_flows:
        stats.taint_flow_details = [
            {
                "source": f.source.symbol,
                "sink": f.sinks[0].symbol if f.sinks else "",
                "path_len": len(f.intermediate_calls or []),
            }
            for f in taint_flows[:5]  # cap at 5 per CVE for storage size
        ]

    stats.mode = determine_mode(taint_flows, entry_nodes, scan_result.get("source_sinks", []))
    stats.status = "success"
    stats.duration_sec = time.time() - t0

    return stats


def run_batch(cve_ids: List[str], max_cves: int | None = None) -> tuple[List[CVEStats], BatchStats]:
    """Run graph analysis on all CVEs and return per-CVE stats + aggregates."""
    results: List[CVEStats] = []
    batch = BatchStats()
    batch.total_cves = len(cve_ids)

    limited = cve_ids[:max_cves] if max_cves else cve_ids
    batch.total_cves = len(limited)

    overall_start = time.time()
    success_count = 0

    for i, cve_id in enumerate(limited):
        t0 = time.time()
        print(f"\n[{i+1}/{batch.total_cves}] {cve_id}", end="", flush=True)

        # Find testbed
        testbed = find_testbed_dir(cve_id)
        if not testbed:
            stats = CVEStats(
                cve_id=cve_id,
                status="no_testbed",
                error_msg="No testbed directory found",
            )
            results.append(stats)
            batch.no_testbed_count += 1
            print(" [NO TESTBED]")
            continue

        batch.has_testbed += 1

        try:
            stats = run_single_cve(cve_id, testbed)
        except Exception as e:
            stats = CVEStats(
                cve_id=cve_id,
                testbed_path=str(testbed),
                status="error",
                error_msg=str(e),
                duration_sec=time.time() - t0,
            )
            results.append(stats)
            batch.failed_index += 1
            print(f" [ERROR: {e}]")
            continue

        if stats.status == "failed_index":
            batch.failed_index += 1
            print(f" [FAIL INDEX: {stats.error_msg}]")
        else:
            success_count += 1
            batch.succeeded_analysis += 1

            # Mode tally
            if stats.mode == "paths_found":
                batch.paths_found += 1
                print(f" [PATHS: {stats.taint_flows_count}] (eps={stats.entry_points_count}, sinks={stats.sinks_count + stats.source_sinks_count})")
            elif stats.mode == "entry_points_only":
                batch.entry_points_only += 1
                print(f" [ENT_ONLY: {stats.entry_points_count} eps] (sinks={stats.sinks_count + stats.source_sinks_count}, src={stats.source_sinks_count})")
            else:
                batch.no_data += 1
                print(f" [NO_DATA] (eps={stats.entry_points_count}, edges={stats.graph_edges})")

        # Aggregate counts
        if stats.status == "success":
            batch.total_graph_nodes += stats.graph_nodes
            batch.total_graph_edges += stats.graph_edges
            batch.total_entry_points += stats.entry_points_count
            batch.total_sinks += stats.sinks_count + stats.source_sinks_count
            batch.total_taint_flows += stats.taint_flows_count

    batch.total_time_sec = time.time() - overall_start
    if success_count > 0:
        batch.avg_graph_nodes = batch.total_graph_nodes / success_count
        batch.avg_graph_edges = batch.total_graph_edges / success_count
        batch.avg_entry_points = batch.total_entry_points / success_count
        batch.avg_sinks = batch.total_sinks / success_count
        batch.avg_taint_flows = batch.total_taint_flows / success_count

    return results, batch


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_summary(batch: BatchStats) -> None:
    """Print a human-readable summary to stdout."""
    print("\n" + "=" * 78)
    print("  BATCH GRAPH ANALYSIS SUMMARY")
    print("=" * 78)
    print(f"\n  CVE Dataset:               {batch.total_cves}")
    print(f"  Found testbed dir:         {batch.has_testbed}")
    print(f"  No testbed dir:            {batch.no_testbed_count}")
    print(f"  Failed indexing:           {batch.failed_index}")
    print(f"  Successful analysis:       {batch.succeeded_analysis}")
    print()
    print("  Mode breakdown (among successful analyses):")
    print(f"    paths_found:             {batch.paths_found}      ← traced data flow paths to sinks")
    print(f"    entry_points_only:       {batch.entry_points_only}  ← entry points found, no reachable sinks")
    print(f"    no_data:                 {batch.no_data}          ← nothing matched (empty graph / heuristics)")
    print()
    print("  Aggregate counts (among successes):")
    print(f"    Total graph nodes:       {batch.total_graph_nodes}")
    print(f"    Total graph edges:       {batch.total_graph_edges}")
    print(f"    Total entry points:      {batch.total_entry_points}")
    print(f"    Total indexed sinks:     {batch.total_sinks}")
    print(f"    Total taint flows:       {batch.total_taint_flows}")
    print()
    print("  Averages (among successful analyses):")
    print(f"    Avg graph nodes:         {batch.avg_graph_nodes:.1f}")
    print(f"    Avg graph edges:         {batch.avg_graph_edges:.1f}")
    print(f"    Avg entry points:        {batch.avg_entry_points:.1f}")
    print(f"    Avg sinks per CVE:       {batch.avg_sinks:.1f}")
    print(f"    Avg taint flows per CVE: {batch.avg_taint_flows:.2f}")
    print()
    print(f"  Total wall time:           {batch.total_time_sec:.1f}s")

    # Success rates
    if batch.has_testbed > 0:
        idx_rate = (batch.succeeded_analysis / batch.has_testbed) * 100
        flow_rate = (batch.paths_found / max(batch.succeeded_analysis, 1)) * 100
        print(f"\n  Success rate (indexed):    {idx_rate:.1f}%")
        print(f"  Flow discovery rate:       {flow_rate:.1f}%")

    # Per-mode tips
    if batch.paths_found > 0:
        print(f"\n  ✅ {batch.paths_found} CVE(s) have traced data flow paths — these are strong candidates for exploit generation.")
    if batch.entry_points_only > 0:
        print(f"\n  ⚠️  {batch.entry_points_only} CVE(s) have entry points but no reachable sinks (SCIP call graph may be sparse).")
    if batch.no_data > 0:
        print(f"\n  ℹ️  {batch.no_data} CVE(s) returned no data — may need diff-based analysis or larger testbeds.")

    print("=" * 78)


def save_results(
    cve_stats: List[CVEStats],
    batch: BatchStats,
    output_path: Path,
) -> None:
    """Save per-CVE results and aggregate stats to a JSON file."""
    out = {
        "batch_stats": asdict(batch),
        "cve_results": [asdict(s) for s in cve_stats],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(out, indent=2, default=str))
    print(f"\n📄 Results saved to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch graph analysis for SecBench.js VFC-filtered CVEs.",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=VFC_DATASET,
        help=f"Path to VFC dataset (default: {VFC_DATASET})",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=None,
        help="Limit analysis to first N CVEs (for testing).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "scripts" / "batch_results.json",
        help="Output JSON file path.",
    )
    args = parser.parse_args()

    # Load CVE IDs
    cve_ids = load_vfc_ids(args.dataset)
    print(f"Loaded {len(cve_ids)} CVE IDs from {args.dataset}")

    if not cve_ids:
        print("ERROR: No CVE IDs found in dataset.", file=sys.stderr)
        sys.exit(1)

    # Run batch analysis
    cve_stats, batch = run_batch(cve_ids, max_cves=args.max_cves)

    # Print summary
    print_summary(batch)

    # Save results
    save_results(cve_stats, batch, args.output)


if __name__ == "__main__":
    main()
