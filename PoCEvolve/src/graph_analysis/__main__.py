"""CLI entry point for graph analysis (AST-based pipeline).

Usage:
    # With a CVE fix diff (full pipeline):
    python3 -B -m src.graph_analysis --testbed <path> --diff <patch.diff>

    # Without a diff — scan all package methods for entry points:
    python3 -B -m src.graph_analysis --testbed <path> --scan
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure the project root is on PYTHONPATH so `src.*` imports work.
_project_root = Path(__file__).resolve().parent.parent  # PoCEvolve/
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from src.graph_analysis._types import AnalysisResult  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sink keyword patterns (mirrors analyzer.py; kept here for CLI-only use)
# ---------------------------------------------------------------------------

_SHELL_SINK_PATTERNS: frozenset[str] = frozenset([
    "ping", "traceroute", "curl", "wget", "exec", "shell",
    "command", "spawn", "eval", "arpping", "arp-scan", "mac_lookup",
])

# Direct call patterns (when the require result is destructured / aliased):
_DIRECT_SINK_RE = re.compile(
    rf"""(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]child_process['"]\s*\)"""
)

# Member-access patterns: `child_process.execFile(`, `cp.spawn(`, etc.
_SINK_MEMBER_RE = re.compile(
    r"""(\w+)\.(exec|execFileSync|execSync|spawn|spawnSync|fork|execArgv)\s*\("""
)


# ---------------------------------------------------------------------------
# Entry-point / sink helpers (for --scan mode without a diff)
# ---------------------------------------------------------------------------

def _is_entry_point(symbol: str, display_name: str) -> bool:
    """Heuristic check whether a symbol is likely a user-input entry point."""
    dn = (display_name or "").lower()
    sym_lower = (symbol or "").lower().replace("`", "")

    parts = sym_lower.split("/")
    last_seg = parts[-1] if parts else ""

    entry_keywords = {
        "execute", "run", "exec", "spawn", "launch", "start", "go",
        "ping", "traceroute", "curl", "wget", "fetch", "request",
        "arpping", "command", "shell", "system",
    }
    for kw in entry_keywords:
        if kw in last_seg or kw in dn:
            return True

    return False


def _is_dangerous_sink(symbol: str, display_name: str) -> bool:
    """Check whether a symbol matches dangerous sink patterns."""
    dn = (display_name or "").lower()
    sym_lower = (symbol or "").lower().replace("`", "")

    for pattern in _SHELL_SINK_PATTERNS:
        if pattern in sym_lower or pattern in dn:
            return True
    return False


# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------

def _print_results(
    entry_points: List[str],
    sinks: List[str],
    flows: List[Dict],
    matched_methods: List[Any] | None = None,
    mode: str = "unknown",
) -> None:
    """Pretty-print scan results for an ``AnalysisResult``.

    *mode* controls the banner and which sections are shown:

    * ``paths_found`` — data flow paths exist (show flows).
    * ``entry_points_only`` — matched methods from diff, but no flows traced.
    * ``no_data`` — nothing matched at all.
    """
    if mode == "paths_found":
        banner_title = "DATA FLOW PATHS — Traced from entry points to targets"
    elif mode == "entry_points_only":
        banner_title = "ENTRY POINTS ONLY — No data flow paths (SCIP disabled)"
    elif mode == "no_data":
        banner_title = "NO DATA — Nothing matched in the call graph"
    else:
        banner_title = "DATA FLOW SCAN RESULTS"

    print("\n" + "=" * 78)
    print(f"  {banner_title}")
    print("=" * 78)

    if entry_points:
        print(f"\n📥 Entry Points ({len(entry_points)}):")
        for ep in entry_points[:20]:
            file_path = ep.get("file_path", "") if isinstance(ep, dict) else ep
            print(f"   • {file_path}")
            exported = ep.get("exported_methods", []) if isinstance(ep, dict) else []
            if exported:
                print(f"     exported methods: [{', '.join(exported)}]")
        if len(entry_points) > 20:
            print(f"   ... and {len(entry_points) - 20} more (use --json for full list)")

    if matched_methods:
        print(f"\n🎯 Matched Methods from commit ({len(matched_methods)}):")
        for mm in matched_methods:
            sym = getattr(mm, "method_name", "") or getattr(mm, "symbol", "") or ""
            fp = getattr(mm, "file_path", "") or ""
            start = getattr(mm, "orig_line_start", None)
            end = getattr(mm, "orig_line_end", None)
            params = getattr(mm, "parameter_names", []) or []
            basename = Path(fp).name if fp else ""
            line_info = f":{start}" if start else ""
            if end and end != start:
                line_info += f"-{end}"
            param_str = ", ".join(params) if params else "(no parameter info)"
            print(f"   • {basename}{line_info}  {sym}")
            removed = getattr(mm, "removed_lines", []) or []
            added = getattr(mm, "added_lines", []) or []
            anchors = getattr(mm, "added_line_anchors", []) or []
            symbols = getattr(mm, "diff_symbols", []) or []
            if removed:
                print(f"     removed lines: {removed}")
            if added:
                print(f"     added lines: {added}")
            if anchors:
                print(f"     vulnerable-source anchors: {anchors}")
            if symbols:
                print(f"     diff symbols: [{', '.join(symbols)}]")
            print(f"     params: [{param_str}]")

    if sinks:
        print(f"\n🚪 Dangerous Sinks ({len(sinks)}):")
        for snk in sinks[:20]:
            basename = Path(snk).name if "/" in snk else str(snk)[:40]
            sym_short = (snk[:80] + "...") if len(str(snk)) > 80 else str(snk)
            print(f"   • {basename}")
            print(f"     symbol: {sym_short}")

    if flows:
        print(f"\n🔗 Taint Flows ({len(flows)}):")
        for i, flow in enumerate(flows, 1):
            source = flow.get("source", "unknown")
            sink = flow.get("sink", "unknown")
            path_nodes = flow.get("path", [])

            print(f"\n  Flow #{i}:")
            print(f"    Source: {source}")
            print(f"    Sink:   {sink}")
            print(f"    Path ({len(path_nodes)} steps):")
            for j, step in enumerate(path_nodes):
                arrow = " → " if j < len(path_nodes) - 1 else ""
                sym = (step.get("symbol", "")[:60] + "...") if len(step.get("symbol", "")) > 60 else step.get("symbol", "")
                dn = step.get("display_name", "")
                label = f"{dn or sym}"
                marker = "📥" if j == 0 else ("🚪" if j == len(path_nodes) - 1 else "  ")
                print(f"      {marker} [{j}] {label}")

    elif not entry_points and not matched_methods:
        print("\n⚠️  No entry points detected (heuristics may need tuning).")
    elif not flows and mode == "entry_points_only":
        pass
    elif not flows:
        print("\nℹ️  No taint flows found from entry points to dangerous sinks.")

    print("\n" + "=" * 78)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AST-based CVE fix-diff analysis (entry points only).",
    )
    parser.add_argument(
        "--testbed",
        help="Existing package root (if omitted, create/reuse a vulnerable git checkout using --cve-id).",
    )
    parser.add_argument(
        "--diff",
        help="CVE fix patch text (file path or '-'). When provided, runs full diff-based pipeline.",
    )
    parser.add_argument(
        "--cve-id",
        help="CVE identifier used as a secondary lookup key for VFC auto-resolution "
             "(e.g. 'SNYK-JS-ISMYJSONVALID-597167' or 'GHSA-f522-ffg8-j8r6'). "
             "When omitted, the testbed directory basename is used.",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan all package methods for entry points (no diff required).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of pretty-print.",
    )
    parser.add_argument(
        "--output",
        help="Write JSON results to this path (requires --json).",
    )
    args = parser.parse_args()

    cve_id = args.cve_id or (Path(args.testbed).name if args.testbed else None)
    if not cve_id:
        parser.error("provide --cve-id when --testbed is omitted")

    if args.testbed:
        testbed_path = Path(args.testbed).resolve()
        if not testbed_path.is_dir():
            print(f"ERROR: testbed directory not found: {testbed_path}", file=sys.stderr)
            sys.exit(1)
    else:
        from src.graph_analysis.testbed_manager import ensure_git_testbed
        testbed_path = ensure_git_testbed(cve_id)

    # ---- Import the AST-based pipeline (no SCIP needed) --------------------
    from src.graph_analysis.analyzer import run_analysis  # noqa: E402
    from src.graph_analysis.vfc_loader import get_diff as vfc_get_diff  # noqa: E402

    # ---- Phase: resolve diff or scan --------------------------------------
    if args.scan or not args.diff:
        # Scan / no-diff mode: try VFC auto-resolution first, fall back to entry-point detection
        testbed_dir = testbed_path.name
        vfc_diff = vfc_get_diff(testbed_dir=testbed_dir, cve_id=cve_id)
        if vfc_diff:
            logger.info("VFC auto-resolved for testbed=%s", testbed_dir)
            result = run_analysis(
                cve_id=cve_id,
                package_root=str(testbed_path),
                diff_text=vfc_diff,
                testbed_dir=testbed_dir,
            )
        else:
            logger.warning("No VFC diff for %s — falling back to entry-point detection", testbed_dir)
            # Run with empty diff to get just entry points (no matched methods from a diff)
            result = run_analysis(
                cve_id=cve_id,
                package_root=str(testbed_path),
                diff_text="",  # no diff → no matched methods; only scanning happens
                testbed_dir=testbed_dir,
            )

    elif args.diff == "-":
        # Read diff from stdin
        diff_text = sys.stdin.read()
        if not diff_text.strip():
            print("ERROR: --diff - received empty input", file=sys.stderr)
            sys.exit(1)
        result = run_analysis(
            cve_id=cve_id,
            package_root=str(testbed_path),
            diff_text=diff_text,
            testbed_dir=testbed_path.name,
        )

    else:
        # Read diff from file
        diff_path = Path(args.diff)
        if not diff_path.is_file():
            print(f"ERROR: diff file not found: {diff_path}", file=sys.stderr)
            sys.exit(1)
        diff_text = diff_path.read_text()
        result = run_analysis(
            cve_id=cve_id,
            package_root=str(testbed_path),
            diff_text=diff_text,
            testbed_dir=testbed_path.name,
        )

    # ---- Phase: output -----------------------------------------------------
    if args.json:
        out = {
            "cve_id": result.cve_id,
            "mode": result.mode,
            "matched_methods": [
                {
                    "file_path": m.file_path,
                    "method_name": m.method_name,
                    "orig_line_start": m.orig_line_start,
                    "orig_line_end": m.orig_line_end,
                    "change_type": m.change_type,
                    "parameter_names": m.parameter_names,
                    "removed_lines": m.removed_lines,
                    "added_lines": m.added_lines,
                    "added_line_anchors": m.added_line_anchors,
                    "diff_symbols": m.diff_symbols,
                }
                for m in result.matched_methods
            ],
            "entry_points": result.entry_points,
            "target_methods": result.target_methods,
            "warnings": [],
        }
        rendered = json.dumps(out, indent=2, default=str)
        if args.output:
            output_path = Path(args.output).resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered + "\n", encoding="utf-8")
            print(f"Analysis JSON written to: {output_path}")
        else:
            print(rendered)
    else:
        # For display, convert AnalysisResult to the shapes _print_results expects
        entry_point_names = list(result.entry_points)
        sink_names: List[str] = []

        # For flows (empty until SCIP is restored)
        flow_dicts: List[Dict] = []

        _print_results(
            entry_points=entry_point_names,
            sinks=sink_names,
            flows=flow_dicts,
            matched_methods=result.matched_methods or [],
            mode=result.mode,
        )

    logger.info("done.")


if __name__ == "__main__":
    main()
