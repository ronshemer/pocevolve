"""Public API for CVE fix-diff analysis.

This package provides ``analyze_cve()``, which runs an **AST-based** pipeline:

1. Parse the diff text → ``DiffEntry`` objects (deleted lines only).
2. Detect entry points via ``module.exports`` expressions using espree AST parsing.
3. For each deleted line, resolve the enclosing function name via
   ``method_resolution.get_enclosing_function_name()``.
4. Check method names against sink keywords (``eval``, ``exec``, ``spawn``, etc.).

**No SCIP call graph or taint propagation is performed** — that functionality
is deferred until a working static index for pure JavaScript becomes available.

Related memories:
- [[zero-cves-skipped-batch-analysis]] — prior batch run context
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from src.graph_analysis._types import AnalysisResult, DiffEntry
from src.graph_analysis.vfc_loader import get_diff as vfc_get_diff  # VFC diff resolver
from src.graph_analysis.diff_parser import parse_diff  # only_deleted=True by default
from src.graph_analysis.method_resolution import get_enclosing_function_name

if TYPE_CHECKING:
    pass  # no heavy imports at module level — keep CLI fast

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------


def analyze_cve(
    cve_id: str,
    package_root: str | Path,
    diff_text: str = "",
    file_path_hint: str | None = None,
    testbed_dir: str | None = None,
) -> AnalysisResult:
    """Analyze a CVE fix diff using AST-based entry-point detection.

    Parameters
    ----------
    cve_id:
        CVE identifier (e.g. ``"CVE-2024-1234"``).
    package_root:
        Path to the checked-out testbed directory containing JS source files.
    diff_text:
        Unified diff text (may come from VFC entries or a raw patch file).
    file_path_hint:
        Optional path hint for narrowing entry-point search.  Ignored in the
        current AST-based pipeline; kept for API compatibility.
    testbed_dir:
        Directory name used as a secondary lookup key for VFC auto-resolution.

    Returns
    -------
    AnalysisResult
        Always has ``mode="entry_points_only"`` because data-flow tracing is
        temporarily disabled (SCIP call graph unavailable for pure JS).

    Example
    -------
    >>> result = analyze_cve(
    ...     cve_id="CVE-2024-1234",
    ...     package_root="/tmp/testbeds/pkg",
    ...     diff_text=vfc_get_diff("pkg"),
    ... )
    >>> print(result.matched_methods)
    """
    # Use run_analysis from analyzer.py — the core AST-based pipeline
    from src.graph_analysis.analyzer import (
        run_analysis as _run_analysis,  # local import to keep CLI fast
    )

    return _run_analysis(
        cve_id=cve_id,
        package_root=str(package_root),
        diff_text=diff_text or "",
        file_path_hint=file_path_hint,
        testbed_dir=testbed_dir,
    )


# ---------------------------------------------------------------------------
# Convenience: auto-resolve VFC diff for a given testbed
# ---------------------------------------------------------------------------


def analyze_testbed(
    testbed_dir: str,
    package_root: str | Path | None = None,
) -> AnalysisResult:
    """Auto-resolve VFC diff for *testbed_dir* and run the analysis pipeline.

    This is a convenience wrapper around ``analyze_cve`` that:
    1. Looks up the CVE fix diff from VFC entries (via ``vfc_loader.get_diff``).
    2. Falls back to scanning all JS files for entry points if no VFC match.

    Parameters
    ----------
    testbed_dir:
        Directory name to look up in VFC data (e.g. ``"arpping@0db06723"``).
    package_root:
        Override for the testbed directory path.  When omitted, ``testbed_dir``
        is used as-is.

    Returns
    -------
    AnalysisResult
        With matched methods and entry points (mode="entry_points_only").
    """
    if package_root is None:
        package_root = testbed_dir

    # Try VFC auto-resolution first
    vfc_diff = vfc_get_diff(testbed_dir=testbed_dir)
    if vfc_diff:
        logger.info("VFC auto-resolved for testbed=%s", testbed_dir)
        return analyze_cve(
            cve_id=testbed_dir,
            package_root=package_root,
            diff_text=vfc_diff,
            testbed_dir=testbed_dir,
        )

    # Fallback: no VFC data — scan all files for entry points only
    logger.warning("No VFC diff for %s — returning empty result", testbed_dir)
    return AnalysisResult(
        cve_id=testbed_dir,
        mode="entry_points_only",
        warnings=[f"No VFC data available for {testbed_dir}"],
    )


# ---------------------------------------------------------------------------
# CLI hook (when run as __main__)
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point — same signature as the old ``__main__.py``.

    Usage:
        python3 -B -m src.graph_analysis --testbed <path> --diff <patch.diff>
        python3 -B -m src.graph_analysis --testbed <path> --scan
    """
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="AST-based CVE fix-diff analysis (entry points only).",
    )
    parser.add_argument(
        "--testbed",
        required=True,
        help="Path to the package root (e.g. PoCEvolve/src/git_testbeds/arpping@0db06723).",
    )
    parser.add_argument(
        "--diff",
        help="CVE fix patch text (file path or '-'). When provided, runs full diff-based pipeline.",
    )
    parser.add_argument(
        "--cve-id",
        help="CVE identifier used as a secondary lookup key for VFC auto-resolution.",
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
    args = parser.parse_args()

    testbed_path = Path(args.testbed).resolve()
    if not testbed_path.is_dir():
        print(f"ERROR: testbed directory not found: {testbed_path}", file=sys.stderr)
        sys.exit(1)

    # ---- Phase 1: resolve diff or scan ------------------------------------
    cve_id = args.cve_id or testbed_path.name

    if args.scan or not args.diff:
        result = analyze_testbed(str(testbed_path.name), str(testbed_path))
    elif args.diff == "-":
        diff_text = sys.stdin.read()
        if not diff_text.strip():
            print("ERROR: --diff - received empty input", file=sys.stderr)
            sys.exit(1)
        result = analyze_cve(
            cve_id=cve_id,
            package_root=str(testbed_path),
            diff_text=diff_text,
            testbed_dir=testbed_path.name,
        )
    else:
        diff_path = Path(args.diff)
        if not diff_path.is_file():
            print(f"ERROR: diff file not found: {diff_path}", file=sys.stderr)
            sys.exit(1)
        result = analyze_cve(
            cve_id=cve_id,
            package_root=str(testbed_path),
            diff_text=diff_path.read_text(),
            testbed_dir=testbed_path.name,
        )

    # ---- Phase 2: output ---------------------------------------------------
    if args.json:
        import json

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
            "warnings": result.warnings,
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        _print_results(result)


def _print_results(result: AnalysisResult) -> None:
    """Pretty-print an ``AnalysisResult`` for CLI consumption."""
    mode_titles = {
        "entry_points_only": "ENTRY POINTS ONLY — No data flow paths (SCIP disabled)",
        "paths_found": "DATA FLOW PATHS — Traced from entry points to targets",
        "no_data": "NO DATA — Nothing matched in the call graph",
    }
    banner = mode_titles.get(result.mode, result.mode.upper())

    print("\n" + "=" * 78)
    print(f"  {banner}")
    print("=" * 78)

    if result.matched_methods:
        print(f"\n🎯 Matched Methods from commit ({len(result.matched_methods)}):")
        for m in result.matched_methods:
            parts = m.file_path.split("#", 1)  # strip any enrichment marker
            fp = parts[0]
            basename = Path(fp).name
            line_info = f":{m.orig_line_start}" if m.orig_line_start else ""
            params = ", ".join(m.parameter_names) if m.parameter_names else "(no param info)"
            print(f"   • {basename}{line_info}  {m.method_name}")
            if m.removed_lines:
                print(f"     removed lines: {m.removed_lines}")
            if m.added_lines:
                print(f"     added lines: {m.added_lines}")
            if m.added_line_anchors:
                print(f"     vulnerable-source anchors: {m.added_line_anchors}")
            if m.diff_symbols:
                print(f"     diff symbols: [{', '.join(m.diff_symbols)}]")
            print(f"     params: [{params}]")

    if result.entry_points:
        print(f"\n📥 Entry Points ({len(result.entry_points)}):")
        for ep in result.entry_points[:10]:
            file_path = ep.get("file_path", "") if isinstance(ep, dict) else ep
            print(f"   • {file_path}")
            exported = ep.get("exported_methods", []) if isinstance(ep, dict) else []
            if exported:
                print(f"     exported methods: [{', '.join(exported)}]")
        if len(result.entry_points) > 10:
            print(f"   ... and {len(result.entry_points) - 10} more (use --json for full list)")

    if result.warnings:
        print("\n⚠️  Warnings:")
        for w in result.warnings:
            print(f"   • {w}")

    print("\n" + "=" * 78)


if __name__ == "__main__":
    main()
