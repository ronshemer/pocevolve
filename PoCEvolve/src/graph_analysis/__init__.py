"""Public API for data flow analysis of CVE fix diffs against call graphs.

This module bridges Phase 1's in-package call graph (from ``src.indexer.scan``)
with exploit-relevant insights: which methods appear in a CVE fix diff, and how
tainted data flows through them to shell-command sinks.

Usage::

    from src.graph_analysis import analyze_cve

    result = analyze_cve(
        cve_id="CVE-2024-1234",
        package_root="/path/to/testbed",
        diff_text=...,  # CVE fix patch text
    )
    for entry in result.matched_methods:
        print(entry.method_name, "changed")
    for flow in result.taint_flows:
        print(flow.source, "→", flow.sinks)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from src.graph_analysis._types import AnalysisResult, TaintFlow
from src.graph_analysis.analyzer import run_analysis
from src.indexer import scan as index_package
from src.indexer.config import default_config

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiffToGraphMatch:
    """A method identified in a CVE fix diff and matched back to the call graph."""

    symbol: str
    file_path: str
    line_range: tuple[int, int]
    change_type: str  # "added", "removed", "modified"


def analyze_cve(
    cve_id: str,
    package_root: str | Path,
    diff_text: str = "",
) -> AnalysisResult:
    """Run Phase 2a analysis for a single CVE.

    Parameters
    ----------
    cve_id:
        Identifier for the CVE (used for tracing / caching).
    package_root:
        Path to the already-generated testbed directory for the vulnerable
        package. This is passed to the Phase 1 indexer.
    diff_text:
        Raw unified diff of the CVE fix patch.

    Returns an :class:`AnalysisResult` that may be empty if the indexer is
    unavailable or no matches are found — **graceful degradation**, never
    blocking.
    """
    # Step 1: build the in-package call graph (Phase 1)
    index_result = index_package(package_root, default_config())

    if not index_result.available:
        logger.debug(
            "graph_analysis skipped for %s (%s); falling back without data flow",
            package_root,
            index_result.error or "empty index",
        )
        return AnalysisResult(cve_id=cve_id, matched_methods=[], taint_flows=[])

    # Step 2: diff-to-graph matching + taint extraction
    try:
        result = run_analysis(
            cve_id=cve_id,
            package_root=str(Path(package_root).resolve()),
            index_result=index_result,
            diff_text=diff_text,
        )
    except Exception as exc:
        logger.warning("graph_analysis error for %s: %s", package_root, exc)
        return AnalysisResult(cve_id=cve_id, matched_methods=[], taint_flows=[])

    return result
