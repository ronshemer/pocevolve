"""Orchestrate Phase 2a analysis: diff parsing → graph matching → taint extraction.

Coordinates the individual components (diff parser, graph matcher, taint flow
analyzer) into a single pipeline that takes a CVE fix diff and produces an enriched
:class:`AnalysisResult` with matched methods and reconstructed data flow paths.
"""

from __future__ import annotations

import logging
from typing import List

from src.graph_analysis._types import AnalysisResult, MatchedMethod, TaintFlow
from src.graph_analysis.diff_parser import parse_diff
from src.graph_analysis.graph_matcher import match_diff_to_graph
from src.graph_analysis.taint_flow import extract_taint_flows
from src.indexer._types import IndexResult

logger = logging.getLogger(__name__)


def run_analysis(
    cve_id: str,
    package_root: str,
    index_result: IndexResult,
    diff_text: str = "",
) -> AnalysisResult:
    """Run the full Phase 2a analysis pipeline for a single CVE.

    Parameters
    ----------
    cve_id:
        Identifier for the CVE being analyzed.
    package_root:
        Absolute path to the package whose call graph *index_result* represents.
    index_result:
        Call graph from :func:`src.indexer.scan`.  Must be **available**.
    diff_text:
        Raw unified diff of the CVE fix patch.

    Returns an :class:`AnalysisResult` with matched methods and taint flows.
    May be empty on both fields if no relevant data is found — this is normal.

    Raises
    ------
    ValueError
        If *index_result* is not available (empty graph).
    """
    if not index_result.available:
        raise ValueError(
            f"Cannot analyze unavailable index for {package_root}: "
            f"{index_result.error or 'no nodes'}"
        )

    logger.info(
        "graph_analysis[%s]: package=%s, diff_lines=%d, graph_nodes=%d, edges=%d",
        cve_id,
        package_root,
        len(diff_text.splitlines()) if diff_text else 0,
        len(index_result.nodes),
        len(index_result.edges),
    )

    # --- Phase A: parse the diff into structured entries ------------------
    diff_entries = parse_diff(diff_text) if diff_text.strip() else []
    logger.debug("diff_parser: %d entries for %s", len(diff_entries), cve_id)

    # --- Phase B: match diff entries to call graph nodes -----------------
    matched_methods: List[MatchedMethod] = []
    if diff_entries:
        matched_methods = match_diff_to_graph(diff_entries, index_result)
        logger.debug("graph_matcher: %d matches for %s", len(matched_methods), cve_id)

    # --- Phase C: extract taint flows from matched entry points ----------
    taint_flows: List[TaintFlow] = []
    if matched_methods and index_result.edges:
        taint_flows = extract_taint_flows(matched_methods, index_result)
        logger.debug("taint_flow: %d paths for %s", len(taint_flows), cve_id)

    return AnalysisResult(
        cve_id=cve_id,
        matched_methods=matched_methods,
        taint_flows=taint_flows,
        package_root=package_root,
    )
