"""Trace tainted data flow from entry points through intermediate calls to shell sinks.

Starting from methods identified in a CVE fix diff, reconstructs paths by which
untrusted values propagate through the in-package call graph until they reach
terminal sink APIs (e.g., ``child_process.exec``, ``os.system``).

This module operates purely on the Phase 1 call graph (nodes + edges) and produces
structured :class:`TaintFlow` objects for downstream prompt injection.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Dict, List, Optional, Set

from src.graph_analysis._types import MatchedMethod, TaintFlow, TaintSink, TaintSource
from src.indexer._types import IndexResult

logger = logging.getLogger(__name__)

# Known shell-command sink patterns in Node.js / TypeScript ecosystems
_SHELL_SINK_PATTERNS = frozenset([
    "child_process.exec",
    "child_process.spawn",
    "child_process.fork",
    "child_process.execFile",
    "child_process.spawnSync",
    "child_process.execFileSync",
    "child_process.execSync",
    "exec(",
    "spawn(",
    "system(",
    "popen(",
])

# Known untrusted / user input entry point patterns (heuristic)
_UNTRUSTED_ENTRY_PATTERNS = frozenset([
    "req.",       # Express.js request object
    "request.body",
    "request.query",
    "request.params",
    "process.argv",
    "stdin",
    "socket.",
])


def extract_taint_flows(
    matched_methods: List[MatchedMethod],
    index_result: IndexResult,
) -> List[TaintFlow]:
    """For each matched method, trace taint propagation to shell sinks.

    Parameters
    ----------
    matched_methods:
        Nodes identified as changed in the CVE fix diff (from :func:`graph_matcher`).
    index_result:
        Call graph output from the Phase 1 indexer.

    Returns an **empty** list when no taint paths can be recovered — never raises.
    """
    if not matched_methods or not index_result.nodes:
        return []

    edges = index_result.edges
    node_map = _build_node_lookup(index_result)

    all_flows: List[TaintFlow] = []
    seen_sources: set[str] = set()

    for method in matched_methods:
        # Determine if this method is itself a taint source (receives untrusted input)
        source = _infer_taint_source(method, node_map)
        if not source or source.symbol in seen_sources:
            continue
        seen_sources.add(source.symbol)

        # BFS through the call graph starting from this method
        flows_from_source = _bfs_taint_path(
            entry_symbol=source.symbol,
            entry_file=source.file_path,
            entry_line=source.line_number,
            edges=edges,
            node_map=node_map,
        )

        if not flows_from_source:
            # No path to a sink — this method may be safe or the graph is incomplete
            continue

        all_flows.extend(flows_from_source)

    return all_flows


def _build_node_lookup(index_result: IndexResult) -> Dict[str, object]:
    """Build a symbol → node lookup for fast edge resolution."""
    result: Dict[str, object] = {}
    if index_result.symbol_map:
        result.update(index_result.symbol_map)
    return result


def _infer_taint_source(
    method: MatchedMethod,
    node_map: Dict[str, object],
) -> Optional[TaintFlow.__dataclass_fields__["source"].default]:  # type: ignore[name-defined]
    """Determine if a matched method receives untrusted input.

    Heuristic: methods whose names contain known vulnerable patterns (e.g., "ping",
    "traceroute", "curl") and that accept parameters are treated as potential sources.
    More sophisticated inference would use static analysis of parameter annotations.
    """
    symbol = method.symbol
    # Common CVE-relevant patterns that suggest taint entry points
    taint_indicators = [
        "ping",
        "traceroute",
        "curl",
        "wget",
        "exec",
        "shell",
        "command",
        "run",
        "spawn",
    ]

    symbol_lower = symbol.lower()
    if any(ind in symbol_lower for ind in taint_indicators):
        return TaintSource(
            symbol=symbol,
            parameter_index=0,
            parameter_name="...",  # Would need full signature for real names
            file_path=method.file_path,
            line_number=method.line_range[0],
        )

    return None


def _bfs_taint_path(
    entry_symbol: str,
    entry_file: str,
    entry_line: int,
    edges: List,
    node_map: Dict[str, object],
) -> list[TaintFlow]:
    """BFS from *entry_symbol* through the call graph to find sink reaches."""
    # Build adjacency list for faster lookup
    adj: Dict[str, List] = {}
    for edge in edges:
        caller = _symbol_name(edge.caller_symbol) if hasattr(edge, "caller_symbol") else ""
        callee = _symbol_name(edge.callee_symbol) if hasattr(edge, "callee_symbol") else ""
        if caller not in adj:
            adj[caller] = []
        adj[caller].append(callee)

    # BFS traversal
    visited: Set[str] = set()
    queue: deque = deque([(entry_symbol, [])])  # (current_node, path_so_far)
    flows: list[TaintFlow] = []

    while queue:
        current, path = queue.popleft()

        if current in visited:
            continue
        visited.add(current)

        callees = adj.get(_symbol_name(current), [])
        for callee in callees:
            if _symbol_name(callee) in visited:
                continue

            # Check if this edge reaches a terminal sink
            is_sink = _is_sink_call(_symbol_name(callee), edges, node_map)

            new_path = path + [callee]
            if is_sink:
                sinks = [_find_sink_details(callee, edges, node_map)]
                flows.append(TaintFlow(
                    source=TaintSource(
                        symbol=entry_symbol,
                        parameter_index=0,
                        parameter_name="...",
                        file_path=entry_file,
                        line_number=entry_line,
                    ),
                    sinks=sinks,
                    intermediate_calls=list(new_path),
                ))
            else:
                queue.append((callee, new_path))

    return flows


def _is_sink_call(
    symbol: str,
    edges: List,
    node_map: Dict[str, object],
) -> bool:
    """Check if *symbol* represents a terminal sink (shell command)."""
    sym_lower = symbol.lower()
    if any(pat in sym_lower for pat in _SHELL_SINK_PATTERNS):
        return True
    # Also check pattern leaf names (for base-name matching in BFS adj list)
    # e.g. "child_process.exec" → leaf "exec" matches symbol "exec"
    for pat in _SHELL_SINK_PATTERNS:
        if "." in pat:
            leaf = pat.split(".")[-1].replace("(", "").rstrip()
            if leaf and sym_lower == leaf.lower():
                return True
    return False


def _find_sink_details(
    symbol: str,
    edges: List,
    node_map: Dict[str, object],
) -> TaintSink:
    """Extract sink type and call site details from a callee symbol."""
    sym_lower = symbol.lower()

    # Classify sink type
    if "exec" in sym_lower:
        sink_type = "shell_exec"
    elif "spawn" in sym_lower:
        sink_type = "shell_spawn"
    elif "system" in sym_lower:
        sink_type = "shell_system"
    else:
        sink_type = "shell_unknown"

    return TaintSink(
        symbol=symbol,
        call_site_file="",  # Would need edge source location for full detail
        call_site_line=0,
        sink_type=sink_type,
    )


def _symbol_name(symbol: str) -> str:
    """Normalize a SCIP symbol to its base name for matching."""
    # Split on common separators and return the last component
    parts = symbol.replace("\\", "/").split("/")
    return parts[-1].lower() if parts else ""
