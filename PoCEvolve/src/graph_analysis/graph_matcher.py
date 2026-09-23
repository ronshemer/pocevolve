"""Match DiffEntry objects against call graph nodes from the Phase 1 indexer.

Maps method names, parameter names, and file paths extracted from a CVE fix diff
back to corresponding nodes (functions/classes/modules) in the indexed in-package
call graph, enabling downstream taint analysis with concrete symbol-level context.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List

from src.graph_analysis._types import DiffEntry, MatchedMethod
from src.indexer._types import IndexResult

logger = logging.getLogger(__name__)


def match_diff_to_graph(
    diff_entries: List[DiffEntry],
    index_result: IndexResult,
) -> List[MatchedMethod]:
    """Map *diff_entries* to call graph nodes identified as modified in the diff.

    For each DiffEntry, attempts to resolve a matching node via three strategies (in
    priority order):

    1. **Symbol-map lookup** by full symbol path (file path + method name).
    2. **Fuzzy file-path + method-name** match against IndexResult.nodes.
    3. **Method-name-only** match when the file cannot be resolved.

    Parameters
    ----------
    diff_entries:
        Parsed diff entries from :func:`src.graph_analysis.diff_parser.parse_diff`.
    index_result:
        Call graph output from :func:`src.indexer.scan`.

    Returns an **empty** list when no nodes match any diff entry — never raises.
    """
    matched: List[MatchedMethod] = []
    seen_symbols: set[str] = set()

    for entry in diff_entries:
        # Strategy 1: symbol_map lookup by constructed full symbol path
        sym = _lookup_symbol_map(entry, index_result)
        if sym and sym not in seen_symbols:
            matched.append(sym)
            seen_symbols.add(sym.symbol)
            continue

        # Strategy 2: fuzzy file-path + method-name match against nodes list
        node = _match_node_by_file_and_name(entry, index_result.nodes)
        if node and node.symbol not in seen_symbols:
            matched.append(node)
            seen_symbols.add(node.symbol)
            continue

        # Strategy 3: method-name-only fallback when file resolution fails
        if not entry.file_path:
            candidates = _match_node_by_name_only(entry.method_name, index_result.nodes)
            for c in candidates[:1]:  # take first match only to reduce noise
                if c.symbol not in seen_symbols:
                    matched.append(c)
                    seen_symbols.add(c.symbol)

    return matched


def _lookup_symbol_map(
    entry: DiffEntry,
    index_result: IndexResult,
) -> MatchedMethod | None:
    """Try to find a matching node via the symbol map."""
    sym_map = index_result.symbol_map
    if not sym_map:
        return None

    # Build candidate paths by normalizing the file path
    candidates = _build_symbol_paths(entry, index_result)
    for candidate in candidates:
        if candidate in sym_map:
            node = sym_map[candidate]
            return MatchedMethod(
                symbol=candidate,
                file_path=node.file_path,
                line_range=(node.line_number, node.line_number + 1),
            )
    return None


def _match_node_by_file_and_name(
    entry: DiffEntry,
    nodes: List,
) -> MatchedMethod | None:
    """Find a node whose file_path and method name match the diff entry."""
    target_file = Path(entry.file_path).as_posix()  # normalize separators

    for node in nodes:
        node_file = Path(node.file_path).as_posix() if hasattr(node, "file_path") else ""
        node_method = _extract_name_from_symbol(node.symbol)

        if node_file and target_file in (node_file, f"src/{node_file}"):
            # Direct file match
            pass
        elif entry.file_path and not Path(entry.file_path).name:
            # Empty filename — skip fuzzy matching
            continue
        elif entry.file_path:
            # Partial or no path match — allow basename-only match
            node_basename = Path(node_file).name if node_file else ""
            target_basename = Path(target_file).name if target_file else ""
            if node_basename and target_basename and node_basename != target_basename:
                continue

        if node_method and entry.method_name and not _names_match(entry.method_name, node_method):
            continue

        return MatchedMethod(
            symbol=node.symbol,
            file_path=node.file_path if hasattr(node, "file_path") else "",
            line_range=(node.line_number, node.line_number + 1) if hasattr(node, "line_number") else (0, 0),
        )
    return None


def _match_node_by_name_only(
    method_name: str,
    nodes: List,
) -> List[MatchedMethod]:
    """Find all nodes whose symbol name matches *method_name*."""
    results: List[MatchedMethod] = []
    for node in nodes:
        node_method = _extract_name_from_symbol(node.symbol)
        if node_method and _names_match(method_name, node_method):
            results.append(MatchedMethod(
                symbol=node.symbol,
                file_path=node.file_path if hasattr(node, "file_path") else "",
                line_range=(node.line_number, node.line_number + 1) if hasattr(node, "line_number") else (0, 0),
            ))
    return results


def _build_symbol_paths(entry: DiffEntry, index_result: IndexResult) -> list[str]:
    """Construct candidate symbol paths from a DiffEntry."""
    paths: list[str] = []
    file_path = entry.file_path or ""

    # Common package prefix patterns to try
    prefixes = ["", "src/", "lib/"]
    suffixes = ["/index", ".js", ".ts", "/index.js", "/index.ts"]

    for prefix in prefixes:
        for suffix in suffixes:
            candidate_path = f"{prefix}{file_path}{suffix}" if file_path else ""
            if entry.method_name and candidate_path:
                paths.append(f"{candidate_path}/{entry.method_name}")
            elif candidate_path:
                paths.append(candidate_path)

    # Also try basename-only paths
    if file_path:
        basename = Path(file_path).name
        for prefix in prefixes:
            for suffix in suffixes:
                candidate_path = f"{prefix}{basename}{suffix}" if basename else ""
                if entry.method_name and candidate_path:
                    paths.append(f"{candidate_path}/{entry.method_name}")
    return paths


def _names_match(method_name: str, symbol_method_name: str) -> bool:
    """Check if *method_name* matches the method part of *symbol_method_name*."""
    # Normalize both names to lowercase for case-insensitive matching
    a = method_name.lower().strip()
    b = symbol_method_name.lower().strip()

    if a == b:
        return True

    # Check prefix/suffix variants (e.g., "fix" vs "__fix__")
    a_stripped = a.strip("_")
    b_stripped = b.strip("_")
    if a_stripped and b_stripped:
        return a_stripped in b_stripped or b_stripped in a_stripped

    return False


def _extract_name_from_symbol(symbol: str) -> str:
    """Extract the final method/class name from a full symbol path.

    Handles various SCIP symbol encodings like:
    - "src/utils.js/parseDiff" → "parseDiff"
    - "foo/bar.baz/MyClass/method" → "method"
    - "/path/to/file.js/functionName" → "functionName"
    """
    # Split on common symbol path separators
    parts = re.split(r"[/:.]", symbol)
    return parts[-1] if parts else symbol
