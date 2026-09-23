"""Normalise parsed SCIP symbols into a clean node / edge call graph.

The parser produces flat :class:`~src.indexer.parser.Document` objects whose
``symbols`` list contains definition symbols (not references).  This module
deduplicates those symbols and extracts edges from relationships to build:

* **Nodes** — unique definitions (functions, classes, modules).
* **Edges** — call-site → callee relationships extracted from symbol
  ``relationships`` and ``occurrences``.

The graph is relative to the provided *root_path* so that file-level paths are
consistent across indexing runs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from src.indexer._proto import scip_pb2 as proto
from src.indexer._types import EdgeInfo, NodeInfo  # node/edge dataclasses

logger = logging.getLogger(__name__)

# Symbolic bit-masks for symbol_roles in Occurrence messages.
ROLE_DEFINITION = 1 << 0   # 1
ROLE_IMPORT     = 1 << 1   # 2
ROLE_WRITE_ACCESS = 1 << 2 # 4
ROLE_READ_ACCESS  = 1 << 3 # 8

# SCIP Kind enum values we consider as graph nodes.
NODE_KINDS = frozenset({
    0x11,  # Function
    0x7,   # Class
    0x1d,  # Module
    0x14,  # Extension
    0x20,  # Interface
    0x2e,  # Trait
    0x2a,  # Struct
    0x35,  # Type
})


@dataclass(slots=True)
class NormalizedGraph:
    """A deduplicated call graph derived from one or more :class:`~src.indexer.parser.Document` objects."""

    nodes: list[NodeInfo] = field(default_factory=list)
    edges: list[EdgeInfo] = field(default_factory=list)
    symbol_map: dict[str, NodeInfo] = field(default_factory=dict)  # full_symbol -> node lookup


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalise(
    documents: list[proto.Document],
    root_path: str,
) -> NormalizedGraph:
    """Build a :class:`NormalizedGraph` from a sequence of SCIP *documents*.

    Parameters
    ----------
    documents : list[:class:`~src.indexer._proto.scip_pb2.Document`]
        Flat document messages from the parsed ``.scip`` file.
    root_path : str
        Filesystem path that the index was rooted at (used for normalisation).

    Returns
    -------
    NormalizedGraph
        Deduplicated nodes and edges covering all *documents*.
    """
    if not documents:
        return NormalizedGraph()

    graph = NormalizedGraph()

    # Phase 1 — collect symbols whose Kind indicates a node-worthy entity.
    definitions: dict[str, proto.SymbolInformation] = {}
    for doc in documents:
        for sym in doc.symbols:
            key = sym.symbol
            if not _is_node_kind(sym) or key in definitions:
                continue
            definitions[key] = sym

    # Phase 2 — turn symbols into graph nodes.
    for sym_def, node in _symbols_to_nodes(definitions, root_path).items():
        graph.nodes.append(node)
        graph.symbol_map[sym_def] = node

    # Phase 3 — extract edges from relationships and occurrences.
    edges: list[EdgeInfo] = []
    seen_edges: set[tuple[str, str, str]] = set()

    for doc in documents:
        # Edges from SymbolInformation.relationships (is_reference=True).
        for sym in doc.symbols:
            if not sym.HasField("relationships"):
                continue
            for rel in sym.relationships:
                edge_key = (sym.symbol, rel.symbol, "calls")
                if edge_key not in seen_edges and rel.is_reference:
                    caller_node = graph.symbol_map.get(sym.symbol)
                    if caller_node:
                        edges.append(EdgeInfo(
                            caller_symbol=caller_node.display_name or sym.symbol,
                            callee_symbol=rel.symbol,
                            kind="calls",
                            location=f"{doc.relative_path}:0",
                        ))
                    seen_edges.add(edge_key)

        # Edges from Occurrence messages pointing to definitions.
        for occ in doc.occurrences:
            roles = _get_occurrence_roles(occ)
            if not (roles & ROLE_DEFINITION):
                continue
            sym_name = occ.symbol
            location = _occurrence_location(doc, occ)

            targets = _resolve_targets(sym_name, doc.symbols)
            for target_sym in targets:
                edge_key = (sym_name, target_sym, "calls")
                if edge_key not in seen_edges:
                    caller_node = graph.symbol_map.get(sym_name)
                    if caller_node:
                        edges.append(EdgeInfo(
                            caller_symbol=caller_node.display_name or sym_name,
                            callee_symbol=target_sym,
                            kind="calls",
                            location=location,
                        ))
                    seen_edges.add(edge_key)

    graph.edges = edges
    return graph


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_node_kind(sym: proto.SymbolInformation) -> bool:
    """Return True if *sym*'s Kind indicates a call-graph node."""
    kind_val = 0
    if hasattr(sym, "kind") and sym.HasField("kind"):
        kind_val = sym.kind
    return kind_val in NODE_KINDS


def _symbols_to_nodes(
    definitions: dict[str, proto.SymbolInformation], root_path: str
) -> dict[str, NodeInfo]:
    """Convert definition symbols to :class:`NodeInfo` entries."""
    nodes: dict[str, NodeInfo] = {}

    for symbol, sym in definitions.items():
        kind = _symbol_kind(sym)
        # Extract short display name from the full qualified symbol.
        parts = symbol.replace("sourcegraph://", "").split("/")
        display_name = parts[-1] if parts else symbol.split(":")[-1]

        # Derive relative file path from the symbol.
        file_path = _extract_file_path(sym, root_path)

        line_range: tuple[int, int] | None = None
        if sym.HasField("signature_documentation") and sym.signature_documentation.HasField("occurrences"):
            occurrences = sym.signature_documentation.occurrences
            if occurrences:
                occ = occurrences[0]
                line_start = _get_line(occ)
                line_range = (line_start, line_start)

        nodes[symbol] = NodeInfo(
            symbol=symbol,
            kind=kind,
            display_name=display_name,
            file_path=file_path,
            line_range=line_range,
        )

    return nodes


def _get_line(occ: proto.Occurrence) -> int:
    """Extract start-line from an :class:`~src.indexer._proto.scip_pb2.Occurrence`."""
    if hasattr(occ, "single_line_range") and occ.HasField("single_line_range"):
        return occ.single_line_range.line + 1  # SCIP is 0-based → 1-based
    if hasattr(occ, "multi_line_range") and occ.HasField("multi_line_range"):
        return occ.multi_line_range.start_line + 1
    return 1


def _get_occurrence_roles(occ: proto.Occurrence) -> int:
    """Return the integer bit-mask of roles from an :class:`~src.indexer._proto.scip_pb2.Occurrence`."""
    if hasattr(occ, "symbol_roles") and occ.HasField("symbol_roles"):
        return occ.symbol_roles
    # Fallback: scan relationships for definition flags.
    role_mask = 0
    for rel in (getattr(occ, "relationships", []) or []):
        if rel.is_definition:
            role_mask |= ROLE_DEFINITION
    return role_mask


def _extract_file_path(sym: proto.SymbolInformation, root_path: str) -> str:
    """Derive a filesystem path from a symbol's full_symbol."""
    # SCIP symbols follow scheme://package/path/to/file:symbol pattern.
    # e.g., "sourcegraph://typescript/nx/src/indexer/parser.ts:Parser.parse"
    clean = sym.symbol.replace("sourcegraph://", "")
    parts = clean.split("/", 1)
    if len(parts) >= 2 and ":" in parts[1]:
        path_part = parts[1].split(":", 1)[0]  # strip ":symbol" suffix
        return str(Path(root_path) / path_part)
    # Fallback: last segments look like a path.
    all_parts = sym.symbol.split("/")
    if len(all_parts) >= 3 and all_parts[-1].endswith((".ts", ".js")):
        file_path = "/".join(all_parts[-2:])
        return str(Path(root_path) / file_path)
    return root_path


def _occurrence_location(doc, occ: proto.Occurrence) -> str:
    """Return a human-readable ``file:line`` string for *occ* within *doc*."""
    line = _get_line(occ)
    path = getattr(doc, "relative_path", "") or ""
    return f"{path}:{line}"


def _symbol_kind(sym: proto.SymbolInformation) -> str:
    """Derive a human-friendly kind string from the SCIP symbol Kind enum."""
    kind_map = {
        1: "Array",
        2: "Assertion",
        5: "Boolean",
        7: "Class",
        8: "Constant",
        9: "Constructor",
        10: "DataFamily",
        11: "Enum",
        12: "EnumMember",
        14: "Extension",
        15: "Field",
        16: "File",
        17: "Function",
        18: "Getter",
        20: "Interface",
        22: "Library",
        23: "Macro",
        24: "Method",
        25: "Mixin",
        26: "Modifier",
        27: "Module",
        28: "Namespace",
        30: "Number",
        31: "Object",
        32: "Operator",
        33: "Package",
        34: "PackageObject",
        35: "Parameter",
        36: "Predicate",
        37: "Property",
        38: "Protocol",
        40: "StaticMethod",
        41: "String",
        42: "Struct",
        43: "Tactic",
        44: "Theorem",
        46: "Trait",
        47: "Type",
        48: "TypeAlias",
        49: "TypeClass",
        50: "TypeFamily",
        51: "TypeParameter",
        52: "Union",
        53: "Variable",
        64: "AbstractMethod",
        72: "Accessor",
        78: "Attribute",
        90: "ConstantProperty",
        103: "TypeClassConstructor",
    }

    kind_val = 0
    if hasattr(sym, "kind") and sym.HasField("kind"):
        kind_val = sym.kind
    return kind_map.get(kind_val, f"Kind({kind_val})")


def _resolve_targets(symbol: str, symbols) -> list[str]:
    """Given a reference *symbol*, find Definition symbols it points to.

    In SCIP each occurrence carries a ``symbol`` field that may point to either
    a definition or a reference.  We resolve references to their corresponding
    Definition by matching on the full_symbol across all known symbols.
    """
    targets: list[str] = []

    # Direct match in symbol table.
    for sym in symbols:
        if hasattr(sym, "symbol") and sym.symbol == symbol:
            targets.append(symbol)
            return targets

    # Fallback: treat the symbol itself as a Definition.
    if not targets and symbol:
        targets.append(symbol)

    return targets
