"""Shared data classes for the SCIP indexer module.

All other sub‑modules in ``src.indexer`` import from here so there are no
circular dependencies between sibling packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class NodeInfo:
    """A node in the call graph (a function / class / module)."""

    symbol: str
    kind: str            # e.g. "Function", "Class"
    display_name: str = ""
    file_path: str = ""
    line_range: tuple[int, int] | None = None


@dataclass(slots=True)
class EdgeInfo:
    """A call-site → callee edge in the call graph."""

    caller_symbol: str
    callee_symbol: str
    kind: str            # e.g. "calls"
    location: str        # file:line


@dataclass(slots=True)
class IndexResult:
    """Result from scanning a package with scip-typescript."""

    root_path: str
    available: bool = False
    nodes: list["NodeInfo"] = field(default_factory=list)  # noqa: F821
    edges: list["EdgeInfo"] = field(default_factory=list)  # noqa: F821
    symbol_map: dict[str, "NodeInfo"] = field(default_factory=dict)  # noqa: F821
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
