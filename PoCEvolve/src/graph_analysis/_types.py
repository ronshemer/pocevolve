"""Core data types for the AST-based CVE analysis pipeline.

These types capture immutable results from static analysis of CVE fix diffs.
The diff-to-method matching uses deleted-line positions to locate removed code,
and entry-point detection scans for ``module.exports`` expressions in source files.

No longer depends on:
- ``src.indexer`` (SCIP / call graph)
- ``graph_matcher`` (diff->graph node mapping)
- ``taint_flow`` (BFS taint propagation)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ---------------------------------------------------------------------------
# DiffEntry (unchanged)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiffEntry:
    """One matched method, grouping relevant deleted diff lines.

    ``orig_line_start / orig_line_end`` refer to the **original** file.
    Added lines are ignored for matching.
    """

    file_path: str  # path relative to package root (e.g. src/foo.js)
    method_name: str  # extracted from the hunk header or diff line
    parameter_names: list[str] = field(default_factory=list)

    orig_line_start: int | None = None  # deleted line range in original file
    orig_line_end: int | None = None

    new_line_start: int | None = None  # added line range (informational only)
    new_line_end: int | None = None

    change_type: str = "unknown"  # "added", "deleted", "modified"
    removed_lines: list[int] = field(default_factory=list)
    added_lines: list[int] = field(default_factory=list)
    added_line_anchors: list[int] = field(default_factory=list)
    diff_symbols: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AnalysisResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnalysisResult:
    """Immutable result of running ``run_analysis()`` on a CVE fix diff.

    Only entry-point details are captured; ``taint_flows`` is always empty
    because data-flow tracing requires the SCIP call graph that we have
    temporarily disabled.
    """

    cve_id: str
    matched_methods: list[DiffEntry] = field(default_factory=list)
    entry_points: list[dict] = field(default_factory=list)
    target_methods: list[dict] = field(default_factory=list)
    taint_flows: list = field(default_factory=list)  # empty until SCIP is restored
    mode: str = "entry_points_only"

    def elapsed(self) -> str:
        """Return the elapsed time as a formatted string."""
        if not hasattr(self, "_start"):
            return "N/A"
        elapsed_secs = time.monotonic() - self._start
        if elapsed_secs < 1:
            return f"{elapsed_secs * 1000:.0f}ms"
        return f"{elapsed_secs:.1f}s"


# ---------------------------------------------------------------------------
# Entry-point categories (for tracking why we detected a function as an entry)
# ---------------------------------------------------------------------------


class EntryPointKind(str, Enum):
    """How the analyzer determined that a file is an entry point."""

    MODULE_EXPORTS = "module.exports"
    PROTOTYPE_ASSIGNMENT = "prototype_assignment"
    ARROW_FUNCTION_PROTOTYPE = "arrow_fn_proto"
