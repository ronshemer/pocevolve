"""Data classes for graph analysis results.

Defines structured representations of diff-matching output, taint sources/sinks,
and data flow paths that feed downstream pipeline stages (Phase 2b prompt injection).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(frozen=True)
class DiffEntry:
    """A change detected in a unified diff that maps to a graph node."""

    file_path: str  # relative path inside the package
    method_name: str
    parameter_names: List[str] = field(default_factory=list)
    line_start: int = 0
    line_end: int = 0
    change_type: str = "modified"  # "added", "removed", "modified"


@dataclass(frozen=True)
class TaintSource:
    """An entry point where untrusted data enters the method."""

    symbol: str
    parameter_index: int  # 0-based index into function parameters
    parameter_name: str
    file_path: str
    line_number: int


@dataclass(frozen=True)
class TaintSink:
    """A terminal point where tainted data reaches a dangerous API (e.g., shell)."""

    symbol: str
    call_site_file: str
    call_site_line: int
    sink_type: str  # "shell_exec", "system", "popen", etc.


@dataclass(frozen=True)
class TaintFlow:
    """A reconstructed path from taint source to one or more sinks."""

    source: TaintSource
    sinks: List[TaintSink] = field(default_factory=list)
    intermediate_calls: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class MatchedMethod:
    """A graph node identified as modified in the CVE fix diff."""

    symbol: str
    file_path: str
    line_range: tuple[int, int]  # (start, end)
    change_type: str = "modified"


@dataclass(frozen=True)
class AnalysisResult:
    """Output of Phase 2a analysis for a single CVE."""

    cve_id: str
    matched_methods: List[MatchedMethod] = field(default_factory=list)
    taint_flows: List[TaintFlow] = field(default_factory=list)
    error: Optional[str] = None
    package_root: str = ""


def _collect_sinks(flow: TaintFlow) -> list[TaintSink]:
    """Return all terminal sinks reachable from *flow*."""
    return flow.sinks if flow.sinks else []
