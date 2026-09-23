"""Parse unified diffs to extract method names, parameter names, and file paths.

Extracts changed regions (file paths, line ranges) and symbols referenced in the
diff lines (method calls like ``foo(bar)``), then classifies each change as added,
removed, or modified based on the diff prefix (+ / -).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from src.graph_analysis._types import DiffEntry

logger = logging.getLogger(__name__)

# Regex to extract a method call from a diff line: e.g. "  foo(bar)" or "baz(qux, quux)"
_METHOD_CALL_RE = re.compile(r"(?:[\.\-\>]\s+)?(\w+)\(([^)]*)\)")

# Regex for file path in diff headers (git diff output): + "-- a/path" / "+ b/path"
_FILE_HEADER_RE = re.compile(r"diff.*a/(.+?)\s+b/(.+)")

# Regex for "@@" hunk headers
_HUNK_HEADER_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_diff(diff_text: str) -> List[DiffEntry]:
    """Parse a unified diff into :class:`DiffEntry` objects.

    Extracts method/parameter changes from lines prefixed with ``+`` or ``-`` that
    contain function-call patterns (e.g., ``foo(bar)``).  Skips non-code diff
    headers (index, ---, +++), commit messages, and context-only lines.

    Parameters
    ----------
    diff_text:
        Raw unified diff text from a git patch or CVE fix.

    Returns an **empty** list when no method-like patterns are found in the diff.
    """
    if not diff_text.strip():
        return []

    entries: List[DiffEntry] = []
    current_file: str = ""
    hunk_line_start: int = 0
    seen: set[tuple[str, str, int]] = set()

    for line in diff_text.splitlines():
        # Track the current file from diff headers
        m = _FILE_HEADER_RE.match(line)
        if m:
            # "a/foo/bar.js" → "foo/bar.js"
            current_file = m.group(2).lstrip("/")
            continue

        # Track hunk line numbers
        m_hunk = _HUNK_HEADER_RE.match(line)
        if m_hunk:
            hunk_line_start = int(m_hunk.group(1))
            continue

        # Skip non-diff lines
        if not line.startswith("+") and not line.startswith("-"):
            continue

        # Determine change type from prefix
        prefix = line[0]
        code_line = line.lstrip("+- ").strip()
        if not code_line:
            continue

        is_added = prefix == "+"
        is_removed = prefix == "-"

        # Extract method calls from this diff line
        for call_name, call_params_str in _METHOD_CALL_RE.findall(code_line):
            key = (current_file, call_name, hunk_line_start)
            if key in seen:
                continue
            seen.add(key)

            params = [p.strip() for p in call_params_str.split(",") if p.strip()] if call_params_str else []

            entries.append(DiffEntry(
                file_path=current_file,
                method_name=call_name,
                parameter_names=params,
                line_start=hunk_line_start,
                line_end=hunk_line_start + 1,
                change_type="added" if is_added and not is_removed else
                           "removed" if is_removed and not is_added else
                           "modified",
            ))

        # Also try to extract the primary function being defined/changed on this line
        # e.g. in a function signature like "function foo(bar)" or "const foo = (bar) =>"
        if not entries:  # avoid double-detection above for signature lines
            sig_match = re.match(
                r"(?:export\s+)?(?:async\s+)?function\s+(\w+)|"
                r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(|"
                r"(?:const|let|var)\s+(\w+):",
                code_line,
            )
            if sig_match:
                method_name = next(n for n in sig_match.groups() if n)
                file_key = (current_file, method_name, hunk_line_start)
                if file_key not in seen:
                    seen.add(file_key)
                    # Try to extract params from the signature itself
                    param_match = re.search(r"\(([^)]*)\)", code_line)
                    params = [p.strip().split(":")[0].strip() for p in param_match.group(1).split(",") if p.strip()] if param_match else []
                    entries.append(DiffEntry(
                        file_path=current_file,
                        method_name=method_name,
                        parameter_names=params,
                        line_start=hunk_line_start,
                        line_end=hunk_line_start + 1,
                        change_type="modified",
                    ))

    return entries
