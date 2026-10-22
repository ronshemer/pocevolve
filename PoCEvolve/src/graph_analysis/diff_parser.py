"""Parse unified diffs to extract method names, parameter names, and file paths.

Extracts changed regions (file paths, line ranges) and symbols referenced in the
diff lines (method calls like ``foo(bar)``), then classifies each change as added,
removed, or modified based on the diff prefix (+ / -).
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List
import dataclasses

from src.graph_analysis._types import DiffEntry

logger = logging.getLogger(__name__)

# Regex to extract a method call from a diff line: e.g. "  foo(bar)" or "baz(qux, quux)"
_METHOD_CALL_RE = re.compile(r"(?:[\.\-\>]\s+)?(\w+)\(([^)]*)\)")

# Function-valued object properties and named function expressions.
_METHOD_DEF_RE = re.compile(r"(?:(?:var|let|const)\s+)?(\w+)\s*[:=]\s*(?:async\s+)?function\b")

# Regex for file path in diff headers (git diff output): + "-- a/path" / "+ b/path"
_FILE_HEADER_RE = re.compile(r"diff.*a/(.+?)\s+b/(.+)")

# Regex for "@@" hunk headers
_HUNK_HEADER_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# Regex to identify prototype method assignments in context lines:
# e.g. "Arpping.prototype.ping = function (flag) {" or "Foo.prototype.bar = function("
_PROTO_METHOD_RE = re.compile(
    r"(\w+)\.prototype\.(\w+)\s*=\s*(?:async\s+)?function"
)


def _git_substantive_deletions(diff_text: str) -> dict[str, set[int]] | None:
    """Map deleted source lines that remain after Git ignores whitespace.

    Each unified-diff hunk is reconstructed on its old and new sides, then
    aligned with ``git diff --ignore-all-space``. Git's own diff algorithm
    decides which old lines still represent substantive changes. ``None``
    means Git could not be run, in which case callers should preserve all
    deletions.
    """
    result: dict[str, set[int]] = {}
    current_file = ""
    hunk_start: int | None = None
    old_lines: list[str] = []
    new_lines: list[str] = []

    def finish_hunk() -> bool:
        nonlocal old_lines, new_lines
        if hunk_start is None:
            return True
        if not old_lines:
            return True
        try:
            with tempfile.TemporaryDirectory(prefix="pocevolve-diff-") as tmp:
                old_path = Path(tmp) / "old"
                new_path = Path(tmp) / "new"
                old_path.write_text("\n".join(old_lines) + "\n", encoding="utf-8")
                new_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                proc = subprocess.run(
                    ["git", "diff", "--no-index", "--ignore-all-space", "--unified=0",
                     "--", str(old_path), str(new_path)],
                    capture_output=True, text=True, check=False,
                )
        except (OSError, subprocess.SubprocessError):
            return False

        # git diff --no-index returns 1 when it found differences.
        if proc.returncode not in (0, 1):
            return False
        for line in proc.stdout.splitlines():
            match = _HUNK_HEADER_RE.match(line)
            if not match:
                continue
            old_index = int(match.group(1))
            old_count = int(match.group(2) or 1)
            for offset in range(old_count):
                result.setdefault(current_file, set()).add(hunk_start + old_index + offset - 1)
        return True

    for line in diff_text.splitlines():
        file_match = _FILE_HEADER_RE.match(line)
        if file_match:
            if not finish_hunk():
                return None
            current_file = file_match.group(2).lstrip("/")
            hunk_start = None
            old_lines, new_lines = [], []
            continue

        hunk_match = _HUNK_HEADER_RE.match(line)
        if hunk_match:
            if not finish_hunk():
                return None
            hunk_start = int(hunk_match.group(1))
            old_lines, new_lines = [], []
            continue

        if hunk_start is None or not line:
            continue
        prefix, content = line[0], line[1:]
        if prefix == " ":
            old_lines.append(content)
            new_lines.append(content)
        elif prefix == "-":
            old_lines.append(content)
        elif prefix == "+":
            new_lines.append(content)

    if not finish_hunk():
        return None
    return result


def parse_diff(
    diff_text: str,
    only_deleted: bool = False,
    only_added: bool = False,
    include_all_lines: bool = False,
    file_path_hint: str | None = None,
) -> List[DiffEntry]:
    """Parse a unified diff into :class:`DiffEntry` objects.

    Extracts method/parameter changes from lines prefixed with ``+`` or ``-`` that
    contain function-call patterns (e.g., ``foo(bar)``).  Skips non-code diff
    headers (index, ---, +++), commit messages, and context-only lines.

    Parameters
    ----------
    diff_text:
        Raw unified diff text from a git patch or CVE fix.
    only_deleted:
        When True, ignore ``+`` (added) lines — only process ``-`` (removed).
        Appropriate for vulnerability analysis where added lines contain the fix.
    only_added:
        When True, ignore ``-`` lines and use added lines as a fallback for
        add-only security fixes. Each added line is anchored to its old-side
        hunk position so callers can inspect the vulnerable checkout.
    include_all_lines:
        Emit an entry even when a changed line has no call or function pattern.
        Used with ``only_added`` for guards and other sanitization statements.
    file_path_hint:
        Optional filename (e.g. ``"index.js"``) used as a fallback when *diff_text*
        lacks a ``diff --git a/X b/Y`` header (common for VFC source_code_changes
        patches).  When provided and no header is found, the patch is wrapped
        with a synthetic header so :class:`DiffEntry` objects get a correct
        ``file_path``.

    Returns an **empty** list when no method-like patterns are found in the diff.
    """
    if only_deleted and only_added:
        raise ValueError("only_deleted and only_added cannot both be true")
    if not diff_text.strip():
        return []

    entries: List[DiffEntry] = []
    substantive_deletions = _git_substantive_deletions(diff_text) if only_deleted else None
    current_file: str = ""
    orig_line: int = 0        # position in the **original** (pre-fix) file
    new_line: int = 0         # position in the **new** (post-fix) file
    seen: set[tuple[str, str, int]] = set()

    # Collect context lines per hunk so we can identify enclosing prototype methods
    hunk_contexts: dict[int, list[str]] = {}      # hunk_start → [context lines]
    current_hunk: int = 0                           # line number of the active @@ header
    for ctx_line in diff_text.splitlines():
        if not ctx_line.startswith("+") and not ctx_line.startswith("-"):
            if current_hunk and current_hunk not in hunk_contexts:
                hunk_contexts[current_hunk] = []
            if current_hunk:
                hunk_contexts.setdefault(current_hunk, []).append(ctx_line)

        m_hunk = _HUNK_HEADER_RE.match(ctx_line)
        if m_hunk:
            current_hunk = int(m_hunk.group(1))

    def _enclosing_methods_for_hunk(hunk_start: int) -> List[str]:
        """Extract unique enclosing prototype identifiers from context lines.

        Returns tokens in "Class.method" form (e.g. ``"Arpping.ping"``) which
        can match both class-level and method-level display_names during graph
        matching.  Also appends bare method names so downstream name-only
        fallbacks still work.
        """
        methods: list[str] = []
        for ctx in hunk_contexts.get(hunk_start, []):
            m = _PROTO_METHOD_RE.search(ctx)
            if m:
                cls_name, meth_name = m.group(1), m.group(2)
                token = f"{cls_name}.{meth_name}"
                # Avoid storing duplicates (bare method or Class.method)
                if token not in methods and meth_name not in methods:
                    methods.append(meth_name)
                    methods.append(token)
        return methods

    for line in diff_text.splitlines():
        # 1. Track file path from diff headers: "diff --git a/X b/Y"
        m_file = _FILE_HEADER_RE.match(line)
        if m_file:
            current_file = m_file.group(2).lstrip("/")
            continue

        # 2. Track hunk headers and reset per-file position counters.
        m_hunk = _HUNK_HEADER_RE.match(line)
        if m_hunk:
            orig_line = int(m_hunk.group(1))   # start in original file (@@ -X ...)
            new_line = int(m_hunk.group(3))    # start in new file      (@@ +A ...)
            current_hunk = orig_line            # use orig_start as dict key
            continue

        # 3. Skip non-diff lines.
        if not line.startswith("+") and not line.startswith("-"):
            # Context line (prefix ' ') — advances both position counters.
            orig_line += 1
            new_line += 1
            continue

        # Determine change type from prefix
        prefix = line[0]
        is_added = prefix == "+"
        is_removed = prefix == "-"

        # Capture the current source position before advancing the counters.
        old_anchor = orig_line
        source_line = orig_line if line.startswith("-") else new_line
        if is_removed:
            orig_line += 1
        else:
            new_line += 1

        if only_deleted and is_added:
            continue
        if only_added and is_removed:
            continue
        if is_removed and substantive_deletions is not None:
            if source_line not in substantive_deletions.get(current_file, set()):
                continue

        code_line = line[1:].strip()
        if not code_line:
            continue

        # Select the canonical line number to associate with this entry.
        # For deleted lines we use the original-file position (orig_line),
        # which is what the SCIP graph represents.  Added lines would use
        # new_line, but only_deleted mode skips those anyway.
        _canonical = old_anchor if is_added and only_added else source_line
        entries_before_line = len(entries)

        # Extract method calls from this diff line
        for call_name, call_params_str in _METHOD_CALL_RE.findall(code_line):
            if call_name == "function":
                continue
            key = (current_file, call_name, _canonical)
            if key in seen:
                continue
            seen.add(key)

            params = [p.strip() for p in call_params_str.split(",") if p.strip()] if call_params_str else []

            entries.append(DiffEntry(
                file_path=current_file,
                method_name=call_name,
                parameter_names=params,
                orig_line_start=source_line if is_removed else (old_anchor if only_added else None),
                new_line_start=source_line if is_added else None,
                change_type="added" if is_added and not is_removed else
                           "removed" if is_removed and not is_added else
                           "modified",
            ))
            # e.g. in a function signature like "function foo(bar)" or "const foo = (bar) =>"
        if not any(e.file_path == current_file and e.orig_line_start == (source_line if is_removed else None)
                   and e.new_line_start == (source_line if is_added else None) for e in entries):
            sig_match = _METHOD_DEF_RE.match(code_line) or re.match(
                r"(?:export\s+)?(?:async\s+)?function\s+(\w+)|"
                r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(|"
                r"(?:const|let|var)\s+(\w+):",
                code_line,
            )
            if sig_match:
                method_name = next(n for n in sig_match.groups() if n)
                file_key = (current_file, method_name, _canonical)
                if file_key not in seen:
                    seen.add(file_key)
                    # Try to extract params from the signature itself
                    param_match = re.search(r"\(([^)]*)\)", code_line)
                    params = [p.strip().split(":")[0].strip() for p in param_match.group(1).split(",") if p.strip()] if param_match else []
                    entries.append(DiffEntry(
                        file_path=current_file,
                        method_name=method_name,
                        parameter_names=params,
                        orig_line_start=source_line if is_removed else (old_anchor if only_added else None),
                        new_line_start=source_line if is_added else None,
                        change_type="removed" if is_removed else "added",
                    ))

        if include_all_lines and len(entries) == entries_before_line:
            entries.append(DiffEntry(
                file_path=current_file,
                method_name="",
                orig_line_start=old_anchor if is_added and only_added else (source_line if is_removed else None),
                new_line_start=source_line if is_added else None,
                change_type="added" if is_added else "removed",
            ))


    # Fallback: when no diff header was found, use file_path_hint as the file path.
    # This handles VFC source_code_changes patches which have filename metadata but
    # lack the "diff --git a/X b/Y" headers that parse_diff normally relies on.
    if file_path_hint and not any(e.file_path for e in entries):
        entries = [dataclasses.replace(entry, file_path=file_path_hint) for entry in entries]

    return entries
