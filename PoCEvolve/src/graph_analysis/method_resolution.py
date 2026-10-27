"""Prototype detection and enclosing-function resolution for graph matching.

This module collects all prototype-detection logic that was previously
coupled inside ``graph_matcher.py``.  Three tiers are offered, applied
in order of increasing cost and decreasing accuracy:

1. **Tier-1** --- espree AST walk (most accurate; requires ``node -e``).
2. **Tier-2** --- ``ClassName.prototype.method = function()`` regex scan.
3. **Tier-3** --- arrow-function prototype pattern regex fallback.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Tier-1: AST-based enclosing-function detection (espree via node -e)
# ---------------------------------------------------------------------------

def _find_enclosing_function_by_espree(
    file_path: str,
    line_number: int,
) -> Optional[str]:
    """Use espree to parse *file_path* and return the innermost function name that spans *line_number*.

    The algorithm collects ALL function/method nodes that contain the target line
    and returns the one with the narrowest span (deepest nesting).  This ensures
    that for code like::

        function outer() {
            function inner() {
                console.log("hello"); // line 3 --> "inner"
            }
        }

    we return ``"inner"``, not ``"outer"``.

    Returns None when espree is unavailable or finds no enclosing function.
    """
    try:
        src_code = Path(file_path).read_text(errors="replace")
    except (OSError, IOError):
        return None

    if not src_code:
        return None

    code = json.dumps(src_code)  # safely escape for shell injection protection
    js_snippet = f"""
    var line = {line_number};
    var espree = require('espree');
    var ast = espree.parse({code}, {{ ecmaVersion: 2022, sourceType: 'module', loc: true }});
    var matches = [];
    function _lhs(node) {{
        if (!node) return null;
        if (node.type === 'Identifier' && node.name) return node.name;
        if (node.type === 'MemberExpression') {{
            if (node.property && node.property.name) return node.property.name;
            if (node.property && node.property.value) return node.property.value;
        }}
        return null;
    }}
    function walk(node, ctx) {{
        if (!node || typeof node !== 'object') return;
        var newCtx = ctx;
        if (node.type === 'AssignmentExpression' && node.left && !ctx) newCtx = _lhs(node.left);
        if (node.type === 'VariableDeclarator' && node.id && node.id.type === 'Identifier' && node.init &&
            (node.init.type === 'FunctionExpression' || node.init.type === 'ArrowFunctionExpression')) {{
            newCtx = node.id.name;
        }}
        if (node.type === 'Property' && node.key && node.key.type === 'Identifier' && node.value &&
            (node.value.type === 'FunctionExpression' || node.value.type === 'ArrowFunctionExpression')) {{
            newCtx = node.key.name;
        }}
        if ((node.type === 'FunctionDeclaration' || node.type === 'MethodDefinition' || node.type === 'FunctionExpression') && node.loc) {{
            var s = node.loc.start.line, e = node.loc.end.line;
            if (line >= s && line <= e) {{
                var name = null;
                if (node.type === 'FunctionDeclaration' && node.id && node.id.name) name = node.id.name;
                else if ((node.type === 'MethodDefinition' || node.type === 'Property') && node.key && node.key.name) name = node.key.name;
                if (!name && newCtx) name = newCtx;
                if (!name && node.type === 'FunctionExpression' && node.params && node.params[0]) {{
                    var p0s = JSON.stringify(node.params[0]);
                    if (p0s.indexOf('onMatch') !== -1) name = '__inline_onMatch__';
                    else if (p0s.indexOf('data') !== -1 || p0s.indexOf('payload') !== -1) name = '__inline_data__';
                }}
                if (name) matches.push([name, s, e]);
            }}
        }}
        var keys = Object.keys(node);
        for (var k = 0; k < keys.length; k++) {{
            if (keys[k] === 'loc' || keys[k] === 'range') continue;
            var v = node[keys[k]];
            if (Array.isArray(v)) {{ for (var i=0;i<v.length;i++) walk(v[i], newCtx); }}
            else if (typeof v === 'object') walk(v, newCtx);
        }}
    }}
    for (var t = 0; t < ast.body.length; t++) walk(ast.body[t], null);
    var bestName = null, bestSpan = -1;
    for (var j = 0; j < matches.length; j++) {{
        if (!matches[j][0]) continue;
        var span = matches[j][2] - matches[j][1];
        if (bestSpan === -1 || span < bestSpan) {{ bestSpan = span; bestName = matches[j][0]; }}
    }}
    console.log(bestName || 'NONE');
"""
    try:
        # Try multiple node module resolution paths
        res = subprocess.run(
            ["node", "-e", js_snippet],
            capture_output=True, text=True, timeout=15,
            env={**os.environ},  # type: ignore[name-defined]
        )
        out = res.stdout.strip()
        if out and out != "NONE":
            return out
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    return None


# ---------------------------------------------------------------------------
# Tier-2: Source-level prototype pattern matching
# ---------------------------------------------------------------------------

_PROTO_RE = re.compile(
    r"(\w+)"               # class name (group 1)
    r"\.prototype\."       # literal dot
    r"(\w+)"              # method name (group 2)
    r"\s*=\s*"            # assignment
    r"(?:function|\(.*\)\s*=>)",  # function keyword or arrow
)

# Also catch named function expressions on prototype: Class.prototype.method = function name() {}
_NAMED_PROTO_RE = re.compile(
    r"(\w+)"              # class name (group 1)
    r"\.prototype\."
    r"(\w+)"             # method name (group 2)
    r"\s*=\s*"
    r"function\s+"
    r"(\w+)"            # explicit function name (group 3)
)


def _collect_proto_definitions(lines: list[str]) -> list[tuple[int, str, str]]:
    """Return all ``ClassName.prototype.method = ...`` definitions as [(start_line, class, method)]."""
    results: list[tuple[int, str, str]] = []
    for idx, line in enumerate(lines):
        m = _NAMED_PROTO_RE.search(line)
        if m:
            results.append((idx + 1, m.group(1), m.group(3)))
            continue
        m = _PROTO_RE.search(line)
        if m:
            results.append((idx + 1, m.group(1), m.group(2)))
    return results


def _find_enclosing_proto(lines: list[str], proto_defs: list[tuple[int, str, str]], target: int) -> Optional[tuple[str, str]]:
    """Pick the prototype method whose definition is closest to but not after *target* line."""
    best: Optional[tuple[int, str, str]] = None
    for def_line, cls, method in proto_defs:
        if def_line > target:
            continue
        if best is None or def_line > best[0]:
            best = (def_line, cls, method)
    if best:
        return (best[1], best[2])
    return None


def _detect_class_for_line_via_source_pattern(
    file_path: str,
    line_number: int,
) -> Optional[tuple[str, str]]:
    """Scan the entire file for ``ClassName.prototype.method = ...`` definitions.

    Returns (class_name, method_name) of the enclosing prototype method for *line_number*, or None
    when no match is found.  The algorithm collects **all** prototype definitions in the file and
    picks the one whose definition line is closest to but not greater than *line_number*.

    This handles JavaScript prototype method definitions that AST parsers often miss because they
    are AssignmentExpression nodes rather than FunctionDeclaration/MethodDefinition.
    """
    try:
        lines = Path(file_path).read_text(errors="replace").splitlines()
    except (OSError, IOError):
        return None

    proto_defs = _collect_proto_definitions(lines)
    return _find_enclosing_proto(lines, proto_defs, line_number)


# ---------------------------------------------------------------------------
# Tier-3: Arrow-function / inline detection via source scanning
# ---------------------------------------------------------------------------

_ARROW_RE = re.compile(
    r"(\w+)"              # class name
    r"\.prototype\."
    r"(\w+)"             # method name
    r"\s*=\s*"
    r"\\?\(",           # arrow function opening
)

# TypeScript-compatible function declaration pattern. This fallback is used
# when espree cannot parse type annotations in a .ts file.
_FUNCTION_DECL_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\("
)


def _find_enclosing_function_by_source(
    file_path: str,
    line_number: int,
) -> Optional[str]:
    """Find a function declaration range without parsing JavaScript syntax.

    This handles TypeScript files whose annotations make espree reject the
    source. It deliberately recognizes only ordinary function declarations;
    other forms continue through the existing prototype and arrow fallbacks.
    """
    try:
        lines = Path(file_path).read_text(errors="replace").splitlines()
    except (OSError, IOError):
        return None

    candidates: list[tuple[str, int, int]] = []
    for index, line in enumerate(lines, start=1):
        match = _FUNCTION_DECL_RE.match(line)
        if not match or index > line_number:
            continue

        depth = 0
        opened = False
        end_line = len(lines)
        for scan_index in range(index - 1, len(lines)):
            source = lines[scan_index]
            for char in source:
                if char == "{":
                    depth += 1
                    opened = True
                elif char == "}" and opened:
                    depth -= 1
                    if depth == 0:
                        end_line = scan_index + 1
                        break
            if opened and depth == 0:
                break

        if opened and index <= line_number <= end_line:
            candidates.append((match.group(1), index, end_line))

    if not candidates:
        return None
    # Prefer the narrowest containing declaration for nested functions.
    return min(candidates, key=lambda candidate: candidate[2] - candidate[1])[0]


def _detect_class_via_arrow_pattern(
    file_path: str,
    line_number: int,
) -> Optional[tuple[str, str]]:
    """Catch Arrow-function prototype methods that the main regex may miss.

    Returns (class_name, method_name) or None.
    """
    try:
        lines = Path(file_path).read_text(errors="replace").splitlines()
    except (OSError, IOError):
        return None

    start = max(0, line_number - 31)
    end = min(len(lines), line_number + 1)
    window = "\n".join(lines[start:end])

    m = _ARROW_RE.search(window)
    if m:
        return (m.group(1), m.group(2))
    return None


# ---------------------------------------------------------------------------
# Public entry point for enclosing-function detection
# ---------------------------------------------------------------------------

def get_enclosing_function_name(
    file_path: str,
    line_number: int,
) -> Optional[str]:
    """Return the most specific function name at *line_number* in *file_path*.

    Tier-1: espree AST walk --> FunctionDeclaration / MethodDefinition names.
    Tier-2: ``ClassName.prototype.method = function()`` regex.
    Tier-3: ``ClassName.prototype.method =>`` arrow-function regex fallback.
    """
    # Tier 1
    name = _find_enclosing_function_by_espree(file_path, line_number)
    if name is not None:
        return name

    # Tier 2 -- prototype method detection
    proto = _detect_class_for_line_via_source_pattern(file_path, line_number)
    if proto:
        cls_name, method_name = proto
        # Return the full class.method as a single identifier for downstream matching
        return f"{cls_name}.{method_name}"

    # Tier 3 -- arrow-function fallback
    arrow = _detect_class_via_arrow_pattern(file_path, line_number)
    if arrow:
        cls_name, method_name = arrow
        return f"{cls_name}.{method_name}"

    # TypeScript source-level fallback for `export function name(...): Type`.
    return _find_enclosing_function_by_source(file_path, line_number)
