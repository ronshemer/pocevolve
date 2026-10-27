"""Static-analysis pipeline for CVE fix diffs.

This module provides ``run_analysis()``, which implements the following
AST-based workflow (SCIP call graph **disabled** for pure JavaScript):

1. Parse the diff text → ``DiffEntry`` objects (deleted lines only).
2. Detect package entry points from package.json and CommonJS exports.
3. For each deleted line in the diff, find the enclosing function name via
   ``method_resolution.get_enclosing_function_name()``.
4. Check if any method names match sink keywords (e.g. ``eval``, ``exec``,
   ``innerHTML``).
5. Return an ``AnalysisResult`` summarizing matched entry points and sinks;
   ``taint_flows`` is always empty until the SCIP call graph is restored.

**Config defaults** (see ``src/config.py`` for tunables):
- SINK_KEYWORDS: list of strings to match against method names.
- MAX_ENTRY_POINTS: cap on module.exports candidates reported per file.

Related memories:
- [[zero-cves-skipped-batch-analysis]] — prior batch run context
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

# Local imports
from src.graph_analysis._types import (
    AnalysisResult,
    DiffEntry,
)
from src.graph_analysis.diff_parser import parse_diff  # only_deleted=True by default
from src.graph_analysis.method_resolution import get_enclosing_function_name

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sink detection keywords — matches method names that indicate dangerous sinks
# ---------------------------------------------------------------------------

# These mirror the patterns previously used in taint_flow.py and __main__.py
SINK_KEYWORDS: list[str] = [
    "eval",
    "exec",
    "execSync",
    "execFileSync",
    "spawn",
    "spawnSync",
    "fork",
    "ping",
    "traceroute",
    "curl",
    "wget",
    "shell",
    "command",
    "system",
    "innerhtml",
    "setimmediate",
    "requirechild",
    "arpping",
    "arp-scan",
    "mac-lookup",
]

# ---------------------------------------------------------------------------
# package entry-point resolution and exported-method extraction
# ---------------------------------------------------------------------------


def _detect_module_exports_entry_points(
    package_root: str,
    max_per_file: int = 10,
) -> list[dict[str, Any]]:
    """Resolve package entry files and extract statically visible exports.

    Declared package entry files take precedence. Compiled output and dependencies
    are excluded to keep the results focused on package source.
    """
    root_path = Path(package_root)
    generated_dirs = {"dist", "build", "lib", "es", "coverage"}
    package_json = root_path / "package.json"
    if package_json.is_file():
        try:
            metadata = json.loads(package_json.read_text(errors="replace"))
            declared = []

            def add_declared_path(value: Any) -> None:
                if not isinstance(value, str):
                    return
                candidate = Path(value)
                if candidate.name.endswith(".d.ts"):
                    return
                if candidate.parts and candidate.parts[0] not in generated_dirs:
                    if (root_path / candidate).is_file():
                        declared.append(candidate.as_posix())

            def collect_export_targets(value: Any) -> None:
                if isinstance(value, str):
                    add_declared_path(value)
                elif isinstance(value, dict):
                    for nested in value.values():
                        collect_export_targets(nested)

            exports = metadata.get("exports")
            if isinstance(exports, dict) and "." in exports:
                collect_export_targets(exports["."])
            else:
                collect_export_targets(exports)
            for field in ("main", "module", "browser"):
                add_declared_path(metadata.get(field))
            if declared:
                files = sorted(set(declared))
                return [_describe_entry_point(root_path / path, path) for path in files]
        except (OSError, ValueError):
            pass

    for fallback in ("src/index.js", "src/index.ts", "index.js", "index.ts"):
        if (root_path / fallback).is_file():
            return [_describe_entry_point(root_path / fallback, fallback)]

    found: set[str] = set()
    src_exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    excluded = {"node_modules", ".git", "test", "tests", "examples", "coverage", "vendor", *generated_dirs}
    for root, dirs, files in os.walk(package_root):
        dirs[:] = [name for name in dirs if name not in excluded and not name.startswith(".")]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in src_exts:
                continue
            fpath = Path(root) / fname
            try:
                text = fpath.read_text(errors="replace")
            except Exception:
                continue

            # Quick pre-check before AST parsing
            if not any(marker in text for marker in ("module.exports", "exports.", "export")):
                continue

            found.add(str(fpath.relative_to(package_root)))
            if len(found) >= max_per_file:
                files = sorted(found)
                return [_describe_entry_point(root_path / path, path) for path in files]

    files = sorted(found)
    return [_describe_entry_point(root_path / file_path, file_path) for file_path in files]


_EXPORT_AST_SCRIPT = r"""
const fs = require('fs');
const espree = require('espree');
const source = fs.readFileSync(process.argv[1], 'utf8');
const ast = espree.parse(source, {
  ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true,
});
const functions = new Set();
const objects = new Map();
const output = new Set();
let recognized = false;

function propertyName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'Literal' && (typeof node.value === 'string' || typeof node.value === 'number')) {
    return String(node.value);
  }
  return null;
}
function isFunction(node) {
  return !!node && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ClassExpression'].includes(node.type);
}
function isCallable(node, seen = new Set()) {
  if (!node) return false;
  if (isFunction(node)) return true;
  if (node.type !== 'Identifier' || seen.has(node.name)) return false;
  seen.add(node.name);
  return functions.has(node.name);
}
function add(name) {
  if (name) output.add(String(name));
}
function collectObject(name, node) {
  if (name && node && node.type === 'ObjectExpression') objects.set(name, node);
}
function addObjectMethods(node) {
  if (node && node.type === 'Identifier') node = objects.get(node.name);
  if (!node || node.type !== 'ObjectExpression') return;
  for (const prop of node.properties) {
    if (prop.type === 'SpreadElement') continue;
    const name = propertyName(prop.key);
    if (prop.method || isCallable(prop.value)) add(name);
  }
}
function isModuleExports(node) {
  return node && node.type === 'MemberExpression' && !node.computed &&
    node.object.type === 'Identifier' && node.object.name === 'module' &&
    node.property.type === 'Identifier' && node.property.name === 'exports';
}
function isExportsObject(node) {
  return node && node.type === 'Identifier' && node.name === 'exports';
}

// Collect local function and object bindings before inspecting exports.
for (const statement of ast.body) {
  const declaration = statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
  if (!declaration) continue;
  if (declaration.type === 'FunctionDeclaration' && declaration.id) functions.add(declaration.id.name);
  if (declaration.type === 'ClassDeclaration' && declaration.id) functions.add(declaration.id.name);
  if (declaration.type === 'VariableDeclaration') {
    for (const item of declaration.declarations) {
      if (item.id.type !== 'Identifier') continue;
      if (isFunction(item.init)) functions.add(item.id.name);
      collectObject(item.id.name, item.init);
    }
  }
}

for (const statement of ast.body) {
  if (statement.type === 'ExportNamedDeclaration') {
    if (statement.declaration || (statement.specifiers || []).length) recognized = true;
    const declaration = statement.declaration;
    if (declaration && declaration.type === 'FunctionDeclaration' && declaration.id) add(declaration.id.name);
    if (declaration && declaration.type === 'ClassDeclaration' && declaration.id) add(declaration.id.name);
    if (declaration && declaration.type === 'VariableDeclaration') {
      for (const item of declaration.declarations) {
        if (item.id.type === 'Identifier' && isCallable(item.init)) add(item.id.name);
      }
    }
    for (const specifier of statement.specifiers || []) {
      // An explicit `export { name }` is part of the public API even when
      // `name` was imported from another file. Resolving whether it is a
      // callable requires following that import, so report the exported name.
      add(propertyName(specifier.exported));
    }
  }
  if (statement.type === 'ExportDefaultDeclaration') {
    const declaration = statement.declaration;
    if (isFunction(declaration) || (declaration.type === 'Identifier' && isCallable(declaration))) {
      recognized = true;
      add('default');
    }
  }
  if (statement.type !== 'ExpressionStatement' || statement.expression.type !== 'AssignmentExpression') continue;
  const assignment = statement.expression;
  const left = assignment.left;
  if (isModuleExports(left)) {
    if (assignment.right.type === 'ObjectExpression' ||
        (assignment.right.type === 'Identifier' && objects.has(assignment.right.name))) {
      recognized = true;
      addObjectMethods(assignment.right);
    } else if (isCallable(assignment.right)) {
      recognized = true;
      add(assignment.right.type === 'Identifier' ? assignment.right.name : assignment.right.id?.name || 'default');
    }
    continue;
  }
  if (left.type === 'MemberExpression' && !left.computed &&
      (isModuleExports(left.object) || isExportsObject(left.object)) && isCallable(assignment.right)) {
    recognized = true;
    add(propertyName(left.property));
  }
}
process.stdout.write(JSON.stringify(recognized ? [...output].sort() : null));
"""


def _extract_exported_methods(file_path: Path) -> list[str] | None:
    """Return statically identifiable exported callable names, or None on failure."""
    try:
        proc = subprocess.run(
            ["node", "-e", _EXPORT_AST_SCRIPT, str(file_path)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0:
            logger.debug("Could not parse exports from %s: %s", file_path, proc.stderr.strip())
            return None
        values = json.loads(proc.stdout)
        if values is None:
            return None
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            return None
        return values
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _describe_entry_point(file_path: Path, relative_path: str) -> dict[str, Any]:
    """Keep the entry file even when AST parsing or export extraction fails."""
    result: dict[str, Any] = {"file_path": relative_path}
    exported = _extract_exported_methods(file_path)
    if exported is not None:
        result["exported_methods"] = exported
    return result


# ---------------------------------------------------------------------------
# Public pipeline
# ---------------------------------------------------------------------------


def run_analysis(
    cve_id: str,
    package_root: str,
    diff_text: str = "",
    file_path_hint: str | None = None,
    testbed_dir: str | None = None,
) -> AnalysisResult:
    """Run the AST-based analysis pipeline on *diff_text*.

    Parameters
    ----------
    cve_id:
        CVE identifier (e.g. ``"CVE-2024-1234"``).
    package_root:
        Path to the checked-out testbed directory containing JS source files.
    diff_text:
        Unified diff text (may come from VFC entries or a raw patch file).
    file_path_hint:
        Optional path hint for narrowing entry-point search.  Ignored in the
        current AST-based pipeline; kept for API compatibility.
    testbed_dir:
        Directory name used as a secondary lookup key for VFC auto-resolution.
        Passed through to downstream callers.

    Returns
    -------
    AnalysisResult
        Always has ``mode="entry_points_only"`` because data-flow tracing is
        temporarily disabled (SCIP call graph unavailable for pure JS).
    """
    # Phase B: resolve exported package entry points (independent of diff content)
    entry_point_files = _detect_module_exports_entry_points(package_root)

    # Phase A: parse diff → DiffEntry objects (deleted lines only)
    if not diff_text or not diff_text.strip():
        logger.info("run_analysis[%s]: empty diff — returning entry points only", cve_id)
        return AnalysisResult(
            cve_id=cve_id,
            matched_methods=[],
            entry_points=entry_point_files[:10],
            mode="entry_points_only",
        )

    entries = parse_diff(diff_text, only_deleted=True)
    analysis_change_type = "removed"
    if not entries:
        # Some fixes add a guard or sanitization without deleting vulnerable
        # code. Anchor each added line to the old side of its hunk and resolve
        # the enclosing method in the vulnerable checkout.
        entries = parse_diff(diff_text, only_added=True, include_all_lines=True)
        analysis_change_type = "added"
    if not entries:
        logger.info("run_analysis[%s]: no DiffEntry produced from diff", cve_id)
        return AnalysisResult(
            cve_id=cve_id,
            matched_methods=[],
            entry_points=entry_point_files[:10],
            mode="entry_points_only",
        )

    # Phase C: for each deleted line, resolve enclosing function name and check sinks
    grouped_methods: dict[tuple[str, str], dict] = {}
    sink_hits: list[str] = []
    for entry in entries:
        # Use orig_line_start (deleted lines only, per project requirement)
        if entry.orig_line_start is not None:
            func_name = _resolve_enclosing_function(package_root, entry)
        else:
            func_name = ""

        # An added guard belongs in the result only when its old-side anchor
        # resolves to a concrete method in the vulnerable source.
        if analysis_change_type == "added" and not func_name:
            continue

        # Check sink keywords against the method name and enclosing function
        matched = False
        for kw in SINK_KEYWORDS:
            if kw in (entry.method_name or "").lower():
                matched = True
                sink_hits.append(entry.method_name)
                break
        if not matched and func_name:
            for kw in SINK_KEYWORDS:
                if kw in func_name.lower():
                    matched = True
                    sink_hits.append(func_name)
                    break

        # Group all matched deleted lines under their enclosing function.
        # When function resolution fails, keep different diff symbols separate.
        group_name = func_name or entry.method_name
        target_key = (entry.file_path, group_name)
        target = grouped_methods.setdefault(target_key, {
            "file_path": entry.file_path,
            "method_name": group_name,
            "function_name": func_name,
            "deleted_lines": [],
            "added_lines": [],
            "added_line_anchors": [],
            "change_types": [],
            "diff_symbols": [],
            "parameter_names": [],
        })
        if entry.change_type == "removed" and entry.orig_line_start is not None:
            if entry.orig_line_start not in target["deleted_lines"]:
                target["deleted_lines"].append(entry.orig_line_start)
        if entry.change_type == "added" and entry.orig_line_start is not None:
            if entry.orig_line_start not in target["added_line_anchors"]:
                target["added_line_anchors"].append(entry.orig_line_start)
        if entry.change_type == "added" and entry.new_line_start is not None:
            if entry.new_line_start not in target["added_lines"]:
                target["added_lines"].append(entry.new_line_start)
        if entry.change_type not in target["change_types"]:
            target["change_types"].append(entry.change_type)
        if entry.method_name and entry.method_name not in target["diff_symbols"]:
            target["diff_symbols"].append(entry.method_name)
        for param in entry.parameter_names:
            if param not in target["parameter_names"]:
                target["parameter_names"].append(param)

    # A deleted method definition and calls to that method can have different
    # enclosing functions.  Merge those initial groups when a diff symbol names
    # another group's enclosing function.  This keeps an edited method together
    # even when the patch also changes one of its callers.
    groups = list(grouped_methods.values())
    parent = list(range(len(groups)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for left, group in enumerate(groups):
        for right, candidate in enumerate(groups):
            if left == right or group["file_path"] != candidate["file_path"]:
                continue
            if candidate["function_name"] and candidate["function_name"] in group["diff_symbols"]:
                union(left, right)

    merged_groups: dict[int, dict] = {}
    for index, group in enumerate(groups):
        root = find(index)
        merged = merged_groups.setdefault(root, {
            "file_path": group["file_path"],
            "function_names": [],
            "deleted_lines": [],
            "added_lines": [],
            "added_line_anchors": [],
            "change_types": [],
            "diff_symbols": [],
            "parameter_names": [],
        })
        for function_name in (group["function_name"],):
            if function_name and function_name not in merged["function_names"]:
                merged["function_names"].append(function_name)
        for field in ("deleted_lines", "added_lines", "added_line_anchors", "change_types", "diff_symbols", "parameter_names"):
            for value in group[field]:
                if value not in merged[field]:
                    merged[field].append(value)

    target_methods = []
    for group in merged_groups.values():
        # Prefer the enclosing function that is not itself one of the diff
        # symbols. For a deleted call such as `this._parseError(...)`, this
        # labels the record with its caller (`parseError`) and keeps the callee
        # in diff_symbols. Fall back to the function name for definition-only
        # changes where it also appears as a diff symbol.
        method_name = next(
            (name for name in group["function_names"] if name not in group["diff_symbols"]),
            group["function_names"][0] if group["function_names"] else group["diff_symbols"][0],
        )
        target_methods.append({
            "file_path": group["file_path"],
            "method_name": method_name,
            "enclosing_functions": group["function_names"],
            "deleted_lines": sorted(group["deleted_lines"]),
            "added_lines": sorted(group["added_lines"]),
            "added_line_anchors": sorted(group["added_line_anchors"]),
            "change_type": "added" if group["change_types"] == ["added"] else "removed",
            "diff_symbols": group["diff_symbols"],
            "parameter_names": group["parameter_names"],
        })

    matched_methods = [
        DiffEntry(
            file_path=f"{group['file_path']}#{group['method_name']}",
            method_name=group["method_name"],
            parameter_names=group["parameter_names"],
            orig_line_start=min(group["deleted_lines"] or group["added_line_anchors"]) if (group["deleted_lines"] or group["added_line_anchors"]) else None,
            orig_line_end=max(group["deleted_lines"] or group["added_line_anchors"]) if (group["deleted_lines"] or group["added_line_anchors"]) else None,
            change_type=group["change_type"],
            removed_lines=sorted(group["deleted_lines"]) if group["change_type"] == "removed" else [],
            added_lines=sorted(group["added_lines"]),
            added_line_anchors=sorted(group["added_line_anchors"]),
            diff_symbols=group["diff_symbols"],
        )
        for group in target_methods
    ]

    # Phase D: report results (no taint flows yet)
    result = AnalysisResult(
        cve_id=cve_id,
        matched_methods=matched_methods,
        entry_points=entry_point_files[:10],  # cap at 10 for brevity
        target_methods=target_methods,
        mode="entry_points_only",
    )

    logger.info(
        "run_analysis[%s]: %d entries → %d matched, %d sink hits, %d entry-point files",
        cve_id,
        len(entries),
        len(matched_methods),
        len(sink_hits),
        len(entry_point_files),
    )

    return result


def _resolve_enclosing_function(package_root: str, entry: DiffEntry) -> str:
    """Return the innermost function name enclosing *entry.orig_line_start*.

    Uses ``method_resolution.get_enclosing_function_name()`` which walks the
    AST via espree.  Returns an empty string when no function is found or the
    file does not exist on disk.
    """
    if entry.orig_line_start is None:
        return ""

    # Resolve full path from package_root
    raw_path = entry.file_path
    full_path = Path(package_root) / raw_path

    # Strip any existing comment marker (from prior enrichment)
    clean_path = str(full_path).split("#")[0]

    if not Path(clean_path).is_file():
        return ""

    try:
        name = get_enclosing_function_name(clean_path, entry.orig_line_start)
        return name or ""
    except Exception as exc:
        logger.warning(
            "enclosing function lookup failed for %s:%d: %s",
            clean_path, entry.orig_line_start, exc,
        )
        return ""
