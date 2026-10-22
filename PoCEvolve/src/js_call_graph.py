"""JavaScript call-graph builder based on **tree-sitter** AST.

Replaces the previous regex-heavy ``js_call_graph.py`` with a parser that
traverses a concrete AST, so every syntactically valid JS pattern is handled
consistently — prototype methods, class fields, nested IIFEs, destructured
requires, etc.

## Grammar nodes of interest

| tree-sitter node type          | maps to                |
|-------------------------------|------------------------|
| `function_declaration`        | function nodes         |
| `class_declaration`           | class nodes            |
| `method_definition`           | method nodes           |
| `field_definition` (with prototype in value) | prototype-method nodes |
| `variable_declarator` + function/arrow | named fn expr / arrow |
| `assignment_expression` (.prototype = func) | prototype method |
| `import_statement` / require() calls | import/edge nodes  |
| `call_expression`             | call-site edges        |
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterator

import tree_sitter_javascript

# ---------------------------------------------------------------------------
# Language / parser (singleton)
# ---------------------------------------------------------------------------

_LANG: object | None = None
_PARSER: object | None = None


def _parser() -> object:
    """Return a ``tree_sitter.Parser`` for JavaScript."""
    global _LANG, _PARSER
    if _PARSER is None:
        from tree_sitter import Language, Parser

        raw = tree_sitter_javascript.language()  # PyCapsule
        _LANG = Language(raw)  # type: ignore[arg-type]
        _PARSER = Parser(_LANG)
    return _PARSER


# ---------------------------------------------------------------------------
# File traversal  (unchanged API)
# ---------------------------------------------------------------------------

def collect_js_files(root: Path, prune_node_modules: bool = False) -> list[Path]:
    """Walk ``root``, return .js file paths."""
    results: list[Path] = []
    for dirpath, dirnames, filenames in root.walk():
        if prune_node_modules and dirpath.name == "node_modules":
            dirnames.clear()
            continue
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in sorted(filenames):
            if fname.endswith(".js"):
                results.append(dirpath / fname)
    return results


# ---------------------------------------------------------------------------
# Tree-sitter helpers
# ---------------------------------------------------------------------------

def _node_line(node: Any) -> int:
    """1-based line number of a tree-sitter node."""
    return node.start_point[0] + 1  # tree-sitter uses 0-based rows/cols


def _walk(node: Any) -> Iterator[Any]:
    """Yield every node (named and unnamed) in document order."""
    yield node
    for child in node.children:
        yield from _walk(child)


# ---------------------------------------------------------------------------
# Symbol name extraction helpers
# ---------------------------------------------------------------------------

def _identifier_text(node: Any) -> str | None:
    """Return the text of an ``Identifier`` or ``PropertyIdentifier`` node."""
    if node is None:
        return None
    t = node.type
    if t in ("identifier", "property_identifier", "field_identifier"):
        src = node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text)
        return src.strip() if src else None
    # Could also be a named export alias — fall through
    for child in _iter_children(node):
        text = _identifier_text(child)
        if text:
            return text
    return None


def _iter_children(node: Any) -> Iterator[Any]:
    """Yield direct named children of *node*."""
    for child in node.named_children:
        yield child


def _children_of(node: Any, type_filter: str | None = None) -> Iterator[Any]:
    """Yield direct children optionally filtered by type."""
    for c in _iter_children(node):
        if type_filter is None or c.type == type_filter:
            yield c


def _has_in_tree(node: Any, type_pattern: str) -> bool:
    """Check whether *node*'s tree contains a descendant of ``type_pattern``."""
    for child in node.named_children:
        if child.type == type_pattern:
            return True
        if _has_in_tree(child, type_pattern):
            return True
    return False


def _text_of(node: Any) -> str | None:
    """Return full source text of *node*."""
    if node is None or node.text is None:
        return None
    return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text)


def _is_require_call(node: Any) -> bool:
    """Check whether *node* (a ``call_expression``) is a ``require('…')`` call."""
    func = node.child_by_field_name("function") or node.child_by_field_name("name")
    if func is None:
        return False
    text = _text_of(func)
    if not text:
        return False
    stripped = text.strip()
    if stripped == "require":
        return True
    if stripped.endswith(".require"):
        return True
    return False


def _extract_require_name(node: Any) -> str | None:
    """Extract the string argument from a ``require('mod')`` call."""
    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return None
    first_arg = list(_children_of(args_node))[0] if hasattr(args_node, '__iter__') else None
    # Could be a string literal or a variable reference
    if first_arg and first_arg.type in ("string_fragment", "string"):
        text = _text_of(first_arg)
        return text.strip().strip("'\"") if text else None
    # Handle import() dynamic — skip (not require)
    if first_arg and first_arg.type == "import_keyword":
        return None
    # Handle variable reference to a string
    if first_arg and first_arg.type == "identifier":
        text = _text_of(first_arg)
        return text.strip().strip("'\"") if text else None
    return None


def _is_prototype_assignment(node: Any) -> bool:
    """Check whether *node* is an assignment like ``X.prototype.method = ...``."""
    left = node.child_by_field_name("left")
    if left is None:
        # child_by_field_name("left") can return None for chained member_expressions.
        # Fall back to iterating named_children — the first named child is always left.
        left = next(iter(node.named_children), None)
    if left is None:
        return False

    # Walk all descendants of `left` looking for the identifier "prototype"
    cursor = left.walk()
    if not cursor.goto_first_child():
        return False
    while True:
        n = cursor.node
        t = n.type
        if t in ("identifier", "field_identifier", "property_identifier"):
            text = _text_of(n)
            if text and text.strip().lower() == "prototype":
                return True
        if not cursor.goto_next_sibling():
            break
    return False


def _get_prototype_method_name(node: Any) -> str | None:
    """Extract the method name from ``X.prototype.methodName = ...``."""
    left = node.child_by_field_name("left")
    if left is None:
        # Fallback for chained member_expressions where field access fails
        left = next(iter(node.named_children), None)
    if left is None:
        return None

    # Walk descendants looking for identifier "prototype", then grab the next
    # property_identifier (which is the method name).
    # Structure: X . prototype . methodName  (or nested member_expressions)
    cursor = left.walk()
    if not cursor.goto_first_child():
        return None

    found_prototype = False
    result: str | None = None
    while True:
        n = cursor.node
        t = n.type
        text = _text_of(n)
        # Look for the literal identifier "prototype" (not just any property_identifier)
        if t in ("identifier", "field_identifier", "property_identifier") and text and text.strip() == "prototype":
            found_prototype = True
        elif found_prototype and t in ("field_identifier", "property_identifier") and text and text.strip():
            result = text.strip()
            break
        if not cursor.goto_next_sibling():
            break

    # Fallback: return last property_identifier if we couldn't correlate it
    if result is None:
        for p in _iter_children(left):
            if p.type in ("field_identifier", "property_identifier"):
                text = _text_of(p)
                if text and text != "prototype":
                    return text.strip()
    return result


def _get_value_node(node: Any) -> Any | None:
    """Get the ``right`` (or ``value``) side of a node."""
    val = node.child_by_field_name("right")  # assignment_expression
    if val is not None:
        return val
    val = node.child_by_field_name("value")  # variable_declarator
    if val is not None:
        return val
    # Fallback: in tree-sitter JS child_by_field_name can return None for some
    # assignment_expression nodes with chained member_expressions. Walk named_children.
    named = list(node.named_children)
    if len(named) >= 2:
        return named[-1]  # Last named child is the 'right' or 'value' side
    return None


# ---------------------------------------------------------------------------
# AST traversal → nodes + edges
# ---------------------------------------------------------------------------

def _parse_one_file(
    src_bytes: bytes,
    rel: str,
    all_nodes: list[dict],
    all_edges: list[dict],
    seen_nodes: set[str],
    seen_edges: set[str],
    symbol_index: dict[str, list[tuple[str, int]]],
) -> None:
    """Walk the AST of one file and populate nodes/edges."""

    tree = _parser().parse(src_bytes)
    root_node = tree.root_node

    # ------------------------------------------------------------------
    # 1. Top-level function declarations
    # ------------------------------------------------------------------
    for child in _iter_children(root_node):
        if child.type == "function_declaration":
            _handle_function_decl(child, rel, all_nodes, seen_nodes, symbol_index)
        elif child.type == "class_declaration":
            _handle_class_decl(child, rel, all_nodes, seen_nodes, symbol_index)
        # Assignment to module.exports — handled below in post-order pass
        # require/import — also in post-order

    # ------------------------------------------------------------------
    # 2. Walk the entire tree for deeper constructs & edges
    # ------------------------------------------------------------------
    for node in _walk(root_node):
        _handle_node(node, rel, all_nodes, seen_edges, all_edges)


def _handle_function_decl(
    node: Any,
    rel: str,
    all_nodes: list[dict],
    seen_nodes: set[str],
    symbol_index: dict[str, list[tuple[str, int]]],
) -> None:
    """Extract a top-level function declaration."""
    name = _identifier_text(node.child_by_field_name("name"))
    if not name:
        return

    line = _node_line(node)
    key = f"{rel}::fn_{name}"

    if key not in seen_nodes:
        all_nodes.append({
            "symbol": key,
            "display_name": name,
            "file_path": rel,
            "line_range": [line, line],
            "kind": "function",
        })
        seen_nodes.add(key)

    symbol_index.setdefault(name, []).append((rel, line))


def _handle_class_decl(
    node: Any,
    rel: str,
    all_nodes: list[dict],
    seen_nodes: set[str],
    symbol_index: dict[str, list[tuple[str, int]]],
) -> None:
    """Extract a class declaration."""
    name = _identifier_text(node.child_by_field_name("name"))
    if not name:
        return

    line = _node_line(node)
    key = f"{rel}::class_{name}"

    if key not in seen_nodes:
        all_nodes.append({
            "symbol": key,
            "display_name": name,
            "file_path": rel,
            "line_range": [line, line],
            "kind": "class",
        })
        seen_nodes.add(key)

    symbol_index.setdefault(name, []).append((rel, line))


def _handle_node(
    node: Any,
    rel: str,
    all_nodes: list[dict],
    seen_edges: set[str],
    all_edges: list[dict],
) -> None:
    """Dispatch tree-sitter nodes to appropriate extractors."""

    # --- variable declarator with function/arrow value (var/let/const x = function) ---
    if node.type == "variable_declarator":
        _handle_variable_declarator(node, rel, all_nodes, seen_edges, all_edges)
        return

    # --- named exports: export function/class/const ---
    if node.type in ("named_import",):
        # ES module import — not a node, just an edge equivalent; skip here
        pass

    # --- require() call ---
    if node.type == "call_expression" and _is_require_call(node):
        mod = _extract_require_name(node)
        if mod:
            _handle_require_call(node, rel, all_nodes, seen_edges, all_edges, mod)
        return

    # --- call sites (obj.method() or name()) ---
    if node.type == "call_expression":
        _handle_call_site(node, rel, all_edges, seen_edges)
        return

    # --- method_definition inside class body ---
    if node.type == "method_definition":
        _handle_method_definition(node, rel, all_nodes, seen_edges, all_edges)
        return

    # --- prototype assignment: X.prototype.method = function/arrow/class ---
    if node.type == "assignment_expression" and _is_prototype_assignment(node):
        method_name = _get_prototype_method_name(node)
        if method_name:
            line = _node_line(node)
            key = f"{rel}::proto_{method_name}"
            all_nodes.append({
                "symbol": key,
                "display_name": method_name,
                "file_path": rel,
                "line_range": [line, line],
                "kind": "prototype_function",
            })
        return

    # --- module.exports.name = function/arrow/class ---
    if node.type == "assignment_expression":
        left_text = _text_of(node.child_by_field_name("left"))
        if left_text and "module.exports" in left_text:
            _handle_module_exports_assign(node, rel, all_nodes, seen_edges, all_edges)
        return

    # --- export const/let/var/function/class name ... ---
    if node.type == "export_statement":
        _handle_export_statement(node, rel, all_nodes, seen_edges, all_edges)
        return


def _handle_variable_declarator(
    node: Any,
    rel: str,
    all_nodes: list[dict],
    seen_edges: set[str],
    all_edges: list[dict],
) -> None:
    """Handle ``var/let/const name = function()`` or ``name = (...) => ...``."""
    value = _get_value_node(node)
    if not value:
        return

    t = value.type
    if t not in ("function_expression", "arrow_function"):
        # Could be a class expression too
        if t != "class":
            return

    name = _identifier_text(node.child_by_field_name("name"))
    if not name:
        return

    line = _node_line(node)
    key = f"{rel}::fn_{name}"

    kind = "function"  # both fn-expr and arrow treated as functions

    all_nodes.append({
        "symbol": key,
        "display_name": name,
        "file_path": rel,
        "line_range": [line, line],
        "kind": kind,
    })

    # Destructured require: const { a } = require('mod')
    if _has_in_tree(value, "call_expression"):
        for inner_call in _iter_descendants_of_type(value, "call_expression"):
            if _is_require_call(inner_call):
                mod = _extract_require_name(inner_call)
                if mod:
                    edge_key = f"{rel}::require::{mod}::{name}"
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        all_edges.append({
                            "caller_file": rel,
                            "callee_symbol": f"{mod}::{name}",
                            "call_kind": "destructuring_require",
                            "line": line,
                        })

    return None


def _iter_descendants_of_type(node: Any, type_filter: str) -> Iterator[Any]:
    """Yield all descendants of ``node`` with the given tree-sitter node ``type_filter``."""
    for child in node.named_children:
        if child.type == type_filter:
            yield child
        yield from _iter_descendants_of_type(child, type_filter)


def _handle_require_call(
    node: Any,
    rel: str,
    all_nodes: list[dict],
    seen_edges: set[str],
    all_edges: list[dict],
    mod_name: str,
) -> None:
    """Record a require() call as both an import-node and a require-edge."""
    line = _node_line(node)

    edge_key = f"{rel}::require::{mod_name}"
    if edge_key not in seen_edges:
        seen_edges.add(edge_key)
        all_edges.append({
            "caller_file": rel,
            "callee_module": mod_name,
            "call_kind": "require",
            "line": line,
        })

    import_key = f"{rel}::$require::{mod_name}"
    if import_key not in seen_edges:
        seen_edges.add(import_key)
        all_nodes.append({
            "symbol": import_key,
            "display_name": mod_name,
            "file_path": rel,
            "line_range": [line, line],
            "kind": "import",
        })


def _handle_method_definition(
    node: Any,
    rel: str,
    all_nodes: list[dict],
    seen_edges: set[str],
    all_edges: list[dict],
) -> None:
    """Extract a class method (``name(params) { ... }``)."""
    name = _identifier_text(node.child_by_field_name("name"))
    if not name or name in ("constructor",):
        return

    line = _node_line(node)
    key = f"{rel}::method_{name}"
    all_nodes.append({
        "symbol": key,
        "display_name": name,
        "file_path": rel,
        "line_range": [line, line],
        "kind": "method",
    })


def _handle_module_exports_assign(
    node: Any,
    rel: str,
    all_nodes: list[dict],
    seen_edges: set[str],
    all_edges: list[dict],
) -> None:
    """Record ``module.exports.name = function/arrow/class``."""
    left = node.child_by_field_name("left")
    if left is None:
        # child_by_field_name can return None for chained member_expressions
        left = next(iter(node.named_children), None)
    if not left:
        return

    # module.exports.methodName or exports.methodName
    for child in _iter_children(left):
        if child.type in ("field_identifier", "property_identifier"):
            name = _text_of(child)
            if name and name != "exports":
                all_nodes.append({
                    "symbol": f"{rel}::export_{name}",
                    "display_name": name,
                    "file_path": rel,
                    "line_range": [_node_line(node), _node_line(node)],
                    "kind": "module_exports",
                })
                break


def _handle_export_statement(
    node: Any,
    rel: str,
    all_nodes: list[dict],
    seen_edges: set[str],
    all_edges: list[dict],
) -> None:
    """Handle ``export const/let/var/function/class name ...``."""
    for child in _iter_children(node):
        if child.type == "declaration":
            for decl_child in _iter_children(child):
                if decl_child.type == "lexical_declaration":
                    # export const/let/var ...
                    for lc in _iter_children(decl_child):
                        if lc.type == "variable_declarator":
                            name = _identifier_text(lc.child_by_field_name("name"))
                            if name:
                                line = _node_line(lc)
                                all_nodes.append({
                                    "symbol": f"{rel}::export_{name}",
                                    "display_name": name,
                                    "file_path": rel,
                                    "line_range": [line, line],
                                    "kind": "export_named",
                                })
                elif decl_child.type in ("function_declaration", "class_declaration"):
                    name = _identifier_text(decl_child.child_by_field_name("name"))
                    if name:
                        line = _node_line(decl_child)
                        kind_map = {"function_declaration": "export_function", "class_declaration": "export_class"}
                        all_nodes.append({
                            "symbol": f"{rel}::{kind_map[decl_child.type]}_{name}",
                            "display_name": name,
                            "file_path": rel,
                            "line_range": [line, line],
                            "kind": kind_map[decl_child.type],
                        })
        # Handle `export default class/function` — skip for now


def _handle_call_site(
    node: Any,
    rel: str,
    all_edges: list[dict],
    seen_edges: set[str],
) -> None:
    """Extract a call-site edge from a ``call_expression`` node."""
    line = _node_line(node)

    func_node = node.child_by_field_name("function")
    if not func_node:
        return

    # obj.method() — member expression
    if func_node.type == "member_expression":
        obj_text = _text_of(func_node.child_by_field_name("object")) or ""
        prop_text = _text_of(func_node.child_by_field_name("property")) or ""
        callee = f"{obj_text}.{prop_text}"
        if obj_text and prop_text:
            edge_key = f"{rel}::call::{callee}"
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                all_edges.append({
                    "caller_file": rel,
                    "callee_symbol": callee,
                    "call_kind": "call",
                    "line": line,
                })


# ---------------------------------------------------------------------------
# Require resolution (unchanged logic, kept for completeness)
# ---------------------------------------------------------------------------

def _resolve_require(root: Path, module_name: str, caller_path: Path) -> Path | None:
    """Try to resolve a require() to a local file under root."""
    if not (module_name.startswith("./") or module_name.startswith("../")):
        nm = root / "node_modules" / module_name
        if nm.is_dir():
            for entry in ("index.js", "package.json"):
                candidate = nm / entry
                if candidate.is_file():
                    return candidate
            return nm
        return None

    try:
        resolved = (caller_path.parent / module_name).resolve()
        if resolved.exists() and resolved.is_file():
            return resolved
        for ext in [".js", "/index.js"]:
            candidate = (resolved.parent / (resolved.name + ext)).resolve()
            if candidate.exists() and candidate.is_file():
                return candidate
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_js_files(root: Path) -> dict[str, Any]:
    """Parse all JS files under ``root`` and return the call-graph dict.

    Returns
    -------
    dict with keys ``root_path``, ``nodes``, ``edges``, ``summary``.
    """
    js_files = collect_js_files(root)
    if not js_files:
        return _empty_result(str(root))

    root_str = str(root.resolve())

    all_nodes: list[dict] = []
    all_edges: list[dict] = []
    seen_nodes: set[str] = set()
    seen_edges: set[str] = set()
    symbol_index: dict[str, list[tuple[str, int]]] = {}  # not used after parse but kept for compat

    files_by_path: dict[str, str] = {}
    for fp in js_files:
        rel = str(fp.relative_to(root))
        files_by_path[rel] = str(fp)

    for fp in js_files:
        rel = str(fp.relative_to(root))
        try:
            src_bytes = fp.read_bytes()
        except Exception:
            continue

        _parse_one_file(
            src_bytes, rel, all_nodes, all_edges, seen_nodes, seen_edges, symbol_index,
        )

    # Resolve require() to local files and add cross-file import nodes
    for edge in all_edges:
        if edge["call_kind"] != "require":
            continue
        mod = edge.get("callee_module", "")
        caller_rel = edge["caller_file"]
        caller_abs = Path(files_by_path.get(caller_rel, root / caller_rel))
        resolved = _resolve_require(Path(str(root)).resolve(), mod, caller_abs)
        if resolved:
            root_abs = Path(str(root)).resolve()
            res_rel = str(resolved.relative_to(root_abs))
            import_key2 = f"{res_rel}::$require_from::{mod}"
            if import_key2 not in seen_nodes:
                seen_nodes.add(import_key2)
                all_nodes.append({
                    "symbol": import_key2,
                    "display_name": mod,
                    "file_path": res_rel,
                    "line_range": [1, 1],
                    "kind": "import",
                })

    return {
        "root_path": root_str,
        "nodes": all_nodes,
        "edges": all_edges,
        "summary": {
            "total_files": len(js_files),
            "total_nodes": len(all_nodes),
            "total_edges": len(all_edges),
        },
    }


def _empty_result(root_path: str) -> dict[str, Any]:
    """Return an empty call-graph result."""
    return {
        "root_path": root_path,
        "nodes": [],
        "edges": [],
        "summary": {"total_files": 0, "total_nodes": 0, "total_edges": 0},
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    if not args:
        print("Usage: python3 js_call_graph.py <dir> [--json | --lines]", file=sys.stderr)
        sys.exit(1)

    root_dir = Path(args[0]).resolve()
    output_format = "lines"

    for arg in args[1:]:
        if arg == "--json":
            output_format = "json"
        elif arg == "--lines":
            output_format = "lines"

    if not root_dir.is_dir():
        print(f"[ERROR] Not a directory: {root_dir}", file=sys.stderr)
        sys.exit(1)

    graph = parse_js_files(root_dir)

    if output_format == "json":
        print(json.dumps(graph, indent=2))
    else:
        print(f"# Root: {graph['root_path']}")
        s = graph["summary"]
        print(f"# Files: {s['total_files']}, Nodes: {s['total_nodes']}, Edges: {s['total_edges']}")

        print("\n--- NODES ---")
        for n in graph["nodes"]:
            ls, le = n["line_range"]
            line_str = f":{ls}" if ls == le else f":{ls}-{le}"
            print(f"[{n['kind']:>15}] {n['symbol']} @ {n['file_path']}{line_str}")

        print("\n--- EDGES ---")
        for e in graph["edges"]:
            target = e.get("callee_symbol") or e.get("callee_module", "(unknown)")
            print(f"[{e['call_kind']:>25}] {e['caller_file']}:{e['line']} -> {target}")


if __name__ == "__main__":
    main()
