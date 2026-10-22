#!/usr/bin/env node
/**
 * js-call-graph.mjs — Build a call graph from JavaScript files using AST parsing.
 *
 * This is a JavaScript-aware call graph builder, meant as a companion to
 * scip-helper (which targets TypeScript via scip-typescript).  It walks all .js
 * files in a directory tree, parses each with Acorn, and extracts:
 *   - function / class / method definitions (nodes)
 *   - require() / import() relationships + call sites (edges)
 *   - exports / module.exports assignments (node symbols)
 *
 * Output format is JSON matching the IndexResult shape consumed by the Phase 2a
 * graph analysis pipeline:
 *
 * {
 *   "root_path": "/abs/path/to/source",
 *   "nodes": [ { "symbol", "display_name", "file_path", "line_range": [start,end], "kind" } ],
 *   "edges": [ { "caller_file", "callee_symbol", "call_kind" } ]
 * }
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, dirname, basename } from 'node:path';
import { parse } from 'acorn';

// ---------------------------------------------------------------------------
// CLI entry
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
let cwd = '.';
let outputFormat = 'json';  // 'json' or 'indexer' (for compatibility with e2e_graph_analyzer)

for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
        case '--cwd':   cwd     = args[++i]; break;
        case '--format': outputFormat = args[++i]; break;
        default:
            if (!args[i].startsWith('--')) cwd = args[i]; break;
    }
}

const root = resolve(cwd);

// ---------------------------------------------------------------------------
// AST helpers — walk tree, extract definitions and calls
// ---------------------------------------------------------------------------

/** Collect all JS files under `dir`, skipping node_modules directories. */
function collectJsFiles(dir) {
    const results = [];
    try {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
            const full = join(dir, entry.name);
            if (entry.isDirectory()) {
                // Skip node_modules directories and hidden dirs
                if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
                results.push(...collectJsFiles(full));
            } else if (entry.isFile() && entry.name.endsWith('.js')) {
                results.push(full);
            }
        }
    } catch { /* skip inaccessible dirs */ }
    return results;
}

/** Parse a JS file and extract AST nodes. */
function parseFile(filePath) {
    try {
        const src = readFileSync(filePath, 'utf-8');
        // Allow module: 'commonjs' + ECMA2020 features
        const ast = parse(src, {
            ecmaVersion: 2020,
            sourceType: 'module',
            locations: true,
        });
        return { ast, src };
    } catch (err) {
        console.error(`[WARN] Failed to parse ${filePath}: ${err.message}`);
        return null;
    }
}

/** Recursively visit all AST nodes. */
function walk(ast, callback) {
    const visited = new Set();
    function _walk(node) {
        if (!node || typeof node !== 'object') return;
        const id = node.range ? node.range[0] : null;
        if (id !== null && visited.has(id)) return;
        if (id !== null) visited.add(id);
        callback(node);
        for (const key of Object.keys(node)) {
            if (key === 'parent') continue; // skip backrefs
            const child = node[key];
            if (Array.isArray(child)) {
                for (const item of child) _walk(item);
            } else if (child && typeof child === 'object') {
                _walk(child);
            }
        }
    }
    _walk(ast);
}

/** Try to resolve a module name to the local file. */
function resolveModule(baseDir, moduleName) {
    // Skip built-in / third-party modules (no node_modules lookup needed — we only care about local files)
    if (moduleName.startsWith('.') || moduleName.startsWith('/')) {
        const resolved = resolve(baseDir, moduleName);
        // Try extensions
        for (const ext of ['', '.js', '/index.js']) {
            const tryPath = resolved + ext;
            try { statSync(tryPath); return tryPath; } catch {}
        }
    }
    // Could also resolve to node_modules/<moduleName> but we only have local source
    return null;
}

/** Try to extract a function / method name from an expression. */
function exprToName(node) {
    if (!node) return '';
    switch (node.type) {
        case 'Identifier':
            return node.name;
        case 'MemberExpression':
            return `${exprToName(node.object)}.${node.property.name || ''}`;
        case 'CallExpression':
            // e.g., require('module').foo => resolve module then property
            if (node.callee.type === 'Identifier' && node.callee.name === 'require') {
                if (node.arguments[0]?.type === 'Literal') {
                    return `$require(${String(node.arguments[0].value)})`;
                }
            }
            return exprToName(node.callee);
        case 'NewExpression':
            return `new ${exprToName(node.callee)}`;
        default:
            return '';
    }
}

/** Extract the file name from a require/import path. */
function importToFileName(moduleName) {
    const base = basename(moduleName);
    // Strip extension if present
    if (base.includes('.')) return base.split('.')[0];
    return 'index';
}

// ---------------------------------------------------------------------------
// Build the call graph
// ---------------------------------------------------------------------------

function buildCallGraph(rootDir) {
    const jsFiles = collectJsFiles(rootDir);
    const allNodes = [];      // node definitions (functions, classes, exports)
    const allEdges = [];      // edges (call sites → callee names)
    const fileContents = new Map();  // filePath -> source

    // First pass: parse all files and collect symbols / exports
    const symbolIndex = new Map(); // symbol -> [{file, line}]
    const exportMap = new Map();   // file -> exported symbols

    for (const filePath of jsFiles) {
        const parsed = parseFile(filePath);
        if (!parsed) continue;
        fileContents.set(filePath, parsed.src);

        // Build relative path from rootDir
        const relPath = filePath.replace(rootDir + '/', '');

        walk(parsed.ast, (node) => {
            // --- Collect function / class definitions ---
            let symbol = '';
            let kind = 'unknown';

            if (node.type === 'FunctionDeclaration') {
                symbol = `fn_${node.id?.name || 'anon'}`;
                kind = 'function';
            } else if (node.type === 'ClassDeclaration') {
                symbol = `class_${node.id?.name || 'anon'}`;
                kind = 'class';
            } else if (node.type === 'FunctionExpression') {
                // Named function expression assigned to a variable
                const parent = node.parent;
                if (parent?.type === 'VariableDeclarator' && parent.init === node) {
                    symbol = `fn_${parent.id?.name || 'anon'}`;
                    kind = 'function';
                } else if (parent?.type === 'AssignmentExpression' && parent.right === node) {
                    symbol = `fn_${parent.left?.property?.name || parent.left?.name || 'anon'}`;
                    kind = 'function';
                }
            } else if (node.type === 'MethodDefinition') {
                const classParent = findAncestor(node, 'ClassBody');
                symbol = `method_${node.key.name ?? ''}`;
                kind = 'method';
            }

            if (symbol && node.loc) {
                allNodes.push({
                    symbol: `${relPath}::${symbol}`,
                    display_name: symbol.replace(/^fn_|^class_|^method_/, ''),
                    file_path: relPath,
                    line_range: [node.loc.start.line, node.loc.end.line],
                    kind,
                });
                if (!symbolIndex.has(symbol)) symbolIndex.set(symbol, []);
                symbolIndex.get(symbol).push({ file: relPath, line: node.loc.start.line });

                // Extract export info
                const ancestor = findAncestor(node, 'ExportNamedDeclaration') ||
                                 findAncestor(node, 'ExportDefaultDeclaration');
                if (ancestor) {
                    if (!exportMap.has(relPath)) exportMap.set(relPath, []);
                    exportMap.get(relPath).push(symbol.replace(/^fn_|^class_|^method_/, ''));
                }
            }

            // --- Collect require() calls ---
            if (node.type === 'CallExpression' &&
                node.callee?.type === 'Identifier' &&
                node.callee.name === 'require') {
                const arg0 = node.arguments[0];
                if (arg0?.type === 'Literal' && typeof arg0.value === 'string') {
                    const moduleName = arg0.value;
                    allEdges.push({
                        caller_file: relPath,
                        callee_module: moduleName,
                        call_kind: 'require',
                        line: node.loc.start.line,
                    });

                    // Try to resolve the require to a local file
                    const resolvedFile = resolveModule(rootDir, moduleName);
                    if (resolvedFile) {
                        allNodes.push({
                            symbol: `$require_${moduleName}::index`,
                            display_name: moduleName,
                            file_path: resolvedFile.replace(rootDir + '/', ''),
                            line_range: [1, 1],
                            kind: 'import',
                        });
                    }
                }
            }

            // --- Collect call sites (name(...), obj.method(...)) ---
            if (node.type === 'CallExpression' && node.callee) {
                const calleeName = exprToName(node.callee);
                if (calleeName && !calleeName.startsWith('$require')) {
                    allEdges.push({
                        caller_file: relPath,
                        callee_symbol: calleeName,
                        call_kind: 'call',
                        line: node.loc.start.line,
                    });
                }
            }

            // --- Collect MemberExpression calls: obj.method() ---
            if (node.type === 'NewExpression') {
                const ctorName = exprToName(node.callee);
                if (ctorName) {
                    allEdges.push({
                        caller_file: relPath,
                        callee_symbol: ctorName,
                        call_kind: 'new',
                        line: node.loc.start.line,
                    });
                }
            }
        });
    }

    // Deduplicate nodes by symbol + file
    const seenNodes = new Set();
    const uniqueNodes = [];
    for (const n of allNodes) {
        const key = `${n.file_path}::${n.symbol}`;
        if (!seenNodes.has(key)) {
            seenNodes.add(key);
            uniqueNodes.push(n);
        }
    }

    // Deduplicate edges
    const seenEdges = new Set();
    const uniqueEdges = [];
    for (const e of allEdges) {
        const key = `${e.caller_file}::${e.callee_symbol || e.callee_module}`;
        if (!seenEdges.has(key)) {
            seenEdges.add(key);
            uniqueEdges.push(e);
        }
    }

    return {
        root_path: rootDir,
        nodes: uniqueNodes,
        edges: uniqueEdges,
        summary: {
            total_files: jsFiles.length,
            total_nodes: uniqueNodes.length,
            total_edges: uniqueEdges.length,
            exports_by_file: Object.fromEntries(exportMap),
        },
    };
}

/** Find the first ancestor node of a given type by walking up parent refs. */
function findAncestor(node, targetType) {
    let current = node.parent;
    let depth = 0;
    while (current && depth < 50) {
        if (current.type === targetType) return current;
        current = current.parent;
        depth++;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Run and output
// ---------------------------------------------------------------------------

const graph = buildCallGraph(root);

if (outputFormat === 'indexer') {
    // Minimal line-based format for compatibility with print_graph.py style:
    console.log(`# Root: ${graph.root_path}`);
    console.log(`# Files: ${graph.summary.total_files}, Nodes: ${graph.summary.total_nodes}, Edges: ${graph.summary.total_edges}`);

    for (const n of graph.nodes) {
        const [lineStart, lineEnd] = n.line_range;
        console.log(
            `[${n.kind}] ${n.symbol} @ ${n.file_path}:${lineStart}${lineEnd > lineStart ? `-${lineEnd}` : ''}`
        );
    }

    for (const e of graph.edges) {
        const target = e.callee_symbol || e.callee_module;
        console.log(`[${e.call_kind}] ${e.caller_file}:${e.line} -> ${target}`);
    }
} else {
    // JSON output — the format consumed by Phase 2a when we wrap in IndexResult
    console.log(JSON.stringify(graph, null, 2));
}
