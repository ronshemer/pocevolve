"""Phase 1: SCIP indexer — public API for indexing package source code.

Takes a package root directory, runs ``@sourcegraph/scip-typescript`` to build
a call graph, and returns an :class:`IndexResult` with nodes (functions/types)
and edges (call relationships).

This module is the only public entry point; all other submodules are internal.

Usage::

    from src.indexer import scan

    result = scan("/path/to/package")
    if result.available:
        for node in result.nodes:
            print(node.symbol, node.kind)
        for edge in result.edges:
            print(f"{edge.caller_symbol} -> {edge.callee_symbol}")
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from src.indexer import config, normalizer, parser
from src.indexer._types import EdgeInfo, IndexResult, NodeInfo

logger = logging.getLogger(__name__)

def scan(package_root: str | Path, opts: config.IndexerConfig | None = None) -> IndexResult:
    """Run SCIP indexing on *package_root* and return an ``IndexResult``.

    Steps:

        1. Create a temporary workspace and copy/symlink the package tree.
        2. Run ``scip-typescript index --output index.scip``.
        3. Parse the gzip-compressed binary protobuf output (with text-fallback).
        4. Normalise parsed symbols into nodes / edges.

    Returns an **unavailable** result when SCIP is not installed or the scan
    produces no nodes — data flow tracing is always optional, never blocking.
    """
    opts = opts or config.default_config()
    result = IndexResult(root_path=str(Path(package_root).resolve()))

    # --- Step 1: run scip-typescript CLI -----------------------------------
    scip_file = _run_scip_indexer(str(package_root), opts)
    if not scip_file or not Path(scip_file).is_file():
        result.error = "scip-typescript produced no output file"
        logger.warning("Index unavailable for %s: %s", package_root, result.error)
        return result

    # --- Step 2: parse binary/scip file ------------------------------------
    try:
        parsed = parser.parse_scip_file(scip_file)
    except Exception as exc:
        result.error = f"SCIP parsing failed: {exc}"
        logger.warning("Index unavailable for %s: %s", package_root, result.error)
        return result

    if not parsed.documents:
        result.error = "scip-typescript returned empty index (no documents)"
        return result

    # --- Step 3: normalise to graph ----------------------------------------
    norm = normalizer.normalise(parsed, root_path=str(Path(package_root).resolve()))
    result.available = len(norm.nodes) > 0
    result.nodes = norm.nodes
    result.edges = norm.edges
    result.symbol_map = norm.symbol_map
    result.metadata = {
        "language": parsed.language,
        "document_count": len(parsed.documents),
        "symbol_count": sum(len(d.symbols) for d in parsed.documents),
        "occurrence_count": sum(
            (len(d.occurrences) if hasattr(d, "occurrences") else 0)
            for d in parsed.documents
        ),
        "project_root": parsed.project_root,
    }

    logger.info(
        "Indexed %s: %d nodes, %d edges (%d docs)",
        package_root,
        len(result.nodes),
        len(result.edges),
        len(parsed.documents),
    )
    return result


# ---------------------------------------------------------------------------
# SCIP CLI invocation (pure subprocess — no external helpers)
# ---------------------------------------------------------------------------

def _run_scip_indexer(package_root: str, opts: config.IndexerConfig) -> str | None:
    """Run scip-typescript and return path to the output .scip file.

    Falls back to text-pb if binary output is rejected by scip-typescript.
    Returns ``None`` when the CLI itself is unavailable (npx / node missing).
    """
    tmp_dir = Path(opts.temp_dir)
    output_path = str(tmp_dir / "index.scip")

    cmd = [
        "npx", "--yes", "@sourcegraph/scip-typescript", "index",
        "--output", output_path,
    ]

    merged_env: dict[str, str] = dict(os.environ)
    if opts.env:
        merged_env.update(opts.env)

    try:
        proc = subprocess.run(
            cmd,
            cwd=package_root,
            env=merged_env,
            capture_output=True,
            timeout=opts.timeout,
        )
        if proc.returncode != 0:
            logger.warning("scip-typescript failed (rc=%d): %s", proc.returncode, proc.stderr.decode(errors="replace").strip())
            return None
    except FileNotFoundError:
        logger.warning("npx not found — SCIP indexing skipped")
        return None  # type: ignore[return-value]
    except subprocess.TimeoutExpired:
        logger.warning("scip-typescript timed out after %ds on %s", opts.timeout, package_root)
        return False

    return output_path


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def available() -> bool:
    """Return True if scip-typescript and protobuf are installed.

    Checks both the Node.js toolchain (via *npx*) and the Python protobuf
    runtime that is needed to read the binary output.
    """
    try:
        __import__("google.protobuf")
    except ImportError:
        return False

    try:
        proc = subprocess.run(
            ["npx", "--yes", "@sourcegraph/scip-typescript", "--version"],
            capture_output=True, text=True, timeout=30,
        )
        return proc.returncode == 0
    except Exception:
        return False
