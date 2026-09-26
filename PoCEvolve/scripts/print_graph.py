#!/usr/bin/env python3
"""Print the SCIP indexer call graph in a human-readable format.

Usage:
    PYTHONPATH=. python3 -B scripts/print_graph.py
    # or override the testbed:
    SCIP_TESTBED=/path/to/package PYTHONPATH=. python3 -B scripts/print_graph.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.indexer import scan


def _default_testbed() -> str:
    return os.environ.get("SCIP_TESTBED", "SNYK-JS-DEEPLY-451026")


ROOT = Path(__file__).resolve().parent.parent
TESTBED = ROOT / "testbed" / _default_testbed()

if not TESTBED.exists():
    print(f"Testbed not found at {TESTBED}. Set SCIP_TESTBED.", file=sys.stderr)
    sys.exit(1)


print(f"\n{'='*72}")
print(f"  Call Graph: {_default_testbed()}")
print(f"  Source:     {TESTBED}")
print(f"{'='*72}\n")

result = scan(TESTBED)

# --- Nodes by file ---
by_file: dict[str, list] = {}
for n in result.nodes:
    fpath = n.file_path or "(root)"
    # trim the root prefix for readability
    try:
        fpath = str(Path(fpath).relative_to(TESTBED))
    except ValueError:
        pass
    by_file.setdefault(fpath, []).append(n)

if not result.nodes:
    print("  (no nodes found)\n")
else:
    print(f"Nodes: {len(result.nodes)} | Edges: {len(result.edges)}\n")
    print("--- Definitions by file ---\n")
    for fpath in sorted(by_file):
        rel = f"[{fpath}]"
        print(rel)
        for n in sorted(by_file[fpath], key=lambda x: x.display_name or ""):
            kind_str = n.kind or "unknown"
            line = f":L{n.line_range[0]}" if n.line_range else ""
            name = n.display_name or n.symbol
            print(f"  [{kind_str:>12}] {name}{line}")
        print()

# --- Edges as call chain ---
if result.edges:
    print("--- Call Edges ---\n")
    for e in result.edges:
        loc = f" @ {e.location}" if e.location else ""
        print(f"  {e.caller_symbol}  --calls-->  {e.callee_symbol}{loc}")
    print()
else:
    print("(no call edges detected)\n")

print(f"{'='*72}\n")
