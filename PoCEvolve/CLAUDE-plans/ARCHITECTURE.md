# PoCEvolve Architecture

PoCEvolve is an iterative exploit generation system for CVE proof-of-concept code. It indexes vulnerable JavaScript packages, maps CVE fix diffs to call-graph nodes, extracts tainted data flows, and feeds that context into LLM-powered exploit generation.

## High-level flow

```
config.py → generator.py | evolver_llm.py | evolver_pocgen.py
                    ↓
              pipeline.py
                    ↓
            graph_analysis (indexer + analysis)  ← enrichment layer
                    ↓
          evaluator.py → evolve_prompt.py → llm.py / prompts.py
```

## Sub-projects

| Directory      | Role                                           |
|---------------|------------------------------------------------|
| `src/`        | Main exploit generation pipeline (generator, evolver, pipeline, eval) |
| `src/indexer/`| SCIP-based JavaScript/TypeScript indexer       |
| `src/graph_analysis/` | Diff-to-graph matching + taint extraction   |

---

## 1. Main Pipeline (`src/`)

### Entry points (CLI modules)

```bash
python -m src.generator              # one-shot exploit generation
python -m src.evolver_llm            # iterative LLM-based evolution
python -m src.evolver_pocgen         # iterative PoCGEN-based evolution
```

### Core modules

**`src/config.py`** — Global configuration via `IndexerConfig` (for indexer) and pipeline config (MODEL_NAME, API_KEY, API_BASE, ITERATION, MINIBATCH_SIZE, MAX_RETRY, MAX_EXEC_OUTPUT_CHARS, VALIDATE_FUNC, CWE_MAP).

**`src/generator.py`** — One-shot exploit generation: reads a CVE dataset, invokes the LLM once per CVE.

**`src/pipeline.py`** — Multi-iteration orchestrator. Drives generate → evaluate → evolve loop across minibatches of CVEs.

**`src/evolver_llm.py`** — Iterative evolution using a generic LLM API. Rewrites failed exploits based on feedback (console output + error traces).

**`src/evolver_pocgen.py`** — Iterative evolution specialized for PoCGEN models. Requires prior training data and existing exploit outputs (managed via `train_set.py`).

**`src/evaluator.py`** — Runs generated exploits against target packages, captures console output and success/failure status.

**`src/evolve_prompt.py`** — Constructs feedback prompts for the evolution loop, incorporating failed code + console output.

### Supporting modules

| Module | Purpose |
|--------|---------|
| `analyzer.py` | Exploit result analysis |
| `selector.py` | CVE selection/deduplication |
| `train_set.py` | Training set management for PoCGEN |
| `verify.py` | Exploit validation |
| `llm.py` | LLM API abstraction |
| `prompts.py` | Prompt templates |
| `utils.py` | Shared utilities |

### Datasets & resources

- `datasets/` — CVE dataset files
- `secbenchjs/` — SecBench JavaScript benchmark data
- `resources/validate_functions/` — Validation function definitions

---

## 2. Indexer (`src/indexer/`)

Standalone SCIP-based indexer for JavaScript/TypeScript packages. Produces an in-package call graph from source code.

### Public API

```python
from src.indexer import scan, default_config, IndexerConfig

result = scan(package_root, opts=default_config())
# result: IndexedGraph { nodes, edges, symbol_map, available, error }
```

**`scan(package_root, opts=...)`** — Boots the SCIP pipeline for a single package directory. Returns `IndexedGraph` with nodes (symbol definitions), edges (call relationships), and a symbol_map for lookup. Gracefully degrades when scip-typescript is unavailable.

### Module layout

| File | Role |
|------|------|
| `__init__.py` | **Public API** — `IndexerConfig` dataclass, `default_config()`, `scan()` |
| `scip-helper.mjs` | Bootstraps tsconfig, runs `@sourcegraph/scip-typescript`, outputs `.scip` |
| `parser.py` | Parses protobuf `.scip` files into Python objects |
| `normalizer.py` | Converts raw SCIP nodes/edges to clean `NormalizedGraph` + `symbol_map` |

### IndexerConfig

```python
@dataclass
class IndexerConfig:
    temp_dir: str
    timeout: int
    env: dict[str, str] | None = None
    prefer_text_fallback: bool = False
```

All config previously in the deleted `config.py` was migrated here. The default uses 180s timeout and system temp directory.

### Internal components (normalizer.py)

**Phase 2.5 — Occurrence-position line ranges:** For each symbol occurrence in the SCIP index, extracts `(start_line, end_line)` from the occurrence's `single_line_range` field. If the range spans multiple lines, uses first and last occurrence positions as bounds. This is the active path for all real usage.

**Symbol normalization:** Maps raw SCIP symbols to nodes with display names (preferring symbol info's `display_name`, falling back to last path component of the symbol). Groups nodes by scope prefix (file path) in `symbol_map`.

**Edge construction:** Builds call edges from `is_reference=True` relationships on definition symbols. Extracts caller/callee full symbols, kind ("calls"), and occurrence line information.

> **Note:** Phase 2.6 (source-file parsing fallback via regex) was removed as dead code — it had no active callers and the degenerate-line-range check that would activate it never fires in practice since Phase 2.5 handles all real cases.

---

## 3. Graph Analysis (`src/graph_analysis/`)

Bridges the indexer's in-package call graph with exploit-relevant analysis: identifying which CVE fix diff entries map to graph nodes and reconstructing tainted data flows through them.

### Public API

```python
from src.graph_analysis import analyze_cve, run_analysis

result = analyze_cve(
    cve_id="CVE-2024-1234",
    package_root="/path/to/testbed",
    diff_text=...,  # unified diff text
)
# result: AnalysisResult { matched_methods, taint_flows, error }
```

**`analyze_cve()`** — High-level entry point. Runs indexer → analyzer pipeline with graceful degradation (returns empty results if indexer unavailable).

**`run_analysis()`** — Core analysis logic. Takes pre-built index + diff text, runs diff-to-graph matching and taint extraction.

### Module layout

| File | Role |
|------|------|
| `__init__.py` | **Public API** — `analyze_cve`, `run_analysis`, `DiffToGraphMatch` |
| `analyzer.py` | Main orchestration: calls diff_parser, graph_matcher, taint_flow |
| `diff_parser.py` | Parses CVE fix unified diffs into `DiffEntry` objects |
| `graph_matcher.py` | Matches `DiffEntry` objects to call-graph nodes by symbol/filename/line range |
| `taint_flow.py` | Reconstructs tainted paths from entry points to shell sinks |
| `_types.py` | Data class definitions (DiffEntry, TaintSource, TaintSink, etc.) |
| `_scoring.py` | Scoring heuristics for match quality |
| `method_resolution.py` | Resolves JavaScript method signatures across scopes |

### Data flow classes (`_types.py`)

| Class | Purpose |
|-------|---------|
| `DiffEntry` | A change in the CVE fix: file_path, method_name, line range, change_type ("added"/"removed"/"modified") |
| `TaintSource` | Entry point of untrusted data: symbol, parameter index/name, location |
| `TaintSink` | Terminal dangerous API call: shell_exec, system, popen, etc. |
| `TaintFlow` | Path from TaintSource → intermediate calls → TaintSinks |
| `MatchedMethod` | Graph node identified in the CVE fix diff |
| `AnalysisResult` | Final output: matched_methods + taint_flows for one CVE |

### Diff-to-graph matching flow (analyzer.py)

1. Parse CVE diff via `diff_parser.py` → list of `DiffEntry` objects
2. For each entry, find matching nodes in the call graph via `graph_matcher.py`:
   - Exact symbol match → highest confidence
   - Filename + line range overlap → medium confidence
   - Method name only (no filename) → low confidence fallback
3. Collect matched methods into `AnalysisResult.matched_methods`

### Taint extraction flow (taint_flow.py)

1. For each entry point (matched method or package-level exports like `index.js:module.exports`):
   - Walk call graph forward from the entry point
   - Track parameters that carry untrusted values (from taint sources)
   - Continue through intermediate calls, propagating tainted parameters
2. Identify terminal sinks: API calls to shell commands (`exec`, `spawn`, `popen`, etc.)
3. Reconstruct full paths: source → intermediate_calls → sinks

### Graceful degradation

Every step in the pipeline degrades silently:
- No SCIP available? → empty results (same as before any of this work)
- Indexer returns empty? → empty analysis
- Analyzer finds no matches? → empty matched_methods, empty taint_flows
- Parsing error? → log warning, return empty result

---

## Architecture diagrams

### Data flow architecture

```
                    ┌─────────────┐
                    │  config.py   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
       ┌──────────┐ ┌──────────┐ ┌───────────┐
       │ generator│ │evolver_  │ │evolver_   │
       │ .py      │ │ llm.py   │ │ pocgen.py │
       └────┬─────┘ └────┬─────┘ └────┬──────┘
            │             │            │
            ▼             ▼            ▼
         ┌──────── pipeline.py ────────┐
         │  generate → evaluate →      │
         │           evolve loop        │
         └──────┬──────────────┬───────┘
                │              │
     ┌──────────▼──┐    ┌─────▼──────────┐
     │evaluator.py │    │ graph_analysis  │
     └──────────────┘    │                 │
                         │ indexer →       │
                         │ analyzer →      │
                         │ taint_flow      │
                         └─────────────────┘
```

### Module dependencies (top-down)

```
generator.py, evolver_*.py, pipeline.py   ← main entry points
    ↓
pipeline.py                               ← orchestrator
    ↓
evaluator.py → analyze_cve()             ← graph_analysis bridge
    ↓
src/indexer/scan()                        ← SCIP indexing
    ↓
@sourcegraph/scip-typescript              ← external tool

src/graph_analysis/*                      ← analysis layer
    ├── analyzer.py                       ← orchestration
    ├── diff_parser.py                   ← diff parsing
    ├── graph_matcher.py                 ← symbol matching
    ├── taint_flow.py                    ← path reconstruction
    ├── _scoring.py                      ← match quality heuristics
    └── method_resolution.py             ← JS signature resolution
```

---

## Run commands

```bash
# One-shot generation
DATASET=<path> python3 -B -m src.generator

# Iterative evolution (LLM)
DATASET=<path> python3 -B -m src.evolver_llm

# Iterative evolution (PoCGEN; needs TRAINING_DATA + prior output)
DATASET=<path> python3 -B -m src.evolver_pocgen

# Eval pipeline
cd eval && cp config.env.example config.env && bash check_baseline.sh && bash run_pipeline.sh
```

---

## Docker

```bash
docker compose -f docker-compose.yml up -d
docker exec -it exploit-generation bash
```

> **Note:** Prefer host for Ollama localhost (the container cannot reach the host's Ollama instance).
