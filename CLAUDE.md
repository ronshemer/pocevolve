# PoCEvolve — CLAUDE.md

**Three sub-projects:** `cves-fixes/`, `PoCGen/`, `PoCEvolve/` (iterative exploit gen).

## Documentation

- [ARCHITECTURE.md](PoCEvolve/CLAUDE-plans/ARCHITECTURE.md) — Full system architecture, module layout, and data flow diagrams.

## PoCEvolve (`PoCEvolve/`)

**Flow:** `config.py` → `generator.py` | `evolver_llm.py` | `evolver_pocgen.py` → `pipeline.py` → `evaluator.py` → `evolve_prompt.py` → `llm.py`+`prompts.py`. Support: `analyzer.py`, `verify.py`, `selector.py`, `train_set.py`.

**Key config** (`src/config.py`): MODEL_NAME, API_KEY, API_BASE, ITERATION=5, MINIBATCH_SIZE=3, MAX_RETRY=2, MAX_EXEC_OUTPUT_CHARS=4000, VALIDATE_FUNC, CWE_MAP. Datasets: `datasets/`, SecBench JS: `secbenchjs/`, Oracles: `resources/validate_functions/`.

**Run:**
```bash
DATASET=<path> python3 -B -m src.generator            # one-shot
DATASET=<path> python3 -B -m src.evolver_llm          # iterative (LLM)
DATASET=<path> python3 -B -m src.evolver_pocgen       # iterative (PoCGEN; needs TRAINING_DATA + prior output via train_set.py)
```

**Eval:** `cd eval && cp config.env.example config.env && bash check_baseline.sh && bash run_pipeline.sh` → `eval/RUNBOOK.md`.

**Docker:** `docker compose -f docker-compose.yml up -d` → `docker exec -it exploit-generation bash`. Prefer host for Ollama localhost.

## Static analysis (`PoCEvolve/src/graph_analysis/`)

The current branch uses an AST-assisted, diff-based analyzer. It parses deleted lines from a VFC patch, resolves their enclosing JavaScript functions when possible, and reports package entry-point files. Results use `mode="entry_points_only"`; SCIP indexing and taint-flow tracing are not currently present.

**Run:** `bash PoCEvolve/eval/analyze_cve.sh <CVE-ID>` creates/reuses the vulnerable checkout and writes JSON under `eval/results/static-analysis/`. Use `python3 -B -m src.graph_analysis --testbed <path> --diff <patch.diff>` from `PoCEvolve/` to analyze a supplied testbed and diff.

**Test:** `python3 -m pytest PoCEvolve/src/graph_analysis/tests/test_graph_analysis.py -v`.
