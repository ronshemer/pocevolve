---
name: poc-evolve-evaluation-runbook
description: Complete evaluation runbook for PoCEvolve before/after comparison of exploit generation approaches
metadata:
  type: project
---

# PoCEvolve Evaluation Runbook

## Purpose

This runbook provides a reproducible pipeline to:
1. Establish baseline metrics for the existing LLM-driven iterative exploit generation approach
2. Rerun the same evaluation after implementing improvements (e.g., static analysis / call graph integration)
3. Produce structured before/after comparison reports

## Pipeline Stages

```
Phase 0: Environment Setup    → Install deps, verify Docker, check dataset integrity
Phase 1: VFC Generation       → Run generator.py on target dataset (if not already done)
Phase 2: Exploit Iteration    → Run evolver_llm.py or evolver_pocgen.py per-dataset
Phase 3: Baseline Metrics     → Aggregate transcripts, compute metrics, write report
Phase 4: Improvement Phase    → (Future) Re-run Phases 1-3 with static analysis module
Phase 5: Comparison Report    → Before vs after comparison output
```

## Quick Start

```bash
# Baseline run
bash PoCEvolve/eval/run_pipeline.sh --mode baseline

# After implementing improvements
bash PoCEvolve/eval/run_pipeline.sh --mode improvement

# Compare results
python3 PoCEvolve/eval/aggregate_metrics.py --baseline baseline/results/baseline_metrics.json --improvement baseline/results/improvement_metrics.json --output baseline/results/comparison.csv
```

## Configuration

All configuration is in `PoCEvolve/src/config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `MODEL_NAME` | gpt-4 | LLM model identifier |
| `API_BASE` | http://host.docker.internal:4000/v1 | OpenAI-compatible API endpoint |
| `ITERATION` | 5 | Max iterations per attempt |
| `MINIBATCH_SIZE` | 3 | Candidates to evolve per iteration |
| `VERIFY_TIME` | 3 | Verify timeout in seconds |
| `COMMAND_TIMEOUT` | 30 | Exploit execution timeout |
| `SEED` | 42 | Random seed for reproducibility |
| `DATASET_LIST` | datasets/SecBench.js.PoCGen.vfc.190 | Target dataset file path |

## Dataset Selection

Two datasets are available:

- `datasets/SecBench.js.PoCGen.vfc.190` — 190 vulnerability IDs with VFC data (recommended for evaluation)
- `datasets/SecBench.js.PoCGen.559` — 559 total vulnerability IDs (larger scope, longer runtime)

## Expected Runtime

| Dataset | Est. LLM Calls per Vuln | Est. Total LLM Calls | Est. Wall Time (baseline) |
|---------|------------------------|---------------------|--------------------------|
| vfc.190 | ~20-40 | ~3,800-7,600 | 2-4 hours (with caching) |
| PoCGen.559 | ~20-40 | ~11,000-22,000 | 6-12 hours (with caching) |

Timing depends heavily on LLM API latency and whether cache is warm.

## Metrics Collected

### Per-Vuln Metrics
- `vuln_id`: CVE or SNYK identifier
- `vulnerability_type`: code-injection, command-injection, path-traversal, prototype-pollution, redos
- `passed`: boolean — any exploit succeeded in triggering the vulnerability
- `total_attempts`: total number of prompt iterations across all attempts
- `avg_score`: average multi-dimensional score across all prompts
- `max_score`: highest individual score observed
- `total_llm_calls`: LLM calls for this vuln (generation + iteration)
- `elapsed_seconds`: total wall time for exploitation

### Aggregated Metrics
- Pass rate per vulnerability type
- Overall pass rate
- Score distribution (mean, median, p25, p75, max)
- Total LLM API cost estimate (tokens × price)
- Average iterations to success/failure
- Distribution of work across CWE categories

## Improvement Integration Points

### Where to add static analysis / call graph support:

1. **New module: `PoCEvolve/src/static_analyzer.py`**
   - Entry: `analyze_package(package_name, vulnerable_api)` returns taint paths, call graphs
   - Output format: JSON with call graph edges, data flow sources/sinks, reachable functions

2. **Modify prompts (PoCEvolve/src/prompts.py)**
   - Add static analysis context to `EXPLOIT_GENERATE_LLM_USER_PROMPT`
   - Add new criteria to `REQUIRED_CONTEXTS` list
   - Extend `SCORING_LLM_SYSTEM_PROMPT` with new scoring dimensions

3. **Modify pipeline (PoCEvolve/src/pipeline.py)**
   - Call static analyzer before iteration loop starts
   - Inject call graph context into seed prompts
   - Track analysis time per vuln as a new metric

4. **Add config flag**: `USE_STATIC_ANALYSIS = False` in config.py — set to `True` for improvement runs

## Files Created by This Runbook

```
PoCEvolve/eval/
├── run_pipeline.sh          # Main orchestrator script
├── aggregate_metrics.py     # Transcript aggregation and metrics extraction
├── config.env.example       # Configuration template (copy as config.env)
└── results/                 # Output directory (gitignored)
    ├── baseline_metrics.json
    ├── improvement_metrics.json
    └── comparison.csv
```

## Prerequisites

1. Docker with patched_node image built and available
2. OpenAI-compatible API endpoint running (e.g., vLLM, Ollama, LMStudio)
3. Python 3.9+ with requirements.txt installed
4. git cloned SecBench.js benchmark repos in PoCEvolve/SecBench.js/

## Monitoring Progress

The evolver writes transcript.json files per-vuln as it runs:

```bash
# Check progress during a run
find PoCEvolve/logs -name "transcript.json" | wc -l
# or tail the output
tail -f PoCEvolve/logs/progress.log
```

A transcript entry looks like:
```json
{
  "id": "SNYK-JS-XXX",
  "attempts": [
    {
      "seed_prompts": [...],
      "iteration": 1,
      "timers": {"initial_evaluation": 45.2},
      "timestamp": "2026-09-02T12:00:00"
    }
  ],
  "testbed": "/app/testbed/...",
  "model": "gpt-4",
  "max_iteration": 5
}
```
