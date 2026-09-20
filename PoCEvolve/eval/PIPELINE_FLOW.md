# PoCEvolve Evaluation Pipeline — Flow Diagram

This document traces the full evaluation run from dataset input to metrics output, showing what each phase does, which files it reads/writes, and how control flows between `run_pipeline.sh` and the Python scripts.

---

## Top-level flow (via `bash eval/run_pipeline.sh`)

```
run_pipeline.sh                          e2e.py  (alternative entrypoint)
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌──────────────┐
│ Phase 0: Env │ --> │ Phase 1: VFC      │ --> │ Phase 2: Evolve │ --> │ Phase 3:     │
│ Verification │     │ Generation         │     │ (Evolver)       │     │ Metrics      │
└─────────────┘     └──────────────────┘     └─────────────────┘     └──────────────┘
```

Both `run_pipeline.sh` and `eval/e2e.py` implement the same four phases but with different implementation details.

---

## Phase 0: Environment Verification

**What it checks:**
- Docker daemon is running (needed for exploit execution)
- `patched_node` Docker image exists (or warns if missing)
- Python dependencies (`openai`, `litellm`) importable
- Dataset file exists
- LLM cache directory (`logs/cache/`)
- Previous VFC data (Phase 1 output) for resuming
- API endpoint connectivity

**Output:** Pass/fail printed to stdout. Aborts on any critical error.

---

## Phase 1: VFC (Vulnerable Function Context) Generation

**What it does:** Extracts the vulnerable function and its surrounding context from each CVE's codebase snapshot, producing a structured JSONL record per vulnerability.

**Script:** `python3 -B -m src.analyzer` → then `python3 -B -m src.generator`

### Step 1a: Analyzer (`src/analyzer.py`)

Reads the active dataset file (one CVE/SNYK/GHSA ID per line). For each ID:
1. Finds the matching entry in `secbenchjs/vfcs.filtered.json` (or `vfcs.predicted.json`).
2. Extracts the vulnerable function's code, source location, and repository snapshot directory.
3. Writes combined analysis to `logs/vfcs.predicted.json` (JSON array of datapoints).

### Step 1b: Generator (`src/generator.py`)

Takes analyzer output and generates initial exploit PoCs:
1. Builds a prompt from the VFC data (function code + context).
2. Calls the LLM (via `src/llm.py` / `src/prompts.py`) to generate an exploit PoC.
3. Executes the generated exploit against the target (via Docker) in a sandboxed container.
4. Checks execution output for `"pass 1"` — this is the **success marker** for the generated exploit.

**Output file:** `logs/vfcs.generated.<dataset_stem>.jsonl`

Each line is a JSON object containing:
- `testbed_dir`: path to the target codebase snapshot
- `generated_exploits`: list of PoC attempts (each with `code`, `console_log`)
- `console_log`: array of execution results per exploit, where each entry has `stdout` and `stderr`

**Critical decision point:** If no exploit in `generated_exploits` contains `"pass 1"` in its stdout, the vulnerability is marked `phase1_no_pass`. The evolver will still run (Phase 2), but all attempts inherit this poor starting point.

---

## Phase 2: Exploit Evolution

**What it does:** Iteratively improves exploits using GEPA (Generative Exploit Prediction Acceleration) optimization loop.

**Script:** `python3 -B -m src.evolver_llm` (for VFC data mode) or `src.evolver_pocgen` (for PoCGen data mode)

### How the evolver works:

1. **Load VFCS data:** Calls `_load_vfcs_generated()` which glob-scan reads all `vfcs.generated.*.jsonl` files into a dict keyed by `testbed_dir`.

2. **Read dataset:** Loads IDs from `$DATASET` (or `$FILTERED_DATASET` set by run_pipeline.sh).

3. **Apply CVE_COUNT filter:** If `$CVE_COUNT` env var is set, limits to first N IDs.

4. **Check for resumption:** Looks at `logs/gepa/<id>/transcript.json`. If a transcript exists and has valid attempts (non-empty seed_prompts) without an error, it skips that CVE.

5. **For each CVE (in tqdm progress bar):**
   - Creates output directory: `logs/gepa/<CVE_ID_with_underscores>/`
   - Initializes `transcript.json` with attempt metadata
   - **If GEPA is enabled** (`SKIP_GEPA=0`):
     - Calls `run_gepa_optimization()` from `src/pipeline.py` — this is the main optimization loop that iterates up to `ITERATION` (config: 5) times.
     - Each iteration: LLM generates an improved exploit → executes it → scores it → feeds feedback back.
   - **If GEPA is skipped** (`SKIP_GEPA=1`, default): The evolver returns early with no optimization. Only the initial PoCs from Phase 1 exist.

6. **Attempt scoring:** Each attempt's exploits are scored by checking if any console_log entry contains `"pass 1"`.

**Key config values** (`src/config.py`):
| Config | Default | Meaning |
|--------|---------|---------|
| `MODEL_NAME` | — | LLM model to use |
| `API_KEY` | — | OpenAI-compatible API key |
| `API_BASE` | — | API endpoint URL |
| `ITERATION` | 5 | Max GEPA optimization iterations per CVE |
| `MINIBATCH_SIZE` | 3 | Batch size for parallel evaluation |
| `MAX_RETRY` | 2 | Retry count for LLM calls |
| `MAX_EXEC_OUTPUT_CHARS` | 4000 | Truncate exploit execution output |

**SKIP_GEPA:** Default is `1` (skip). Override with `--run-gepa` or `SKIP_GEPA=0`.

---

## Phase 3: Metrics Aggregation

**Script:** `python3 eval/aggregate_metrics.py --logs-dir <PoCEvolve/logs> --output <metrics.json> --dataset-list <active_dataset>`

### How metrics are computed:

For each CVE in the dataset:
1. Look for `transcript.json` at `logs/gepa/<CVE_ID>/transcript.json`.
2. If transcript exists and has attempts → status is `"completed"`.
3. Check `_transcript_succeeded()`: does any seed_prompt have an `exploit_result` that's True?
4. If no transcript or no succeeded attempts:
   - Fall back to checking VFC data for initial PoCs.
   - If no exploits passed the basic gate → `status_detail: "phase1_no_pass"`.

**Output fields per vulnerability:**
```json
{
  "vuln_id": "SNYK-JS-XXXX",
  "status": "completed",           // or "incomplete" / "error"
  "passed": false,                 // final pass/fail decision
  "total_attempts": 5,             // how many exploit attempts were made
  "total_iterations": 0,           // how many GEPA iterations ran (0 if skipped)
  "success_attempt_index": null,   // index of first successful attempt (or null)
  "avg_score": null,               // mean score across attempts
  "max_score": null,
  "vulnerability_type": "command-injection",
  "status_detail": "phase1_no_pass",  // "phase1_success" or "phase1_no_pass"
  "generation_time": 436.02,       // seconds for Phase 1 (VFC generation)
  "generated_exploits_available": true  // VFC data exists
}
```

### Summary metrics:
- `total_vulns`: count of IDs in dataset
- `completed` / `failed` / `passed`: counts by final status
- `overall_pass_rate`: passed / completed (0% if none)
- `per_category`: breakdown by vulnerability type
- `work_distribution`: total_attempts, avg_attempts_per_vuln, min/max

---

## Data flow between phases

```
secbenchjs/vfcs.filtered.json  ──→  src/analyzer.py  ──→  logs/vfcs.predicted.json
                                                          ↓
                                              src/generator.py (with LLM API calls)
                                                          ↓
                                    vfcs.generated.<dataset>.jsonl   (Phase 1 output)
                                                          ↓
                                                    evolver_llm.py
                                    (reads vfcs.generated.*.jsonl, writes transcript.json)
                                                          ↓
                                        logs/gepa/<CVE_ID>/transcript.json   (Phase 2 output)
                                                          ↓
                                            aggregate_metrics.py
                                    (reads transcripts + vfcs data + dataset list)
                                                          ↓
                                        results/<RUN_ID>_metrics.json      (final output)
```

---

## Why the recent run produced zero successes

**Root cause: `SKIP_GEPA=1` is the default.**

With GEPA disabled, Phase 2 (the evolver) returns immediately without running any optimization iterations. The only exploits that exist are the raw initial PoCs from the LLM in Phase 1. These initial PoCs were not good enough to pass the basic execution gate (`"pass 1"` in stdout).

**Evidence:**
- All 21 CVEs show `total_iterations: 0` — no GEPA loop ran on any of them.
- All show `status_detail: "phase1_no_pass"` — none of the Phase 1 PoCs passed.
- `generated_exploits_available: true` for all — the VFC data was generated, but those exploits couldn't execute successfully.

**Fix:** Run with `SKIP_GEPA=0` or `--run-gepa` to re-enable the GEPA optimization loop. This will iterate up to `ITERATION=5` times per CVE, refining the exploit each round based on execution feedback.

---

## Environment variables reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATASET` | `datasets/SecBench.js.PoCGen.vfc.190` | Path to dataset file |
| `CVE_COUNT` | — | Limit to first N CVEs |
| `SKIP_GEPA` | `"1"` (skip) | Set `"0"` to enable GEPA optimization |
| `USE_STATIC_ANALYSIS` | — | Enable improvement mode |
| `RUN_OUTPUT_DIR` | — | Results directory path |
| `PYTHONUNBUFFERED` | `"1"` | Force unbuffered Python output |
