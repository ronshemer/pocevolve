# PoCEvolve

## Requirements

- Docker and Docker Compose
- A `patched_node` Docker image available locally, tagged `patched_node`. Build from PoCGen's original codebase.
- An OpenAI-compatible LLM endpoint. Model, API key, and base URL are set in `src/config.py` (`MODEL_NAME`, `API_KEY`, `API_BASE`).
- A folder called `testbed`, this folder is created by PoCGen when running its experiment, copy it to here for the experiment.

## Setup

```bash
# Build and start the container
docker compose up -d

# Enter the container
docker exec -it exploit-generation bash

# Inside the container: install Python dependencies
pip install -r requirements.txt
```

The repo is bind-mounted into the container at `/app`, so all commands below run from there, in or out of the container.

## PoCEvolve (LLM)

All pipeline variants read a dataset file via the `DATASET` environment variable (default: `datasets/failed.txt`, see `src/config.py`). Dataset files are plain text, one vulnerability ID per line — see `datasets/`.

```bash
# Generate vulnerability descriptions
python3 -B -m src.analyzer

# Generate exploits (one-shot LLM)
DATASET=<dataset_path> python3 -B -m src.generator

# Iterative optimization via LLM feedback
DATASET=<dataset_path> python3 -B -m src.evolver_llm
```

### PoCEvolve

```bash
# Generate vulnerability descriptions
python3 -B -m src.analyzer

# PoCGen results are from PoCGen repo

# Iterative optimization via LLM feedback
DATASET=<dataset_path> python3 -B -m src.evolver_pocgen
```

1. Run the original PoCGen tool (from its own repository) against the target dataset to produce its raw run artifacts (`prompt.json` / `RunnerResult_DefaultRefiner.json` per testbed entry).
2. Point `src/train_set.py` at that PoCGen output (`POCGEN_DIR`) and convert it into this project's training-set format:
   ```bash
   python3 -B -m src.train_set
   ```
   This reads `DATASET_LIST`/`VFCS_JSON` (from `secbenchjs/vfcs.json`) and writes one JSON file per ID under `OUTPUT_DIR`.
3. Point `TRAINING_DATA` in `src/config.py` at that output directory before running `src.evolver_pocgen`.

## Architecture

| Module | Role |
|--------|------|
| `src/config.py` | Central config: paths, model name, CWE oracle definitions, timeouts |
| `src/pipeline.py` | Optimization loop |
| `src/generator.py` | LLM call → extract JS code → run verifier |
| `src/evolver_llm.py` | Iterative optimization seeded from LLM-generated prompts |
| `src/evolver_pocgen.py` | Iterative optimization seeded from a prior PoCGen run |
| `src/analyzer.py` | Generates vulnerability descriptions from VFC data via LLM |
| `src/evaluator.py` | Execute exploit, scores, generate feedback |
| `src/verify.py` | Run exploit in isolated testbed, parse `pass 1` from output |
| `src/llm.py` | OpenAI-compatible API wrapper (uses `MODEL_NAME` from config), with on-disk response caching |
| `src/prompts.py` | All LLM prompt templates (generation, scoring, feedback) |
| `src/selector.py` | Minibatch selection from scored candidates |
| `src/evolve_prompt.py` | Incorporate evaluator feedback into next prompt |
| `src/train_set.py` | Converts a raw PoCGen run into training data for `src.evolver_pocgen` |

## Configuration

All tunable parameters live in `src/config.py`

## Data

- `datasets/` — text files with one vulnerability ID per line
- `secbenchjs/` — SecBench.js benchmark metadata (`vfcs.json`, `vfcs.filtered.json`, `vfcs.testbed.json`) and `clone.SecBench.js.sh` to fetch the upstream benchmark repo
- `resources/validate_functions/` — per-vulnerability-type JS oracle functions referenced by `CWE_MAP`
