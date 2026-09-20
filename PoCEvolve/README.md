# PoCEvolve

## Setup
- Config: `src/config.py` → MODEL_NAME, API_KEY, API_BASE, ITERATION, MINIBATCH_SIZE, VALIDATE_FUNC, CWE_MAP, TRAINING_DATA
- Datasets: `datasets/` (one vuln ID/line). Oracle: `resources/validate_functions/`. SecBench JS: `secbenchjs/`.

## Run
```bash
cd PoCEvolve/ && DATASET=<path> python3 -B -m src.analyzer          # Phase 1: VFC gen
DATASET=<path> python3 -B -m src.generator                           # one-shot
DATASET=<path> python3 -B -m src.evolver_llm                        # iterative (LLM)
DATASET=<path> python3 -B -m src.evolver_pocgen                     # iterative (PoCGen; needs TRAINING_DATA)
```
PoCGen seed: `cd ../PoCGen && npm install` → build images → `./run-mnt.sh output node index.js pipeline -v <dataset>` → `python3 -B -m src.train_set`.

The SecBench analyzer reads `GITHUB_API_KEY` from the repository-level `.env` file
(the parent directory of `PoCEvolve`) for authenticated GitHub API requests:

```dotenv
GITHUB_API_KEY=ghp_your_token_here
```

An existing environment variable takes precedence over `.env`; the token is never
printed by the analyzer.

## Validate SecBench data

Before generating prompts from VFC metadata, validate the records and their external
evidence:

```bash
cd PoCEvolve
python3 scripts/validate_secbench_dataset.py secbenchjs/vfcs.json --json-report /tmp/vfcs-report.json

# Build a separate cleaned database and quarantine log
python3 scripts/validate_secbench_dataset.py secbenchjs/vfcs.json \
  --clean-output secbenchjs/vfcs.cleaned.json \
  --quarantine-output secbenchjs/vfcs.cleaned.quarantine.json
```

The validator checks the JSON schema, change-list counts, testbed directories, fix
URLs, and whether each GitHub fix repository matches the repository declared by the
affected npm package version. Use `--no-check-links --no-check-package-repos` for an
offline-only pass. Errors are suitable for excluding a record; owner-only repository
differences are warnings because repositories can move between GitHub owners.

With `--clean-output`, structural failures are excluded, derived counts are repaired,
and dead or cross-package fix metadata is cleared while retaining the advisory record.
The quarantine file records every excluded record and every mutation. The input file
is never modified.

## Eval
```bash
cd eval && cp config.env.example config.env && bash check_baseline.sh && bash run_pipeline.sh  # Phases 0-4
```
Details: `eval/RUNBOOK.md`.

## Modules
`config.py` → `generator.py` | `evolver_llm.py` | `evolver_pocgen.py` → `pipeline.py` → `evaluator.py` → `evolve_prompt.py` → `llm.py`+`prompts.py`. Support: `analyzer.py`, `verify.py`, `selector.py`, `train_set.py`.

## Docker
`docker compose -f docker-compose.yml up -d` → `docker exec -it exploit-generation bash`. Prefer host for Ollama localhost.
