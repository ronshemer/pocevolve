# PoCEvolve — Evaluation Runbook

This runbook documents the complete evaluation workflow for the PoCEvolve research paper. Follow Phases 0–4 in order to reproduce the benchmark results.

---

## Prerequisites

| Item | Requirement |
|------|-------------|
| Docker | Installed and running |
| Ollama | Installed with `qwen36` model (`ollama pull qwen36`) |
| SecBench.js testbed | Downloaded to `testbed/` directory (190 vulnerabilities) |

```bash
# Pull the LLM model if not already present
ollama pull qwen36
```

---

## Recommended Workflow: Run from Host

**PoCEvolve is designed to be run from the host machine**, not inside a Docker container. This is because Ollama (the local LLM server) binds to `127.0.0.1` by default, which prevents Docker containers on Linux from reaching the host's API.

### Why Not Run Inside the Container?

Ollama listens only on `127.0.0.1:11434` (localhost), not on network interfaces. On Linux, Docker uses a bridge network where `host.docker.internal` resolves to `172.17.0.1` — but Ollama isn't listening there. This means:

- Container → host API access fails with "Connection refused" regardless of networking config
- The workaround (exposing Ollama via `OLLAMA_HOST=0.0.0.0`) is not recommended for security
- Running directly from the host avoids all Docker networking issues

### Primary Setup Steps

**1. Install SecBench.js testbed** (if not already present):
```bash
cd /path/to/pocevolve
python3 -B secbenchjs/clone_secbenchjs.py  # or run manually
# Verify: ls testbed/ should show vulnerability directories
```

**2. Configure API endpoint** (`PoCEvolve/src/config.py`):
- `API_BASE = "http://localhost:11434/v1"` (default, works on host)
- No changes needed for host workflow

**3. Set dataset path**:
```bash
export DATASET=/path/to/dataset  # one of: datasets/*.txt
```

---

## Phase 0 — Environment Verification

Run the health check to verify all prerequisites are met:

```bash
cd PoCEvolve/eval
bash check_baseline.sh
```

This verifies:
- Docker can run containers
- Ollama API responds on localhost:11434
- Disk space is sufficient (>5GB)
- Phase 1 output exists (VFC descriptions)

### Troubleshooting check_baseline.sh

| Error | Fix |
|-------|-----|
| "Ollama API not reachable" | Verify Ollama is running: `curl http://localhost:11434/v1/models` |
| Empty testbed directory | Clone SecBench.js testbed (see Phase 0 setup) |
| Docker permission denied | Add user to docker group: `sudo usermod -aG docker $USER` |

---

## Phase 1 — Vulnerability Description Generation

Generate vulnerability descriptions from VFC (Vulnerable Function Class) data using the LLM:

```bash
cd PoCEvolve
python3 -B -m src.analyzer
```

Output: Generated description files in `results/vfc_descriptions/`

**Manual verification**:
```bash
ls results/vfc_descriptions/ | wc -l  # should match dataset count
head -n 5 results/vfc_descriptions/*.json | head -30
```

---

## Phase 2 — Exploit Iteration (Core Evaluation)

Run iterative exploit generation with PoCEvolve's optimization loop:

### Option A: LLM-seeded iteration (primary approach)
```bash
cd PoCEvolve
DATASET=/path/to/datasets/pocevolve.txt python3 -B -m src.evolver_llm
```

### Option B: PoCGen-seeded iteration
First convert PoCGen raw output to training data:
```bash
cd PoCEvolve
python3 -B -m src.train_set  # converts from raw PoCGen output
# Then update TRAINING_DATA path in PoCEvolve/src/config.py
DATASET=/path/to/datasets/pocevolve-pocgen.txt python3 -B -m src.evolver_pocgen
```

### Monitoring progress
```bash
# Watch iteration output directory
watch -n 5 'ls -la results/evolve_llm_output/'

# View latest feedback
cat results/evolve_llm_output/*/feedback*.txt | tail -30
```

**Stop condition**: Iterations complete when no new improvements are made or max iterations reached. Default: monitor `results/evolve_llm_output/` for final transcript files.

---

## Phase 3 — Metrics Extraction

Extract per-vulnerability metrics and aggregate scores from the evaluation results:

```bash
cd PoCEvolve/eval
python3 -B aggregate_metrics.py results/evolve_llm_output/ --output results/metrics.json
```

Output metrics include:
- `total_vulnerabilities`: Count of vulnerabilities evaluated
- `successful_exploits`: Count with passing exploits (score >= threshold)
- `avg_score`: Average exploit score across all candidates
- `per_vuln_scores`: Per-vulnerability breakdown
- `iterations_per_vuln`: Average iterations before convergence

---

## Phase 4 — Before/After Comparison

Compare improved results against the baseline (unmodified PoCGen):

```bash
cd PoCEvolve/eval
bash run_pipeline.sh  # phases 0–4 full pipeline
# OR compare specific runs:
python3 -B aggregate_metrics.py results/baseline/ --output results/baseline/metrics.json
python3 -B aggregate_metrics.py results/improvement/ --output results/improvement/metrics.json
diff results/baseline/metrics.json results/improvement/metrics.json
```

---

## Docker Compose Infrastructure (Optional)

**Note**: The `docker-compose.yml` service is provided for reference only. Due to Ollama's localhost-only binding, it cannot reach the host API on Linux without significant workarounds. Use the **host workflow** described above.

### If you must use Docker (requires Ollama exposed externally)

```bash
cd PoCEvolve
docker compose up -d  # start container
docker exec -it exploit-generation bash  # enter container
cd /app
DATASET=/app/path/to/dataset python3 -B -m src.evolver_llm
```

---

## Directory Structure After Run

```
PoCEvolve/
├── results/
│   ├── evolve_llm_output/      # Phase 2 output
│   │   ├── transcript_*.json   # Per-iteration transcripts
│   │   └── ...                 # Feedback and scores
│   ├── vfc_descriptions/       # Phase 1 output
│   ├── baseline/               # Phase 4 comparison
│   └── metrics.json            # Phase 3 aggregate metrics
├── testbed/                    # SecBench.js testbed (190 vulns)
├── datasets/                   # Dataset files
└── eval/
    └── RUNBOOK.md              # This file
```
