# Manual Runbook — Reproduce One CVE End-to-End

This runbook walks through running a single CVE from raw data to final metrics, step by step. Use it to debug why exploits fail or to understand each pipeline stage's output.

---

## Setup (do once)

```bash
cd /home/ron/Projects/cve_pocs/pocevolve/PoCEvolve

# Activate your Python environment if needed
source venv/bin/activate  # or however you manage deps

# Verify Docker is running
docker info > /dev/null 2>&1 && echo "Docker OK" || echo "Docker NOT running"

# Check that patched_node image exists (needed for exploit execution)
docker images | grep patched_node
```

---

## Step 0: Pick a CVE

From your recent filtered dataset (`SecBench.js.PoCGen.vfc.173` or similar):

```bash
# List available CVEs from the most recent filtered dataset
cat datasets/SecBench.js.PoCGen.vfc.173 | head -5
```

For this runbook, replace `<CVE_ID>` with your chosen ID (e.g., `SNYK-JS-ARPPING-1060047`).

---

## Step 1: Verify CVE exists in source data

```bash
cd /home/ron/Projects/cve_pocs/pocevolve/PoCEvolve

# Check that this CVE has entries in vfcs.filtered.json
python3 -c "
import json
data = json.load(open('secbenchjs/vfcs.filtered.json'))
for entry in data:
    testbed = entry.get('testbed_dir', '')
    ids = entry.get('ids', [])
    if '<CVE_ID>' in [e.replace(':', '_') for e in ids] or '<CVE_ID>'.replace(':', '_') == testbed:
        print(json.dumps(entry, indent=2))
"
```

**If nothing prints**, this CVE has no corresponding source data. Pick another one.

---

## Step 2: Run Phase 1 — VFC Generation (analyzer + generator)

### 2a: Analyzer — extract vulnerable function context

```bash
cd /home/ron/Projects/cve_pocs/pocevolve/PoCEvolve

# Create a single-CVE dataset file
echo '<CVE_ID>' > /tmp/single_cve_dataset.txt

DATASET=/tmp/single_cve_dataset.txt python3 -B -m src.analyzer
```

This reads `secbenchjs/vfcs.filtered.json`, finds the matching entry for your CVE, and writes analysis output to `logs/vfcs.predicted.json`.

**Check:** Look at `logs/vfcs.predicted.json` — each JSON object contains the extracted function code, source location, and target directory path.

### 2b: Generator — create initial exploit PoC

```bash
DATASET=/tmp/single_cve_dataset.txt python3 -B -m src.generator
```

The generator:
1. Builds a prompt from the VFC data (function code + context)
2. Sends it to the LLM via API (`API_BASE` in `src/config.py`)
3. Receives a PoC exploit script
4. Executes it against the target codebase inside Docker
5. Checks for `"pass 1"` in stdout — the basic execution gate

**Check the output:** The generator prints the prompt, LLM response, and execution result. Look for:
- `generated_exploits` in the VFCS generated file at `logs/vfcs.generated.*.jsonl`
- Each exploit's `console_log` entries — check if any contain `"pass 1"`

```bash
# Find the VFC output for your CVE
grep -A50 '<CVE_ID>' logs/vfcs.generated.*.jsonl 2>/dev/null | head -80
```

**If no exploit contains "pass 1" in its stdout:** The basic gate failed. This is expected if:
- The Docker container couldn't start (check `docker ps` / `docker images`)
- The patched_node image is missing
- The exploit syntax errors caused a crash before reaching the test gate
- The API returned a poor/noisy PoC

---

## Step 2.5: Manually Run an Individual CVE Exploit

Use this when you want to see exactly what the exploit does — stdout, stderr, exit code, and whether `/.executed` gets created. This is the fastest way to debug a single CVE's failures.

### 2a: Extract the exploit code from the JSONL output

Each line in `logs/vfcs.generated.*.jsonl` (or `results/.../*.jsonl`) is a JSON entry with `generated_exploits` — a list of 5 exploit attempts per CVE. Each attempt has:
- `response`: the exploit code (wrapped in ```javascript ... ```)
- `console_log`: array of `{stdout, stderr, command, status}` dicts from each run
- `exploit_result`: True if `"pass 1"` was found in stdout

Extract the exploit for CVE `<CVE_ID>`:

```bash
# Dump all exploits for a specific CVE as numbered blocks
python3 -c "
import json, re, sys
jsonl = '$(ls PoCEvolve/logs/vfcs.generated.*.jsonl 2>/dev/null | head -1)'
if not jsonl:
    jsonl = '$(ls PoCEvolve/eval/results/*/vfcs.generated.*.jsonl 2>/dev/null | head -1)'
cve = '<CVE_ID>'
with open(jsonl) as f:
    for line in f:
        entry = json.loads(line)
        # Check multiple possible id fields
        ids = entry.get('ids', []) + entry.get('advisory_descriptions', [])
        if cve not in str(ids):
            continue
        vuln_type = entry.get('vulnerability_type', 'unknown')
        pkg = entry.get('vulnerable_package', '?')
        print(f'--- CVE: {cve} | Package: {pkg} | Type: {vuln_type} ---')
        for i, exp in enumerate(entry.get('generated_exploits', [])):
            resp = exp.get('response', '')
            result = exp.get('exploit_result', False)
            # Strip markdown code fence if present
            resp = re.sub(r'\`\`\`javascript\s*\n?', '', resp)
            resp = re.sub(r'\`\`\`?\s*$', '', resp)
            print(f'  [{i}] result={result}')
            print(resp.strip())
            print()
" 
```

**Alternative: extract a single exploit attempt to a file:**

```bash
# Extract exploit #2 for SNYK-JS-ARPPING-1060047
python3 << 'PYEOF' > /tmp/exploit_attempt_2.js
import json, re

jsonl = "$(ls PoCEvolve/logs/vfcs.generated.*.jsonl 2>/dev/null | head -1)"
if not jsonl:
    jsonl = "$(ls PoCEvolve/eval/results/*/vfcs.generated.*.jsonl 2>/dev/null | head -1)"

with open(jsonl) as f:
    for line in f:
        entry = json.loads(line)
        cve_id = '<CVE_ID>'
        ids = entry.get('ids', []) + entry.get('advisory_descriptions', [])
        if cve_id not in str(ids):
            continue
        exp = entry['generated_exploits'][2]  # attempt index 2
        resp = exp['response']
        # Strip markdown fences
        resp = re.sub(r'\`\`\`javascript\s*\n?', '', resp)
        resp = re.sub(r'\`\`\`?\s*$', '', resp)
        print(resp.strip())
PYEOF

echo "Wrote exploit to /tmp/exploit_attempt_2.js"
cat /tmp/exploit_attempt_2.js
```

### 2b: Set up the testbed and run manually

The pipeline wraps each exploit in a harness (`EXPLOIT_CODE_TEMPLATE`) that imports `test/assert`, calls your `exploit()` function, then runs `validate()` to check for `/.executed`. You can reproduce this by running the generated test file directly.

**First, ensure the vulnerable package is installed:**

```bash
# The testbed dirs are created during Phase 1 — they already have node_modules/
cd /home/ron/Projects/cve_pocs/pocevolve/PoCEvolve

TESTBED="testbed/SNYK_JS_ARPPING_1060047/command-injection_2"

# If you need to install the vulnerable version:
cd "$TESTBED" || mkdir -p "$TESTBED"; cd "$TESTBED"
npm init -y 2>/dev/null || true
npm install arpping@2.0.0  # replace with the actual package and version
```

**Run the harness directly (same command verify.py uses) — inside the container:**

> `genpoc` is a C binary installed inside the `exploit-generation` container, not on your host. All commands below must run there.

```bash
# Reset state first (clears /.executed in the container's root filesystem)
docker exec exploit-generation /usr/bin/genpoc reset

# Run with no-warnings, use --test-reporter spec for readable output
# The testbed is mounted at /app/testbed inside the container
docker exec -i exploit-generation node --test --test-force-exit --no-warnings \
  /app/testbed/SNYK-JS-ARPPING-1060047/command-injection_2/gepa_test.js 2>&1 | head -60
```

**Expected outputs:**
- **If the exploit works**: `pass 1` appears in stdout, test shows `ok`, and `/.executed` exists
- **If it fails**: You'll see the assertion error (`assert.ok(success)`) or a Node.js crash

**Check whether genpoc ran at all (from your host):**

```bash
docker exec exploit-generation ls -la /.executed 2>&1 || echo "No /.executed — genpoc was NOT reached"
```

**For reDoS CVEs**, use the regexp engine flags (also inside the container):

```bash
docker exec -i exploit-generation node --test --enable-experimental-regexp-engine-on-excessive-backtracks \
    --regexp-backtracks-before-fallback=30000 --no-warnings \
    /app/testbed/SNYK_JS-<PKG>_N/redos_0/gepa_test.js 2>&1 | head -60
```

### 2c: Run your own custom exploit without the harness

If you just want to test raw payload behavior (skip the `node --test` wrapper entirely):

```bash
cd /home/ron/Projects/cve_pocs/pocevolve/PoCEvolve

# Reset state inside the container
docker exec exploit-generation /usr/bin/genpoc reset

# Run the pure exploit code directly inside the container
# (update the CVE path as needed)
docker exec -i exploit-generation node -e \
  "$(cat /tmp/exploit_attempt_2.js)" 2>&1

# Check result from your host
docker exec exploit-generation ls -la /.executed && echo "SUCCESS: genpoc was reached" || echo "FAIL: genpoc not reached"
```

### 2d: Read the stored output (no manual run needed)

Each entry in `generated_exploits` already contains the stdout/stderr from every iteration. You don't always need to re-run — just inspect what's already recorded:

```bash
python3 << 'PYEOF'
import json, re

jsonl = "$(ls PoCEvolve/logs/vfcs.generated.*.jsonl 2>/dev/null | head -1)"
if not jsonl:
    jsonl = "$(ls PoCEvolve/eval/results/*/vfcs.generated.*.jsonl 2>/dev/null | head -1)"

cve_id = '<CVE_ID>'
with open(jsonl) as f:
    for line in f:
        entry = json.loads(line)
        ids = entry.get('ids', []) + entry.get('advisory_descriptions', [])
        if cve_id not in str(ids):
            continue
        for i, exp in enumerate(entry['generated_exploits']):
            print(f"=== Attempt {i} (result={exp['exploit_result']}) ===")
            resp = exp['response']
            resp = re.sub(r'\`\`\`javascript\s*\n?', '', resp)
            resp = re.sub(r'\`\`\`?\s*$', '', resp)
            print(resp.strip()[:400])  # first 400 chars of exploit code
            for j, log in enumerate(exp.get('console_log', [])):
                stdout = log.get('stdout', '')
                stderr = log.get('stderr', '')
                if 'pass 1' in stdout:
                    print(f"  Run {j}: ** PASS ** — 'pass 1' found")
                elif stderr:
                    print(f"  Run {j}: STDERR: {stderr[:200]}")
                else:
                    # Show last line of TAP output for diagnostic
                    lines = stdout.strip().split('\n')[-3:]
                    print(f"  Run {j}: TAP tail: {' | '.join(lines)}")
PYEOF
```

---

## Step 3: Run Phase 2 — Exploit Evolution (GEPA optimization)

### Option A: With GEPA enabled (recommended for debugging)

```bash
cd /home/ron/Projects/cve_pocs/poCEvolve/PoCEvolve

# Create single-CVE dataset
echo '<CVE_ID>' > /tmp/single_cve_dataset.txt

SKIP_GEPA=0 DATASET=/tmp/single_cve_dataset.txt python3 -B -m src.evolver_llm
```

This runs the GEPA optimization loop for your CVE:
1. Loads VFCS data from `logs/vfcs.generated.*.jsonl`
2. Reads your CVE from the dataset
3. Runs up to `ITERATION=5` optimization cycles via `src/pipeline.py`'s `run_gepa_optimization()`
4. Each cycle: LLM generates improved exploit → execute → score → feedback → next iteration

**Output:** A transcript at `logs/gepa/<CVE_ID_with_underscores>/transcript.json`:

```bash
cat logs/gepa/SNYK_JS_ARPPING_1060047/transcript.json | python3 -m json.tool | head -100
```

### Option B: Without GEPA (default — just checks initial PoCs)

```bash
SKIP_GEPA=1 DATASET=/tmp/single_cve_dataset.txt python3 -B -m src.evolver_llm
```

This returns immediately with no optimization. Only the Phase 1 PoCs are available for scoring.

---

## Step 4: Inspect the transcript

```bash
TRANSCRIPT="logs/gepa/SNYK_JS_ARPPING_1060047/transcript.json"

# Full transcript
cat "$TRANSCRIPT" | python3 -m json.tool

# Key fields to check:
python3 -c "
import json
t = json.load(open('$TRANSCRIPT'))
print('status:', t.get('status'))
print('passed:', t.get('passed'))
print('attempts:', len(t.get('attempts', [])))
for i, att in enumerate(t.get('attempts', [])):
    print(f'  Attempt {i}:')
    for j, prompt in enumerate(att.get('seed_prompts', [])):
        print(f'    Prompt {j}: result={prompt.get(\"exploit_result\")}')
"
```

**What to look for:**
- `passed: true` → CVE succeeded
- `passed: false` but attempts > 0 → exploits ran but didn't pass
- No attempts → Phase 1 failed (no VFC data) or GEPA was skipped

---

## Step 5: Run the full pipeline end-to-end for one CVE

### Using run_pipeline.sh:

```bash
cd /home/ron/Projects/cve_pocs/pocevolve/PoCEvolve/eval

echo '<CVE_ID>' > /tmp/single_cve_dataset.txt

# Enable GEPA to get meaningful results
SKIP_GEPA=0 bash run_pipeline.sh --dataset /tmp/single_cve_dataset.txt --cve-count 1
```

### Using e2e.py:

```bash
cd /home/ron/Projects/cve_pocs/poCEvolve/PoCEvolve/eval

echo '<CVE_ID>' > /tmp/single_cve_dataset.txt

# Enable GEPA for meaningful optimization
SKIP_GEPA=0 python3 e2e.py --dataset /tmp/single_cve_dataset.txt --cve-count 1
```

Both produce:
- A run directory under `eval/results/<RUN_ID>/`
- Metrics at `eval/results/<RUN_ID>/<RUN_ID>_metrics.json`
- Full log at `eval/results/<RUN_ID>/<RUN_ID>.log`

---

## Troubleshooting checklist

### No VFCS data generated (Phase 1 output missing)

```bash
# Check if vfcs.filtered.json has your CVE's testbed_dir
python3 -c "
import json
data = json.load(open('../secbenchjs/vfcs.filtered.json'))
testbeds = [e.get('testbed_dir', '') for e in data]
print('<CVE_ID>' in testbeds or any('<CVE_ID>'.replace(':', '_') in t for t in testbeds))
"

# If False, the CVE is not in the source data — pick another or update vfcs.filtered.json
```

### Docker / patched_node image issues

```bash
# Check if Docker daemon is running
docker info > /dev/null 2>&1 && echo "OK" || echo "FAIL: start Docker"

# Check for patched_node image
docker images | grep patched_node
# If missing, rebuild it:
cd ..  # go to PoCEvolve root
cat Dockerfile | head -30  # check what the image builds
```

### Exploit executes but doesn't reach "pass 1"

The `"pass 1"` marker is a string in the exploit code that gets printed when a test case passes. If the exploit crashes before reaching it, check:
- Python/Node syntax errors in the generated PoC (check `console_log[].stderr`)
- Missing dependencies in the Docker container
- Wrong working directory or file paths in the exploit

### LLM API issues

```bash
# Check your config
grep -E 'API_BASE|API_KEY|MODEL_NAME' src/config.py

# Test connectivity (replace with actual API_BASE value)
curl -sf --max-time 3 <API_BASE>/v1/models && echo "API OK" || echo "API UNREACHABLE"
```

---

## Why zero successes in the recent run

The most recent baseline run produced `0/21 passed` because:

1. **`SKIP_GEPA=1` is the default** — the evolver returns immediately without running any GEPA optimization. The only exploits available are raw initial PoCs from the LLM's single-shot generation.
2. Those initial PoCs failed the basic execution gate (`"pass 1"` not found in any console_log).
3. With no successful starting point, `aggregate_metrics.py` sets `status_detail: "phase1_no_pass"` for all CVEs.

**To get meaningful results:** Set `SKIP_GEPA=0` (or use `--run-gepa`) so the GEPA loop iterates and refines exploits over 5 rounds per CVE.
