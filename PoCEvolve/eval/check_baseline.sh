#!/usr/bin/env bash
# Quick status check for PoCEvolve evaluation pipeline readiness.
# Run from this directory (PoCEvolve/eval/).

set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'
BOLD='\033[1m'

ok()  { printf "${GREEN}✓%b %s\n" "$1" "$2"; }
warn() { printf "${YELLOW}⚠%b %s\n" "$1" "$2"; }
fail() { printf "${RED}✗%b %s\n" "$1" "$2"; }

echo "═══════════════════════════════════════════"
echo "  PoCEvolve Evaluation — Environment Check"
echo "═══════════════════════════════════════════"

# Docker testbed container
printf "\n${BOLD}Docker Testbed:${NC}\n"
TESTBED=$(docker ps --format '{{.Names}}' | grep '^patched_node$' || true)
if [ -n "$TESTBED" ]; then
    status=$(docker inspect -f '{{.State.Status}}' "$TESTBED" 2>/dev/null || echo "unknown")
    if [ "$status" = "running" ]; then
        node_v=$(docker exec "$TESTBED" node --version 2>/dev/null || echo "?")
        ok "" "Container running (node $node_v)"
    else
        fail "" "Container exists but status: $status"
    fi
else
    warn "" "No patched_node container — start with:"
    printf "      docker compose -f PoCEvolve/docker-compose.yml up -d\n"
fi

# LLM API endpoint
printf "\n${BOLD}LLM API Endpoint:${NC}\n"
API_BASE=$(python3 -c "import src.config as c; print(c.API_BASE)" 2>/dev/null || echo "?")
if [ "$API_BASE" != "?" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${API_BASE}/models" 2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
        ok "" "Endpoint reachable ($API_BASE)"
    else
        warn "" "Endpoint returned HTTP $code — check API server status"
    fi
else
    fail "" "Could not read config.API_BASE"
fi

# Phase 1 output (VFC data)
printf "\n${BOLD}Phase 1 Output (VFC Generation):${NC}\n"
vfc_files=$(find PoCEvolve/logs -name 'vfcs.generated.*.jsonl' -type f 2>/dev/null || true)
if [ -z "$vfc_files" ]; then
    fail "" "No vfcs.generated.*.jsonl found — Phase 1 not run"
else
    for f in $vfc_files; do
        lines=$(wc -l < "$f")
        size=$(du -h "$f" | cut -f1)
        ok "" "$f ($lines VFCs, ${size})"
    done
fi

# Cache directory
printf "\n${BOLD}LLM Response Cache:${NC}\n"
cache_size=$(du -sh PoCEvolve/logs/cache/ 2>/dev/null | cut -f1 || echo "?")
ok "" "Cache size: $cache_size"

# Phase 2 output (transcripts)
printf "\n${BOLD}Phase 2 Output (Transcripts):${NC}\n"
transcripts=$(find PoCEvolve/logs/*/transcript.json -type f 2>/dev/null | wc -l || echo "0")
if [ "$transcripts" -gt 0 ]; then
    ok "" "Found $transcripts transcript files"

    # Count completed vs incomplete from first transcript found
    for t in $(find PoCEvolve/logs/*/transcript.json -type f | head -1); do
        dir=$(dirname "$t")
        printf "  Sample: %s\n" "$dir"
        if [ -f "$t" ]; then
            # Try to read from transcript (may fail for non-JSON)
            python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    attempts = len(data.get('attempts', []))
    success = sum(1 for a in data.get('attempts', [])
                  for p in (a.get('seed_prompts') or []) if p.get('exploit_result'))
    print(f'  attempts: {attempts}, successes: {success}')
except Exception as e:
    print(f'  (transcript parsing error: {e})')
" "$t" 2>/dev/null || true
        fi
    done
else
    warn "" "No transcript files yet — Phase 2 not started"
fi

# Disk space
printf "\n${BOLD}Disk Space:${NC}\n"
disk_avail=$(df -h PoCEvolve/logs/ | tail -1 | awk '{print $4}')
ok "" "$disk_avail available on logs partition"

# Results directory
printf "\n${BOLD}Results Directory:${NC}\n"
if [ -d "results/baseline/" ]; then
    ok "" "Baseline results directory exists"
else
    warn "" "Create with: mkdir -p PoCEvolve/results/{baseline,improvement,comparison}"
fi

# Dataset
printf "\n${BOLD}Datasets:${NC}\n"
for d in PoCEvolve/datasets/*; do
    if [ -f "$d" ]; then
        vulns=$(wc -l < "$d")
        ok "" "$(basename "$d"): $vulns entries"
    fi
done

echo ""
echo "═══════════════════════════════════════════"
printf "\nRun order: Phase 1 → Phase 2 → Phase 3\n"
printf "Rerun with: bash run_pipeline.sh <phase>\n"
echo ""
