#!/usr/bin/env bash
# Rerun the baseline evaluation from scratch or resume from a specific phase.
# Run from this directory (PoCEvolve/eval/).

set -euo pipefail
cd "$(dirname "$0)/.."

PHASE="${1:-2}"  # default to Phase 2 if not specified

show_help() {
    echo "Usage: $0 [phase_number]"
    echo ""
    echo "Phases:"
    echo "  0   — Verify environment only"
    echo "  1   — Run VFC generation (Phase 1)"
    echo "  2   — Run evolver (Phase 2)"
    echo "  3   — Aggregate metrics (Phase 3)"
    echo "  all — Run phases 0→3 in sequence"
    echo ""
    echo "If DATASET is not set, defaults to vfc.190."
}

if [ "$PHASE" = "help" ] || [ "$PHASE" = "-h" ] || [ "$PHASE" = "--help" ]; then
    show_help
    exit 0
fi

# Dataset (default to vfc.190)
DATASET="${DATASET:-PoCEvolve/datasets/SecBench.js.PoCGen.vfc.190}"
if [ ! -f "$DATASET" ]; then
    echo "Error: dataset not found at $DATASET" >&2
    exit 1
fi

# Ensure results directory exists
mkdir -p PoCEvolve/results/{baseline,improvement,comparison}

case "$PHASE" in
    0)
        echo "=== Phase 0: Verify Environment ==="
        bash "$(dirname "$0")/check_baseline.sh"
        ;;

    1)
        echo "=== Phase 1: Generate VFC Data ==="
        cd PoCEvolve
        echo "DATASET=$DATASET"
        python3 -B -m src.analyzer
        python3 -B -m src.generator
        cd ../eval
        echo "Phase 1 complete."
        ls -lh "${DATASET%/}.generated.*.jsonl" 2>/dev/null || \
            echo "(no vfcs.generated output found)"
        ;;

    2)
        echo "=== Phase 2: Run Evolver ==="
        cd PoCEvolve
        echo "DATASET=$DATASET"
        # Choose evolver mode based on dataset name
        if [[ "$DATASET" == *"559"* ]]; then
            echo "Mode: evolver_pocgen (pocgen seeding)"
            python3 -B src/evolver_pocgen.py
        else
            echo "Mode: evolver_llm (LLM feedback)"
            python3 -B src/evolver_llm.py
        fi
        cd ../eval
        echo "Phase 2 complete."
        ;;

    3)
        echo "=== Phase 3: Aggregate Metrics ==="
        mkdir -p PoCEvolve/results/baseline
        python3 -B eval/aggregate_metrics.py \
            --logs-dir logs \
            --output results/baseline/metrics.json \
            --csv-output results/baseline/per_vuln.csv
        echo "Metrics written to PoCEvolve/results/baseline/"
        ;;

    all)
        echo "=== Running Phases 0→3 ==="
        bash "$0" 0 || echo "(Phase 0 had issues — check Phase 2 prerequisites)"
        bash "$0" 1
        bash "$0" 2
        bash "$0" 3
        echo "=== All phases complete ==="
        ;;

    *)
        echo "Unknown phase: $PHASE" >&2
        show_help
        exit 1
        ;;
esac
