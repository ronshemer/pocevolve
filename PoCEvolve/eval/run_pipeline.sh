#!/usr/bin/env bash
# run_pipeline.sh — Evaluate PoCEvolve pipeline end-to-end
# Usage:
#   bash run_pipeline.sh [--mode baseline|improvement] [--dataset <path>] [--cve-count N] [--dry-run]
#
# Arguments:
#   --mode baseline|improvement   Run mode (default: baseline)
#   --dataset <path>              Path to dataset file with one vulnerability ID per line
#   --cve-count N                 Process at most N CVEs (default: process all CVEs)
#   --dry-run                     Verify environment only, skip pipeline execution
#
# This script runs the full exploitation pipeline and captures metrics.
# - baseline: run existing pipeline as-is (no static analysis)
# - improvement: run pipeline with USE_STATIC_ANALYSIS=true

usage() {
    echo "Usage: $0 [--mode baseline|improvement] [--dataset <path>] [--cve-count N] [--dry-run]"
    echo ""
    echo "Arguments:"
    echo "  --mode baseline|improvement   Run mode (default: baseline)"
    echo "  --dataset <path>              Dataset file with one vulnerability ID per line"
    echo "  --cve-count N                 Process at most N CVEs (default: all CVEs in dataset)"
    echo "  --dry-run                     Verify environment only, skip pipeline execution"
}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"  # PoCEvolve/
RESULTS_DIR="$SCRIPT_DIR/results"

MODE="baseline"
DATASET=""
CVE_COUNT=""
DRY_RUN=false
TOTAL_CVES=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --mode) MODE="$2"; shift 2 ;;
        --dataset) DATASET="$2"; shift 2 ;;
        --cve-count) CVE_COUNT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# Defaults
if [[ -z "$DATASET" ]]; then
    DATASET="$PARENT_DIR/datasets/SecBench.js.PoCGen.vfc.190"
fi

mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_ID="${MODE}_${TIMESTAMP}"
RUN_LOG="$RESULTS_DIR/${RUN_ID}.log"

# Count total CVEs from dataset (strip blank lines/comments)
if [[ -f "$DATASET" ]]; then
    TOTAL_CVES=$(grep -c '.' "$DATASET" 2>/dev/null || echo 0)
fi

# Apply --cve-count if specified: create a truncated temp file
FILTERED_DATASET="$RESULTS_DIR/.filtered_dataset.txt"
if [[ -n "$CVE_COUNT" && "$CVE_COUNT" -gt 0 ]]; then
    head -n "$CVE_COUNT" "$DATASET" > "$FILTERED_DATASET"
    TOTAL_CVES=$CVE_COUNT
else
    cp "$DATASET" "$FILTERED_DATASET"
fi

PHASE_COMPLETED=0  # cumulative count of completed items for progress bar

# ============================================================
# Progress Tracking Helpers (tqdm-style)
# ============================================================
count_completed() {
    local dir="${1:-$PARENT_DIR/logs}"
    find "$dir" -maxdepth 3 -name "transcript.json" 2>/dev/null | wc -l
}

show_progress() {
    local phase="$1"
    local done="$2"
    local total="${3:-$TOTAL_CVES}"
    [[ $total -eq 0 ]] && return

    if (( total >= done )); then
        local pct=$(( done * 100 / total ))
    else
        local pct=100
    fi
    (( pct > 100 )) && pct=100

    local bar_len=40
    local filled=$(( pct * bar_len / total ))
    (( filled > bar_len )) && filled=$bar_len
    local empty=$(( bar_len - filled ))
    local bar=""
    for (( i=0; i<filled; i++ )); do bar+="█"; done
    for (( i=0; i<empty; i++ )); do bar+="░"; done

    printf "\r\033[1m[%s]\033[0m \033[93m%s/%s\033[0m %s|%d%%|\n" \
        "$phase" "$done" "$total" "$bar" "$pct" >&2
}

phase_start() {
    PHASE_COMPLETED=0  # reset per phase — prevents prior-phase transcript count from polluting progress
    show_progress "$1" 0 "${2:-$TOTAL_CVES}"
}

phase_end() {
    local total_done=$(( $(count_completed) ))
    (( PHASE_COMPLETED = total_done ))
    printf "\033[2K\r\033[92m[DONE] %s: %d items done (global)\033[0m\n" "$1" "$total_done" >&2
}

echo "=== PoCEvolve Evaluation Run ==="
echo "Mode:       $MODE"
echo "Dataset:    $DATASET"
echo "Run ID:     $RUN_ID"
echo "Log:        $RUN_LOG"
echo "Results:    $RESULTS_DIR/${RUN_ID}_metrics.json"
echo ""

# ============================================================
# Signal Handling — ensures Ctrl+C always terminates running phases
# ============================================================

kill_children() {
    printf "\033[91m\n[Interrupt] Force-killing python processes...\033[0m\n" >&2
    # Kill all python3 children of this script
    pkill -P $$ -TERM python3 2>/dev/null || true
    sleep 1.5
    pkill -P $$ -KILL python3 2>/dev/null || true
}
trap kill_children INT

# ============================================================
# Phase 0: Environment Verification
# ============================================================
phase_0_verify_env() {
    echo "=== Phase 0: Environment Verification ==="

    local errors=0

    # Check Docker
    if ! command -v docker &>/dev/null; then
        echo "[FAIL] Docker not found. Install Docker before running."
        errors=$((errors + 1))
    elif ! docker info &>/dev/null; then
        echo "[FAIL] Docker daemon not running. Start it and try again."
        errors=$((errors + 1))
    else
        echo "[OK] Docker is available"
    fi

    # Check patched_node image
    if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "patched_node"; then
        echo "[OK] patched_node image found"
    else
        echo "[WARN] patched_node image not found — exploit execution may fail"
    fi

    # Check Python dependencies
    if python3 -c "import openai, json" 2>/dev/null; then
        echo "[OK] Python dependencies (openai, json) available"
    else
        echo "[FAIL] Install Python dependencies: pip install -r $PARENT_DIR/requirements.txt"
        errors=$((errors + 1))
    fi

    # Check dataset file
    if [[ -f "$DATASET" ]]; then
        local vuln_count
        vuln_count=$(wc -l < "$DATASET")
        echo "[OK] Dataset found: $DATASET ($vuln_count vulnerabilities)"
    else
        echo "[FAIL] Dataset not found: $DATASET"
        errors=$((errors + 1))
    fi

    # Check LLM cache directory
    local cache_dir="$PARENT_DIR/logs/cache"
    if [[ -d "$cache_dir" ]]; then
        local cache_files
        cache_files=$(find "$cache_dir" -name "*.json" | wc -l)
        echo "[OK] LLM cache: $cache_files cached responses"
    else
        echo "[WARN] No LLM cache found — all calls will hit the API"
    fi

    # Check VFC generated data (Phase 1 prerequisite)
    local vfcs_file="$PARENT_DIR/logs/vfcs.generated.$(basename "$DATASET" .txt).jsonl"
    if [[ -f "$vfcs_file" ]]; then
        local entry_count
        entry_count=$(wc -l < "$vfcs_file")
        echo "[OK] Phase 1 VFC data: $entry_count entries ready for Phase 2"
    else
        # Also check with the dataset basename minus extension
        local alt_vfcs="$PARENT_DIR/logs/vfcs.generated.$(basename "$DATASET").jsonl"
        if [[ -f "$alt_vfcs" ]]; then
            local entry_count
            entry_count=$(wc -l < "$alt_vfcs")
            echo "[OK] Phase 1 VFC data: $entry_count entries ready for Phase 2 ($alt_vfcs)"
        else
            echo "[WARN] No generated exploits found. Run Phase 1 first:"
            echo "  cd $PARENT_DIR && python3 src/generator.py"
        fi
    fi

    # Check API connectivity
    if [[ -n "${POC_EVALUATE_API_BASE:-}" ]]; then
        local api_base="$POC_EVALUATE_API_BASE"
    else
        # Read from config
        local api_base
        api_base=$(grep "^API_BASE" "$PARENT_DIR/src/config.py" | sed "s/API_BASE = '//;s/'$//")
    fi

    if [[ -n "$api_base" ]]; then
        echo "[INFO] API endpoint: $api_base"
        # Quick connectivity check (non-blocking)
        curl -sf --max-time 3 "$api_base/v1/models" &>/dev/null && \
            echo "[OK] API is reachable" || \
            echo "[WARN] Cannot connect to API — exploitation will likely fail"
    fi

    echo ""
    if [[ $errors -gt 0 ]]; then
        echo "[ABORTED] $errors errors found. Fix before re-running."
        exit 1
    else
        echo "[PASS] Environment verification complete"
    fi
}

# ============================================================
# Phase 1: VFC Generation (if needed)
# ============================================================
phase_1_vfc_generation() {
    echo "=== Phase 1: VFC Generation ==="

    local dataset_stem
    dataset_stem=$(basename "$DATASET" .txt)
    local vfcs_file="$PARENT_DIR/logs/vfcs.generated.${dataset_stem}.jsonl"

    if [[ -f "$vfcs_file" ]]; then
        local entry_count
        entry_count=$(wc -l < "$vfcs_file")
        echo "[SKIP] VFC data already exists ($entry_count entries). Skipping Phase 1."
        return 0
    fi

    echo "Running generator.py..."
    cd "$PARENT_DIR"
    python3 src/generator.py 2>&1 | tee -a "$RUN_LOG"
    cd "$SCRIPT_DIR"

    if [[ -f "$vfcs_file" ]]; then
        local entry_count
        entry_count=$(wc -l < "$vfcs_file")
        echo "[DONE] VFC generation complete: $entry_count entries"
    else
        echo "[FAIL] VFC generation did not produce output file"
        exit 1
    fi
}

# ============================================================
# Phase 2: Exploit Iteration (Evolver)
# ============================================================
phase_2_evolution() {
    echo "=== Phase 2: Exploit Evolution ==="

    # Set improvement flag if needed
    local export_line=""
    if [[ "$MODE" == "improvement" ]]; then
        export_line="USE_STATIC_ANALYSIS=true; "
        echo "[INFO] Improvement mode enabled (USE_STATIC_ANALYSIS=true)"
    fi

    # Export CVE_COUNT so evolver scripts read it from env for --cve-count filtering
    export CVE_COUNT="$CVE_COUNT"

    # Pass through GEPA skip flag (default: enabled — set SKIP_GEPA=0 to re-enable GEPA)
    export SKIP_GEPA="${SKIP_GEPA:-1}"

    # Export FILTERED_DATASET path via DATASET env var so evolvers pick it up
    if [[ -f "$FILTERED_DATASET" ]]; then
        export DATASET="$FILTERED_DATASET"
    fi

    cd "$PARENT_DIR"

    # Phase 2 baseline: count pre-existing transcripts before this phase starts
    local baseline_done
    baseline_done=$(count_completed)
    echo "[INFO] Pre-existing transcripts (from prior phases): $baseline_done"

    # Create temp file for current CVE name display during execution
    local CURRENT_CVE_FILE="$RESULTS_DIR/.current_cve_phase2.txt"
    > "$CURRENT_CVE_FILE"
    export CURRENT_CVE_FILE

    # Determine which evolver to run based on dataset type
    local evolver_script="src.evolver_llm"
    local dataset_name
    dataset_name=$(basename "$DATASET" .txt)
    if echo "$dataset_name" | grep -q "vfc"; then
        echo "Running evolver_llm.py (VFC data mode)..."
    else
        echo "Running evolver_pocgen.py (PoCGen data mode)..."
        evolver_script="src.evolver_pocgen"
    fi

    # Start the evolver in background FIRST (so EVOLVER_PID is set before tracker starts)
    python3 -m "$evolver_script" 2>&1 | tee -a "$RUN_LOG" &
    EVOLVER_PID=$!

    # Launch background spinner/progress tracker AFTER evolver PID is known.
    # It reads CURRENT_CVE_FILE and counts transcripts for per-phase progress display.
    (
        local last_done=-1
        while kill -0 "$EVOLVER_PID" 2>/dev/null; do
            local done_now
            done_now=$(count_completed)
            local phase_done=$(( done_now - baseline_done ))
            (( phase_done < 0 )) && phase_done=0

            # Only show progress if phase_done changed since last check
            if (( phase_done != last_done )); then
                local pct=0
                if (( TOTAL_CVES > 0 )); then
                    pct=$(( phase_done * 1000 / TOTAL_CVES ))
                    local pct_int=$(( pct / 10 ))
                    local pct_dec=$(( pct % 10 ))
                    printf "\033[2K\r\033[93mPhase 2/Evolve: %d/%d (%d.%d%%)\033[0m\n" \
                        "$phase_done" "$TOTAL_CVES" "$pct_int" "$pct_dec" >&2
                fi
                last_done=$phase_done
            fi

            # Show current CVE being processed (written by evolver to temp file)
            if [[ -f "$CURRENT_CVE_FILE" ]] && [[ -s "$CURRENT_CVE_FILE" ]]; then
                local cve_name
                cve_name=$(cat "$CURRENT_CVE_FILE" 2>/dev/null || true)
                if [[ -n "$cve_name" ]]; then
                    printf "  \033[94mCVE: %s\033[0m\n" "$cve_name" >&2
                fi
            fi

            sleep 3
        done
    ) &
    TRACKER_PID=$!

    # Wait for evolver to complete
    wait $EVOLVER_PID || true

    cd "$SCRIPT_DIR"

    # Kill spinner tracker when evolver finishes
    kill $TRACKER_PID 2>/dev/null || true
    wait $TRACKER_PID 2>/dev/null || true

    # Report Phase 2 results with delta from baseline
    local transcript_count
    transcript_count=$(count_completed)
    local phase_done=$(( transcript_count - baseline_done ))
    (( phase_done < 0 )) && phase_done=0
    printf "\033[92m[DONE] Phase 2/Evolve: %d new transcripts (%d pre-existing, total %d)\033[0m\n" \
        "$phase_done" "$baseline_done" "$transcript_count" >&2

    # Clean up temp file
    rm -f "$CURRENT_CVE_FILE"
}

# ============================================================
# Phase 3: Metric Extraction and Report Generation
# ============================================================
phase_3_metrics() {
    echo "=== Phase 3: Metrics Aggregation ==="

    cd "$SCRIPT_DIR"
    python3 "$SCRIPT_DIR/aggregate_metrics.py" \
        --logs-dir "$PARENT_DIR/logs" \
        --output "$RESULTS_DIR/${RUN_ID}_metrics.json" \
        --dataset-list "$DATASET" \
        2>&1 | tee -a "$RUN_LOG"

    echo "[DONE] Metrics written to ${RESULTS_DIR}/${RUN_ID}_metrics.json"
}

# ============================================================
# Run Phases
# ============================================================

if [[ "$DRY_RUN" == "true" ]]; then
    echo "[DRY-RUN MODE — no commands will execute]"
    phase_0_verify_env
    echo ""
    echo "Full pipeline: bash $0 --mode $MODE"
    exit 0
fi

echo ""
phase_start "Phase 0/Env"
phase_0_verify_env >> "$RUN_LOG" 2>&1
phase_end "Phase 0/Env"
echo ""

phase_start "Phase 1/VFC" "$TOTAL_CVES"
phase_1_vfc_generation >> "$RUN_LOG" 2>&1
phase_end "Phase 1/VFC"
echo ""

phase_start "Phase 2/Evolve" "$TOTAL_CVES"
phase_2_evolution >> "$RUN_LOG" 2>&1
phase_end "Phase 2/Evolve"
echo ""

phase_start "Phase 3/Metrics"
phase_3_metrics

echo ""
echo "=== Run Complete ==="
echo "Metrics:    $RESULTS_DIR/${RUN_ID}_metrics.json"
echo "Log:        $RUN_LOG"
echo ""
echo "To compare with another run:"
echo "  python3 $SCRIPT_DIR/aggregate_metrics.py --baseline <run1_metrics.json> --improvement <run2_metrics.json>"
