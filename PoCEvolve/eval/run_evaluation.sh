#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"
EVAL_ARGS=("$@")
mkdir -p "$PROJECT_DIR/eval/testbeds"
export TESTBED_DIR="eval/testbeds"
PREP_ARGS=()
RESUME_DIR=""
OUTPUT_DIR=""
while (($#)); do
  case "$1" in
    --cve|--dataset) PREP_ARGS=("$1" "$2"); shift 2 ;;
    --resume-dir) RESUME_DIR="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -n "$RESUME_DIR" ]]; then
  OUTPUT_DIR="$RESUME_DIR"
  if ((${#PREP_ARGS[@]} == 0)); then
    PREP_ARGS=(--dataset "$RESUME_DIR/dataset.txt")
  fi
else
  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="eval/results/direct_$(date -u +%Y%m%d_%H%M%S)"
    EVAL_ARGS+=(--output-dir "$OUTPUT_DIR")
  fi
fi
case "$OUTPUT_DIR" in
  /*) ;;
  *) OUTPUT_DIR="$PROJECT_DIR/$OUTPUT_DIR" ;;
esac
printf 'Evaluation output directory: %s\n' "$OUTPUT_DIR"
python3 eval/prepare_testbeds.py "${PREP_ARGS[@]}"
export HOST_UID="$(id -u)" HOST_GID="$(id -g)"
if ! docker image inspect patched_node >/dev/null 2>&1; then
  echo "Build PoCGen's patched_node base image first; see PoCGen/README.md." >&2
  exit 1
fi
docker compose build app
exec docker compose run --rm --user "$HOST_UID:$HOST_GID" app python3 eval/run_evaluation.py "${EVAL_ARGS[@]}"
