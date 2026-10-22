#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

usage() {
    echo "Usage: $0 <CVE-ID> [output.json]" >&2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 2
fi

CVE_ID="$1"
SAFE_ID="${CVE_ID//:/_}"
OUTPUT="${2:-$SCRIPT_DIR/results/static-analysis/$SAFE_ID.json}"
cd "$PROJECT_DIR"
exec python3 -B -m src.graph_analysis \
    --cve-id "$CVE_ID" \
    --json \
    --output "$OUTPUT"
