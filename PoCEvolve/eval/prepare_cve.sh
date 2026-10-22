#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
usage() {
    echo "Usage: $0 <CVE-ID>" >&2
    echo "Creates/reuses the vulnerable git testbed and runs entry-point/target-method static analysis." >&2
}

if [[ $# -lt 1 ]]; then
    usage
    exit 2
fi

CVE_ID="$1"
shift
if [[ $# -gt 0 ]]; then
    echo "Unexpected arguments: $*" >&2
    usage
    exit 2
fi

exec bash "$SCRIPT_DIR/analyze_cve.sh" "$CVE_ID"
