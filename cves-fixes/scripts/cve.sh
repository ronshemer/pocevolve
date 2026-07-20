#!/bin/bash
set -euo pipefail

URL="https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-06-22_1800Z/2026-06-22_all_CVEs_at_midnight.zip.zip"
OUTER_ZIP="$(mktemp /tmp/cvelistV5_outer_XXXXXX.zip)"
INNER_ZIP="$(mktemp /tmp/cvelistV5_inner_XXXXXX.zip)"

mkdir -p "./outputs"

echo "Downloading CVE dataset..."
curl -L --fail --show-error --progress-bar -o "$OUTER_ZIP" "$URL"

echo "Extracting outer zip..."
unzip -o -q -p "$OUTER_ZIP" > "$INNER_ZIP"

echo "Extracting inner zip to ./outputs ..."
unzip -o -q "$INNER_ZIP" -d "./outputs"

rm -f "$OUTER_ZIP" "$INNER_ZIP"
echo "Done. $(find "./outputs/cves" -name 'CVE-*.json' | wc -l | tr -d ' ') CVE files in ./outputs/cves"