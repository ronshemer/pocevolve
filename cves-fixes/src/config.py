from pathlib import Path

OUTPUT_DIR = Path("outputs")

CVE_DIR = OUTPUT_DIR / "cves"
PATCH_DIR = OUTPUT_DIR / "patch"
WHEN_DIR = OUTPUT_DIR / "when"
CACHE_DIR = OUTPUT_DIR / "cache"

CODE_CHANGES_DIR = OUTPUT_DIR / "code_changes"

GITHUB_DATES_CACHE_FILE = CACHE_DIR / "github_dates.json"
GITHUB_TOKEN = "ghp_xxx"