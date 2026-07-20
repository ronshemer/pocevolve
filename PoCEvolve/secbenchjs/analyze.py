import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


DEFAULT_CATEGORY_DIRS = (
    "code-injection",
    "command-injection",
    "path-traversal",
    "prototype-pollution",
    "redos",
)
SUPPORTED_FILE_EXTENSIONS = {
    ".js",
    ".jst",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".mts",
    ".cts",
    ".tsx",
    ".d.ts",
    ".d.mts",
    ".d.cts",
    ".vue",
    ".svelte",
    ".astro",
    ".coffee",
}
GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "Authorization": "Bearer ghp_xxx",
}
MAX_WORKERS = 8

# Paths relative to the script's directory so the script is location-independent.
_SCRIPT_DIR = Path(__file__).parent
TESTBED_ROOT = _SCRIPT_DIR / ".." / "testbed"
DATASETS_DIR = _SCRIPT_DIR / ".." / "datasets"
OUTPUT_JSON_PATH = _SCRIPT_DIR / "vfcs.json"
OUTPUT_TESTBED_JSON_PATH = _SCRIPT_DIR / "vfcs.testbed.json"
OUTPUT_FILTERED_JSON_PATH = _SCRIPT_DIR / "vfcs.filtered.json"


def read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def find_repo_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if any((candidate / name).is_dir() for name in DEFAULT_CATEGORY_DIRS):
            return candidate

        for alt in ("SecBench.js", "secbench.js", "secbenchjs"):
            alt_dir = candidate / alt
            if alt_dir.is_dir() and any((alt_dir / name).is_dir() for name in DEFAULT_CATEGORY_DIRS):
                return alt_dir

    return current


def discover_category_roots(root: Path, category_names: list[str] | None = None) -> list[Path]:
    if category_names:
        return [root / name for name in category_names if (root / name).is_dir()]

    return [root / name for name in DEFAULT_CATEGORY_DIRS if (root / name).is_dir()]


def is_test_file(path: Path) -> bool:
    return path.is_file() and "test" in str(path).lower()


def normalize_filename(filename: str) -> str:
    return filename.split("?", 1)[0].split("#", 1)[0]


def has_supported_extension(filename: str) -> bool:
    path = Path(normalize_filename(filename))
    suffixes = [suffix.lower() for suffix in path.suffixes]
    candidates = ["".join(suffixes[index:]) for index in range(len(suffixes))] if suffixes else []
    return any(extension in SUPPORTED_FILE_EXTENSIONS for extension in candidates)


def extract_code_changes(file_changes: list[dict[str, Any]], *, filtered: bool) -> list[dict[str, str]]:
    extracted_changes: list[dict[str, str]] = []

    for file_change in file_changes:
        filename = file_change.get("filename", "") or ""
        patch = file_change.get("patch", "") or ""

        if filtered and "test" in filename.lower():
            continue

        if filtered and not has_supported_extension(filename):
            continue

        extracted_changes.append({"filename": filename, "patch": patch})

    return extracted_changes


def collect_module_data(module_dir: Path) -> dict[str, Any]:
    package_json_path = module_dir / "package.json"
    test_files = [path for path in sorted(module_dir.iterdir()) if is_test_file(path)]

    return {
        "module_dir": str(module_dir),
        "package_json": {
            "path": str(package_json_path),
            "content": read_json_file(package_json_path),
        }
        if package_json_path.exists()
        else None,
        "test_files": [
            {
                "path": str(path),
                "content": read_text_file(path),
            }
            for path in test_files
        ],
    }


def collect_category_assets(category_root: Path) -> dict[str, Any]:
    modules = []

    for package_json_path in sorted(category_root.rglob("*/package.json")):
        if "node_modules" in package_json_path.parts or ".git" in package_json_path.parts:
            continue
        modules.append(collect_module_data(package_json_path.parent))

    return {
        "category": category_root.name,
        "root": str(category_root),
        "modules": modules,
    }


def load_vulnerable_assets(root: Path, category_names: list[str] | None = None) -> dict[str, Any]:
    category_roots = discover_category_roots(root, category_names)

    return {
        "root": str(root),
        "categories": [collect_category_assets(category_root) for category_root in category_roots],
    }


def clean_vfc_info(vfc_info: dict[str, Any]) -> dict[str, Any]:
    commit_message = vfc_info.get("commit", {}).get("message", "")
    all_changes = extract_code_changes(vfc_info.get("files", []), filtered=False)
    filtered_changes = extract_code_changes(vfc_info.get("files", []), filtered=True)

    return {
        "commit_message": commit_message,
        "source_code_changes": filtered_changes,
        "number_code_changes": len(filtered_changes),
        "all_code_changes": all_changes,
        "number_all_code_changes": len(all_changes),
    }


def get_pr_discussion_comments(owner: str, repo: str, pr_number: str) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []

    issue_comments_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    issue_comments_response = requests.get(issue_comments_url, headers=GITHUB_API_HEADERS)
    if issue_comments_response.status_code == 200:
        for comment in issue_comments_response.json():
            comments.append(
                {
                    "comment_type": "issue",
                    "author": (comment.get("user") or {}).get("login", "n/a"),
                    "body": comment.get("body", "n/a"),
                    "created_at": comment.get("created_at", "n/a"),
                }
            )

    review_comments_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
    review_comments_response = requests.get(review_comments_url, headers=GITHUB_API_HEADERS)
    if review_comments_response.status_code == 200:
        for comment in review_comments_response.json():
            comments.append(
                {
                    "comment_type": "review",
                    "author": (comment.get("user") or {}).get("login", "n/a"),
                    "body": comment.get("body", "n/a"),
                    "created_at": comment.get("created_at", "n/a"),
                }
            )

    return comments


def get_vfc(vfc_url: str) -> dict[str, Any]:
    try:
        parts = vfc_url.strip().split("/")
        owner = parts[3]
        repo = parts[4]

        vfc_info: dict[str, Any] = {
            "commit_message": "n/a",
            "source_code_changes": [],
            "number_code_changes": 0,
            "all_code_changes": [],
            "number_all_code_changes": 0,
            "pr_title": "n/a",
            "pr_description": "n/a",
            "discussion_comments": [],
        }

        if "pull" in parts:
            pr_number = parts[6]
            commit_sha_from_url = ""
            if "commits" in parts:
                commits_index = parts.index("commits")
                if commits_index + 1 < len(parts):
                    commit_sha_from_url = parts[commits_index + 1].strip()

            api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
            response = requests.get(api_url, headers=GITHUB_API_HEADERS)

            if response.status_code == 200:
                pr_info = response.json()
                pr_title = pr_info.get("title", "n/a")
                pr_description = pr_info.get("body", "n/a")
                vfc_info["pr_title"] = pr_title if isinstance(pr_title, str) and pr_title else "n/a"
                vfc_info["pr_description"] = (
                    pr_description if isinstance(pr_description, str) and pr_description else "n/a"
                )
                vfc_info["discussion_comments"] = get_pr_discussion_comments(owner, repo, pr_number)

                if not commit_sha_from_url:
                    commit_sha_from_url = (pr_info.get("head") or {}).get("sha", "")

            commit_sha = commit_sha_from_url
            if commit_sha:
                commit_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
                commit_resp = requests.get(commit_url, headers=GITHUB_API_HEADERS)
                if commit_resp.status_code == 200:
                    vfc_info.update(clean_vfc_info(commit_resp.json()))
        else:
            commit_sha = parts[-1]
            api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
            response = requests.get(api_url, headers=GITHUB_API_HEADERS)

            if response.status_code == 200:
                vfc_info.update(clean_vfc_info(response.json()))

    except Exception:
        vfc_info = {}

    return vfc_info


def _detect_source_type(url: str) -> str:
    if "security.snyk.io" in url or "snyk.io/vuln" in url:
        return "snyk"
    if "github.com/advisories/" in url:
        return "ghsa"
    return "unknown"


def fetch_snyk_report(url: str) -> dict[str, Any]:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    })
    try:
        response = session.get(url, timeout=30)
        if response.status_code != 200:
            return {}

        soup = BeautifulSoup(response.text, "html.parser")
        report: dict[str, Any] = {"source": "snyk", "url": url}

        title_el = soup.find("h1", class_=lambda c: c and "heading" in c and "title" in c)
        if title_el:
            report["title"] = title_el.get_text(strip=True)

        date_el = soup.find("h4", class_=lambda c: c and "heading" in c and "date" in c)
        if date_el:
            report["date"] = date_el.get_text(strip=True).removeprefix("Introduced: ")

        cve_span = soup.find("span", class_="cve")
        if cve_span:
            cve_link = cve_span.find("a")
            cve_id = (cve_link or {}).get("id", "")
            if re.match(r"^CVE-\d{4}-\d{4,}$", cve_id or ""):
                report["cve_id"] = cve_id

        cwe_span = soup.find("span", {"data-snyk-test": "cwe"})
        if cwe_span:
            cwe_link = cwe_span.find("a", href=True)
            if cwe_link:
                cwe_text = (cwe_link.string or cwe_link.get_text(strip=True)).split("(")[0].strip()
                if cwe_text:
                    report["cwe_id"] = cwe_text

        for h2 in soup.find_all("h2"):
            if h2.get_text(strip=True) == "Overview":
                sibling = h2.find_next_sibling()
                if sibling:
                    cleaned = re.sub(r"<\w+>POC.*?</\w+>", "", str(sibling), flags=re.IGNORECASE | re.DOTALL)
                    report["description"] = BeautifulSoup(cleaned, "html.parser").get_text(strip=True)
                break

        subtitle = soup.find("span", {"data-snyk-test": "vulnpage subtitle"})
        if subtitle:
            pkg_link = subtitle.find("a")
            if pkg_link and "/package/npm/" in (pkg_link.get("href") or ""):
                report["package"] = unquote(pkg_link["href"]).split("/package/npm/")[1]

        version_els = soup.find_all("strong", {"data-snyk-test": "vuln versions"})
        if version_els:
            report["vulnerable_versions"] = [el.get_text(strip=True) for el in version_els]

        refs = []
        for container in soup.find_all("div", class_="markdown-to-html markdown-description"):
            for a in container.find_all("a", href=True):
                refs.append(a["href"])
        if refs:
            report["references"] = refs

        return report
    except Exception:
        return {}


def fetch_ghsa_report(url: str) -> dict[str, Any]:
    parts = url.rstrip("/").split("/")
    ghsa_id = parts[-1]
    if not ghsa_id.startswith("GHSA-"):
        return {}

    try:
        api_url = f"https://api.github.com/advisories/{ghsa_id}"
        response = requests.get(api_url, headers=GITHUB_API_HEADERS, timeout=30)
        if response.status_code != 200:
            return {}

        data = response.json()
        report: dict[str, Any] = {"source": "ghsa", "url": url, "ghsa_id": ghsa_id}

        for field in ("summary", "description", "severity", "published_at", "updated_at"):
            if data.get(field):
                report[field] = data[field]

        if data.get("cve_id"):
            report["cve_id"] = data["cve_id"]
        else:
            for alias in data.get("identifiers") or []:
                if alias.get("type") == "CVE":
                    report["cve_id"] = alias["value"]
                    break

        cvss = data.get("cvss") or {}
        if cvss.get("score"):
            report["cvss_score"] = cvss["score"]
            report["cvss_vector"] = cvss.get("vector_string", "")

        cwes = [c["cwe_id"] for c in (data.get("cwes") or []) if c.get("cwe_id")]
        if cwes:
            report["cwe_ids"] = cwes

        affected = []
        for v in data.get("vulnerabilities") or []:
            pkg = v.get("package") or {}
            affected.append({
                "package": pkg.get("name", ""),
                "ecosystem": pkg.get("ecosystem", ""),
                "vulnerable_version_range": v.get("vulnerable_version_range", ""),
                "first_patched_version": (v.get("first_patched_version") or {}).get("identifier", ""),
            })
        if affected:
            report["affected_packages"] = affected

        refs = [r["url"] for r in (data.get("references") or []) if r.get("url")]
        if refs:
            report["references"] = refs

        return report
    except Exception:
        return {}


def extract_advisory_descriptions(reports: dict[str, Any]) -> list[str]:
    descriptions = []
    for report in reports.values():
        desc = report.get("description") or report.get("summary", "")
        if desc:
            descriptions.append(desc)
    return descriptions


def fetch_vulnerability_report(links: dict[str, str]) -> dict[str, Any]:
    reports: dict[str, Any] = {}
    for key, url in links.items():
        if not url:
            continue
        source_type = _detect_source_type(url)
        if source_type == "snyk":
            reports[key] = fetch_snyk_report(url)
        elif source_type == "ghsa":
            reports[key] = fetch_ghsa_report(url)
    return reports


def extract_vulnerability_ids(links: dict[str, str]) -> list[str]:
    ids: list[str] = []

    if not links or not isinstance(links, dict):
        return ids

    for url in links.values():
        if not isinstance(url, str):
            continue

        cve = re.search(r"CVE-\d{4}-\d{4,5}", url)
        if cve:
            ids.append(cve.group(0))

        snyk = re.search(r"SNYK-[A-Z]+-[A-Z0-9-]+", url)
        if snyk:
            ids.append(snyk.group(0))

        ghsa = re.search(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", url)
        if ghsa:
            ids.append(ghsa.group(0))

        npm = re.search(r"npm:[^/\s\"\'?#]+:[^/\s\"\'?#]+", url, re.IGNORECASE)
        if npm:
            ids.append(npm.group(0))

    seen: set[str] = set()
    unique: list[str] = []
    for id_val in ids:
        if id_val not in seen:
            seen.add(id_val)
            unique.append(id_val)
    return unique


def resolve_testbed_dir(ids: list[str], available: set[str]) -> str | None:
    for vuln_id in ids:
        folder = vuln_id.replace(":", "_")
        if folder in available:
            return folder
    return None


def load_testbed_dirs() -> set[str]:
    testbed = TESTBED_ROOT.resolve()
    if not testbed.is_dir():
        return set()
    return {path.name for path in testbed.iterdir() if path.is_dir()}


def primary_id(record: dict[str, Any]) -> str:
    """Return the canonical vulnerability ID in original format (colons for npm IDs).

    The testbed folder name (testbed_dir) uses underscores in place of colons so it
    can be used as a filesystem path. This function finds the ids[] entry that maps
    back to that folder name, preserving the original colon-separated form.
    """
    ids = record.get("ids") or []
    testbed_dir = record.get("testbed_dir") or ""
    for id_val in ids:
        if id_val.replace(":", "_") == testbed_dir:
            return id_val
    # Fall back to first known ID, then to testbed_dir itself.
    return ids[0] if ids else testbed_dir


def write_id_file(records: list[dict[str, Any]], stem: str) -> Path:
    """Write one ID per line to datasets/<stem>.<count>, removing any stale file
    with the same stem but a different count from a previous run."""
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    ids = [primary_id(r) for r in records]
    # Remove old files with the same stem but a different count.
    for stale in DATASETS_DIR.glob(f"{stem}.*"):
        if stale.name != f"{stem}.{len(ids)}":
            stale.unlink()
    out = DATASETS_DIR / f"{stem}.{len(ids)}"
    out.write_text("\n".join(ids), encoding="utf-8")
    return out


def serialize_vfc_record(vfc_record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        for key, value in vfc_record.items()
    }


repo_root = find_repo_root()
assets = load_vulnerable_assets(repo_root)
available_testbed_dirs = load_testbed_dirs()

print(f"Repository root: {repo_root}")
print(f"Categories loaded: {len(assets['categories'])}")
for category in assets["categories"]:
    print(f"- {category['category']}: {len(category['modules'])} modules")
print(f"Testbed dirs available: {len(available_testbed_dirs)}")

_EMPTY_VFC: dict[str, Any] = {
    "commit_message": "n/a",
    "source_code_changes": [],
    "number_code_changes": 0,
    "all_code_changes": [],
    "number_all_code_changes": 0,
    "pr_title": "n/a",
    "pr_description": "n/a",
    "discussion_comments": [],
}


def process_module(vulnerability_type: str, module: dict[str, Any]) -> dict[str, Any]:
    test_file = module["test_files"][0]["content"] if module["test_files"] else ""
    package_json = module["package_json"]

    # Prefer the actual package name from the dependencies field — more reliable
    # than slicing the directory name, which breaks for packages with underscores.
    dependencies = (package_json["content"].get("dependencies") or {}) if package_json else {}
    if dependencies:
        vulnerable_package = next(iter(dependencies))
        vulnerable_version = next(iter(dependencies.values()))
    else:
        module_name = Path(module["module_dir"]).name
        vulnerable_package = module_name.split("_")[0]
        vulnerable_version = module_name.split("_")[-1]

    fix_commit = package_json["content"]["fixCommit"] if package_json else "n/a"
    links = package_json["content"].get("links", {}) if package_json else {}

    advisory_reports = fetch_vulnerability_report(links)
    ids = extract_vulnerability_ids(links)
    testbed_dir = resolve_testbed_dir(ids, available_testbed_dirs)

    if fix_commit.strip() and fix_commit.strip().lower() != "n/a":
        vfc = get_vfc(fix_commit) or dict(_EMPTY_VFC)
    else:
        vfc = dict(_EMPTY_VFC)

    vfc.update({
        "vulnerability_type": vulnerability_type,
        "vulnerable_package": vulnerable_package,
        "vulnerable_version": vulnerable_version,
        "vulnerability_fix_commit": fix_commit,
        "commit_type": "pull" if "pull" in fix_commit else "commit" if "commit" in fix_commit or "tag" in fix_commit else "n/a",
        "secbench_test": test_file,
        "advisory_descriptions": extract_advisory_descriptions(advisory_reports),
        "ids": ids,
        "testbed_dir": testbed_dir,
    })
    return vfc


tasks: list[tuple[str, dict[str, Any]]] = [
    (category["category"], module)
    for category in assets["categories"]
    for module in category["modules"]
]

vfcs: list[dict[str, Any]] = [None] * len(tasks)  # type: ignore[list-item]

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    future_to_index = {
        executor.submit(process_module, vuln_type, module): i
        for i, (vuln_type, module) in enumerate(tasks)
    }
    with tqdm(total=len(tasks), desc="Processing modules", unit="module") as progress:
        for future in as_completed(future_to_index):
            i = future_to_index[future]
            try:
                vfcs[i] = future.result()
            except Exception as exc:
                vuln_type, module = tasks[i]
                tqdm.write(f"Error processing {module['module_dir']}: {exc}")
                vfcs[i] = dict(_EMPTY_VFC)
            progress.update(1)

# ── Output 1: all records, every field ───────────────────────────────────────
OUTPUT_JSON_PATH.write_text(json.dumps(vfcs, indent=2), encoding="utf-8")
print(f"\nWrote {len(vfcs)} records → {OUTPUT_JSON_PATH}")

# ── Output 2: one record per testbed folder (≈560) ───────────────────────────
seen_testbed: set[str] = set()
testbed_vfcs: list[dict[str, Any]] = []
for record in vfcs:
    td = record.get("testbed_dir")
    if not td or td in seen_testbed:
        continue
    seen_testbed.add(td)
    testbed_vfcs.append(record)

OUTPUT_TESTBED_JSON_PATH.write_text(json.dumps(testbed_vfcs, indent=2), encoding="utf-8")
print(f"Wrote {len(testbed_vfcs)} records → {OUTPUT_TESTBED_JSON_PATH}")

# ── Output 3: fully filtered (≈193) ──────────────────────────────────────────
# Requires: testbed match + non-empty source diff + valid fix commit + unique fix commit
seen_fix_commits: set[str] = set()
filtered_vfcs: list[dict[str, Any]] = []
for record in vfcs:
    fix_commit = record.get("vulnerability_fix_commit")
    if not record.get("testbed_dir"):
        continue
    if not record.get("source_code_changes"):
        continue
    if not fix_commit or fix_commit == "n/a":
        continue
    if fix_commit in seen_fix_commits:
        continue
    seen_fix_commits.add(fix_commit)
    filtered_vfcs.append(record)

OUTPUT_FILTERED_JSON_PATH.write_text(json.dumps(filtered_vfcs, indent=2), encoding="utf-8")
print(f"Wrote {len(filtered_vfcs)} records → {OUTPUT_FILTERED_JSON_PATH}")

# ── ID list files (one ID per line, filename encodes count) ──────────────────
p = write_id_file(vfcs, "SecBench.js.all")
print(f"Wrote {len(vfcs)} IDs      → {p}")

p = write_id_file(testbed_vfcs, "SecBench.js.PoCGen")
print(f"Wrote {len(testbed_vfcs)} IDs      → {p}")

p = write_id_file(filtered_vfcs, "SecBench.js.PoCGen.vfc")
print(f"Wrote {len(filtered_vfcs)} IDs      → {p}")
