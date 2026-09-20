#!/usr/bin/env python3
"""Validate the internal consistency and external references of SecBench VFCS data.

The validator is intentionally read-only.  It reports an issue per record and exits
non-zero only for errors, which makes it usable before starting an experiment:

    python3 scripts/validate_secbench_dataset.py
    python3 scripts/validate_secbench_dataset.py secbenchjs/vfcs.filtered.json --no-check-links
    python3 scripts/validate_secbench_dataset.py --json-report /tmp/vfcs-report.json

Network checks are enabled by default because a fix URL which no longer resolves is
not useful evidence for an exploit-generation prompt.  Use --no-check-links for an
offline/schema-only pass.  A failed network request is reported as a warning, not a
broken link, so a transient DNS/rate-limit problem cannot corrupt the diagnosis.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler


REQUIRED_FIELDS = {
    "commit_message": str,
    "source_code_changes": list,
    "number_code_changes": int,
    "all_code_changes": list,
    "number_all_code_changes": int,
    "pr_title": str,
    "pr_description": str,
    "discussion_comments": list,
    "vulnerability_type": str,
    "vulnerable_package": str,
    "vulnerable_version": str,
    "vulnerability_fix_commit": str,
    "commit_type": str,
    "secbench_test": str,
    "advisory_descriptions": list,
    "ids": list,
    "testbed_dir": (str, type(None)),
}
OPTIONAL_TEXT_FIELDS = ("commit_message", "pr_title", "pr_description")
NPM_PACKAGE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
VULN_ID = re.compile(r"^(?:SNYK-[A-Z0-9-]+-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\d{4}-\d{4,}|npm:[a-z0-9._-]+:\d{8})$", re.I)
GITHUB_COMMIT = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/(?:commit|pull/\d+/commits)/([0-9a-f]{7,64})/?$", re.I)


@dataclass(frozen=True)
class Issue:
    index: int
    package: str
    ids: list[str]
    severity: str  # error or warning
    code: str
    detail: str


def issue(entry: dict[str, Any], index: int, severity: str, code: str, detail: str) -> Issue:
    ids = entry.get("ids")
    return Issue(index, str(entry.get("vulnerable_package", "<missing>")), ids if isinstance(ids, list) else [], severity, code, detail)


def is_missing(value: Any) -> bool:
    return value is None or (isinstance(value, str) and (not value.strip() or value.strip().lower() == "n/a"))


def validate_change_list(entry: dict[str, Any], index: int, field: str, count_field: str) -> list[Issue]:
    value = entry.get(field)
    if not isinstance(value, list):
        return []  # The type error is emitted by validate_record.
    problems: list[Issue] = []
    if entry.get(count_field) != len(value):
        problems.append(issue(entry, index, "error", "change_count_mismatch", f"{count_field}={entry.get(count_field)!r}, but {field} has {len(value)} item(s)"))
    for change_index, change in enumerate(value):
        if not isinstance(change, dict):
            problems.append(issue(entry, index, "error", "invalid_change", f"{field}[{change_index}] must be an object, not {type(change).__name__}"))
            continue
        for key in ("filename", "patch"):
            if not isinstance(change.get(key), str) or not change[key].strip():
                problems.append(issue(entry, index, "error", "invalid_change", f"{field}[{change_index}].{key} must be a non-empty string"))
    return problems


def validate_record(entry: Any, index: int) -> list[Issue]:
    if not isinstance(entry, dict):
        return [Issue(index, "<not an object>", [], "error", "invalid_record", f"record is {type(entry).__name__}, not an object")]

    problems: list[Issue] = []
    for name, expected_type in REQUIRED_FIELDS.items():
        if name not in entry:
            problems.append(issue(entry, index, "error", "missing_field", f"missing required field {name!r}"))
        elif not isinstance(entry[name], expected_type):
            expected = "/".join(t.__name__ for t in expected_type) if isinstance(expected_type, tuple) else expected_type.__name__
            problems.append(issue(entry, index, "error", "invalid_type", f"{name} must be {expected}, not {type(entry[name]).__name__}"))

    package = entry.get("vulnerable_package")
    if isinstance(package, str) and not NPM_PACKAGE.fullmatch(package):
        problems.append(issue(entry, index, "error", "invalid_package_name", f"vulnerable_package={package!r} is not a valid npm package name"))
    version = entry.get("vulnerable_version")
    if isinstance(version, str) and is_missing(version):
        problems.append(issue(entry, index, "error", "missing_version", "vulnerable_version is empty or n/a"))
    if isinstance(entry.get("vulnerability_type"), str) and is_missing(entry["vulnerability_type"]):
        problems.append(issue(entry, index, "error", "missing_vulnerability_type", "vulnerability_type is empty or n/a"))
    if isinstance(entry.get("secbench_test"), str) and not entry["secbench_test"].strip():
        problems.append(issue(entry, index, "warning", "missing_test", "secbench_test is empty"))

    ids = entry.get("ids")
    if isinstance(ids, list):
        if not ids:
            problems.append(issue(entry, index, "error", "missing_ids", "ids must contain at least one advisory identifier"))
        for value in ids:
            if not isinstance(value, str) or not VULN_ID.fullmatch(value):
                problems.append(issue(entry, index, "warning", "unrecognized_vulnerability_id", f"ids contains {value!r}"))

    for text_field in OPTIONAL_TEXT_FIELDS:
        value = entry.get(text_field)
        if isinstance(value, str) and value.strip().lower() == "n/a":
            continue
        if isinstance(value, str) and not value.strip():
            problems.append(issue(entry, index, "warning", "empty_optional_text", f"{text_field} is empty; use n/a for absent metadata"))

    problems.extend(validate_change_list(entry, index, "source_code_changes", "number_code_changes"))
    problems.extend(validate_change_list(entry, index, "all_code_changes", "number_all_code_changes"))

    source = entry.get("source_code_changes")
    all_changes = entry.get("all_code_changes")
    if isinstance(source, list) and isinstance(all_changes, list):
        all_fingerprints = {json.dumps(change, sort_keys=True, ensure_ascii=False) for change in all_changes if isinstance(change, dict)}
        for change_index, change in enumerate(source):
            if isinstance(change, dict) and json.dumps(change, sort_keys=True, ensure_ascii=False) not in all_fingerprints:
                problems.append(issue(entry, index, "error", "source_change_not_in_all_changes", f"source_code_changes[{change_index}] is absent from all_code_changes"))

    fix = entry.get("vulnerability_fix_commit")
    commit_type = entry.get("commit_type")
    if isinstance(fix, str) and not is_missing(fix):
        parsed = urlparse(fix)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            problems.append(issue(entry, index, "error", "invalid_fix_url", f"vulnerability_fix_commit is not an HTTP(S) URL: {fix!r}"))
        elif "github.com" in parsed.netloc.lower() and not GITHUB_COMMIT.fullmatch(fix):
            problems.append(issue(entry, index, "warning", "noncanonical_github_fix_url", "GitHub fix URL is not a commit URL or PR-commit URL"))
        # Compare URLs (for example /compare/v3.10.3...v3.11.5) are valid
        # provenance but do not identify one commit, so n/a is appropriate there.
        known_commit_url = bool(re.search(r"/(?:commit|pull/\d+/commits|tag)/", parsed.path, re.I))
        if commit_type not in ("commit", "pull", "tag", "n/a") or (known_commit_url and commit_type == "n/a"):
            problems.append(issue(entry, index, "error", "invalid_commit_type", f"commit_type={commit_type!r} does not describe the supplied fix URL"))
    elif commit_type not in ("n/a", None):
        problems.append(issue(entry, index, "error", "commit_type_without_fix", f"commit_type={commit_type!r} but vulnerability_fix_commit is absent"))
    return problems


class NoRedirect(HTTPRedirectHandler):
    """Keep a response's final URL visible while accepting normal redirects."""


def check_url(url: str, timeout: float) -> tuple[str, str]:
    """Return (status, detail), where status is ok, broken, or unavailable."""
    request = Request(url, headers={"User-Agent": "PoCEvolve-dataset-validator/1.0"}, method="HEAD")
    try:
        with build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            return "ok", f"HTTP {response.status}"
    except HTTPError as exc:
        # Some hosting sites reject HEAD but accept GET.  Client and server errors are real failures.
        if exc.code in (405, 501):
            try:
                with build_opener(NoRedirect()).open(Request(url, headers={"User-Agent": "PoCEvolve-dataset-validator/1.0", "Range": "bytes=0-0"}), timeout=timeout) as response:
                    return "ok", f"HTTP {response.status} (GET fallback)"
            except HTTPError as get_exc:
                return "broken", f"HTTP {get_exc.code}"
            except (URLError, TimeoutError) as get_exc:
                return "unavailable", str(get_exc.reason if isinstance(get_exc, URLError) else get_exc)
        return "broken", f"HTTP {exc.code}"
    except (URLError, TimeoutError) as exc:
        return "unavailable", str(exc.reason if isinstance(exc, URLError) else exc)


def validate_links(records: list[Any], timeout: float, workers: int) -> list[Issue]:
    urls: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, entry in enumerate(records):
        if isinstance(entry, dict) and isinstance(entry.get("vulnerability_fix_commit"), str) and not is_missing(entry["vulnerability_fix_commit"]):
            urls.setdefault(entry["vulnerability_fix_commit"], []).append((index, entry))
    problems: list[Issue] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_url, url, timeout): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            status, detail = future.result()
            if status == "ok":
                continue
            severity = "error" if status == "broken" else "warning"
            for index, entry in urls[url]:
                problems.append(issue(entry, index, severity, f"fix_link_{status}", f"{url}: {detail}"))
    return problems


def validate_local_relationships(records: list[Any], testbed_root: Path) -> list[Issue]:
    """Check that the local exploit test and optional testbed identify the same record."""
    problems: list[Issue] = []
    for index, entry in enumerate(records):
        if not isinstance(entry, dict):
            continue
        testbed_dir = entry.get("testbed_dir")
        if isinstance(testbed_dir, str) and testbed_dir.strip() and not (testbed_root / testbed_dir).is_dir():
            problems.append(issue(entry, index, "error", "missing_testbed_directory", f"testbed_dir {testbed_dir!r} does not exist below {testbed_root}"))
    return problems


def github_repo(url: str) -> str | None:
    """Return lower-case owner/repo for a GitHub URL, including git+ URLs."""
    match = re.search(r"github\.com[/:]([^/]+)/([^/#.]+)", url, re.I)
    return f"{match.group(1).lower()}/{match.group(2).lower()}" if match else None


def npm_repository(package: str, version: str, timeout: float) -> tuple[str, str | None]:
    """Fetch the repository declared by the exact published npm package version."""
    registry_url = f"https://registry.npmjs.org/{quote(package, safe='@')}/{quote(version, safe='')}"
    try:
        with build_opener().open(Request(registry_url, headers={"User-Agent": "PoCEvolve-dataset-validator/1.0"}), timeout=timeout) as response:
            metadata = json.load(response)
    except HTTPError as exc:
        return "unavailable", f"HTTP {exc.code}"
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        return "unavailable", str(exc.reason if isinstance(exc, URLError) else exc)
    repository = metadata.get("repository")
    repository_url = repository.get("url") if isinstance(repository, dict) else repository
    if not isinstance(repository_url, str):
        return "missing", None
    return "ok", github_repo(repository_url)


def validate_package_repositories(records: list[Any], timeout: float, workers: int) -> list[Issue]:
    """Compare each GitHub fix repository to the repository in npm's exact version metadata."""
    candidates: list[tuple[int, dict[str, Any], str]] = []
    for index, entry in enumerate(records):
        if not isinstance(entry, dict):
            continue
        fix = entry.get("vulnerability_fix_commit")
        package = entry.get("vulnerable_package")
        version = entry.get("vulnerable_version")
        if isinstance(fix, str) and isinstance(package, str) and isinstance(version, str) and not is_missing(fix) and github_repo(fix):
            candidates.append((index, entry, fix))
    problems: list[Issue] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(npm_repository, entry["vulnerable_package"], entry["vulnerable_version"], timeout): (index, entry, fix) for index, entry, fix in candidates}
        for future in concurrent.futures.as_completed(futures):
            index, entry, fix = futures[future]
            status, expected_repo = future.result()
            if status == "unavailable":
                problems.append(issue(entry, index, "warning", "npm_metadata_unavailable", f"could not obtain package repository: {expected_repo}"))
            elif status == "ok" and expected_repo and expected_repo != github_repo(fix):
                fix_repo = github_repo(fix)
                # Owner-only differences are common after GitHub transfers and forks.  A
                # different repository name is strong evidence of cross-contamination.
                severity = "warning" if fix_repo and fix_repo.split("/", 1)[1] == expected_repo.split("/", 1)[1] else "error"
                problems.append(issue(entry, index, severity, "fix_repo_package_mismatch", f"fix is in {fix_repo}, but npm metadata for {entry['vulnerable_package']}@{entry['vulnerable_version']} declares {expected_repo}"))
    return problems


def render_text(problems: list[Issue], total: int, links_checked: bool) -> None:
    counts = Counter(problem.severity for problem in problems)
    print(f"Validated {total} record(s){' with link checks' if links_checked else ' (offline)'}.")
    print(f"Errors: {counts['error']}; warnings: {counts['warning']}; clean: {total - len({p.index for p in problems})}.")
    for problem in sorted(problems, key=lambda p: (p.index, p.severity, p.code)):
        id_text = ", ".join(problem.ids) or "no-id"
        print(f"[{problem.severity.upper()}] record {problem.index} | {problem.package} | {id_text} | {problem.code}: {problem.detail}")


FIX_METADATA_FIELDS = (
    "commit_message", "source_code_changes", "number_code_changes",
    "all_code_changes", "number_all_code_changes", "pr_title",
    "pr_description", "discussion_comments", "vulnerability_fix_commit",
    "commit_type",
)
STRUCTURAL_EXCLUSION_CODES = {
    "invalid_record", "missing_field", "invalid_type", "invalid_package_name",
    "missing_ids", "missing_version", "missing_vulnerability_type",
    "invalid_change", "source_change_not_in_all_changes", "missing_testbed_directory",
}


def repair_and_filter(records: list[Any], problems: list[Issue]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Create a cleaned copy without guessing security-relevant source data."""
    by_index: dict[int, list[Issue]] = {}
    for problem in problems:
        by_index.setdefault(problem.index, []).append(problem)
    clean: list[dict[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    for index, original in enumerate(records):
        record_issues = by_index.get(index, [])
        if not isinstance(original, dict):
            quarantine.append({"index": index, "reason": "invalid_record", "issues": [asdict(x) for x in record_issues]})
            continue
        repaired = copy.deepcopy(original)
        codes = {problem.code for problem in record_issues}
        if codes & STRUCTURAL_EXCLUSION_CODES:
            quarantine.append({"index": index, "package": original.get("vulnerable_package"), "ids": original.get("ids", []), "reason": "structural_validation_failure", "issues": [asdict(x) for x in record_issues]})
            continue
        record_actions: list[str] = []
        for field, count_field in (("source_code_changes", "number_code_changes"), ("all_code_changes", "number_all_code_changes")):
            if isinstance(repaired.get(field), list) and repaired.get(count_field) != len(repaired[field]):
                repaired[count_field] = len(repaired[field])
                record_actions.append(f"recalculated {count_field}")
        discarded = sorted({"fix_link_broken", "fix_repo_package_mismatch"} & codes)
        if discarded:
            for field in FIX_METADATA_FIELDS:
                if field not in repaired:
                    continue
                if field in ("source_code_changes", "all_code_changes", "discussion_comments"):
                    repaired[field] = []
                elif field in ("number_code_changes", "number_all_code_changes"):
                    repaired[field] = 0
                elif field == "commit_type":
                    repaired[field] = "n/a"
                else:
                    repaired[field] = "n/a"
            record_actions.append("cleared unusable fix/patch metadata: " + ", ".join(discarded))
        clean.append(repaired)
        if record_actions:
            actions.append({"index": index, "package": original.get("vulnerable_package"), "ids": original.get("ids", []), "actions": record_actions})
    return clean, quarantine, actions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("secbenchjs/vfcs.json"), help="VFCS JSON array (default: secbenchjs/vfcs.json)")
    parser.add_argument("--no-check-links", action="store_true", help="skip HTTP validation of vulnerability_fix_commit URLs")
    parser.add_argument("--no-check-package-repos", action="store_true", help="skip comparison of GitHub fixes with the exact npm package version's repository")
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds per link request (default: 10)")
    parser.add_argument("--workers", type=int, default=12, help="parallel link requests (default: 12)")
    parser.add_argument("--testbed-root", type=Path, help="directory containing testbed_dir values (default: <dataset parent>/../testbed)")
    parser.add_argument("--json-report", type=Path, help="write machine-readable report to this path")
    parser.add_argument("--clean-output", type=Path, help="write repaired/filtered JSON dataset to this path")
    parser.add_argument("--quarantine-output", type=Path, help="write excluded records and repair actions (requires --clean-output)")
    args = parser.parse_args()
    if args.timeout <= 0 or args.workers <= 0:
        parser.error("--timeout and --workers must be positive")
    try:
        records = json.loads(args.dataset.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot read {args.dataset}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(records, list):
        print(f"{args.dataset} must contain a JSON array, not {type(records).__name__}", file=sys.stderr)
        return 2

    testbed_root = args.testbed_root or args.dataset.parent.parent / "testbed"
    problems = [problem for index, entry in enumerate(records) for problem in validate_record(entry, index)]
    problems.extend(validate_local_relationships(records, testbed_root))
    if not args.no_check_links:
        problems.extend(validate_links(records, args.timeout, args.workers))
    if not args.no_check_package_repos:
        problems.extend(validate_package_repositories(records, args.timeout, args.workers))
    render_text(problems, len(records), not args.no_check_links)
    if args.json_report:
        report = {"dataset": str(args.dataset), "records": len(records), "links_checked": not args.no_check_links, "package_repositories_checked": not args.no_check_package_repos, "summary": dict(Counter(p.severity for p in problems)), "issues": [asdict(p) for p in problems]}
        args.json_report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"JSON report: {args.json_report}")
    if args.quarantine_output and not args.clean_output:
        parser.error("--quarantine-output requires --clean-output")
    if args.clean_output:
        cleaned, quarantine, actions = repair_and_filter(records, problems)
        args.clean_output.write_text(json.dumps(cleaned, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        quarantine_path = args.quarantine_output or args.clean_output.with_name(args.clean_output.stem + ".quarantine.json")
        quarantine_path.write_text(json.dumps({"source": str(args.dataset), "kept": len(cleaned), "excluded": len(quarantine), "repaired": len(actions), "quarantine": quarantine, "repairs": actions}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Clean dataset: {args.clean_output} ({len(cleaned)} records; {len(quarantine)} excluded; {len(actions)} repaired)")
        print(f"Quarantine/actions: {quarantine_path}")
    return 1 if any(problem.severity == "error" for problem in problems) else 0


if __name__ == "__main__":
    raise SystemExit(main())
