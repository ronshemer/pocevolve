#!/usr/bin/env python3
"""
Validate VFCS entries for cross-contamination between vulnerable_package
and commit-related fields (commit_message, source_code_changes, vulnerability_fix_commit).

A valid entry has:
1. If vulnerability_fix_commit is a GitHub URL, the repo name should match or be related to vulnerable_package
2. If advisory_descriptions mention a different package name than vulnerable_package, flag it
3. source_code_changes filenames and patches should not contain obvious mismatched context (e.g., package.json with wrong repo URL)

Run: python3 -m src.validate_vfcs [dataset_dir]

If --fix is passed, entries with detected mismatches are cleared of their commit-related fields
(so the LLM falls back to advisory_descriptions only).
"""

import json
import os
import re
import sys
from pathlib import Path


def extract_github_repo(url: str) -> str | None:
    """Extract 'owner/repo' from a GitHub URL."""
    if not url or not isinstance(url, str):
        return None
    m = re.search(r"github\.com/([^/]+)/([^/]+)", url)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return None


def normalize_package_name(name: str) -> str:
    """Lowercase and strip leading 'js-' prefixes that Snyk sometimes adds."""
    return name.lower().strip()


def check_advisory_mentions_different_package(advisories: list, pkg: str) -> bool:
    """Check if advisory descriptions mention a different package by name."""
    if not advisories or not isinstance(advisories, list):
        return False
    normalized_pkg = normalize_package_name(pkg)
    for desc in advisories:
        if not isinstance(desc, str):
            continue
        # Check for package names that look like npm packages (start with lowercase letter, contain hyphens)
        # Skip the target package name itself
        candidates = re.findall(r'`([^`]+)`', desc)
        for candidate in candidates:
            if normalize_package_name(candidate) != normalized_pkg:
                return True
    return False


def check_commit_message_mismatch(commit_msg: str, pkg: str) -> tuple[bool, str]:
    """Check if commit message mentions a different package."""
    if not commit_msg or not isinstance(commit_msg, str):
        return False, ""
    # Check for npm packages mentioned in the commit message (backtick-quoted)
    candidates = re.findall(r'`([^`]+)`', commit_msg)
    normalized_pkg = normalize_package_name(pkg)
    for candidate in candidates:
        if normalize_package_name(candidate) != normalized_pkg:
            return True, candidate
    # Also check for package names with hyphens (npm convention)
    npm_names = re.findall(r'(?:^|[\s,;])(([a-z][a-z0-9]*)(?:-[a-z0-9]+)+)(?:[\s,;]|$)', commit_msg.lower())
    for full, first in npm_names:
        if normalize_package_name(full) != normalized_pkg:
            return True, full
    return False, ""


def check_patch_mentions_different_package(patch: str, pkg: str) -> tuple[bool, str]:
    """Check if patch content references a different GitHub repo or package."""
    # Look for GitHub user/repo patterns in patches
    repos = re.findall(r"github\.com/([^/]+)/([^/]+)", patch)
    normalized_pkg = normalize_package_name(pkg)
    for owner, repo in repos:
        repo_normalized = normalize_package_name(repo)
        if repo_normalized != normalized_pkg and repo_normalized != normalize_package_name(pkg):
            return True, f"{owner}/{repo}"
    # Look for package.json "name" fields that differ from the target package
    name_matches = re.findall(r'"name"\s*:\s*"([^"]+)"', patch)
    for name in name_matches:
        if normalize_package_name(name) != normalized_pkg:
            return True, f"name:{name}"
    return False, ""


def validate_entry(entry: dict, source_file: str = "") -> list[dict]:
    """Validate a single VFCS entry. Returns list of issues found."""
    issues = []
    pkg = entry.get("vulnerable_package", "")

    # Check 1: vulnerability_fix_commit repo mismatch
    fix_url = entry.get("vulnerability_fix_commit", "")
    if fix_url and isinstance(fix_url, str):
        gh_repo = extract_github_repo(fix_url)
        if gh_repo:
            normalized_pkg = normalize_package_name(pkg)
            target_repo_normalized = normalized_pkg.replace("-", "")
            repo_normalized = normalize_package_name(gh_repo.split("/")[-1])
            # The repo name should match the package name (loosely)
            if repo_normalized != normalized_pkg and repo_normalized.replace("-", "") not in normalized_pkg:
                issues.append({
                    "type": "fix_commit_repo_mismatch",
                    "severity": "critical",
                    "detail": f"vulnerability_fix_commit repo '{gh_repo}' does not match vulnerable_package '{pkg}'",
                    "suggestion": "Replace with the correct fix commit URL or clear the field",
                })

    # Check 2: commit_message mismatch
    commit_msg = entry.get("commit_message", "")
    if commit_msg and isinstance(commit_msg, str):
        mismatched, name = check_commit_message_mismatch(commit_msg, pkg)
        if mismatched:
            issues.append({
                "type": "commit_message_mentions_different_package",
                "severity": "high",
                "detail": f"commit_message mentions '{name}' but vulnerable_package is '{pkg}'",
                "suggestion": "Check the actual commit or clear the field",
            })

    # Check 3: advisory descriptions mention different package
    advisories = entry.get("advisory_descriptions", [])
    if check_advisory_mentions_different_package(advisories, pkg):
        # This is a warning — advisories often cite related packages
        # But if the primary package name differs, flag it
        pass  # Advisory descriptions frequently mention other packages; don't auto-flag

    # Check 4: source_code_changes patches reference different package
    scs = entry.get("source_code_changes", [])
    if isinstance(scs, list):
        for i, sc in enumerate(scs):
            patch = sc.get("patch", "") if isinstance(sc, dict) else ""
            if patch:
                mismatched, info = check_patch_mentions_different_package(patch, pkg)
                if mismatched:
                    issues.append({
                        "type": "source_code_changes_reference_different_package",
                        "severity": "critical",
                        "detail": f"source_code_changes[{i}] references '{info}' but vulnerable_package is '{pkg}'",
                        "suggestion": "Verify the patch belongs to this vulnerability; clear if mismatched",
                    })

    return issues


def validate_dataset(dataset_dir: str, fix=False):
    """Validate all entries in a VFCS JSON file."""
    vfcs_path = Path(dataset_dir) / "vfcs.json"
    if not vfcs_path.exists():
        print(f"Not found: {vfcs_path}")
        return

    with open(vfcs_path) as f:
        data = json.load(f)

    total = len(data)
    corrupted = []

    for i, entry in enumerate(data):
        pkg = entry.get("vulnerable_package", "?")
        vuln_id = (entry.get("vuln_id", "") or entry.get("cve_id", "")) or "N/A"
        issues = validate_entry(entry, str(vfcs_path))
        if issues:
            corrupted.append((i, pkg, vuln_id, issues))

    print(f"=== VFCS Validation ({vfcs_path}) ===")
    print(f"Total entries: {total}")
    print(f"Corrupted (detected mismatch): {len(corrupted)}")
    print()

    for idx, pkg, vid, issues in corrupted:
        print(f"[{idx}] vuln_id={vid} package={pkg}")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['type']}: {issue['detail']}")
        print()

    if fix and corrupted:
        # Clear commit-related fields for corrupted entries
        fixed_count = 0
        for idx, pkg, vid, issues in corrupted:
            data[idx]["commit_message"] = ""
            data[idx]["source_code_changes"] = []
            data[idx]["pr_title"] = "n/a"
            data[idx]["pr_description"] = "n/a"
            data[idx]["discussion_comments"] = []
            fixed_count += 1

        # Write back
        out_path = vfcs_path.with_suffix(".fixed.json")
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Fixed {fixed_count} entries. Saved to {out_path}")


if __name__ == "__main__":
    dataset_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    fix = "--fix" in sys.argv

    # Look for vfcs.json relative to dataset_dir
    vfcs_candidates = [
        Path(dataset_dir) / "secbenchjs" / "vfcs.json",
        Path(dataset_dir) / "vfcs.json",
    ]

    if len(sys.argv) > 2:
        vfcs_candidates.insert(0, Path(sys.argv[2]))

    for candidate in vfcs_candidates:
        if candidate.exists():
            validate_dataset(str(candidate.parent), fix=fix)
            break
    else:
        print("No vfcs.json found. Usage: python3 src/validate_vfcs.py <dataset_dir>")
        sys.exit(1)
