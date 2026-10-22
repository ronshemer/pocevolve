"""Resolve and create vulnerable git checkouts from SecBench VFC metadata."""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class TestbedUnavailableError(RuntimeError):
    """Raised when the vulnerable source checkout cannot be prepared."""


def _vfc_path() -> Path:
    return Path(__file__).resolve().parents[2] / "secbenchjs" / "vfcs.filtered.json"


def find_vfc_record(cve_id: str) -> dict:
    """Find a VFC record by any ID alias or its testbed directory."""
    path = _vfc_path()
    if not path.is_file():
        raise FileNotFoundError(f"VFC metadata not found: {path}")
    records = json.loads(path.read_text(encoding="utf-8"))
    wanted = cve_id.strip().lower().replace(":", "_")
    for record in records:
        keys = [*(record.get("ids") or []), record.get("testbed_dir", "")]
        if any(str(key).strip().lower().replace(":", "_") == wanted for key in keys):
            return record
    raise LookupError(f"CVE ID not found in {path.name}: {cve_id}")


def _repo_and_fix_ref(fix_url: str) -> tuple[str, str]:
    parsed = urlparse(fix_url)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.netloc.lower() not in {"github.com", "www.github.com"} or len(parts) < 4:
        raise ValueError(f"Unsupported vulnerability_fix_commit URL: {fix_url}")
    owner, repo = parts[0], parts[1]
    if parts[2] == "commit":
        fix_ref = parts[3]
    elif len(parts) >= 6 and parts[2] == "pull" and parts[4] == "commits":
        fix_ref = parts[5]
    else:
        raise ValueError(f"Cannot extract a fix commit from: {fix_url}")
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", fix_ref):
        raise ValueError(f"Invalid GitHub fix commit in: {fix_url}")
    return f"https://github.com/{owner}/{repo}.git", fix_ref


def ensure_git_testbed(cve_id: str, destination: Path | None = None) -> Path:
    """Return a checkout at the parent of the fix commit, creating it if needed."""
    record = find_vfc_record(cve_id)
    fix_url = str(record.get("vulnerability_fix_commit", ""))
    repo_url, fix_ref = _repo_and_fix_ref(fix_url)
    root = Path(__file__).resolve().parents[1] / "git_testbeds" / "auto"
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", cve_id.strip())
    target = (destination or root / safe_id).resolve()

    if target.is_dir() and (target / ".git").exists():
        origin = subprocess.run(
            ["git", "-C", str(target), "remote", "get-url", "origin"],
            check=False, capture_output=True, text=True,
        ).stdout.strip().removesuffix(".git")
        head = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            check=False, capture_output=True, text=True,
        ).stdout.strip()
        if origin.endswith(urlparse(repo_url).path.removesuffix(".git")) and head:
            parent = subprocess.run(
                ["git", "-C", str(target), "rev-parse", f"{fix_ref}^"],
                check=False, capture_output=True, text=True,
            )
            expected = parent.stdout.strip()
            if parent.returncode == 0 and head == expected:
                return target

    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=f"{safe_id}-", dir=target.parent) as temp:
            checkout = Path(temp) / "checkout"
            subprocess.run(
                ["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(checkout)],
                check=True, capture_output=True, text=True,
            )
            subprocess.run(
                ["git", "-C", str(checkout), "fetch", "--quiet", "origin", fix_ref],
                check=True, capture_output=True, text=True,
            )
            parent = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "FETCH_HEAD^"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "-C", str(checkout), "checkout", "--quiet", "--detach", parent],
                check=True, capture_output=True, text=True,
            )
            subprocess.run(
                ["git", "-C", str(checkout), "remote", "set-url", "origin", repo_url],
                check=True, capture_output=True, text=True,
            )
            if target.exists():
                raise FileExistsError(
                    f"Testbed path already exists but is not the expected checkout: {target}. "
                    "Choose a different --testbed path or move the existing directory."
                )
            checkout.rename(target)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        logger.warning("Cannot prepare vulnerable testbed for %s from %s: %s", cve_id, repo_url, detail)
        raise TestbedUnavailableError(
            f"Cannot prepare vulnerable testbed for {cve_id} from {repo_url}: {detail}"
        ) from exc
    logger.info("Created vulnerable testbed for %s at %s (parent of fix %s)", cve_id, target, fix_ref)
    return target
