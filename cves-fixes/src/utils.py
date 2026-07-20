from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence


def _as_path(path: str | Path) -> Path:
    return path if isinstance(path, Path) else Path(path)


def _ensure_parent_dir(path: str | Path) -> Path:
    file_path = _as_path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    return file_path


def read_text_file(path: str | Path, encoding: str = "utf-8") -> str:
    return _as_path(path).read_text(encoding=encoding)


def dump_text_file(path: str | Path, content: str, encoding: str = "utf-8") -> None:
    file_path = _ensure_parent_dir(path)
    with tempfile.NamedTemporaryFile(
        "w", dir=file_path.parent, delete=False, suffix=".tmp", encoding=encoding
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    os.replace(tmp_path, file_path)


def read_json_file(path: str | Path, encoding: str = "utf-8") -> Any:
    with _as_path(path).open("r", encoding=encoding) as fh:
        return json.load(fh)


def safe_read_json_file(path: str | Path, encoding: str = "utf-8") -> Any | None:
    """Returns None instead of raising if the file is missing or malformed."""
    try:
        return read_json_file(path, encoding=encoding)
    except Exception:
        return None


def is_error_record(path: str | Path) -> bool:
    """Returns True if the file exists and was written as an error record.
    Error records have {"error": true, ...} at the top level."""
    data = safe_read_json_file(path)
    return isinstance(data, dict) and data.get("error") is True


def dump_json_file(
    path: str | Path,
    content: Any,
    encoding: str = "utf-8",
    indent: int = 2,
) -> None:
    """Atomic write: serialises to a temp file then renames, so readers never
    see a partial file even if the process is killed mid-write."""
    file_path = _ensure_parent_dir(path)
    with tempfile.NamedTemporaryFile(
        "w", dir=file_path.parent, delete=False, suffix=".tmp", encoding=encoding
    ) as tmp:
        json.dump(content, tmp, ensure_ascii=False, indent=indent)
        tmp.write("\n")
        tmp_path = tmp.name
    os.replace(tmp_path, file_path)


def read_jsonl_file(path: str | Path, encoding: str = "utf-8") -> list[Any]:
    records: list[Any] = []
    with _as_path(path).open("r", encoding=encoding) as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    return records


def dump_jsonl_file(
    path: str | Path,
    records: Iterable[Any],
    encoding: str = "utf-8",
) -> None:
    file_path = _ensure_parent_dir(path)
    with tempfile.NamedTemporaryFile(
        "w", dir=file_path.parent, delete=False, suffix=".tmp", encoding=encoding
    ) as tmp:
        for record in records:
            tmp.write(json.dumps(record, ensure_ascii=False))
            tmp.write("\n")
        tmp_path = tmp.name
    os.replace(tmp_path, file_path)


def execute_command_at_folder(
    command: str | Sequence[str],
    folder: str | Path,
    *,
    check: bool = True,
    capture_output: bool = False,
    text: bool = True,
    shell: bool | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    working_directory = _as_path(folder)
    if shell is None:
        shell = isinstance(command, str)
    return subprocess.run(  # noqa: S603
        command,
        cwd=working_directory,
        check=check,
        capture_output=capture_output,
        text=text,
        shell=shell,
        env=env,
    )
