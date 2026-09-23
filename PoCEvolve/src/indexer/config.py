"""Configuration for SCIP indexer invocation.

Controls temp directory, timeout, environment overrides, and whether to fall
back to text protocol-buffer output when binary parsing is unavailable.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field


@dataclass(slots=True)
class IndexerConfig:
    """Parameters that govern how *scip-typescript* is invoked and what to do
    with its output.

    Parameters
    ----------
    temp_dir : str
        Directory where the intermediate ``index.scip`` (or ``index.text``)
        file will be written. Defaults to ``tempfile.mkdtemp()``.
    timeout : int
        Maximum seconds to wait for scip-typescript to finish (default 300).
    env : dict[str, str] | None
        Extra environment variables merged into the running process env.
    prefer_text_fallback : bool
        When ``True``, ask scip-typescript to emit text proto (``index.text``)
        instead of binary protobuf and parse that.  Text output is easier to
        inspect but slower; binary is preferred for production use.
    """

    temp_dir: str = field(default_factory=lambda: tempfile.mkdtemp(prefix="scip-"))
    timeout: int = 300
    env: dict[str, str] | None = None
    prefer_text_fallback: bool = False


def default_config() -> IndexerConfig:
    """Return a production-ready :class:`IndexerConfig` with sensible defaults."""
    return IndexerConfig(
        timeout=300,
        env=None,
        prefer_text_fallback=False,
    )
