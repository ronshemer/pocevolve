"""Binary protobuf parser for SCIP (``.scip``) index files.

Reads the gzip-compressed protocol-buffer output from ``scip-typescript`` and
extracts a flat list of :class:`Document` messages, each carrying its own
symbol list and occurrences.

The compiled :mod:`scip_pb2` module lives alongside this file (generated from
the upstream ``scip.proto`` schema).  If protobuf is not installed callers
should check :func:`~src.indexer.available()` before invoking this module.
"""

from __future__ import annotations

import gzip
import logging
from dataclasses import dataclass, field

from src.indexer._proto import scip_pb2 as proto

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Document:
    """A single indexed document (source file)."""

    relative_path: str
    language: str  # e.g. "JavaScript", "TypeScript"
    project_root: str = ""
    symbols: list[proto.SymbolInformation] = field(default_factory=list)
    occurrences: list[proto.Occurrence] = field(default_factory=list)


@dataclass(slots=True)
class ParseScipResult:
    """Parsed output from a SCIP ``.scip`` file."""

    documents: list[Document] = field(default_factory=list)
    language: str = ""
    project_root: str = ""
    tool_name: str = ""
    tool_version: str = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_scip_file(path: str | None = None, data: bytes | None = None) -> ParseScipResult:
    """Parse a SCIP ``.scip`` file (gzip-compressed protobuf).

    Parameters
    ----------
    path : str | None
        Filesystem path to the ``.scip`` file. Mutually exclusive with *data*.
    data : bytes | None
        Raw gzip-compressed bytes. Mutually exclusive with *path*.

    Returns
    -------
    ParseScipResult
        Flat list of :class:`Document` messages plus top-level metadata.

    Raises
    ------
    ValueError
        If neither *path* nor *data* is given, or both are given.
    """
    if path and data:
        raise ValueError("Specify exactly one of path= or data=")
    if not path and data is None:
        raise ValueError("Must provide either path= or data=")

    raw: bytes
    if path is not None:
        try:
            with open(path, "rb") as fh:
                raw = gzip.decompress(fh.read())
        except FileNotFoundError:
            return None
        except OSError:
            logger.warning("Failed to decompress %s — returning empty result", path)
            return ParseScipResult()
    else:
        try:
            raw = gzip.decompress(data)  # type: ignore[arg-type]
        except OSError:
            logger.warning("Failed to decompress provided data — returning empty result")
            return ParseScipResult()

    index = proto.Index()
    index.ParseFromString(raw)

    return _extract(index)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract(index: proto.Index) -> ParseScipResult:
    """Flatten an :class:`proto.Index` into :class:`ParseScipResult`."""
    meta = index.metadata if hasattr(index, "metadata") and index.HasField("metadata") else None

    result = ParseScipResult(
        project_root=meta.project_root if meta else "",
        tool_name=meta.tool_info.name if meta and hasattr(meta, "tool_info") and meta.HasField("tool_info") else "",
        tool_version=meta.tool_info.version if meta and hasattr(meta, "tool_info") and meta.HasField("tool_info") else "",
    )

    for doc in index.documents:
        parsed_doc = Document(
            relative_path=getattr(doc, "relative_path", ""),
            language=getattr(doc, "language", ""),
            project_root=getattr(doc, "project_root", getattr(meta, "project_root", "")),
            symbols=list(doc.symbols),
            occurrences=list(getattr(doc, "occurrences", [])),
        )
        result.documents.append(parsed_doc)

    if not getattr(index, "language", "") and meta and hasattr(meta, "text_document_encoding"):
        encoding = meta.text_document_encoding
        encoding_names: dict[int, str] = {
            1: "UTF8",
            2: "UTF16",
        }
        result.language = encoding_names.get(encoding, "unknown")

    # scip-typescript always uses UTF8; record it explicitly if not set.
    if not result.language:
        result.language = "UTF8"

    return result

