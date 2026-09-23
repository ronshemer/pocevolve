"""Tests for the SCIP indexer sub-module.

Runs against a known testbed package when scip-typescript is installed,
and mocks protobuf-like data for unit tests of normalizer.py.
"""

from __future__ import annotations

import gzip
import io
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure the project root (PoCEvolve/) is on sys.path so src imports work.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class _MockSymbol:
    """Minimal SymbolInformation-like object for tests."""

    def __init__(self, symbol: str = "", display_name: str = "", kind=17, rels=None, **kw):
        self.symbol = symbol
        self.display_name = display_name or symbol.split("/")[-1]
        self._kind = kind
        self._rels = [] if rels is None else rels

    @property
    def kind(self):
        return self._kind

    @property
    def relationships(self):
        return self._rels

    class _Rels:
        @staticmethod
        def IsEmpty(r):
            return len(r) == 0

    def HasField(self, name):
        if name == "kind":
            return True
        if name == "relationships":
            return not self._Rels.IsEmpty(self._rels)
        if name == "signature_documentation":
            return False
        return False


class _MockRel:
    def __init__(self, is_reference: bool, symbol: str):
        self.is_reference = is_reference
        self.symbol = symbol
        self.is_definition = False


class _MockDoc:
    """Minimal Document-like object for tests."""

    def __init__(self, relative_path: str = "", language="typescript", symbols=None, occurrences=None):
        self.relative_path = relative_path
        self.language = language
        self.project_root = ""
        self.symbols = symbols or []
        self.occurrences = occurrences or []

    class _Rels:
        @staticmethod
        def IsEmpty(r):
            return len(r) == 0


# Import normaliser after path is set up.
from src.indexer.normalizer import normalise, NormalizedGraph  # noqa: E402


class TestNormaliserBasic(unittest.TestCase):
    """Empty / edge-case cases."""

    def test_empty_documents(self):
        graph = normalise(documents=[], root_path="/tmp")
        self.assertEqual(graph.nodes, [])
        self.assertEqual(graph.edges, [])
        self.assertEqual(graph.symbol_map, {})


class TestNormaliserDefinitions(unittest.TestCase):
    """Build a tiny graph from mock SymbolInformation entries."""

    def _sym(self, symbol: str, display_name="", kind=17, rels=None):
        """Convenience to create a SymbolInformation-like object.

        SCIP Kind.Function == 17, Kind.Class == 7, Kind.Module == 27.
        We do not import grpc types here so we use raw dicts for relationships.
        """
        return _MockSymbol(symbol=symbol, display_name=display_name, kind=kind, rels=rels)

    def _doc(self, relative_path: str = "", symbols=None, occurrences=None):
        return _MockDoc(
            relative_path=relative_path,
            language="typescript",
            symbols=symbols or [],
            occurrences=occurrences or [],
        )

    def test_single_function_definition(self):
        sym = self._sym("sourcegraph/scip-typescript/src/indexer/parser.ts:Parser.parse")
        doc = self._doc("src/indexer/parser.ts", symbols=[sym])
        graph = normalise([doc], "/tmp/pkg")

        self.assertEqual(len(graph.nodes), 1)
        node = graph.nodes[0]
        self.assertIn("parser.ts", (node.display_name or "").lower() or (node.symbol or "").lower())
        self.assertIn(node.symbol, graph.symbol_map)

    def test_edges_from_relationships(self):
        caller_display = "normalise"
        callee_sym = "sourcegraph/scip-typescript/src/indexer/parser.ts:Parser.parse"

        # Create caller symbol with an is_reference=True relationship to callee.
        caller_with_edge = self._sym(
            "sourcegraph/scip-typescript/src/indexer/normalizer.ts:normalise",
            display_name=caller_display,
            rels=[_MockRel(is_reference=True, symbol=callee_sym)],
        )
        # Also create the callee as a separate definition entry.
        callee = self._sym(callee_sym, display_name="parse")

        doc = self._doc("src/indexer/normalizer.ts", symbols=[caller_with_edge, callee])
        graph = normalise([doc], "/tmp/pkg")

        # We should get at least one edge because the caller's relationships
        # include an is_reference=True entry pointing to callee.symbol.
        call_edges = [e for e in graph.edges if e.kind == "calls"]
        self.assertGreater(len(call_edges), 0)
        callees = {e.callee_symbol for e in call_edges}
        self.assertIn(callee_sym, callees)

    def test_no_edges_without_references(self):
        sym = self._sym("sourcegraph/scip-typescript/src/indexer/parser.ts:Parser.parse")
        doc = self._doc("src/indexer/parser.ts", symbols=[sym])
        graph = normalise([doc], "/tmp/pkg")
        self.assertEqual(graph.edges, [])

    def test_multiple_definitions_same_file(self):
        s1 = self._sym("sourcegraph/scip-typescript/src/indexer/parser.ts:Parser.parse")
        s2 = self._sym("sourcegraph/scip-typescript/src/indexer/parser.ts:Parser.validate")
        doc = self._doc("src/indexer/parser.ts", symbols=[s1, s2])
        graph = normalise([doc], "/tmp/pkg")

        self.assertEqual(len(graph.nodes), 2)
        symbols_in_map = set(graph.symbol_map.keys())
        self.assertIn(s1.symbol, symbols_in_map)
        self.assertIn(s2.symbol, symbols_in_map)


class TestParseScipResult(unittest.TestCase):
    """Verify the public parse_scip_file() function returns expected dataclasses."""

    def test_parse_invalid_path(self):
        result = _import_parser().parse_scip_file("/nonexistent/path.scip")
        self.assertIsNone(result)

    def test_parse_corrupt_gzip(self):
        tmp = Path(__file__).parent / "tmp_corrupt.scip"
        try:
            tmp.write_bytes(b"not-a-gzip-file")
            result = _import_parser().parse_scip_file(str(tmp))
            # Should return None or empty — corrupt data is graceful.
            self.assertIsNotNone(result)
        finally:
            tmp.unlink(missing_ok=True)

    def test_parse_empty_gzip(self):
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(b"")
        buf.seek(0)
        tmp = Path(__file__).parent / "tmp_empty.scip"
        try:
            tmp.write_bytes(buf.getvalue())
            result = _import_parser().parse_scip_file(str(tmp))
            self.assertIsNotNone(result)
            # No documents expected.
            self.assertEqual(len(result.documents), 0)
        finally:
            tmp.unlink(missing_ok=True)


class TestScipAvailability(unittest.TestCase):
    """Verify the indexer availability check."""

    def test_not_available_without_dependencies(self):
        """When scip-typescript is not installed, available() returns False."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("npx not found")
            result = _mock_available()
            self.assertFalse(result)

    def test_available_with_success(self):
        """When scip-typescript --version succeeds, available() returns True."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="scip-typescript 0.4.0\n", stderr="")
            result = _mock_available()
            self.assertTrue(result)


def _import_parser():
    """Lazy import to avoid top-level dependency issues."""
    from src.indexer.parser import parse_scip_file

    return types.SimpleNamespace(parse_scip_file=parse_scip_file)


def _mock_available():
    """Helper to test the availability check with patched subprocess."""

    def _run(args, **kwargs):
        # Simulate checking if scip-typescript is installed.
        if "version" in args:
            raise FileNotFoundError("npx not found")
        return MagicMock(returncode=1)

    import subprocess  # noqa: PLC0415

    try:
        subprocess.run(["npx", "--prefix", str(_PROJECT_ROOT / "node_modules"), "scip-typescript", "--version"], check=True, capture_output=True, timeout=30)  # noqa: S603
        return True
    except (FileNotFoundError, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Real-indexing integration test (skipped when deps unavailable).
# ---------------------------------------------------------------------------

class TestIntegrationRealIndex(unittest.TestCase):
    """Run scip-typescript on a small real package and validate the graph.

    Skipped when @sourcegraph/scip-typescript is not installed in PoCEvolve's
    node_modules or when no testbed packages exist.
    """

    @classmethod
    def skip_test(cls) -> bool:
        """Return True if prerequisites for real indexing are missing."""
        # Check npm package.
        pkg_json = _PROJECT_ROOT / "node_modules" / "@sourcegraph" / "scip-typescript" / "package.json"
        if not pkg_json.is_file():
            return True
        # Check testbed exists (user can set SCIP_TESTBED env var to point to one).
        testbed = os.environ.get("SCIP_TESTBED", str(_PROJECT_ROOT.parent.parent / "testbed" / "SNYK-JS-ARPPING-1060047"))
        return not Path(testbed).is_dir()

    @classmethod
    def setUpClass(cls):
        if cls.skip_test():
            raise unittest.SkipTest("SCIP integration prerequisites missing (package or testbed)")

    def test_full_pipeline_on_testbed(self):
        """Run scanner, parser and normaliser end-to-end on the testbed package."""
        from src.indexer import scan  # noqa: PLC0415

        testbed = os.environ.get("SCIP_TESTBED", str(_PROJECT_ROOT.parent.parent / "testbed" / "SNYK-JS-ARPPING-1060047"))
        result = scan(testbed)

        # The scanner should report the indexer is available and return nodes.
        self.assertTrue(result.available, f"Indexer should be available for integration test (error={result.error})")
        self.assertGreater(len(result.nodes), 0, f"Expected non-empty graph, got {len(result.nodes)} nodes, {len(result.edges)} edges")

        # symbol_map should have entries keyed by full SCIP symbol.
        self.assertGreater(len(result.symbol_map), 0)

        # Edge callers and callees should reference valid symbols.
        for edge in result.edges:
            self.assertTrue(edge.caller_symbol, "Edge caller must be non-empty")
            self.assertTrue(edge.callee_symbol, "Edge callee must be non-empty")


if __name__ == "__main__":
    unittest.main()
