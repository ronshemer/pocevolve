"""Unit tests for graph analysis components.

Tests diff-to-graph matching and taint extraction in isolation from SCIP / Node.js —
all inputs are synthetic IndexResult objects built programmatically so the entire
pipeline can run without external dependencies.
"""

import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Synthetic helpers: build a minimal IndexResult without running SCIP
# ---------------------------------------------------------------------------

from src.indexer._types import EdgeInfo, IndexResult, NodeInfo


def _make_node(
    symbol: str = "src/foo.js/Bar",
    kind: int = 17,  # NodeKind.Function
    file_path: str = "test.js",
    line_range: tuple[int, int] | None = (1, 20),
) -> NodeInfo:
    return NodeInfo(
        symbol=symbol,
        kind=kind,
        display_name=symbol,
        file_path=file_path,
        line_range=line_range,
    )


def _make_edge(caller_symbol: str, callee_symbol: str) -> EdgeInfo:
    return EdgeInfo(
        caller_symbol=caller_symbol,
        callee_symbol=callee_symbol,
        kind="calls",
        location="test.js:0",
    )


def _make_index(
    node_defs: list[NodeInfo],
    edge_defs: list[EdgeInfo] | None = None,
) -> IndexResult:
    result = IndexResult(root_path="/fake/pkg")
    result.available = True
    result.nodes = node_defs
    result.edges = edge_defs or []
    result.symbol_map = {n.symbol: n for n in node_defs}
    return result


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class TestDiffParser(unittest.TestCase):
    """Test unified-diff parsing into DiffEntry objects."""

    def test_parses_method_calls(self):
        from src.graph_analysis.diff_parser import parse_diff

        diff = (
            'diff --git a/src/ping.js b/src/ping.js\n'
            '@@ -10,0 +11,3 @@\n'
            '+function ping(host) {\n'
            '+  var cmd = "ping -c 1 " + host;\n'
            '+  exec(cmd);\n'
        )
        entries = parse_diff(diff)
        self.assertGreater(len(entries), 0)
        # Should capture both the function definition and the exec call
        methods = {e.method_name for e in entries}
        self.assertIn("ping", methods)

    def test_empty_diff_returns_nothing(self):
        from src.graph_analysis.diff_parser import parse_diff

        self.assertEqual(parse_diff(""), [])
        self.assertEqual(parse_diff("\n\n"), [])


class TestGraphMatcher(unittest.TestCase):
    """Test DiffEntry → IndexResult node matching."""

    def test_exact_symbol_match(self):
        from src.graph_analysis.graph_matcher import match_diff_to_graph
        from src.graph_analysis._types import DiffEntry

        node = _make_node(
            symbol="src/ping.js/ping",
            file_path="src/ping.js",
            line_range=(10, 20),
        )
        index = _make_index([node])

        entry = DiffEntry(
            file_path="src/ping.js",
            method_name="ping",
            parameter_names=["host"],
            line_start=10,
            line_end=15,
        )
        matched = match_diff_to_graph([entry], index)
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].symbol, "src/ping.js/ping")

    def test_no_match_on_unknown_method(self):
        from src.graph_analysis.graph_matcher import match_diff_to_graph
        from src.graph_analysis._types import DiffEntry

        node = _make_node(symbol="src/foo.js/other", file_path="src/foo.js")
        index = _make_index([node])

        entry = DiffEntry(
            file_path="src/bar.js",
            method_name="nonexistent",
            line_start=5,
            line_end=10,
        )
        matched = match_diff_to_graph([entry], index)
        self.assertEqual(matched, [])


class TestTaintFlow(unittest.TestCase):
    """Test taint propagation from entry points to shell sinks."""

    def test_trace_path_to_shell_exec(self):
        from src.graph_analysis.taint_flow import extract_taint_flows

        ping_node = _make_node(
            symbol="src/ping.js/ping",
            file_path="src/ping.js",
            line_range=(10, 20),
        )
        exec_node = _make_node(
            symbol="src/utils.js/exec",
            file_path="src/utils.js",
            line_range=(5, 15),
        )
        edges = [
            _make_edge(caller_symbol="src/ping.js/ping", callee_symbol="src/utils.js/exec"),
        ]
        index = _make_index([ping_node, exec_node], edges)

        from src.graph_analysis._types import MatchedMethod
        matched = [MatchedMethod(
            symbol="src/ping.js/ping",
            file_path="src/ping.js",
            line_range=(10, 15),
        )]

        flows = extract_taint_flows(matched, index)
        # ping contains a known taint indicator, should produce at least one flow
        self.assertGreater(len(flows), 0)
        # The flow should have exec in its sinks
        all_sink_symbols = [s.symbol for f in flows for s in f.sinks]
        self.assertTrue(any("exec" in s.lower() for s in all_sink_symbols))

    def test_no_flow_when_no_edges(self):
        from src.graph_analysis.taint_flow import extract_taint_flows

        node = _make_node(symbol="src/ping.js/ping", file_path="src/ping.js")
        index = _make_index([node], [])

        from src.graph_analysis._types import MatchedMethod
        matched = [MatchedMethod(
            symbol="src/ping.js/ping",
            file_path="src/ping.js",
            line_range=(10, 15),
        )]

        flows = extract_taint_flows(matched, index)
        self.assertEqual(flows, [])


class TestAnalyzerIntegration(unittest.TestCase):
    """End-to-end test: diff → analysis result."""

    def test_full_pipeline(self):
        from src.graph_analysis.analyzer import run_analysis
        from src.graph_analysis._types import AnalysisResult

        ping_node = _make_node(
            symbol="src/ping.js/ping",
            file_path="src/ping.js",
            line_range=(10, 20),
        )
        exec_node = _make_node(
            symbol="src/utils.js/exec",
            file_path="src/utils.js",
            line_range=(5, 15),
        )
        edges = [
            _make_edge(caller_symbol="src/ping.js/ping", callee_symbol="src/utils.js/exec"),
        ]
        index = _make_index([ping_node, exec_node], edges)

        diff = (
            'diff --git a/src/ping.js b/src/ping.js\n'
            '@@ -10,0 +11,3 @@\n'
            '+function ping(host) {\n'
            '+  var cmd = "ping -c 1 " + host;\n'
            '+  exec(cmd);\n'
        )

        result = run_analysis(
            cve_id="CVE-2024-9999",
            package_root="/fake/pkg",
            index_result=index,
            diff_text=diff,
        )
        self.assertIsInstance(result, AnalysisResult)
        self.assertEqual(result.cve_id, "CVE-2024-9999")
        # Should have at least one matched method and possibly a taint flow
        self.assertGreater(len(result.matched_methods), 0)


class TestGracefulDegradation(unittest.TestCase):
    """Test that empty / missing data produces safe defaults, not crashes."""

    def test_empty_diff_no_crash(self):
        from src.graph_analysis.analyzer import run_analysis

        index = _make_index([_make_node(symbol="src/foo.js/other")])
        result = run_analysis(
            cve_id="CVE-0000-0000",
            package_root="/fake/pkg",
            index_result=index,
            diff_text="",
        )
        self.assertEqual(result.matched_methods, [])

    def test_unavailable_index_raises(self):
        from src.graph_analysis.analyzer import run_analysis

        unavailable = IndexResult(root_path="/fake")
        # available defaults to False → should raise
        with self.assertRaises(ValueError):
            run_analysis(
                cve_id="CVE-0000-0001",
                package_root="/fake/pkg",
                index_result=unavailable,
                diff_text="some diff",
            )


if __name__ == "__main__":
    unittest.main()
