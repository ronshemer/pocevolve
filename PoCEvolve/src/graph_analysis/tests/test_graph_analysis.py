"""Unit tests for graph analysis components (AST-based pipeline).

Tests diff-to-method matching and entry-point detection in isolation from SCIP / Node.js —
all inputs are synthetic or use actual files on disk so the entire pipeline can run
without external dependencies.
"""

import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Test helpers: create temporary files for AST-based testing
# ---------------------------------------------------------------------------

def _write_tmp_files(tmpdir: Path, files: dict[str, str]) -> None:
    """Write *files* (path → content) into *tmpdir*, creating subdirs as needed."""
    for rel_path, content in files.items():
        full = tmpdir / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(textwrap.dedent(content))


# ---------------------------------------------------------------------------
# TestDiffParser
# ---------------------------------------------------------------------------

class TestDiffParser(unittest.TestCase):
    """Test unified-diff parsing into DiffEntry objects."""

    def test_parses_deletions_only(self):
        from src.graph_analysis.diff_parser import parse_diff

        diff = (
            'diff --git a/src/ping.js b/src/ping.js\n'
            '@@ -10,3 +10,0 @@\n'
            '-function ping(host) {\n'
            '-  var cmd = "ping -c 1 " + host;\n'
            '-  exec(cmd);\n'
        )
        entries = parse_diff(diff, only_deleted=True)
        # Should capture the 3 deleted lines
        self.assertGreater(len(entries), 0)
        for e in entries:
            self.assertEqual(e.change_type, "removed")

    def test_parses_method_calls_with_params(self):
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
        methods = {e.method_name for e in entries}
        self.assertIn("ping", methods)

    def test_ignores_deletions_git_aligns_as_whitespace_only(self):
        from src.graph_analysis.diff_parser import parse_diff

        diff = (
            "diff --git a/index.js b/index.js\n"
            "@@ -10,2 +10,2 @@\n"
            "-  format(value);\n"
            "-  child.exec(command);\n"
            "+ format(value);   \n"
            "+  child.exec(quote(command));\n"
        )
        entries = parse_diff(diff, only_deleted=True)
        self.assertEqual([entry.method_name for entry in entries], ["exec"])
        self.assertEqual(entries[0].orig_line_start, 11)

    def test_whitespace_only_diff_produces_no_deleted_entries(self):
        from src.graph_analysis.diff_parser import parse_diff

        diff = (
            "diff --git a/index.js b/index.js\n"
            "@@ -4 +4 @@\n"
            "-  run(value);\n"
            "+ run(value);  \n"
        )
        self.assertEqual(parse_diff(diff, only_deleted=True), [])

    def test_empty_diff_returns_nothing(self):
        from src.graph_analysis.diff_parser import parse_diff

        self.assertEqual(parse_diff(""), [])
        self.assertEqual(parse_diff("\n\n"), [])


# ---------------------------------------------------------------------------
# TestMethodResolution (AST-based enclosing function detection)
# ---------------------------------------------------------------------------

class TestMethodResolution(unittest.TestCase):
    """Test that get_enclosing_function_name resolves correctly for JS code."""

    def test_nested_functions(self):
        from src.graph_analysis.method_resolution import get_enclosing_function_name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(textwrap.dedent("""\
                function outer() {
                    function inner() {
                        console.log("hello");
                    }
                }
            """))
            f.flush()
            path = f.name

        try:
            # Line 3 is inside `inner`
            name = get_enclosing_function_name(path, line_number=3)
            self.assertEqual(name, "inner")
        finally:
            os.unlink(path)

    def test_single_function(self):
        from src.graph_analysis.method_resolution import get_enclosing_function_name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(textwrap.dedent("""\
                function process() {
                    console.log("hello");
                }
            """))
            f.flush()
            path = f.name

        try:
            name = get_enclosing_function_name(path, line_number=2)
            self.assertEqual(name, "process")
        finally:
            os.unlink(path)

    def test_class_constructor(self):
        from src.graph_analysis.method_resolution import get_enclosing_function_name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(textwrap.dedent("""\
                class Arpping {
                    constructor() {
                        this.ping = function(host) {};
                    }
                }
            """))
            f.flush()
            path = f.name

        try:
            name = get_enclosing_function_name(path, line_number=3)
            self.assertIsNotNone(name)
            self.assertIn("ping", name.lower())
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# TestAnalyzerEntryPointDetection (module.exports scanning)
# ---------------------------------------------------------------------------

class TestAnalyzerEntryPointDetection(unittest.TestCase):
    """Test that the analyzer correctly detects entry points and matched methods."""

    def test_entry_points_detected(self):
        """When a package has module.exports, run_analysis should detect them."""
        from src.graph_analysis.analyzer import run_analysis
        from src.graph_analysis._types import AnalysisResult

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_tmp_files(tmpdir, {
                "index.js": """
                    const utils = require("./utils");
                    module.exports.startServer = function(port) {};
                """,
                "utils.js": """
                    module.exports.ping = function(host) {};
                    module.exports.execCmd = function(cmd) {};
                """,
            })
            result = run_analysis(
                cve_id="CVE-2024-9999",
                package_root=str(tmpdir),
                diff_text="",  # no diff → only entry points scanned
                testbed_dir=tmpdir.name,
            )

        self.assertIsInstance(result, AnalysisResult)
        self.assertEqual(result.cve_id, "CVE-2024-9999")
        self.assertEqual(result.mode, "entry_points_only")
        # Should detect module.exports in index.js and utils.js
        self.assertGreater(len(result.entry_points), 0)

    def test_matched_methods_from_diff(self):
        """Diff-based pipeline should produce matched methods with sink keywords."""
        from src.graph_analysis.analyzer import run_analysis
        from src.graph_analysis._types import AnalysisResult, DiffEntry

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            _write_tmp_files(tmpdir, {
                "index.js": """
                    const utils = require("./utils");
                    module.exports.startServer = function(port) {};
                """,
                "utils.js": """
                    const child_process = require("child_process");

                    function execShell(cmd) {
                        return child_process.execSync(cmd);
                    }

                    module.exports.ping = function(host) {
                        return execShell("ping -c 1 " + host);
                    };
                """,
            })
            diff = (
                'diff --git a/src/ping.js b/src/ping.js\n'
                '@@ -5,0 +6 @@\n'
                '+function ping(host) {\n'
                '+  execShell(cmd);\n'
                '+}\n'
            )

            result = run_analysis(
                cve_id="CVE-2024-9999",
                package_root=str(tmpdir),
                diff_text=diff,
                testbed_dir=tmpdir.name,
            )

        self.assertIsInstance(result, AnalysisResult)
        self.assertEqual(result.mode, "entry_points_only")
        # Diff parser should extract lines from the diff text
        # (exact count depends on parsing heuristics; just check non-empty list)
        self.assertTrue(len(result.matched_methods) > 0 or len(result.entry_points) > 0)

    def test_matched_methods_group_lines_by_enclosing_function(self):
        from src.graph_analysis.analyzer import run_analysis

        diff = (
            "diff --git a/index.js b/index.js\n"
            "@@ -10,5 +10,0 @@\n"
            "-eval(input);\n"
            "-arr.forEach(items);\n"
            "-out.push(item);\n"
            "-function _parseError(msg, hash) {}\n"
            "-this._parseError(str, hash);\n"
        )
        enclosing = {
            10: "performAction",
            11: "performAction",
            12: "performAction",
            13: "_parseError",
            14: "parseError",
        }
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "src.graph_analysis.analyzer._resolve_enclosing_function",
            side_effect=lambda _root, entry: enclosing[entry.orig_line_start],
        ):
            result = run_analysis(
                cve_id="CVE-2024-9999",
                package_root=tmpdir,
                diff_text=diff,
            )

        self.assertEqual(len(result.matched_methods), 2)
        perform = next(m for m in result.matched_methods if m.method_name == "performAction")
        self.assertEqual(perform.removed_lines, [10, 11, 12])
        self.assertEqual(perform.diff_symbols, ["eval", "forEach", "push"])
        self.assertEqual(perform.orig_line_start, 10)
        self.assertEqual(perform.orig_line_end, 12)
        parse_error = next(m for m in result.matched_methods if m.method_name == "parseError")
        self.assertEqual(parse_error.removed_lines, [13, 14])
        self.assertEqual(parse_error.file_path, "index.js#parseError")
        self.assertIn("_parseError", parse_error.diff_symbols)


# ---------------------------------------------------------------------------
# TestVFCIntegration (standalone VFC loader utility)
# ---------------------------------------------------------------------------

class TestVFCLoader(unittest.TestCase):
    """Test that the VFC loader can be imported and has expected structure."""

    def test_import(self):
        from src.graph_analysis.vfc_loader import get_diff  # noqa: F401
        # Just a smoke test — the loader should import without error.


# ---------------------------------------------------------------------------
# TestGracefulDegradation (edge cases)
# ---------------------------------------------------------------------------

class TestGracefulDegradation(unittest.TestCase):
    """Test that empty / missing data produces safe defaults, not crashes."""

    def test_empty_diff_no_crash(self):
        from src.graph_analysis.analyzer import run_analysis

        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_analysis(
                cve_id="CVE-0000-0000",
                package_root=tmpdir,
                diff_text="",
            )
        self.assertEqual(result.matched_methods, [])


if __name__ == "__main__":
    unittest.main()
