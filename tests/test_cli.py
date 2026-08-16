import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from mcp_permission_linter.cli import main


class CliTests(unittest.TestCase):
    def _manifest(self, directory: str, data: dict) -> Path:
        path = Path(directory) / "mcp.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_clean_manifest_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._manifest(directory, {"command": "node", "args": ["server.js"]})
            stream = StringIO()
            with redirect_stdout(stream):
                code = main([str(path)])
        self.assertEqual(code, 0)
        self.assertIn("OK", stream.getvalue())

    def test_high_finding_exits_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._manifest(directory, {"command": "npx", "args": ["unversioned"]})
            with redirect_stdout(StringIO()):
                code = main([str(path)])
        self.assertEqual(code, 1)

    def test_json_output_is_machine_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._manifest(directory, {"tools": ["*"]})
            stream = StringIO()
            with redirect_stdout(stream):
                main([str(path), "--format", "json"])
            report = json.loads(stream.getvalue())
        self.assertEqual(report["findings"][0]["rule_id"], "MPL008")

    def test_sarif_output_has_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._manifest(directory, {"tools": ["*"]})
            stream = StringIO()
            with redirect_stdout(stream):
                main([str(path), "--format", "sarif"])
            report = json.loads(stream.getvalue())
        self.assertEqual(report["version"], "2.1.0")

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._manifest(directory, {"command": "node"})
            output = Path(directory) / "reports" / "report.json"
            code = main([str(path), "--format", "json", "--output", str(output)])
            self.assertTrue(output.exists())
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
