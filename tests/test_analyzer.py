import json
import tempfile
import unittest
from pathlib import Path

from mcp_permission_linter.analyzer import analyze_document, analyze_path, candidate_paths
from mcp_permission_linter.models import Severity
from mcp_permission_linter.policy import Policy


class AnalyzerTests(unittest.TestCase):
    def test_secure_server_has_no_findings(self):
        document = {
            "mcpServers": {
                "local": {
                    "command": "node",
                    "args": ["server.js", "C:/workspace"],
                    "env": {"API_TOKEN": "${MCP_API_TOKEN}"},
                }
            }
        }
        self.assertEqual(analyze_document(document), [])

    def test_shell_is_critical(self):
        findings = analyze_document({"command": "powershell", "args": ["-File", "server.ps1"]})
        self.assertEqual(findings[0].rule_id, "MPL001")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_unpinned_npx_package_is_high(self):
        findings = analyze_document({"command": "npx", "args": ["some-mcp-server"]})
        self.assertEqual([item.rule_id for item in findings], ["MPL002"])

    def test_pinned_scoped_package_is_accepted(self):
        findings = analyze_document({"command": "npx", "args": ["@vendor/mcp@1.2.3"]})
        self.assertEqual(findings, [])

    def test_package_tag_is_not_an_exact_pin(self):
        findings = analyze_document({"command": "npx", "args": ["@vendor/mcp@latest"]})
        self.assertEqual([item.rule_id for item in findings], ["MPL002"])

    def test_dangerous_flag_and_root_access(self):
        findings = analyze_document({"command": "node", "args": ["server.js", "/", "--allow-all"]})
        self.assertEqual({item.rule_id for item in findings}, {"MPL003", "MPL004"})

    def test_any_windows_drive_root_is_high(self):
        findings = analyze_document({"command": "node", "args": ["server.js", "D:\\"]})
        self.assertEqual([item.rule_id for item in findings], ["MPL004"])

    def test_cleartext_remote_endpoint_is_high(self):
        findings = analyze_document({"url": "http://example.com/mcp"})
        self.assertEqual(findings[0].rule_id, "MPL005")

    def test_localhost_http_is_accepted(self):
        self.assertEqual(analyze_document({"url": "http://localhost:3000/mcp"}), [])

    def test_host_allowlist(self):
        policy = Policy(allowed_hosts={"trusted.example"})
        findings = analyze_document({"url": "https://other.example/mcp"}, policy=policy)
        self.assertEqual(findings[0].rule_id, "MPL006")

    def test_literal_secret_is_critical(self):
        findings = analyze_document({"command": "node", "env": {"API_KEY": "live-secret-value"}})
        self.assertEqual(findings[0].rule_id, "MPL007")

    def test_environment_secret_reference_is_accepted(self):
        self.assertEqual(analyze_document({"command": "node", "env": {"API_KEY": "${API_KEY}"}}), [])

    def test_codex_input_secret_reference_is_accepted(self):
        document = {"command": "node", "http_headers": {"Authorization": "${env:MCP_AUTH_TOKEN}"}}
        self.assertEqual(analyze_document(document), [])

    def test_bearer_environment_reference_is_accepted(self):
        document = {"url": "https://mcp.example", "http_headers": {"Authorization": "Bearer ${MCP_TOKEN}"}}
        self.assertEqual(analyze_document(document), [])

    def test_literal_secret_in_codex_http_headers_is_critical(self):
        document = {"url": "https://mcp.example", "http_headers": {"Authorization": "Bearer secret-value"}}
        findings = analyze_document(document)
        self.assertEqual(findings[0].rule_id, "MPL007")

    def test_wildcard_tools_are_high(self):
        findings = analyze_document({"tools": ["*"]})
        self.assertEqual(findings[0].rule_id, "MPL008")

    def test_contradictory_read_only_hint(self):
        findings = analyze_document({"tools": [{"name": "delete_file", "annotations": {"readOnlyHint": True}}]})
        self.assertEqual(findings[0].rule_id, "MPL009")

    def test_destructive_tool_requires_annotation(self):
        findings = analyze_document({"tools": [{"name": "delete_account"}]})
        self.assertEqual(findings[0].rule_id, "MPL010")

    def test_external_tool_requires_idempotency(self):
        findings = analyze_document({"tools": [{"name": "send_email"}]})
        self.assertEqual(findings[0].rule_id, "MPL011")

    def test_external_tool_cannot_claim_closed_world(self):
        document = {
            "tools": [
                {
                    "name": "send_email",
                    "annotations": {"idempotentHint": True, "openWorldHint": False},
                }
            ]
        }
        findings = analyze_document(document)
        self.assertEqual([item.rule_id for item in findings], ["MPL012"])

    def test_sensitive_path_is_high(self):
        findings = analyze_document({"command": "node", "args": ["server.js", "~/.ssh"]})
        self.assertEqual([item.rule_id for item in findings], ["MPL013"])

    def test_wildcard_environment_forwarding_is_high(self):
        findings = analyze_document({"command": "node", "env_vars": ["*"]})
        self.assertEqual([item.rule_id for item in findings], ["MPL014"])

    def test_codex_mcp_servers_table_is_supported(self):
        document = {
            "mcp_servers": {
                "context7": {
                    "command": "npx",
                    "args": ["-y", "@upstash/context7-mcp"],
                }
            }
        }
        findings = analyze_document(document)
        self.assertEqual([item.rule_id for item in findings], ["MPL002"])

    def test_codex_enabled_tools_wildcard_is_high(self):
        document = {"mcp_servers": {"remote": {"url": "https://mcp.example", "enabled_tools": ["*"]}}}
        findings = analyze_document(document)
        self.assertEqual([item.rule_id for item in findings], ["MPL008"])

    def test_codex_toml_file_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                '[mcp_servers.docs]\ncommand = "uvx"\nargs = ["example-mcp==1.2.3"]\nenv_vars = ["DOCS_TOKEN"]\n',
                encoding="utf-8",
            )
            findings = analyze_path(path)
        self.assertEqual(findings, [])

    def test_policy_can_ignore_rule(self):
        policy = Policy(ignore_rules={"MPL002"})
        self.assertEqual(analyze_document({"command": "npx", "args": ["package"]}, policy=policy), [])

    def test_invalid_document_root(self):
        findings = analyze_document([])
        self.assertEqual(findings[0].rule_id, "MPL000")

    def test_invalid_json_becomes_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.json"
            path.write_text("{", encoding="utf-8")
            findings = analyze_path(path)
        self.assertEqual(findings[0].rule_id, "MPL000")

    def test_directory_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.json").write_text(json.dumps({"command": "node"}), encoding="utf-8")
            (root / "two.toml").write_text('[mcp_servers.docs]\nurl="https://example.com/mcp"', encoding="utf-8")
            (root / "skip.txt").write_text("x", encoding="utf-8")
            self.assertEqual(len(candidate_paths([directory])), 2)

    def test_directory_discovery_skips_unrelated_json_and_toml(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(json.dumps({"name": "example"}), encoding="utf-8")
            (root / "pyproject.toml").write_text('[project]\nname="example"', encoding="utf-8")
            self.assertEqual(candidate_paths([directory]), [])


if __name__ == "__main__":
    unittest.main()
