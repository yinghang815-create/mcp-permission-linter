from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import Finding


def to_sarif(findings: Iterable[Finding], version: str) -> dict[str, Any]:
    items = list(findings)
    rules: dict[str, dict[str, Any]] = {}
    for finding in items:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.message},
                "help": {"text": finding.remediation or finding.message},
                "properties": {"security-severity": str(int(finding.severity) / 10)},
            },
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "mcp-permission-linter", "version": version, "rules": list(rules.values())}
                },
                "results": [
                    {
                        "ruleId": finding.rule_id,
                        "level": "error" if finding.severity.name in {"HIGH", "CRITICAL"} else "warning",
                        "message": {"text": finding.message},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.path}}}],
                        "properties": {
                            "severity": finding.severity.name.lower(),
                            "server": finding.server,
                            "tool": finding.tool,
                        },
                    }
                    for finding in items
                ],
            }
        ],
    }
