from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .analyzer import analyze_path, candidate_paths
from .models import Finding, Severity
from .policy import load_policy
from .sarif import to_sarif


def _text(findings: list[Finding]) -> str:
    if not findings:
        return "OK: no permission risks found"
    lines = []
    for item in findings:
        target = "/".join(part for part in (item.server, item.tool) if part)
        suffix = f" [{target}]" if target else ""
        lines.append(f"{item.path}: {item.severity.name.lower():8} {item.rule_id} {item.message}{suffix}")
    counts = {severity: sum(item.severity == severity for item in findings) for severity in Severity}
    summary = ", ".join(f"{count} {severity.name.lower()}" for severity, count in counts.items() if count)
    lines.append(f"\nFound {len(findings)} issue(s): {summary}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-permission-linter",
        description="Audit MCP manifests for least-privilege and side-effect risks.",
    )
    parser.add_argument("paths", nargs="+", help="JSON/TOML manifest files or directories")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--output", help="write the report to a file instead of stdout")
    parser.add_argument("--policy", help="JSON policy with allowlists and ignored rule IDs")
    parser.add_argument("--fail-on", choices=tuple(item.name.lower() for item in Severity))
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
        fail_on = Severity.parse(args.fail_on) if args.fail_on else policy.fail_on
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    findings = [finding for path in candidate_paths(args.paths) for finding in analyze_path(path, policy=policy)]
    if args.format == "json":
        report = json.dumps({"version": __version__, "findings": [item.to_dict() for item in findings]}, indent=2)
    elif args.format == "sarif":
        report = json.dumps(to_sarif(findings, __version__), indent=2)
    else:
        report = _text(findings)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(report + "\n")
    else:
        print(report)
    return 1 if any(item.severity >= fail_on for item in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
