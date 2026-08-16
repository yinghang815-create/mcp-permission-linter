from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from .models import Finding, Severity
from .policy import Policy

SHELL_COMMANDS = {"bash", "cmd", "cmd.exe", "powershell", "pwsh", "sh", "zsh"}
PACKAGE_RUNNERS = {"bunx", "npx", "pipx", "pnpx", "uvx"}
SECRET_KEY = re.compile(r"(?:api[_-]?key|authorization|credential|password|private[_-]?key|secret|token)", re.I)
PLACEHOLDER = re.compile(r"^(?:\$\{?[A-Z0-9_]+\}?|<[^>]+>|changeme|redacted)$", re.I)
DANGEROUS_FLAGS = {
    "--allow-all",
    "--dangerously-skip-permissions",
    "--disable-sandbox",
    "--no-sandbox",
    "--unsafe",
}

TOOL_CATEGORIES: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("financial", re.compile(r"(?:^|[_-])(charge|pay|purchase|refund|transfer)(?:$|[_-])", re.I), Severity.CRITICAL),
    ("execute", re.compile(r"(?:^|[_-])(command|exec|execute|run_script|shell)(?:$|[_-])", re.I), Severity.CRITICAL),
    (
        "destructive",
        re.compile(r"(?:^|[_-])(delete|destroy|drop|purge|remove|terminate|wipe)(?:$|[_-])", re.I),
        Severity.HIGH,
    ),
    (
        "external",
        re.compile(r"(?:^|[_-])(deploy|email|message|post|publish|send|upload)(?:$|[_-])", re.I),
        Severity.HIGH,
    ),
    ("write", re.compile(r"(?:^|[_-])(create|edit|modify|patch|update|write)(?:$|[_-])", re.I), Severity.MEDIUM),
)


def load_document(path: str | Path) -> Any:
    manifest_path = Path(path)
    with manifest_path.open("rb") as handle:
        if manifest_path.suffix.lower() == ".toml":
            return tomllib.load(handle)
        return json.loads(handle.read().decode("utf-8-sig"))


def _finding(
    rule_id: str,
    severity: Severity,
    message: str,
    path: str,
    *,
    server: str | None = None,
    tool: str | None = None,
    remediation: str | None = None,
) -> Finding:
    return Finding(rule_id, severity, message, path, server, tool, remediation)


def _server_entries(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    for key in ("mcpServers", "servers"):
        value = document.get(key)
        if isinstance(value, dict):
            return [(str(name), config) for name, config in value.items() if isinstance(config, dict)]
        if isinstance(value, list):
            return [
                (str(item.get("name", f"server-{index}")), item)
                for index, item in enumerate(value)
                if isinstance(item, dict)
            ]
    if any(key in document for key in ("command", "url", "tools")):
        return [(str(document.get("name", "manifest")), document)]
    return []


def _package_is_pinned(package: str) -> bool:
    if "==" in package:
        return True
    if package.startswith("@"):
        return package.count("@") >= 2
    return "@" in package


def _analyze_command(config: dict[str, Any], path: str, server: str, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    command = str(config.get("command", "")).strip()
    command_name = Path(command).name.lower()
    args = [str(item) for item in config.get("args", [])] if isinstance(config.get("args", []), list) else []

    if command_name in SHELL_COMMANDS and command_name not in policy.allowed_commands:
        findings.append(
            _finding(
                "MPL001",
                Severity.CRITICAL,
                f"server launches a general-purpose shell: {command_name}",
                path,
                server=server,
                remediation="Use a dedicated executable or explicitly allow the command in policy.",
            )
        )

    if command_name in PACKAGE_RUNNERS and command_name not in policy.allowed_commands:
        package = next((arg for arg in args if arg and not arg.startswith("-")), "")
        if package and not _package_is_pinned(package):
            findings.append(
                _finding(
                    "MPL002",
                    Severity.HIGH,
                    f"package runner executes an unpinned package: {package}",
                    path,
                    server=server,
                    remediation="Pin an exact package version, for example package@1.2.3 or package==1.2.3.",
                )
            )

    flagged = sorted({arg for arg in args if arg.lower() in DANGEROUS_FLAGS})
    if flagged:
        findings.append(
            _finding(
                "MPL003",
                Severity.CRITICAL,
                f"permission or sandbox bypass flag present: {', '.join(flagged)}",
                path,
                server=server,
                remediation="Remove the bypass and grant only the paths and capabilities the server needs.",
            )
        )

    broad_paths = [arg for arg in args if arg in {"/", "C:\\", "C:/"}]
    if broad_paths:
        findings.append(
            _finding(
                "MPL004",
                Severity.HIGH,
                "server is granted a filesystem root",
                path,
                server=server,
                remediation="Grant a project or data subdirectory instead of a filesystem root.",
            )
        )
    return findings


def _analyze_transport(config: dict[str, Any], path: str, server: str, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    url = str(config.get("url") or config.get("endpoint") or "").strip()
    if url:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "http" and host not in {"127.0.0.1", "localhost", "::1"}:
            findings.append(
                _finding(
                    "MPL005",
                    Severity.HIGH,
                    f"remote MCP endpoint uses cleartext HTTP: {url}",
                    path,
                    server=server,
                    remediation="Use HTTPS for non-local MCP endpoints.",
                )
            )
        if policy.allowed_hosts and host and host not in policy.allowed_hosts:
            findings.append(
                _finding(
                    "MPL006",
                    Severity.HIGH,
                    f"remote host is not in policy allowlist: {host}",
                    path,
                    server=server,
                    remediation="Review the endpoint and add the exact host to allowed_hosts if trusted.",
                )
            )
    return findings


def _analyze_secrets(config: dict[str, Any], path: str, server: str) -> list[Finding]:
    findings: list[Finding] = []
    for section_name in ("env", "headers"):
        section = config.get(section_name, {})
        if not isinstance(section, dict):
            continue
        for key, value in section.items():
            text = str(value).strip()
            if SECRET_KEY.search(str(key)) and text and not PLACEHOLDER.match(text):
                findings.append(
                    _finding(
                        "MPL007",
                        Severity.CRITICAL,
                        f"possible literal secret in {section_name}.{key}",
                        path,
                        server=server,
                        remediation="Reference an environment variable or secret store; never commit the credential.",
                    )
                )
    return findings


def _tool_category(name: str) -> tuple[str, Severity] | None:
    normalized = name.replace(" ", "_")
    for category, pattern, severity in TOOL_CATEGORIES:
        if pattern.search(normalized):
            return category, severity
    return None


def _analyze_tools(config: dict[str, Any], path: str, server: str) -> list[Finding]:
    findings: list[Finding] = []
    tools = config.get("tools", [])
    if tools == "*" or (isinstance(tools, list) and "*" in tools):
        findings.append(
            _finding(
                "MPL008",
                Severity.HIGH,
                "wildcard tool access grants every tool exposed by the server",
                path,
                server=server,
                remediation="Use an explicit allowlist of tool names.",
            )
        )
        return findings
    if not isinstance(tools, list):
        return findings

    for tool in tools:
        if isinstance(tool, str):
            tool = {"name": tool}
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name", "unnamed-tool"))
        category = _tool_category(name)
        if category is None:
            continue
        category_name, severity = category
        annotations = tool.get("annotations", {}) if isinstance(tool.get("annotations", {}), dict) else {}
        read_only = annotations.get("readOnlyHint") is True
        destructive = annotations.get("destructiveHint") is True
        idempotent = annotations.get("idempotentHint") is True

        if read_only:
            findings.append(
                _finding(
                    "MPL009",
                    Severity.HIGH,
                    f"mutating-looking tool is marked read-only ({category_name})",
                    path,
                    server=server,
                    tool=name,
                    remediation="Correct the tool name or remove the contradictory readOnlyHint.",
                )
            )
            continue
        if category_name in {"destructive", "execute", "financial"} and not destructive:
            findings.append(
                _finding(
                    "MPL010",
                    severity,
                    f"{category_name} tool is missing destructiveHint=true",
                    path,
                    server=server,
                    tool=name,
                    remediation="Mark destructive behavior explicitly and require confirmation in the client.",
                )
            )
        if category_name in {"external", "financial", "write"} and not idempotent:
            findings.append(
                _finding(
                    "MPL011",
                    Severity.MEDIUM,
                    "side-effecting tool is not marked idempotent",
                    path,
                    server=server,
                    tool=name,
                    remediation=(
                        "Add idempotentHint=true only when retries are safe; "
                        "otherwise enforce an idempotency key."
                    ),
                )
            )
    return findings


def analyze_document(document: Any, *, path: str = "<memory>", policy: Policy | None = None) -> list[Finding]:
    active_policy = policy or Policy()
    if not isinstance(document, dict):
        return [_finding("MPL000", Severity.HIGH, "manifest root must be an object", path)]
    servers = _server_entries(document)
    if not servers:
        return [
            _finding(
                "MPL000",
                Severity.MEDIUM,
                "no MCP servers or tool manifest found",
                path,
                remediation="Provide mcpServers, servers, command/url, or tools.",
            )
        ]

    findings: list[Finding] = []
    for server, config in servers:
        findings.extend(_analyze_command(config, path, server, active_policy))
        findings.extend(_analyze_transport(config, path, server, active_policy))
        findings.extend(_analyze_secrets(config, path, server))
        findings.extend(_analyze_tools(config, path, server))
    return sorted(
        (finding for finding in findings if finding.rule_id not in active_policy.ignore_rules),
        key=lambda item: (-int(item.severity), item.rule_id, item.server or "", item.tool or ""),
    )


def analyze_path(path: str | Path, *, policy: Policy | None = None) -> list[Finding]:
    manifest_path = Path(path)
    try:
        document = load_document(manifest_path)
    except (OSError, UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        return [_finding("MPL000", Severity.HIGH, f"cannot parse manifest: {exc}", str(manifest_path))]
    return analyze_document(document, path=str(manifest_path), policy=policy)


def candidate_paths(paths: Iterable[str]) -> list[Path]:
    candidates: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            candidates.extend(sorted(item for item in path.rglob("*") if item.suffix.lower() in {".json", ".toml"}))
        else:
            candidates.append(path)
    return candidates
