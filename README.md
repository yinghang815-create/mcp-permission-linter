# MCP Permission Linter

[![CI](https://github.com/yinghang815-create/mcp-permission-linter/actions/workflows/ci.yml/badge.svg)](https://github.com/yinghang815-create/mcp-permission-linter/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/yinghang815-create/mcp-permission-linter)](https://github.com/yinghang815-create/mcp-permission-linter/releases)
[![GitHub release downloads](https://img.shields.io/github/downloads/yinghang815-create/mcp-permission-linter/total)](https://github.com/yinghang815-create/mcp-permission-linter/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`mcp-permission-linter` is a lightweight Python CLI for auditing Model Context Protocol (MCP) server manifests and tool schemas. It finds permissions, security, credential, destructive-action, and AI-agent side-effect risks before a configuration reaches production. Python 3.11+ uses only the standard library; Python 3.10 installs the small `tomli` compatibility package for TOML parsing.

## Why

MCP clients can give servers access to files, shells, networks, credentials, publishing systems, and payment tools. The linter converts those capabilities into deterministic findings that work locally and in GitHub Actions—without sending manifests to an external model.

## Checks

- shell execution and sandbox-bypass flags;
- unpinned packages launched through `npx`, `uvx`, or similar runners;
- filesystem-root, sensitive-directory, and cleartext remote access;
- likely hard-coded tokens, passwords, and authorization headers;
- wildcard tool access and environment forwarding;
- destructive, financial, publishing, and write tools with missing or contradictory annotations;
- policy-based command and host allowlists.

See the complete [rule catalog](docs/rules.md).

## Install

Install the versioned release artifact directly from GitHub:

```bash
python -m pip install https://github.com/yinghang815-create/mcp-permission-linter/releases/download/v0.2.0/mcp_permission_linter-0.2.0-py3-none-any.whl
```

Or install from a checkout for development:

```bash
python -m pip install .
```

## Use

```bash
mcp-permission-linter mcp.json
mcp-permission-linter ~/.codex/config.toml
mcp-permission-linter . --policy examples/policy.json
mcp-permission-linter mcp.json --format json --output report.json
mcp-permission-linter mcp.json --format sarif --output results.sarif
```

The default failure threshold is `high`. Change it with `--fail-on medium` or in the policy file.

Example finding:

```text
examples/insecure-mcp.json: critical MPL003 permission or sandbox bypass flag present: --allow-all [shell-admin]
```

## GitHub Actions

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: python -m pip install https://github.com/yinghang815-create/mcp-permission-linter/releases/download/v0.2.0/mcp_permission_linter-0.2.0-py3-none-any.whl
- run: mcp-permission-linter path/to/mcp.json --format sarif --output mcp.sarif
```

Add `continue-on-error: true` if a later step uploads SARIF and should always run. The repository's own CI tests Linux and Windows.

## Supported input

JSON and TOML are supported. The linter recognizes:

- Codex `config.toml` files with `[mcp_servers.<name>]` tables;
- Claude Desktop, Cursor, VS Code, and similar JSON files using `mcpServers`;
- generic `servers`, single-server, and MCP `tools` list shapes.

See [supported formats](docs/supported-formats.md) and the client-specific [examples](examples). The linter deliberately does not execute servers or interpolate environment variables.

Codex configuration support follows the [official OpenAI MCP configuration reference](https://learn.chatgpt.com/docs/extend/mcp?surface=cli). Security rules are informed by the [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) and current tool-annotation semantics.

## Security model

This is a static guardrail, not a sandbox or formal proof. Tool names and annotations can be inaccurate. Treat every finding as review evidence and combine the linter with runtime isolation, explicit user confirmation, and narrowly scoped credentials.

## Contributing

New manifest fixtures and low-false-positive rules are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), review the [roadmap](ROADMAP.md), and report vulnerabilities through [SECURITY.md](SECURITY.md).
