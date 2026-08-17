# Changelog

## 0.2.0 - 2026-08-17

- Audit Codex `config.toml` files using the official `mcp_servers` table shape.
- Recognize Codex `http_headers`, `env_vars`, and `enabled_tools` settings.
- Flag sensitive filesystem grants, wildcard environment forwarding, and contradictory open-world annotations.
- Accept common Codex, VS Code, Windows, and shell environment-variable references without false secret findings.
- Add client-specific fixtures, supported-format documentation, and issue/PR contribution templates.

## 0.1.1 - 2026-08-16

- Add the conditional `tomli` compatibility dependency for Python 3.10.
- Keep Python 3.11+ on the standard-library `tomllib` implementation.

## 0.1.0 - 2026-08-16

- Add deterministic checks for commands, transports, credentials, filesystem scope, and MCP tool annotations.
- Add text, JSON, and SARIF reports with configurable failure thresholds.
- Add policy allowlists, examples, cross-platform CI, and 23 unit tests.
