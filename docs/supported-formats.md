# Supported formats

The linter reads JSON and TOML without executing a server or expanding environment variables.

## Codex

Codex stores MCP servers in `[mcp_servers.<name>]` TOML tables. Version 0.2.0 audits STDIO and remote-server settings including `command`, `args`, `env`, `env_vars`, `url`, `http_headers`, `enabled_tools`, and per-tool policy tables.

```toml
[mcp_servers.docs]
command = "uvx"
args = ["example-mcp==1.2.3"]
env_vars = ["DOCS_TOKEN"]
enabled_tools = ["search", "read"]
```

Audit the user-level configuration:

```text
mcp-permission-linter ~/.codex/config.toml
```

On Windows PowerShell, use `$env:USERPROFILE\.codex\config.toml`.

## JSON clients

Claude Desktop, Cursor, VS Code, and other clients commonly use an `mcpServers` object. Each value is analyzed as an independent server.

```json
{
  "mcpServers": {
    "project-files": {
      "command": "node",
      "args": ["server.js", "C:/workspace/project"]
    }
  }
}
```

The generic `servers` object or array and single-server documents with `command` or `url` are also accepted.

When a directory is scanned, unrelated JSON and TOML files are skipped after a lightweight structure check. Explicitly named files are always analyzed, so malformed manifests still produce a finding.

## Tool-list documents

MCP tool-list fixtures can be audited for contradictions between tool names and the standard `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` annotations.

## Current limits

- The linter performs static analysis and does not connect to a server.
- Client-specific settings outside the documented keys are preserved but not interpreted.
- Tool names are heuristics; annotations supplied by an untrusted server remain untrusted.
- OAuth discovery documents and dynamic runtime scopes are not yet analyzed.
