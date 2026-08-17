# Rules

| Rule | Default severity | Detects |
|---|---|---|
| MPL000 | Medium/High | Invalid or unsupported manifest structure |
| MPL001 | Critical | General-purpose shell launch |
| MPL002 | High | Unpinned package executed through a package runner |
| MPL003 | Critical | Permission or sandbox bypass flags |
| MPL004 | High | Filesystem-root access |
| MPL005 | High | Cleartext remote HTTP transport |
| MPL006 | High | Remote host outside the policy allowlist |
| MPL007 | Critical | Possible literal credential in environment or headers |
| MPL008 | High | Wildcard tool access |
| MPL009 | High | Mutating tool incorrectly marked read-only |
| MPL010 | High/Critical | Dangerous tool missing `destructiveHint=true` |
| MPL011 | Medium | Side-effecting tool without an idempotency declaration |
| MPL012 | High | Externally acting tool incorrectly marked `openWorldHint=false` |
| MPL013 | High | Sensitive user or system directory access |
| MPL014 | High | Wildcard environment-variable forwarding |

The linter uses names and manifest metadata as static signals. Tool annotations are untrusted hints, not enforcement. A clean report does not prove a server is safe; review server code, client approvals, sandboxing, network policy, and runtime controls as well.
