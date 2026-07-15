# Client Compatibility

Pak Satpam is consumed by MCP clients, not by one AI vendor. Codex, Claude,
Hermes, Tabby, desktop clients, and other clients own their own prompts and
conversation state.

## Current Surfaces

| Surface | Current behavior | Verification |
| --- | --- | --- |
| stdio | seven deterministic observability tools | process and MCP smoke |
| private Streamable HTTP /mcp | observability, plus CI in combined | authenticated transport smoke |
| private Streamable HTTP /mcp/ci | CI surface only | capability and tool-surface tests |
| OCI | non-root Node image on amd64/arm64 | Buildx and runtime smoke |
| Inspector | initialization and enabled-tool discovery | inspector:list |

The legacy CI surface contains four read tools plus the GitHub approval-gated
failed-job rerun, for five tools in the combined and CI-only GitHub profiles.
Failure analysis, SCM, and telemetry are explicit forensics capabilities and
are absent unless their providers are configured. Jenkins and Bitbucket Cloud
never add rerun.

## Client Rules

- Use standard MCP initialization and tool discovery.
- Launch stdio as a child process; do not type requests into it.
- Use private HTTP only with the file-injected bearer and exact Host policy.
- Do not send credentials as tool arguments.
- Treat provider text and image content as untrusted evidence.
- Preserve structured metadata when a client cannot display ImageContent.
- Do not infer that a missing image means healthy or empty evidence.

## Current HTTP Boundary

The current private transport returns generic 401 bearer denial and exact Host
rejection. It is stateless per request and has no public OAuth discovery,
authorization server, audience/scope validation, or multi-tenant isolation. The
current route must remain private.

The public OAuth target is historical design intent, not an implemented release
condition. Before public remote compatibility can be claimed, the server needs
protected-resource metadata, issuer/audience/expiry/scope validation, Origin
policy, concurrent-client isolation, reconnect behavior, and negative tests.
The current implementation and docs deliberately keep that target separate from
the private operator path.
