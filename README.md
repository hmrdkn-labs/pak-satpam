# Observability Agent MCP

A portable Model Context Protocol server for bounded observability evidence and
an optional approval-gated CI operations module.

## Status

Runnable provider-backed MCP. The default TypeScript server exposes seven
bounded, read-only observability tools over stdio and authenticated Streamable
HTTP. An optional GitHub Actions module adds four read-only CI tools and one
strictly approval-gated failed-job rerun. It includes
VictoriaMetrics/Prometheus-compatible metrics and alert adapters, allowlisted
Grafana PNG rendering, deterministic local fixtures, npm packaging, and a
non-root OCI runtime. Private deployment configuration remains outside this
public repository.

## Product Boundary

This project provides deterministic tools for observability and CI evidence. It
does not run an LLM, receive chat messages, execute shell commands, modify
source, deploy workloads, or expand repository trust.

```text
AI client
  | stdio (implemented)
  v
Observability Agent MCP
  - strict tool schemas
  - query and response limits
  - label and value redaction
  - normalized evidence bundles
  |
  +--> deterministic fake provider
  +--> allowlisted Grafana render API
  +--> named-query Prometheus-compatible API
       +--> VictoriaMetrics alert API
       - Prometheus
       - VictoriaMetrics
```

The model and agent loop remain in the client. The only optional mutation is an
allowlisted rerun of failed jobs after a fresh, one-time operator approval.

## First Tool Set

| Tool | Purpose |
| --- | --- |
| `observability.capabilities` | Describe configured providers and safe limits. |
| `observability.health_snapshot` | Return bounded service and target health. |
| `observability.active_alerts` | Return normalized active alert metadata. |
| `observability.query_metrics` | Run a bounded instant or range metrics query. |
| `observability.render_panel` | Return one allowlisted Grafana panel as PNG evidence. |
| `observability.render_dashboard` | Return one allowlisted Grafana dashboard as PNG evidence. |
| `observability.incident_context` | Build a compact evidence bundle for one alert or service. |

Version 1 is read-only. It will not create dashboards, modify alert rules,
silence alerts, restart services, run scripts, or trigger deployments.

## Optional CI Tool Set

| Tool | Purpose |
| --- | --- |
| `ci.workflow_status` | Inspect one allowlisted workflow run. |
| `ci.failed_job_analysis` | Classify failed jobs deterministically. |
| `ci.log_evidence` | Return bounded, redacted job-log evidence. |
| `ci.remediation_plan` | Produce a runbook-backed dry-run plan. |
| `ci.rerun_failed_workflow` | Rerun failed jobs after a bound one-time approval. |

The CI module is disabled unless a deployment supplies an allowlist, GitHub App
installation identity, approval key, replay store, and metadata-only audit
store. The public controlled fixture is
`.github/workflows/goal14-controlled-fixture.yml`: attempt 1 fails and an
approved failed-job rerun succeeds. See [CI/CD Runbook](docs/ci-cd-runbook.md).

## Portability

The server can be consumed through:

- stdio for local desktop and CLI agents;
- an authenticated Streamable HTTP endpoint on a private network;
- a non-root OCI image;
- the package CLI produced by `npm pack`.

The implemented HTTP mode uses a file-injected Bearer credential and a strict
Host allowlist for a private, single-operator deployment. It is not a public or
multi-tenant OAuth deployment.

The public multi-architecture image is published for `linux/amd64` and
`linux/arm64` at:

```text
ghcr.io/hamardikan/observability-agent-mcp
```

Production deployments should consume an immutable `@sha256:` digest from the
GitHub Actions publisher, not a mutable tag. Runtime policy, credentials, and
network exposure remain deployment-owned and are intentionally excluded from
the image.

Remote HTTP deployment requires authentication. Publishing this repository does
not imply that an MCP endpoint should be exposed without OAuth, network policy,
rate limits, and audience-bound scopes.

## Run Locally

Node.js 22 and npm are required.

```bash
npm ci
npm run build
node dist/cli.js
```

The process speaks MCP over stdio, so launch it from an MCP client rather than
typing into the terminal. A client command definition is:

```json
{
  "command": "node",
  "args": ["/absolute/path/to/observability-agent-mcp/dist/cli.js"]
}
```

Inspect tool discovery and run every local gate with:

```bash
npm run inspector:list
npm run validate
```

Build and run the non-root OCI image over stdio with:

```bash
npm run container:build
docker run --rm -i observability-agent-mcp:local
```

Production HTTP mode requires a strict YAML provider policy and `0600` runtime
credential files. See [Client Compatibility](docs/client-compatibility.md)
and [Security Model](docs/security-model.md) before deploying it.

## Relationship To Grafana MCP

The [official Grafana MCP server](https://github.com/grafana/mcp-grafana) is the
preferred reference and fast path for broad Grafana capabilities. This project
will not duplicate its dashboard and administration surface.

| Capability | Grafana MCP | This project |
| --- | --- | --- |
| Broad Grafana dashboards and administration | Primary owner | Not implemented |
| Grafana datasource queries | Supported | Narrow adapter only |
| Direct Prometheus-compatible backend without Grafana | Not the primary path | Supported goal |
| Provider-neutral incident evidence | Provider-specific | Primary owner |
| Conservative read-only public contract | Configurable broad surface | Required default |

The unique scope here is:

- compact incident-context evidence;
- conservative read-only defaults;
- direct Prometheus-compatible operation when Grafana is absent;
- provider-neutral schemas;
- predictable limits and redaction for agent use.

Grafana visuals are first-class evidence. Rendering tools return an MCP
`ImageContent` PNG plus structured metadata for the source, observation window,
dimensions, byte size, freshness, truncation, and warnings. Visuals are opt-in;
normal metric queries do not spend rendering resources or image context.

There is no automatic delegation between the two servers. Use Grafana MCP when
an agent needs Grafana-native dashboards, incidents, administration, or its
existing query tools. Use this project's namespace when the client needs the
same bounded evidence contract across Grafana and direct
Prometheus-compatible backends. `active_alerts` and `incident_context` are
normalized here rather than forwarded to Grafana MCP; `query_metrics` selects
one configured adapter and never calls another MCP server. Deployments may
offer both namespaces, but each request has one explicit owner.

## Read Next

- [Architecture](docs/architecture.md)
- [Security Model](docs/security-model.md)
- [Tool Surface](docs/tool-surface.md)
- [Client Compatibility](docs/client-compatibility.md)
- [Test Strategy](docs/test-strategy.md)
- [Roadmap](docs/roadmap.md)
- [Implementation Status](docs/implementation-status.md)
- [Grafana Visual Context ADR](docs/decisions/0002-grafana-visual-context.md)
- [Contributing](CONTRIBUTING.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
