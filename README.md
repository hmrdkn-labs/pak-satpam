<div align="center">

# Pak Satpam

### The bounded observability and CI guard for AI agents

Pak Satpam gives an AI agent the evidence it needs to understand infrastructure
health, investigate incidents, inspect CI failures, and show Grafana visuals
without handing the model a shell or unrestricted infrastructure access.

[![Validate](https://github.com/hmrdkn-labs/pak-satpam/actions/workflows/validate.yml/badge.svg)](https://github.com/hmrdkn-labs/pak-satpam/actions/workflows/validate.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-2f6f4e.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-43853d.svg)](package.json)
[![MCP](https://img.shields.io/badge/protocol-MCP-111827.svg)](https://modelcontextprotocol.io/)

</div>

> **Pak Satpam** means *the security guard*. It watches, reports, and follows a
> strict access policy. It does not become the infrastructure administrator.

This is the production-ready evolution of the original Pak Satpam prototype:
a portable Model Context Protocol server with deterministic provider adapters,
bounded responses, redaction, and approval-gated CI operations. The agent and
chat experience remain separate, so the same MCP can serve Hermes/Tabby,
desktop agents, CI assistants, or another MCP-compatible client.

## What It Does

```text
Engineer
   |
   v
AI agent (Hermes, Tabby, desktop client, or another MCP client)
   |
   |  stdio or authenticated private HTTP
   v
Pak Satpam
   |-- validates every request against a strict schema
   |-- bounds queries, time windows, output size, and labels
   |-- normalizes and redacts provider evidence
   |
   +--> Grafana panels and dashboard PNGs
   +--> Prometheus / VictoriaMetrics metrics
   +--> VictoriaMetrics alert state
   +--> GitHub Actions evidence
```

The default server exposes seven read-only observability tools. An optional CI
module adds four read-only tools and one tightly scoped operation that can rerun
failed GitHub Actions jobs only after a fresh, one-time operator approval.

Pak Satpam does **not** run an LLM, receive chat messages, execute arbitrary
shell commands, modify source, deploy workloads, read secrets, or silently
expand its own permissions.

## Tool Surface

### Observability

| Tool | What the agent receives |
| --- | --- |
| `observability.capabilities` | Configured providers, features, and safety limits |
| `observability.health_snapshot` | Bounded service and scrape-target health |
| `observability.active_alerts` | Normalized active-alert metadata |
| `observability.query_metrics` | Allowlisted instant or range metrics results |
| `observability.render_panel` | One allowlisted Grafana panel as PNG evidence |
| `observability.render_dashboard` | One allowlisted Grafana dashboard as PNG evidence |
| `observability.incident_context` | A compact evidence bundle for an alert or service |

### CI/CD (optional)

| Tool | What the agent receives or may request |
| --- | --- |
| `ci.workflow_status` | Status for one allowlisted workflow run |
| `ci.failed_job_analysis` | Deterministic failure classification |
| `ci.log_evidence` | Bounded and redacted job-log evidence |
| `ci.remediation_plan` | A runbook-backed dry-run plan |
| `ci.rerun_failed_workflow` | Approved rerun of failed jobs only |

The CI module stays disabled until the deployment provides repository and
workflow allowlists, a GitHub App identity, a replay-safe approval key, and
metadata-only audit storage. The public
`.github/workflows/goal14-controlled-fixture.yml` workflow provides a bounded
failure-and-rerun test. See the [CI/CD runbook](docs/ci-cd-runbook.md).

### CI observer (optional)

The package and OCI image also include `observability-agent-mcp-observer`. It
polls only configured GitHub Actions workflow allowlists, stores private
metadata-only cursor and dedupe state, and sends signed success or failure
events to operator-controlled internal routes. It does not add MCP tools and
cannot rerun workflows, modify source, deploy, or own a chat gateway.

Run it only in a private deployment with file-injected GitHub App and HMAC
credentials:

```bash
OBSERVER_CONFIG_FILE=/run/runtime/observer.yml \
  observability-agent-mcp-observer
```

See the [CI observer deployment contract](docs/ci-observer.md).

## Run It

Pak Satpam requires Node.js 22 or newer.

```bash
npm ci
npm run build
node dist/cli.js
```

The command speaks MCP over stdio. Configure it in a compatible client instead
of typing into the process directly:

```json
{
  "command": "node",
  "args": ["/absolute/path/to/pak-satpam/dist/cli.js"]
}
```

Run the complete local verification suite with:

```bash
npm run validate
```

### Container

The public non-root image supports `linux/amd64` and `linux/arm64`:

```text
ghcr.io/hamardikan/observability-agent-mcp
```

Production deployments should pin the image by immutable `@sha256:` digest.
For a local build and stdio smoke run:

```bash
npm run container:build
docker run --rm -i observability-agent-mcp:local
```

## Connect It to an Agent

| Client location | Recommended transport | Intended use |
| --- | --- | --- |
| Same machine | stdio | Desktop and CLI agents |
| Private network | Streamable HTTP | Shared Hermes/Tabby or agent runtime |
| OCI host | stdio or private HTTP | Podman/Docker deployments |
| Public network | Not ready | Requires OAuth and tenant isolation first |

Private HTTP mode uses a file-injected bearer credential and an exact Host
allowlist. It is designed for a private, single-operator network. Publishing
the repository or image does not make an unauthenticated public endpoint safe.
See [Client compatibility](docs/client-compatibility.md) and the
[Security model](docs/security-model.md) before deployment.

## Visual Evidence

Grafana visuals are first-class MCP evidence. Panel and dashboard tools return
PNG `ImageContent` together with structured metadata: source, observation
window, dimensions, byte size, freshness, truncation, and warnings.

Rendering is opt-in. Normal health and metrics requests do not spend browser,
renderer, or image-context resources. If rendering is unavailable, Pak Satpam
fails to a structured evidence response instead of inventing a graph.

## Why Not Just Use Grafana MCP?

The official [Grafana MCP](https://github.com/grafana/mcp-grafana) is the right
choice for broad Grafana-native queries and administration. Pak Satpam owns a
narrower boundary intended for operational agents:

| Capability | Grafana MCP | Pak Satpam |
| --- | --- | --- |
| Grafana administration | Primary owner | Not implemented |
| Grafana datasource queries | Broad support | Narrow allowlisted adapter |
| Direct Prometheus-compatible backend | Secondary path | Supported |
| Provider-neutral incident evidence | Provider-specific | Primary contract |
| Conservative read-only default | Configurable | Required |
| Approval-gated CI evidence | Not its scope | Optional module |

Both servers can be offered to one agent, but every request must have one clear
owner. Pak Satpam never silently delegates to another MCP server.

## Project Boundary

This public repository owns the portable protocol, schemas, provider adapters,
redaction, tests, npm package, and OCI image. A deployment repository should
own private endpoints, network policy, provider allowlists, credentials, and
runtime configuration. Private topology and secrets do not belong here.

## Documentation

- [Architecture](docs/architecture.md)
- [Tool surface](docs/tool-surface.md)
- [Security model](docs/security-model.md)
- [Client compatibility](docs/client-compatibility.md)
- [Portability and release contract](docs/portability.md)
- [CI/CD integration contract](docs/ci-cd-integration-contract.md)
- [CI observer deployment contract](docs/ci-observer.md)
- [Goal prompt: CI event loop and portable release](docs/goals/goal-ci-event-loop-portable-release.md)
- [Test strategy](docs/test-strategy.md)
- [Implementation status](docs/implementation-status.md)
- [Roadmap](docs/roadmap.md)
- [Grafana visual context ADR](docs/decisions/0002-grafana-visual-context.md)
- [Contributing](CONTRIBUTING.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
