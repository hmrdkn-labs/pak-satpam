# Implementation Status

Last updated: 2026-07-12

## Goal 14: CI/CD Analysis And Gated Rerun

Implemented locally:

- Provider-neutral CI schemas and a GitHub Actions adapter.
- Four bounded read-only tools plus one approval-gated failed-job rerun.
- Eight deterministic failure classes and runbook-backed dry-run plans.
- Pre-output log redaction, strict allowlists, freshness checks, GitHub App
  installation auth, atomic replay protection, and metadata-only audit events.
- An operator-only approval CLI and controlled first-attempt failure workflow.

The public multi-architecture OCI image is published at
`ghcr.io/hamardikan/observability-agent-mcp`; production uses the immutable
digest recorded by the private infra evidence. Live edge deployment and
controlled Discord evidence remain private-infra responsibilities.

## Goal 11: Private Provider Shadow

Implemented:

- Seven namespaced read-only tools with strict input and output schemas.
- Discriminated instant/range and available/unavailable result invariants.
- Exact named-query, service, dashboard, and panel allowlists.
- VictoriaMetrics metrics and vmalert alert normalization with bounded output.
- Grafana Viewer-token PNG adapter with type, size, route, and timeout checks.
- Explicit fresh/cached/stale/unknown semantics; provider failure remains unknown.
- Deterministic light/dark synthetic visuals for local tests.
- Stdio and authenticated stateless Streamable HTTP transports.
- Host allowlisting, constant-time Bearer checks, and sanitized health/errors.
- Strict YAML runtime policy plus `0600` file-injected credentials.
- Installed-package, Inspector, stdio, HTTP, and non-root OCI smoke tests.

Verified private-shadow behavior:

- Seven observability tools discovered by the edge agent client as read-only,
  plus four read-only CI tools and one approval-gated failed-job rerun.
- Metrics series and active-alert counts match direct provider counts.
- Grafana renderer absence returns structured unknown/unavailable evidence.
- Deployment, network placement, and secrets remain owned by the private infra repo.

Current boundaries:

- No public endpoint or OAuth authorization-server integration.
- No shell, source write, deployment, alert mutation, or dashboard mutation tools.
- No logs or traces until the metrics contract is stable.
- The OCI release is published through the main-only multi-architecture GitHub
  Actions workflow; package visibility is public while runtime credentials and
  deployment policy remain private.

Verification command: `npm run validate`

Next checkpoint: preserve the read-only contract while adding only capability
that is justified by observed operator pain; do not infer a need for OAuth or
broader deployment authority from the public package release.
