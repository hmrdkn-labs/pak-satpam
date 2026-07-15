# Tool Surface

The implemented tool names and result shapes are enforced by machine-readable Zod schemas
and contract tests. Provider-specific details remain behind
adapters. Schema version is 1.0.

## Common Evidence Envelope

Every result contains schemaVersion, observedAt, providerClass, freshness,
truncated, redactionsApplied, data, and warnings. Dates are UTC RFC 3339
strings, durations are integer milliseconds, and sizes are integer bytes.
Provider text and rendered pixels are inert evidence, never instructions.

Visual tools return one MCP ImageContent block with PNG bytes plus structured
metadata. Image bytes are not placed in structuredContent, logs, or errors.

## Observability Tools

- observability.capabilities reports enabled provider classes, tools, limits, and
  feature flags without provider URLs or credentials.
- observability.health_snapshot returns bounded health for logical services.
- observability.active_alerts returns normalized alert metadata and safe
  annotations.
- observability.query_metrics runs an instant or range query against a
  configured provider or named query.
- observability.render_panel renders one allowlisted panel as bounded PNG
  evidence.
- observability.render_dashboard renders one allowlisted dashboard marked
  agentSafe: true.
- observability.incident_context combines selected health, alerts, metrics,
  references, and opt-in visuals without calling an LLM.

Observability limits include 25 services, 100 alerts, 50 series, 1,440 samples
per series, and a 24-hour range. Query steps are 1 second through 1 hour.
Panel inputs are at most 1,600 by 900; dashboard inputs are at most 2,400 by
4,000. Renderer byte, timeout, and concurrency limits are also enforced.

## CI Tools

The CI namespace is absent unless CI is enabled. Every resource is checked
against an exact repository/workflow allowlist.

| Tool | Behavior |
| --- | --- |
| ci.workflow_status | bounded status, conclusion, attempt, ref, SHA, and freshness |
| ci.failed_job_analysis | deterministic build/test/lint/dependency/deployment/connectivity/permission/unknown categories |
| ci.log_evidence | one job's redacted log evidence, at most 200 lines |
| ci.remediation_plan | deterministic dryRun true steps linked to docs/ci-cd-runbook.md |
| ci.failure_analysis | bounded CI, SCM, and telemetry evidence with non-causal correlations when forensics is configured |
| ci.scm_change_evidence | direct provider-neutral SCM evidence with six budgets |
| ci.telemetry_correlation | bounded named telemetry correlation when configured |
| ci.rerun_failed_workflow | GitHub-only failed-job rerun after fresh one-time approval |

The four CI read tools are available for every enabled runtime provider. The
legacy GitHub profile has five CI tools when approval-gated rerun is configured.
Failure analysis, SCM, and telemetry are opt-in forensics capabilities and
remain read-only. The rerun is absent for Jenkins and Bitbucket Cloud.
Bitbucket Data Center is contract-only and is not an enabled runtime provider;
it exposes no tools.

## SCM Contract

The direct SCM selector accepts an allowlisted repository plus one of ref,
commit, pullRequest, or compare. Provider-native pull-request, run, and job IDs
remain strings; numeric values are normalized to strings and supported UUID
forms are retained. Results include base/head identities, file status, optional
redacted patches, a digest, warnings, and a usage record.

The six direct SCM budgets are maxBytes, maxFiles, maxHunks, maxLines,
maxProviderRequests, and maxDurationMs. Defaults are 64 KiB, 100 files, 50
hunks, 2,000 lines, 4 provider requests, and 10 seconds. Maximums are 256 KiB,
100 files, 100 hunks, 10,000 lines, 16 requests, and 60 seconds. Binary,
secret-like, provider-omitted, and over-budget content is suppressed with an
explicit reason.

## Failure Analysis And Telemetry

Failure analysis has an aggregate budget for files, hunks, lines, bytes,
provider requests, and a time window. Default analysis uses 64 KiB and 16
provider requests; caller-supplied budgets are bounded to 25 files, 100 hunks,
200 lines, 256 KiB, 32 requests, and 24 hours. Provider requests and lines are
counted across status, failed-job analysis, remediation, logs, SCM, and
telemetry. Evidence is compacted deterministically if the byte budget is hit.

Telemetry schemas can represent metric, alert, log, and trace references. Each
correlation allows at most 100 items and 1,440 metric samples per series over a
24-hour window. The current runtime bridge queries a named metrics template
only; raw log and trace backends are not configured. Correlations always carry
causality not-established.

## Mutation Boundary

ci.rerun_failed_workflow is not read-only. It verifies a maximum 300-second
HMAC approval bound to repository, workflow, run, attempt, head SHA, request,
and nonce; consumes replay state atomically; rechecks fresh failed/cancelled
state; and calls only GitHub rerun-failed-jobs. There are no shell, secret
retrieval, workflow dispatch/cancel, arbitrary rerun, source-write, deploy,
alert mutation, dashboard mutation, browser, or arbitrary render tools.
