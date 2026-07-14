# CI/CD Integration Contract

This reusable adapter contract connects the existing bounded CI evidence tools
to a CI event loop without adding a new tool surface or autonomous behavior.
The optional observer companion may own bounded polling and delivery state; the
deployment still owns its exact allowlists, routes, credentials, and lifecycle.

```text
observe -> classify -> bounded redacted evidence -> dry-run plan
       -> explicit one-time approval -> rerun failed jobs only
       -> observe the follow-up run
```

Each step is an explicit request. A failed follow-up returns to observation; it
does not trigger another rerun automatically.

## Provider Boundary

An adapter implements the existing `CIProvider` interface:

| Operation | Required result |
| --- | --- |
| `getWorkflowStatus` | bounded status, conclusion, attempt, ref, SHA, freshness |
| `getFailedJobAnalysis` | bounded failed jobs with deterministic categories |
| `getLogEvidence` | at most 200 redacted lines and a digest |
| `getRemediationPlan` | `dryRun: true` steps linked to the public runbook |
| `rerunFailedWorkflow` | only `rerun-failed-jobs` for the exact approved run |

Inputs use `owner/repository`, workflow, decimal run/job IDs, a 40-character
lowercase commit SHA, and `schemaVersion: "1.0"`. Provider URLs, tokens, raw
payloads, and raw logs do not cross the MCP boundary.

The server enforces the repository/workflow allowlist, freshness, run binding,
short-lived one-time approval, replay protection, redaction, and metadata-only
audit. The adapter must not add shell execution, secret retrieval, workflow
dispatch, arbitrary rerun, source mutation, deployment, or alert mutation.

## Release Handoff

1. Run TypeScript, tests, stdio, package, and private HTTP gates.
2. Build and smoke-test the non-root OCI image.
3. Build `linux/amd64` and `linux/arm64` without publishing.
4. On the explicitly authorized main-branch workflow, publish the existing
   GHCR image with the `sha-<commit>` tag, provenance, and SBOM.
5. Record the immutable digest for the private deployment owner.

The release loop never consumes CI approval tokens and never deploys the image.
The exact evidence and operator decisions remain in
[the CI/CD runbook](ci-cd-runbook.md).
