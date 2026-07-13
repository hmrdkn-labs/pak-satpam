# Goal Prompt: CI Event Loop And Portable Release

> Implement the smallest end-to-end slice that connects the existing bounded
> CI evidence event loop to a portable npm and OCI release. Preserve the public
> MCP, npm, CLI, and GHCR identifiers. Support stdio and private Streamable HTTP
> on Node.js 22 and OCI images for `linux/amd64` and `linux/arm64`. Verify both
> target platforms in CI without publishing from validation jobs. Keep provider
> credentials, approval keys, runtime configuration, deployment policy, and
> private topology outside public runtime artifacts.

## Constraints

- Reuse `CIProvider` and schema version `1.0`.
- Keep the explicit loop: observe, analyze, redact bounded evidence, plan,
  approve once, rerun failed jobs only, then observe again.
- Do not add shell execution, secret retrieval, deployment, workflow dispatch,
  arbitrary rerun, source mutation, or autonomous remediation tools.
- Do not rename `@hamardikan/observability-agent-mcp` or
  `ghcr.io/hamardikan/observability-agent-mcp`.
- Do not deploy or push while implementing or verifying the goal.

## Done When

- stdio, private HTTP, and OCI usage is documented for both Linux platforms;
- the CI/CD integration contract is reusable by another provider adapter;
- tests assert package, OCI, GHCR, and multi-platform workflow compatibility;
- CI performs a non-publishing Buildx verification for both platforms;
- focused gates pass, or the exact environment blocker and residual risk are
  reported.
