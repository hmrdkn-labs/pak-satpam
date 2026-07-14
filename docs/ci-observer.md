# CI Observer Deployment Contract

The optional observer turns terminal GitHub Actions results into signed private
events. It is a companion process, not an MCP tool and not a chat bot.

```text
GitHub Actions -> bounded GitHub App polling -> observer state/dedupe
               -> success route (direct status delivery)
               -> failure route (agent calls Pak Satpam read-only CI tools)
```

## Required Runtime Inputs

- one exact repository/workflow allowlist;
- a GitHub App ID and private key in regular `0600` files;
- exact owner or repository installation ID mappings in `0600` files;
- an HMAC key in a `0600` file;
- a private writable state directory;
- separate internal success and analysis URLs;
- bounded poll, page, payload, retry, timeout, lease, and evidence limits.

Configuration is strict YAML. Unknown fields, duplicate repositories, duplicate
workflows, non-private files, public HTTP destinations, wildcard trusted hosts,
and unsupported GitHub API origins fail closed.

## Runtime Behavior

The observer requests only completed workflow runs and rescans the newest
bounded pages every poll. Durable seen records deduplicate repository, workflow,
run ID, and attempt. This avoids a creation-time cursor missing a long-running
workflow that completes later. A page window that remains truncated degrades
health and is visible in metadata-only metrics.

Success, skipped, neutral, stale, and other non-analysis outcomes use the
status route. Failure, cancelled, timed-out, and action-required outcomes use
the analysis route. The observer never invokes `rerun-failed-jobs`; an agent may
request that action only through Pak Satpam's separate short-lived approval
contract.

## Health And Metrics

When configured, `/healthz` returns sanitized observer counters and current
health. `/metrics` exposes poll, delivery, error, outcome, target, and truncated
target counters. Bind these endpoints only to a private operator-controlled
interface. They contain no GitHub token, HMAC key, provider payload, raw log,
or chat identity.

## Deployment Ownership

The public package owns observer code and schemas. A private deployment owns
network bindings, credentials, exact allowlists, internal agent routes,
resource limits, restart policy, rollback, and evidence. Production images must
be digest-pinned and the previous observer runtime must remain available for a
bounded rollback rehearsal.
