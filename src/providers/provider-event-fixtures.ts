/** Synthetic, non-production provider payloads used by portability tests. */
const SHA = "a".repeat(40);
const DIGEST = `sha256:${"b".repeat(64)}`;

export const githubActionsFixture = Object.freeze({
  repository: { full_name: "acme/app" },
  workflow_run: {
    id: 101,
    name: "ci.yml",
    workflow_id: "ci.yml",
    status: "completed",
    conclusion: "failure",
    run_attempt: 1,
    event: "push",
    head_branch: "main",
    head_sha: SHA,
    created_at: "2026-07-17T12:00:00.000Z",
    updated_at: "2026-07-17T12:01:00.000Z",
    html_url: "https://github.example/acme/app/actions/runs/101",
  },
  jobs: [{ id: 9, name: "test", status: "completed", conclusion: "failure", failedSteps: ["unit"] }],
  files: [{ filename: "src/a.ts", status: "modified", additions: 2, deletions: 1, patch: "@@ -1 +1 @@\n-safe\n+safe" }],
  logs: [{ jobId: 9, text: "Authorization: Bearer ghp_synthetic-fixture-token\nfailed unit" }],
  metrics: [{ name: "ci.duration", state: "degraded", value: 42, sampleCount: 1, reference: "metric-fixture" }],
  traces: [{ id: "trace-fixture", durationMs: 42, status: "error", reference: "trace-fixture" }],
  artifact: { name: "pak", digest: DIGEST, url: "https://ci.example/artifacts/1" },
});

export const jenkinsFixture = Object.freeze({
  repository: "acme/app",
  number: 101,
  workflow: "ci.yml",
  displayName: "#101",
  result: "FAILURE",
  building: false,
  timestamp: Date.parse("2026-07-17T12:00:00.000Z"),
  duration: 60_000,
  branchName: "main",
  event: "push",
  actions: [{ lastBuiltRevision: { SHA1: SHA } }],
  jobs: [{ id: "9", name: "test", status: "completed", result: "FAILURE", steps: ["unit"] }],
  files: [{ file: "src/a.ts", editType: "edit", additions: 2, deletions: 1, hunkCount: 1 }],
  changeSets: [{ items: [{ id: "9", paths: [{ editType: "edit", file: "src/a.ts" }] }] }],
  log: "Authorization: Bearer jenkins_synthetic-fixture-token\nfailed unit",
  metrics: [{ name: "ci.duration", state: "degraded", value: 42, sampleCount: 1, reference: "metric-fixture" }],
  traces: [{ id: "trace-fixture", durationMs: 42, status: "error", reference: "trace-fixture" }],
  url: "https://jenkins.example/job/ci/101/",
  artifact: { name: "pak", digest: DIGEST, url: "https://ci.example/artifacts/1" },
});

export const bitbucketPipelinesFixture = Object.freeze({
  repository: { full_name: "acme/app" },
  build_number: 101,
  workflow: "ci.yml",
  state: { name: "COMPLETED", result: { name: "FAILED" } },
  target: { ref_name: "main", commit: { hash: SHA } },
  event: "push",
  created_on: "2026-07-17T12:00:00.000Z",
  completed_on: "2026-07-17T12:01:00.000Z",
  steps: [{ uuid: "9", id: "9", name: "test", steps: ["unit"], state: { name: "COMPLETED", result: { name: "FAILED" } } }],
  diffstat: [{ old: { path: "src/a.ts" }, new: { path: "src/a.ts" }, status: { type: "modified" }, lines_added: 2, lines_removed: 1, hunkCount: 1 }],
  logs: [{ jobId: "9", text: "Authorization: Bearer bb_synthetic-fixture-token\nfailed unit" }],
  metrics: [{ name: "ci.duration", state: "degraded", value: 42, sampleCount: 1, reference: "metric-fixture" }],
  traces: [{ id: "trace-fixture", durationMs: 42, status: "error", reference: "trace-fixture" }],
  artifact: { name: "pak", digest: DIGEST, url: "https://ci.example/artifacts/1" },
  links: [{ kind: "run", href: "https://bitbucket.example/acme/app/pipelines/results/101" }],
});

export const providerEventFixtures = Object.freeze({
  githubActions: githubActionsFixture,
  jenkins: jenkinsFixture,
  bitbucketPipelines: bitbucketPipelinesFixture,
});
export const PROVIDER_EVENT_FIXTURES = providerEventFixtures;
export const syntheticProviderFixtures = providerEventFixtures;
