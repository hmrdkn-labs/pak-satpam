import { createHash } from "node:crypto";
import {
  CIFailedJobAnalysisResultSchema,
  CILogEvidenceResultSchema,
  CIRemediationPlanResultSchema,
  CIRerunFailedWorkflowResultSchema,
  CIWorkflowStatusResultSchema,
  classifyFailure,
  makeCIEvidence,
  type CIFailedJobAnalysisInput,
  type CIFailedJobAnalysisResult,
  type CILogEvidenceInput,
  type CILogEvidenceResult,
  type CIRerunFailedWorkflowResult,
  type CIWorkflowStatusInput,
  type CIWorkflowStatusResult,
} from "../domain/ci-schemas.js";
import { CIProviderError, type CIProvider, type CITokenProvider } from "./ci-provider.js";
import { StaticGitHubTokenProvider } from "./github-app-token-provider.js";
import { redactText } from "../ci/redaction.js";

const GITHUB_API_VERSION = "2022-11-28";
const MAX_RESPONSE_BYTES = 2 * 1_024 * 1_024;

export interface GitHubActionsProviderOptions {
  readonly token?: string;
  readonly tokenProvider?: CITokenProvider;
  readonly fetch: typeof globalThis.fetch;
  readonly clock?: () => Date;
  readonly apiBaseUrl?: string;
  readonly maxFreshnessMs?: number;
}

export class GitHubActionsProvider implements CIProvider {
  readonly #tokenProvider: CITokenProvider;
  readonly #fetch: typeof globalThis.fetch;
  readonly #clock: () => Date;
  readonly #apiBaseUrl: string;
  readonly #maxFreshnessMs: number;

  constructor(options: GitHubActionsProviderOptions) {
    if (options.token === undefined && options.tokenProvider === undefined) throw new Error("GitHub token provider is required");
    this.#tokenProvider = options.tokenProvider ?? new StaticGitHubTokenProvider(options.token ?? "");
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? (() => new Date());
    this.#apiBaseUrl = trustedGitHubApiBase(options.apiBaseUrl);
    this.#maxFreshnessMs = options.maxFreshnessMs ?? 5 * 60_000;
  }

  async getWorkflowStatus(input: CIWorkflowStatusInput): Promise<CIWorkflowStatusResult> {
    const path = input.runId === undefined
      ? `/repos/${input.repo}/actions/workflows/${encode(input.workflow)}/runs?per_page=1`
      : `/repos/${input.repo}/actions/runs/${input.runId}`;
    const value = await this.getJson(path, input.repo);
    const rawRun = input.runId === undefined ? firstRun(value) : value;
    const run = normalizeRun(rawRun, input.repo, input.workflow);
    return CIWorkflowStatusResultSchema.parse(makeCIEvidence("github-actions", this.#clock(), { run }, { freshness: freshness(run.updatedAt, this.#clock, this.#maxFreshnessMs) }));
  }

  async getFailedJobAnalysis(input: CIFailedJobAnalysisInput): Promise<CIFailedJobAnalysisResult> {
    const status = await this.getWorkflowStatus(input);
    const value = await this.getJson(`/repos/${input.repo}/actions/runs/${input.runId}/jobs?per_page=100`, input.repo);
    const jobs = arrayField(value, "jobs").map((job) => normalizeJob(job));
    const failedJobs = jobs.filter((job) => job.conclusion !== "success" && job.conclusion !== "skipped" && job.conclusion !== "neutral");
    const categorySummary = Object.fromEntries(
      ["build", "test", "lint", "dependency", "deployment", "infrastructure-connectivity", "permission", "unknown"].map((category) => [category, failedJobs.filter((job) => job.category === category).length]),
    );
    return CIFailedJobAnalysisResultSchema.parse({ ...status, data: { run: status.data.run, failedJobs, categorySummary } });
  }

  async getLogEvidence(input: CILogEvidenceInput): Promise<CILogEvidenceResult> {
    const initial = await this.request(`/repos/${input.repo}/actions/jobs/${input.jobId}/logs`, "GET", input.repo, "manual");
    const response = isRedirect(initial.status)
      ? await this.followLogRedirect(initial, input.repo)
      : initial;
    if (!response.ok) throw httpError(response.status);
    const contentType = response.headers.get("content-type") ?? "";
    if (/zip|octet-stream/i.test(contentType)) throw new CIProviderError("malformed");
    const raw = await response.text();
    if (raw.length > MAX_RESPONSE_BYTES) throw new CIProviderError("malformed");
    const rawLines = raw.split(/\r?\n/).filter((line) => line.length > 0);
    const selected = rawLines.slice(0, input.maxLines).map((line, index) => ({ sequence: index + 1, ...redactText(line) }));
    const lines = selected.map(({ sequence, text }) => ({ sequence, text }));
    const redactionsApplied = selected.some((line) => line.redacted);
    return CILogEvidenceResultSchema.parse(makeCIEvidence("github-actions", this.#clock(), {
      runId: input.runId,
      jobId: input.jobId,
      jobName: `job-${input.jobId}`,
      available: true,
      lines,
      sha256: createHash("sha256").update(lines.map((line) => line.text).join("\n")).digest("hex"),
    }, { truncated: rawLines.length > input.maxLines, redactionsApplied }));
  }

  async getRemediationPlan(input: { repo: string; workflow: string; runId: string }) {
    const analysis = await this.getFailedJobAnalysis(input);
    const actions = [...new Map(analysis.data.failedJobs.map((job) => [job.category, {
      category: job.category,
      title: remediationTitle(job.category),
      steps: remediationSteps(job.category),
      runbook: `docs/ci-cd-runbook.md#${job.category}`,
    }])).values()];
    return CIRemediationPlanResultSchema.parse(makeCIEvidence("github-actions", this.#clock(), { runId: input.runId, dryRun: true, actions }, { freshness: analysis.freshness, warnings: analysis.warnings, redactionsApplied: analysis.redactionsApplied }));
  }

  async rerunFailedWorkflow(input: { repo: string; workflow: string; runId: string }): Promise<CIRerunFailedWorkflowResult> {
    const response = await this.request(`/repos/${input.repo}/actions/runs/${input.runId}/rerun-failed-jobs`, "POST", input.repo);
    if (![200, 201, 202, 204].includes(response.status)) throw httpError(response.status);
    return CIRerunFailedWorkflowResultSchema.parse(makeCIEvidence("github-actions", this.#clock(), { runId: input.runId, requestId: "operator-approved", accepted: true, action: "rerun-failed-jobs" }));
  }

  private async getJson(path: string, repository: string): Promise<Record<string, unknown>> {
    const response = await this.request(path, "GET", repository);
    if (!response.ok) throw httpError(response.status);
    const text = await response.text();
    if (text.length > MAX_RESPONSE_BYTES) throw new CIProviderError("malformed");
    try {
      const value: unknown = JSON.parse(text);
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
      return value as Record<string, unknown>;
    } catch { throw new CIProviderError("malformed"); }
  }

  private async followLogRedirect(response: Response, repository: string): Promise<Response> {
    const location = response.headers.get("location");
    if (location === null) throw new CIProviderError("malformed");
    let target: URL;
    try { target = new URL(location); } catch { throw new CIProviderError("malformed"); }
    if (target.protocol !== "https:" || target.port !== "" || target.username !== "" || target.password !== "" || !isGitHubActionsLogHost(target.hostname)) {
      throw new CIProviderError("permission");
    }
    return this.#fetch(target, {
      method: "GET",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    }).catch(() => { throw new CIProviderError("unavailable"); });
  }

  private async request(path: string, method: "GET" | "POST", repository: string, redirect: "error" | "manual" = "error"): Promise<Response> {
    const token = await this.#tokenProvider.getToken(repository);
    const init: RequestInit = {
      method,
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "x-github-api-version": GITHUB_API_VERSION,
      },
      redirect,
      signal: AbortSignal.timeout(10_000),
    };
    return this.#fetch(`${this.#apiBaseUrl}${path}`, init).catch(() => { throw new CIProviderError("unavailable"); });
  }
}

function isRedirect(status: number): boolean { return status >= 300 && status < 400; }
function isGitHubActionsLogHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return normalized === "pipelines.actions.githubusercontent.com"
    || normalized === "results-receiver.actions.githubusercontent.com"
    || normalized.endsWith(".blob.core.windows.net");
}
function trustedGitHubApiBase(value: string | undefined): string {
  const url = new URL(value ?? "https://api.github.com");
  if (url.protocol !== "https:" || url.hostname !== "api.github.com" || url.port !== "" || url.username !== "" || url.password !== "" || (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("GitHub API base URL is not trusted");
  }
  return "https://api.github.com";
}

function encode(value: string): string { return encodeURIComponent(value); }
function firstRun(value: Record<string, unknown>): unknown { return arrayField(value, "workflow_runs")[0]; }
function arrayField(value: Record<string, unknown>, key: string): unknown[] {
  const field = value[key];
  if (!Array.isArray(field)) throw new CIProviderError("malformed");
  return field;
}
function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CIProviderError("malformed");
  return value as Record<string, unknown>;
}
function stringField(value: Record<string, unknown>, key: string): string {
  if (typeof value[key] !== "string" || value[key].length === 0) throw new CIProviderError("malformed");
  return value[key];
}
function normalizeRun(value: unknown, repository: string, workflow: string) {
  const raw = record(value);
  const id = typeof raw.id === "number" || typeof raw.id === "string" ? String(raw.id) : "";
  const status = raw.status;
  const conclusion = raw.conclusion === null ? null : raw.conclusion;
  if (!/^\d{1,20}$/.test(id) || !["queued", "in_progress", "completed"].includes(String(status)) || (conclusion !== null && !["success", "failure", "cancelled", "skipped", "neutral", "timed_out", "action_required"].includes(String(conclusion)))) throw new CIProviderError("malformed");
  const createdAt = new Date(stringField(raw, "created_at"));
  const updatedAt = new Date(stringField(raw, "updated_at"));
  const runAttempt = raw.run_attempt;
  const sha = stringField(raw, "head_sha").toLowerCase();
  if (typeof runAttempt !== "number" || !Number.isInteger(runAttempt) || runAttempt < 1 || !/^[a-f0-9]{40}$/.test(sha) || Number.isNaN(createdAt.getTime()) || Number.isNaN(updatedAt.getTime())) throw new CIProviderError("malformed");
  return { id, repository, workflow, status, conclusion, runAttempt, event: stringField(raw, "event"), ref: stringField(raw, "head_branch"), sha, createdAt: createdAt.toISOString(), updatedAt: updatedAt.toISOString() };
}
function normalizeJob(value: unknown) {
  const raw = record(value);
  const id = typeof raw.id === "number" || typeof raw.id === "string" ? String(raw.id) : "";
  const name = stringField(raw, "name");
  const status = raw.status;
  const conclusion = raw.conclusion;
  if (!/^\d{1,20}$/.test(id) || !["queued", "in_progress", "completed"].includes(String(status)) || !["success", "failure", "cancelled", "skipped", "neutral", "timed_out", "action_required"].includes(String(conclusion))) throw new CIProviderError("malformed");
  const steps = Array.isArray(raw.steps) ? raw.steps.flatMap((step) => {
    try { const value = record(step); return typeof value.name === "string" && value.conclusion !== "success" ? [value.name] : []; } catch { return []; }
  }) : [];
  return { id, name, status, conclusion, category: classifyFailure(name, ...steps), failedSteps: steps.slice(0, 50) };
}
function freshness(updatedAt: string, clock: () => Date, maxAgeMs: number): "fresh" | "stale" | "unknown" {
  const age = clock().getTime() - Date.parse(updatedAt);
  if (!Number.isFinite(age) || age < 0) return "unknown";
  return age <= maxAgeMs ? "fresh" : "stale";
}
function httpError(status: number): CIProviderError {
  return new CIProviderError(status === 401 || status === 403 ? "permission" : "unavailable");
}
function remediationTitle(category: string): string { return `${category} remediation review`; }
function remediationSteps(category: string): string[] {
  const steps: Record<string, string[]> = {
    build: ["Inspect the bounded build failure and compiler diagnostics", "Run the same build check locally from the pinned lockfile"],
    test: ["Inspect the failed test names and first failing assertion", "Reproduce the focused test before changing code"],
    lint: ["Inspect the reported lint or formatting rule", "Run the repository lint gate on the affected files"],
    dependency: ["Review the dependency or lockfile change", "Update only through the repository dependency policy"],
    deployment: ["Confirm the deployment workflow inputs and environment state", "Escalate to the deployment owner; this tool does not deploy"],
    "infrastructure-connectivity": ["Check the named endpoint or connectivity evidence", "Verify network policy and provider availability outside this tool"],
    permission: ["Check the declared GitHub App installation permission", "Ask an operator to correct access; this tool does not change trust"],
    unknown: ["Inspect the bounded failed-job evidence", "Escalate when the failure class remains unknown"],
  };
  return steps[category] ?? steps.unknown ?? ["Inspect the bounded failure evidence"];
}
