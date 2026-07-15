import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import {
  CIFailedJobAnalysisResultSchema,
  CILogEvidenceResultSchema,
  CIRemediationPlanResultSchema,
  CIWorkflowStatusResultSchema,
  classifyFailure,
  makeCIEvidence,
  type CIFailedJobAnalysisInput,
  type CIFailedJobAnalysisResult,
  type CILogEvidenceInput,
  type CILogEvidenceResult,
  type CIRemediationPlanInput,
  type CIRemediationPlanResult,
  type CIWorkflowStatusInput,
  type CIWorkflowStatusResult,
  type CIWorkflowRun,
} from "../domain/ci-schemas.js";
import { CIProviderNativeIdSchema } from "../domain/ci-schemas.js";
import {
  assertCIProviderTransport,
  ciProviderEndpointFromUrl,
  normalizeCIProviderEndpoint,
  resolveCIProviderUrl,
  type CIProviderEndpoint,
  type CIProviderName,
  CIProviderNameSchema,
} from "../domain/ci-provider-contracts.js";
import { redactText } from "../ci/redaction.js";
import { CIProviderError, type CIProvider } from "./ci-provider.js";

const MAX_RESPONSE_BYTES = 2 * 1_024 * 1_024;
const ZERO_SHA = "0".repeat(40);
const BITBUCKET_PROVIDER_NAME = "bitbucket-cloud" as const;
type JsonRecord = Record<string, unknown>;

export interface BitbucketCommitStatus {
  readonly key: string;
  readonly state: string;
  readonly name?: string;
  readonly description?: string;
}

export interface BitbucketPullRequestStatus {
  readonly id: string;
  readonly state: string;
  readonly title?: string;
  readonly source?: string;
  readonly destination?: string;
}

export interface BitbucketProviderOptions {
  /** Origin or reverse-proxy base URL. Use endpoint for structured configuration. */
  readonly baseUrl?: string;
  /** Origin plus base path, kept separate to prevent complete URL/path ambiguity. */
  readonly endpoint?: CIProviderEndpoint;
  /** A 0600 file containing username:token, or a token when username is set. */
  readonly tokenFile?: string;
  readonly username?: string;
  readonly token?: string;
  readonly fetch: typeof globalThis.fetch;
  readonly clock?: () => Date;
  readonly maxFreshnessMs?: number;
  readonly providerName?: CIProviderName;
}

/** Read-only Bitbucket Cloud adapter. Bitbucket Data Center is not supported. */
export class BitbucketProvider implements CIProvider {
  readonly ciProviderType = "bitbucket" as const;
  readonly #endpoint: CIProviderEndpoint;
  readonly #authorization: string;
  readonly #fetch: typeof globalThis.fetch;
  readonly #clock: () => Date;
  readonly #maxFreshnessMs: number;
  readonly #providerName: string;

  constructor(options: BitbucketProviderOptions) {
    this.#endpoint = configuredEndpoint(options.baseUrl, options.endpoint, "Bitbucket");
    this.#authorization = basicAuthorization(options);
    assertCIProviderTransport(this.#endpoint, { providerLabel: "Bitbucket", credentialed: true });
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? (() => new Date());
    this.#maxFreshnessMs = options.maxFreshnessMs ?? 5 * 60_000;
    this.#providerName = CIProviderNameSchema.parse(options.providerName ?? BITBUCKET_PROVIDER_NAME);
  }

  async getWorkflowStatus(input: CIWorkflowStatusInput): Promise<CIWorkflowStatusResult> {
    const raw = await this.pipeline(input.repo, input.runId);
    const run = normalizePipeline(raw, input.repo, input.workflow, input.runId);
    return CIWorkflowStatusResultSchema.parse(makeCIEvidence(this.#providerName, this.#clock(), { run }, {
      freshness: freshness(run.updatedAt, this.#clock, this.#maxFreshnessMs),
    }));
  }

  async getFailedJobAnalysis(input: CIFailedJobAnalysisInput): Promise<CIFailedJobAnalysisResult> {
    const status = await this.getWorkflowStatus(input);
    const run = status.data.run;
    const failed = run.conclusion !== "success" && run.conclusion !== "skipped" && run.conclusion !== "neutral";
    const failedJobs = failed
      ? [{ id: run.id, name: run.workflow, status: run.status, conclusion: run.conclusion ?? "unknown", category: classifyFailure(run.workflow, run.conclusion ?? "unknown"), failedSteps: [] }]
      : [];
    const categorySummary = Object.fromEntries(
      ["build", "test", "lint", "dependency", "deployment", "infrastructure-connectivity", "permission", "unknown"].map((category) => [category, failedJobs.filter((job) => job.category === category).length]),
    );
    return CIFailedJobAnalysisResultSchema.parse({ ...status, data: { run, failedJobs, categorySummary } });
  }

  async getLogEvidence(input: CILogEvidenceInput): Promise<CILogEvidenceResult> {
    const response = await this.request(`/repositories/${repositoryPath(input.repo)}/pipelines/${encodeURIComponent(input.runId)}/steps/${encodeURIComponent(input.jobId)}/log`);
    if (!response.ok) throw httpError(response.status);
    const raw = await boundedText(response);
    const rawLines = raw.split(/\r?\n/).filter((line) => line.length > 0);
    const selected = rawLines.slice(0, Math.min(input.maxLines, 200)).map((line, index) => ({ sequence: index + 1, ...redactText(line) }));
    const lines = selected.map(({ sequence, text }) => ({ sequence, text }));
    return CILogEvidenceResultSchema.parse(makeCIEvidence(this.#providerName, this.#clock(), {
      runId: input.runId,
      jobId: input.jobId,
      jobName: input.workflow,
      available: true,
      lines,
      sha256: createHash("sha256").update(lines.map((line) => line.text).join("\n")).digest("hex"),
    }, { truncated: rawLines.length > selected.length || selected.some((line) => line.truncated), redactionsApplied: selected.some((line) => line.redactionsApplied) }));
  }

  async getRemediationPlan(input: CIRemediationPlanInput): Promise<CIRemediationPlanResult> {
    const analysis = await this.getFailedJobAnalysis(input);
    const actions = [...new Map(analysis.data.failedJobs.map((job) => [job.category, {
      category: job.category,
      title: `${job.category} remediation review`,
      steps: ["Inspect the bounded Bitbucket failure evidence", "Reproduce the focused check before changing code"],
      runbook: `docs/ci-cd-runbook.md#${job.category}`,
    }])).values()];
    return CIRemediationPlanResultSchema.parse(makeCIEvidence(this.#providerName, this.#clock(), { runId: input.runId, dryRun: true, actions }, {
      freshness: analysis.freshness,
      warnings: analysis.warnings,
      redactionsApplied: analysis.redactionsApplied,
    }));
  }

  async rerunFailedWorkflow(_input: { readonly repo: string; readonly workflow: string; readonly runId: string }): Promise<never> {
    throw new CIProviderError("permission");
  }

  /** Read-only commit status endpoint for callers that already have a CI evidence boundary. */
  async getCommitStatus(repository: string, commit: string): Promise<readonly BitbucketCommitStatus[]> {
    const value = await this.json(`/repositories/${repositoryPath(repository)}/commit/${encodeURIComponent(commit)}/statuses`);
    const values = Array.isArray(value.values) ? value.values : [];
    return values.flatMap((item) => {
      if (item === null || typeof item !== "object" || Array.isArray(item)) return [];
      const record = item as JsonRecord;
      if (typeof record.key !== "string" || typeof record.state !== "string") return [];
      return [{
        key: record.key.slice(0, 128),
        state: record.state.slice(0, 64),
        ...(typeof record.name === "string" ? { name: record.name.slice(0, 256) } : {}),
        ...(typeof record.description === "string" ? { description: redactText(record.description, 512).text } : {}),
      }];
    }).slice(0, 100);
  }

  /** Read-only pull-request metadata endpoint. */
  async getPullRequestStatus(repository: string, pullRequest: string): Promise<BitbucketPullRequestStatus> {
    const value = await this.json(`/repositories/${repositoryPath(repository)}/pullrequests/${encodeURIComponent(pullRequest)}`);
    if ((typeof value.id !== "number" && typeof value.id !== "string") || typeof value.state !== "string") throw new CIProviderError("malformed");
    const source = value.source !== null && typeof value.source === "object" && !Array.isArray(value.source) ? value.source as JsonRecord : undefined;
    const destination = value.destination !== null && typeof value.destination === "object" && !Array.isArray(value.destination) ? value.destination as JsonRecord : undefined;
    return {
      id: String(value.id),
      state: value.state.slice(0, 64),
      ...(typeof value.title === "string" ? { title: value.title.slice(0, 512) } : {}),
      ...(typeof source?.branch === "object" && source.branch !== null && !Array.isArray(source.branch) && typeof (source.branch as JsonRecord).name === "string" ? { source: String((source.branch as JsonRecord).name).slice(0, 256) } : {}),
      ...(typeof destination?.branch === "object" && destination.branch !== null && !Array.isArray(destination.branch) && typeof (destination.branch as JsonRecord).name === "string" ? { destination: String((destination.branch as JsonRecord).name).slice(0, 256) } : {}),
    };
  }

  /** Return bounded unified-diff hunks without exposing the raw provider payload. */
  async getDiffHunks(repository: string, pullRequest: string): Promise<{ readonly hunks: readonly string[]; readonly truncated: boolean }> {
    const response = await this.request(`/repositories/${repositoryPath(repository)}/pullrequests/${encodeURIComponent(pullRequest)}/diff`);
    if (!response.ok) throw httpError(response.status);
    const text = await boundedText(response);
    const hunks = text.split(/\r?\n(?=@@)/).filter((hunk) => hunk.startsWith("@@")).slice(0, 100).map((hunk) => redactText(hunk, 4_096).text);
    return { hunks, truncated: hunks.length >= 100 };
  }

  private async pipeline(repository: string, runId?: string): Promise<JsonRecord> {
    const path = runId === undefined
      ? `/repositories/${repositoryPath(repository)}/pipelines/?pagelen=1&sort=-created_on`
      : `/repositories/${repositoryPath(repository)}/pipelines/${encodeURIComponent(runId)}`;
    const value = await this.json(path);
    if (runId === undefined) {
      const values = Array.isArray(value.values) ? value.values : [];
      if (values.length === 0 || values[0] === null || typeof values[0] !== "object" || Array.isArray(values[0])) throw new CIProviderError("malformed");
      return values[0] as JsonRecord;
    }
    return value;
  }

  private async json(path: string): Promise<JsonRecord> {
    const response = await this.request(path);
    if (!response.ok) throw httpError(response.status);
    const text = await response.text();
    if (text.length > MAX_RESPONSE_BYTES) throw new CIProviderError("malformed");
    try {
      const value: unknown = JSON.parse(text);
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
      return value as JsonRecord;
    } catch {
      throw new CIProviderError("malformed");
    }
  }

  private async request(path: string): Promise<Response> {
    try {
      return await this.#fetch(resolveCIProviderUrl(this.#endpoint, path), {
        method: "GET",
        headers: { accept: "application/json, text/plain", authorization: this.#authorization },
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new CIProviderError("unavailable");
    }
  }
}

function configuredEndpoint(baseUrl: string | undefined, endpoint: CIProviderEndpoint | undefined, label: string): CIProviderEndpoint {
  if ((baseUrl === undefined) === (endpoint === undefined)) throw new Error(`${label} requires exactly one baseUrl or endpoint`);
  return endpoint === undefined ? ciProviderEndpointFromUrl(baseUrl as string) : normalizeCIProviderEndpoint(endpoint);
}

function basicAuthorization(options: BitbucketProviderOptions): string {
  let value = options.token;
  if (options.tokenFile !== undefined) {
    const metadata = statSync(options.tokenFile);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > 4 * 1_024 || (metadata.mode & 0o077) !== 0) throw new Error("Invalid Bitbucket token file");
    value = readFileSync(options.tokenFile, "utf8").trim();
  }
  if (value === undefined || value.length === 0) throw new Error("Bitbucket token is required");
  const credential = options.username === undefined ? value : `${options.username}:${value}`;
  if (!credential.includes(":")) throw new Error("Bitbucket Basic auth requires username:token in the token file");
  return `Basic ${Buffer.from(credential, "utf8").toString("base64")}`;
}

function repositoryPath(repository: string): string {
  const [workspace, slug, extra] = repository.split("/");
  if (workspace === undefined || slug === undefined || extra !== undefined || workspace.length === 0 || slug.length === 0) throw new CIProviderError("malformed");
  return `${encodeURIComponent(workspace)}/${encodeURIComponent(slug)}`;
}

function normalizePipeline(raw: JsonRecord, repository: string, workflow: string, requestedRunId?: string): CIWorkflowRun {
  const buildNumber = raw.build_number;
  const id = typeof buildNumber === "number" || typeof buildNumber === "string" ? String(buildNumber) : requestedRunId ?? "";
  if (!CIProviderNativeIdSchema.safeParse(id).success) throw new CIProviderError("malformed");
  const state = raw.state !== null && typeof raw.state === "object" && !Array.isArray(raw.state) ? raw.state as JsonRecord : {};
  const stateName = typeof state.name === "string" ? state.name.toUpperCase() : "UNKNOWN";
  const result = state.result !== null && typeof state.result === "object" && !Array.isArray(state.result) ? state.result as JsonRecord : {};
  const resultName = typeof result.name === "string" ? result.name.toUpperCase() : stateName;
  const conclusion = pipelineConclusion(stateName, resultName);
  const status = ["PENDING", "IN_PROGRESS", "PAUSED", "RUNNING"].includes(stateName) ? "in_progress" : "completed";
  const created = timestamp(raw.created_on);
  if (created === undefined) throw new CIProviderError("malformed");
  const updated = timestamp(raw.completed_on) ?? created;
  const target = raw.target !== null && typeof raw.target === "object" && !Array.isArray(raw.target) ? raw.target as JsonRecord : {};
  const commit = target.commit !== null && typeof target.commit === "object" && !Array.isArray(target.commit) ? target.commit as JsonRecord : {};
  const ref = target.ref_name;
  const sha = typeof commit.hash === "string" && /^[a-f0-9]{40}$/i.test(commit.hash) ? commit.hash.toLowerCase() : ZERO_SHA;
  return { id, repository, workflow, status, conclusion, runAttempt: 1, event: BITBUCKET_PROVIDER_NAME, ref: typeof ref === "string" && ref.length > 0 ? ref : "unknown", sha, createdAt: created, updatedAt: updated };
}

function pipelineConclusion(stateName: string, resultName: string): CIWorkflowRun["conclusion"] {
  if (["PENDING", "IN_PROGRESS", "RUNNING"].includes(stateName)) return null;
  if (stateName === "PAUSED") return "action_required";
  if (resultName === "SUCCESSFUL") return "success";
  if (["FAILED", "ERROR"].includes(resultName)) return "failure";
  if (["STOPPED", "HALTED"].includes(resultName) || ["STOPPED", "HALTED"].includes(stateName)) return "cancelled";
  return "unknown";
}

function timestamp(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function freshness(updatedAt: string, clock: () => Date, maxAgeMs: number): "fresh" | "stale" | "unknown" {
  const age = clock().getTime() - Date.parse(updatedAt);
  if (!Number.isFinite(age) || age < 0) return "unknown";
  return age <= maxAgeMs ? "fresh" : "stale";
}

async function boundedText(response: Response): Promise<string> {
  const text = await response.text();
  if (text.length > MAX_RESPONSE_BYTES) throw new CIProviderError("malformed");
  return text;
}

function httpError(status: number): CIProviderError {
  return new CIProviderError(status === 401 || status === 403 ? "permission" : status === 404 ? "malformed" : "unavailable");
}
