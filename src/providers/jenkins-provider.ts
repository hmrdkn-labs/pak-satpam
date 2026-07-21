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
const JENKINS_PROVIDER_NAME = "jenkins" as const;

type JsonRecord = Record<string, unknown>;

export interface JenkinsProviderOptions {
  /** Origin or reverse-proxy base URL. Use endpoint for structured configuration. */
  readonly baseUrl?: string;
  /** Origin plus base path, kept separate to prevent complete URL/path ambiguity. */
  readonly endpoint?: CIProviderEndpoint;
  /** Optional extra job segment appended only when set; workflow is the full multibranch job path (folder[/branch]). */
  readonly branch?: string;
  /** Jenkins API token authentication; anonymous read access remains supported. */
  readonly username?: string;
  readonly token?: string;
  readonly tokenFile?: string;
  readonly fetch: typeof globalThis.fetch;
  readonly clock?: () => Date;
  readonly maxFreshnessMs?: number;
  readonly providerName?: CIProviderName;
  readonly allowInsecureHttp?: boolean;
}

/** Read-only Jenkins adapter. The rerun port is deliberately disabled. */
export class JenkinsProvider implements CIProvider {
  readonly ciProviderType = "jenkins" as const;
  matchesWorkflow(allowlistEntry: string, workflow: string): boolean {
    return workflow === allowlistEntry || workflow.startsWith(allowlistEntry + "/");
  }
  readonly #endpoint: CIProviderEndpoint;
  readonly #fetch: typeof globalThis.fetch;
  readonly #clock: () => Date;
  readonly #maxFreshnessMs: number;
  readonly #branch: string | undefined;
  readonly #authorization: string | undefined;
  readonly #providerName: string;
  constructor(options: JenkinsProviderOptions) {
    this.#endpoint = configuredEndpoint(options.baseUrl, options.endpoint, "Jenkins");
    assertCIProviderTransport(this.#endpoint, {
      providerLabel: "Jenkins",
      credentialed: options.username !== undefined || options.token !== undefined || options.tokenFile !== undefined,
      ...(options.allowInsecureHttp === undefined ? {} : { allowInsecureHttp: options.allowInsecureHttp }),
    });
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? (() => new Date());
    this.#maxFreshnessMs = options.maxFreshnessMs ?? 5 * 60_000;
    this.#branch = options.branch;
    this.#authorization = basicAuthorization(options);
    this.#providerName = CIProviderNameSchema.parse(options.providerName ?? JENKINS_PROVIDER_NAME);
  }

  async getWorkflowStatus(input: CIWorkflowStatusInput): Promise<CIWorkflowStatusResult> {
    const build = await this.getBuild(input.workflow, input.runId);
    const run = normalizeBuild(build, input.repo, input.workflow, input.runId);
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
    const response = await this.request(buildPath(input.workflow, this.#branch, input.runId, "consoleText"));
    if (!response.ok) throw httpError(response.status);
    const { text: rawText, truncated: bytesTruncated } = await boundedText(response);
    const rawLines = rawText.split(/\r?\n/).filter((line) => line.length > 0);
    const linesBeforeSelect = bytesTruncated && rawLines.length > 0 ? rawLines.slice(1) : rawLines;
    const lineCountBeforeSelect = linesBeforeSelect.length;
    const selected = linesBeforeSelect
      .slice(Math.max(0, lineCountBeforeSelect - Math.min(input.maxLines, 200)))
      .map((line, index) => ({ sequence: index + 1, ...redactText(line) }));
    const lines = selected.map(({ sequence, text }) => ({ sequence, text }));
    return CILogEvidenceResultSchema.parse(makeCIEvidence(this.#providerName, this.#clock(), {
      runId: input.runId,
      jobId: input.jobId,
      jobName: input.workflow,
      available: true,
      lines,
      sha256: createHash("sha256").update(lines.map((line) => line.text).join("\n")).digest("hex"),
    }, {
      truncated: bytesTruncated || lineCountBeforeSelect > selected.length || selected.some((line) => line.truncated),
      redactionsApplied: selected.some((line) => line.redactionsApplied),
    }));
  }

  async getRemediationPlan(input: CIRemediationPlanInput): Promise<CIRemediationPlanResult> {
    const analysis = await this.getFailedJobAnalysis(input);
    const actions = [...new Map(analysis.data.failedJobs.map((job) => [job.category, {
      category: job.category,
      title: `${job.category} remediation review`,
      steps: ["Inspect the bounded Jenkins failure evidence", "Reproduce the focused check before changing code"],
      runbook: `docs/ci-cd-runbook.md#${job.category}`,
    }])).values()];
    return CIRemediationPlanResultSchema.parse(makeCIEvidence(this.#providerName, this.#clock(), {
      runId: input.runId,
      dryRun: true,
      actions,
    }, { freshness: analysis.freshness, warnings: analysis.warnings, redactionsApplied: analysis.redactionsApplied }));
  }

  async rerunFailedWorkflow(_input: { readonly repo: string; readonly workflow: string; readonly runId: string }): Promise<never> {
    throw new CIProviderError("permission");
  }

  private async getBuild(workflow: string, runId?: string): Promise<JsonRecord> {
    const response = await this.request(buildPath(workflow, this.#branch, runId === undefined ? "lastBuild" : runId, "api/json"));
    return parseJson(response);
  }

  private async request(path: string): Promise<Response> {
    try {
      return await this.#fetch(resolveCIProviderUrl(this.#endpoint, path), {
        method: "GET",
        headers: {
          accept: "application/json, text/plain",
          ...(this.#authorization === undefined ? {} : { authorization: this.#authorization }),
        },
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

function basicAuthorization(options: JenkinsProviderOptions): string | undefined {
  if (options.token !== undefined && options.tokenFile !== undefined) throw new Error("Configure one Jenkins token source");
  let token = options.token;
  if (options.tokenFile !== undefined) {
    const metadata = statSync(options.tokenFile);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > 4 * 1_024 || (metadata.mode & 0o077) !== 0) {
      throw new Error("Invalid Jenkins token file");
    }
    token = readFileSync(options.tokenFile, "utf8").trim();
  }
  if (token === undefined && options.username === undefined) return undefined;
  if (options.username === undefined || token === undefined || options.username.length === 0 || token.length === 0) {
    throw new Error("Jenkins Basic auth requires username and token");
  }
  return `Basic ${Buffer.from(`${options.username}:${token}`, "utf8").toString("base64")}`;
}

function buildPath(workflow: string, branch: string | undefined, ...parts: string[]): string {
  const segments = workflow.split("/");
  if (segments.length === 0 || segments.some((segment) => segment.length === 0 || segment === "." || segment === "..") || (branch !== undefined && (branch.length === 0 || branch === "." || branch === ".."))) throw new CIProviderError("malformed");
  const jobSegments = branch === undefined ? segments : [...segments, branch];
  const endpoint = parts.pop();
  const path = `/${jobSegments.map((segment) => `job/${encodeURIComponent(segment)}`).join("/")}/${parts.map((part) => encodeURIComponent(part)).join("/")}`;
  return endpoint === undefined ? path : `${path}/${endpoint}`;
}

function parseJson(response: Response): Promise<JsonRecord> {
  return response.ok
    ? response.text().then((text) => {
        if (text.length > MAX_RESPONSE_BYTES) throw new CIProviderError("malformed");
        try {
          const value: unknown = JSON.parse(text);
          if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
          return value as JsonRecord;
        } catch {
          throw new CIProviderError("malformed");
        }
      })
    : Promise.reject(httpError(response.status));
}

async function boundedText(response: Response): Promise<{ text: string; truncated: boolean }> {
  const text = await response.text();
  if (text.length > MAX_RESPONSE_BYTES) return { text: text.slice(text.length - MAX_RESPONSE_BYTES), truncated: true };
  return { text, truncated: false };
}

function normalizeBuild(raw: JsonRecord, repository: string, workflow: string, requestedRunId?: string): CIWorkflowRun {
  const nativeId = raw.number ?? raw.id ?? requestedRunId;
  const id = typeof nativeId === "number" || typeof nativeId === "string" ? String(nativeId) : "";
  if (!CIProviderNativeIdSchema.safeParse(id).success) throw new CIProviderError("malformed");
  const building = raw.building === true;
  const result = raw.result;
  const conclusion = building ? null : result === "SUCCESS" ? "success" : result === "ABORTED" ? "cancelled" : result === null || result === undefined ? "unknown" : "failure";
  const timestamp = typeof raw.timestamp === "number" ? new Date(raw.timestamp) : undefined;
  if (timestamp === undefined || Number.isNaN(timestamp.getTime())) throw new CIProviderError("malformed");
  const updated = new Date(timestamp.getTime() + (typeof raw.duration === "number" ? Math.max(0, raw.duration) : 0));
  return {
    id,
    repository,
    workflow,
    status: building ? "in_progress" : "completed",
    conclusion,
    runAttempt: 1,
    event: "jenkins",
    ref: buildRef(raw) ?? "unknown",
    sha: buildSha(raw),
    createdAt: timestamp.toISOString(),
    updatedAt: updated.toISOString(),
  };
}

function buildSha(raw: JsonRecord): string {
  const actions = Array.isArray(raw.actions) ? raw.actions : [];
  const values = actions.flatMap((action) => {
    if (action === null || typeof action !== "object" || Array.isArray(action)) return [];
    const record = action as JsonRecord;
    const revision = record.lastBuiltRevision;
    if (revision !== null && typeof revision === "object" && !Array.isArray(revision) && typeof (revision as JsonRecord).SHA1 === "string") return [(revision as JsonRecord).SHA1];
    return Array.isArray(record.parameters) ? record.parameters.flatMap((parameter) => parameter !== null && typeof parameter === "object" && !Array.isArray(parameter) && typeof (parameter as JsonRecord).value === "string" && /(?:sha|commit)/i.test(String((parameter as JsonRecord).name)) ? [(parameter as JsonRecord).value] : []) : [];
  });
  const sha = values.find((value) => typeof value === "string" && /^[a-f0-9]{40}$/i.test(value));
  return typeof sha === "string" ? sha.toLowerCase() : ZERO_SHA;
}

function buildRef(raw: JsonRecord): string | undefined {
  for (const key of ["branchName", "branch", "ref"]) {
    if (typeof raw[key] === "string" && raw[key].length > 0) return raw[key] as string;
  }
  if (typeof raw.displayName === "string" && raw.displayName.length > 0 && !/^#\d+$/.test(raw.displayName)) return raw.displayName;
  const actions = Array.isArray(raw.actions) ? raw.actions : [];
  for (const action of actions) {
    if (action !== null && typeof action === "object" && !Array.isArray(action)) {
      const parameters = (action as JsonRecord).parameters;
      if (Array.isArray(parameters)) {
        const branch = parameters.find((parameter) => parameter !== null && typeof parameter === "object" && !Array.isArray(parameter) && /branch/i.test(String((parameter as JsonRecord).name)) && typeof (parameter as JsonRecord).value === "string");
        if (branch !== undefined && typeof (branch as JsonRecord).value === "string") return String((branch as JsonRecord).value);
      }
    }
  }
  return undefined;
}

function freshness(updatedAt: string, clock: () => Date, maxAgeMs: number): "fresh" | "stale" | "unknown" {
  const age = clock().getTime() - Date.parse(updatedAt);
  if (!Number.isFinite(age) || age < 0) return "unknown";
  return age <= maxAgeMs ? "fresh" : "stale";
}

function httpError(status: number): CIProviderError {
  return new CIProviderError(status === 401 || status === 403 ? "permission" : status === 404 ? "malformed" : "unavailable");
}
