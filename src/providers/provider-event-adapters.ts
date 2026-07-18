import { createHash } from "node:crypto";
import { z } from "zod";
import { classifyFailure, CIProviderNativeIdSchema } from "../domain/ci-schemas.js";
import { createGoal23EventEnvelope } from "../observer/event-envelope.js";
import {
  ProviderNormalizedEventSchema,
  PROVIDER_EVENT_SCHEMA_VERSION,
  type ProviderCapabilities,
  type ProviderNormalizedEvent,
} from "../domain/provider-event-schemas.js";
import { SCMFileStatusSchema } from "../scm/schemas.js";
import { redactText } from "../ci/redaction.js";

const DEFAULT_LIMITS = Object.freeze({ maxPayloadBytes: 64 * 1024, maxJobs: 50, maxDiff: 10, maxLogs: 50, maxMetrics: 20, maxTraces: 20 });
const FORBIDDEN_PROVIDER_KEYS = new Set(["authorization", "bearer", "cookie", "password", "private_key", "secret", "token", "webhook", "raw_payload", "raw_logs", "raw_messages"]);
type JsonRecord = Record<string, unknown>;
type ProviderKind = "github-actions" | "jenkins" | "bitbucket-pipelines";
type ProviderCollectionLimits = Readonly<Pick<Required<ProviderEventAdapterOptions>, "maxJobs" | "maxDiff" | "maxLogs" | "maxMetrics" | "maxTraces">>;

export interface ProviderEventAdapterOptions {
  readonly observedAt?: Date | string;
  readonly source?: "poll" | "webhook";
  readonly maxPayloadBytes?: number;
  readonly maxJobs?: number;
  readonly maxDiff?: number;
  readonly maxLogs?: number;
  readonly maxMetrics?: number;
  readonly maxTraces?: number;
  readonly includeGoal23Envelope?: boolean;
}

export class ProviderEventAdapterError extends Error {
  constructor(readonly code: "malformed" | "oversized" | "unsupported") {
    super(`Provider event ${code}`);
    this.name = "ProviderEventAdapterError";
  }
}

export function normalizeProviderEvent(provider: ProviderKind | string, payload: unknown, options: ProviderEventAdapterOptions = {}): ProviderNormalizedEvent {
  try {
    return normalizeProviderEventUnchecked(provider, payload, options);
  } catch (error) {
    if (error instanceof ProviderEventAdapterError) throw error;
    throw new ProviderEventAdapterError("malformed");
  }
}

function normalizeProviderEventUnchecked(provider: ProviderKind | string, payload: unknown, options: ProviderEventAdapterOptions): ProviderNormalizedEvent {
  if (provider === "gitlab" || provider === "gitlab-ci") throw new ProviderEventAdapterError("unsupported");
  if (provider !== "github-actions" && provider !== "jenkins" && provider !== "bitbucket-pipelines") throw new ProviderEventAdapterError("unsupported");
  const limits = { ...DEFAULT_LIMITS, ...options };
  if (!Number.isInteger(limits.maxPayloadBytes) || limits.maxPayloadBytes < 1_024 || limits.maxPayloadBytes > DEFAULT_LIMITS.maxPayloadBytes) throw new ProviderEventAdapterError("malformed");
  for (const key of ["maxJobs", "maxDiff", "maxLogs", "maxMetrics", "maxTraces"] as const) {
    if (!Number.isInteger(limits[key]) || limits[key] < 1 || limits[key] > DEFAULT_LIMITS[key]) throw new ProviderEventAdapterError("malformed");
  }
  let serialized: string;
  try { serialized = JSON.stringify(payload); } catch { throw new ProviderEventAdapterError("malformed"); }
  if (Buffer.byteLength(serialized, "utf8") > limits.maxPayloadBytes) throw new ProviderEventAdapterError("oversized");
  const sanitized = sanitizeProviderPayload(payload);
  const record = object(sanitized.value);
  const observedAt = iso(options.observedAt ?? new Date());
  const raw = provider === "github-actions" ? githubRoot(record) : record;
  const run = normalizeRun(provider, raw, record, observedAt);
  const jobs = normalizeJobs(provider, raw, limits.maxJobs);
  const diff = normalizeDiff(raw, limits.maxDiff);
  const logs = normalizeLogs(raw, jobs, limits.maxLogs);
  const metrics = normalizeMetrics(raw, limits.maxMetrics);
  const traces = normalizeTraces(raw, limits.maxTraces);
  const artifact = normalizeArtifact(raw);
  const links = normalizeLinks(raw, run);
  const redactionsApplied = sanitized.redactionsApplied;
  const truncated = sanitized.truncated || hasTruncatedProviderCollections(provider, raw, limits);
  const capabilities = capabilitiesFor(provider, { jobs, diff, logs, metrics, traces, artifact, links });
  const warnings = [
    ...(truncated ? [{ code: "provider-event-bounds", message: "Provider evidence was bounded" }] : []),
    ...(run.conclusion === "unknown" ? [{ code: "provider-conclusion-unknown", message: "Provider conclusion is explicitly unavailable" }] : []),
  ];
  const resultBase = {
    schemaVersion: PROVIDER_EVENT_SCHEMA_VERSION,
    provider,
    observedAt,
    run,
    commit: { available: true as const, value: run.sha },
    workflowInfo: { id: workflowId(raw, run.workflow), name: run.workflow, ref: run.ref, ...firstLink(links, "workflow") },
    jobs,
    diff,
    logs,
    metrics,
    traces,
    artifact,
    links,
    capabilities,
    freshness: "fresh" as const,
    truncated,
    redactionsApplied,
    warnings,
  };
  const parsed = ProviderNormalizedEventSchema.parse(resultBase);
  if (options.includeGoal23Envelope !== false && run.status === "completed" && run.conclusion !== null && run.conclusion !== "unknown") {
    const digest = artifact.digest.available ? artifact.digest.value : undefined;
    const envelope = createGoal23EventEnvelope({
      eventId: `${run.repository}:${run.workflow}:${run.sha}:${run.conclusion}`,
      observedAt,
      source: options.source ?? "poll",
      providerClass: provider,
      repo: run.repository,
      workflow: run.workflow,
      runId: run.id,
      runAttempt: run.runAttempt,
      terminalConclusion: run.conclusion,
      outcome: run.conclusion,
      notification: run.conclusion === "success" ? "recovery" : "failure",
      severity: run.conclusion === "success" ? "green" : "red",
      threadId: `${run.repository}:${run.workflow}`,
      freshness: "fresh",
      updatedAt: run.updatedAt,
      correlation: { commitSha: run.sha, ...(digest === undefined ? {} : { artifactDigest: digest }), ...(traces[0] === undefined ? {} : { traceId: traces[0].spanDigest }) },
      warnings,
    });
    return ProviderNormalizedEventSchema.parse({ ...parsed, envelope });
  }
  return parsed;
}

export const normalizeGitHubActionsEvent = (payload: unknown, options?: ProviderEventAdapterOptions) => normalizeProviderEvent("github-actions", payload, options);
export const normalizeJenkinsEvent = (payload: unknown, options?: ProviderEventAdapterOptions) => normalizeProviderEvent("jenkins", payload, options);
export const normalizeBitbucketPipelineEvent = (payload: unknown, options?: ProviderEventAdapterOptions) => normalizeProviderEvent("bitbucket-pipelines", payload, options);
export const normalizeBitbucketPipelinesEvent = normalizeBitbucketPipelineEvent;
export const normalizeCIProviderEvent = normalizeProviderEvent;

function githubRoot(record: JsonRecord): JsonRecord {
  const run = object(record.workflow_run);
  return Object.keys(run).length === 0 ? record : { ...record, ...run, repository: record.repository ?? run.repository };
}

function normalizeRun(provider: ProviderKind, raw: JsonRecord, outer: JsonRecord, observedAt: string): ProviderNormalizedEvent["run"] {
  const source = provider === "github-actions" ? raw : raw;
  const native = provider === "jenkins" ? source.number ?? source.id : provider === "bitbucket-pipelines" ? source.build_number ?? source.id : source.id ?? source.run_id;
  const id = nativeId(native);
  const repository = requiredString(source.repository && typeof source.repository === "object" ? object(source.repository).full_name : source.repository ?? outer.repository);
  const workflowCandidate = provider === "jenkins" ? requiredString(source.workflow ?? source.job ?? source.jobName ?? source.fullDisplayName ?? source.displayName) : provider === "bitbucket-pipelines" ? requiredString(source.workflow ?? object(source.pipeline).name) : requiredString(source.path ?? object(source.workflow).path ?? source.name ?? source.workflow_name);
  const workflow = workflowCandidate.replace(/^\/?\.github\/workflows\//, "");
  const statusName = provider === "jenkins" ? source.building === true ? "in_progress" : source.building === false ? "completed" : requiredString(source.status) : provider === "bitbucket-pipelines" ? requiredString(object(source.state).name) : requiredString(source.status);
  const resultName = provider === "jenkins" ? source.result : provider === "bitbucket-pipelines" ? object(object(source.state).result).name : source.conclusion;
  const status = normalizeRunStatus(statusName, provider);
  const conclusion = status === "completed" ? normalizeConclusion(resultName ?? statusName, provider) : null;
  const target = object(source.target);
  const commitValue = provider === "bitbucket-pipelines" ? object(target.commit).hash : provider === "jenkins" ? jenkinsSha(source) : source.head_sha ?? source.sha;
  const sha = commit(commitValue);
  const ref = provider === "bitbucket-pipelines" ? requiredString(target.ref_name) : provider === "jenkins" ? requiredString(source.branchName ?? source.branch ?? source.ref) : requiredString(source.head_branch ?? source.ref);
  const createdValue = provider === "jenkins" ? source.timestamp : source.created_at ?? source.created_on ?? source.createdOn;
  const updatedValue = provider === "jenkins" && typeof source.timestamp === "number" && typeof source.duration === "number" ? source.timestamp + Math.max(0, source.duration) : provider === "jenkins" ? source.timestamp : source.updated_at ?? source.completed_on ?? source.completedAt;
  const createdAt = requiredTimestamp(createdValue);
  const updatedAt = requiredTimestamp(updatedValue);
  const runAttempt = provider === "github-actions" ? requiredPositiveInteger(source.run_attempt ?? source.runAttempt) : integer(source.run_attempt ?? source.runAttempt, 1);
  const event = provider === "github-actions" ? requiredString(source.event) : stringValue(source.event ?? source.trigger, provider);
  return { id, repository, workflow, status, conclusion, runAttempt, event, ref, sha, createdAt, updatedAt };
}

function normalizeJobs(provider: ProviderKind, raw: JsonRecord, max: number): ProviderNormalizedEvent["jobs"] {
  const source = provider === "github-actions" ? array(object(raw.jobs).jobs).concat(array(raw.jobs)) : provider === "jenkins" ? (array(raw.jobs).length > 0 ? array(raw.jobs) : jenkinsChangeJobs(raw)) : array(raw.steps).concat(array(raw.jobs));
  return source.slice(0, max).map((value, index) => {
    const item = object(value);
    const name = stringValue(item.name ?? item.displayName ?? item.stage, `job-${index + 1}`);
    const statusName = requiredString(item.status ?? object(item.state).name ?? item.state);
    const status = normalizeRunStatus(statusName, provider);
    const providerResult = item.conclusion ?? item.result ?? object(item.state).result;
    const conclusion = status === "completed" ? normalizeConclusion(object(providerResult).name ?? providerResult, provider) ?? "unknown" : "unknown";
    const failedSteps = array(item.failedSteps ?? item.steps).map((step) => typeof step === "string" ? redactText(step, 256).text : stringValue(object(step).name ?? object(step).displayName, "step")).slice(0, 50);
    return { id: nativeId(item.id ?? item.databaseId ?? item.number ?? `${index + 1}`), name, status, conclusion, category: classifyFailure(name, conclusion), failedSteps };
  }).sort((a, b) => a.id.localeCompare(b.id));
}

function normalizeDiff(raw: JsonRecord, max: number): ProviderNormalizedEvent["diff"] {
  const source = array(raw.files).concat(array(raw.changes)).concat(array(raw.diffstat));
  return source.slice(0, max).flatMap((value) => {
    const item = object(value);
    const path = stringValue(item.path ?? item.filename ?? item.file ?? object(item.new).path ?? object(item.old).path, "");
    if (path.length === 0 || path.startsWith("/") || path.split("/").some((part) => part === "..")) return [];
    const statusRaw = stringValue(item.status ?? item.changeType ?? item.editType ?? object(item.status).type, "modified").toLowerCase();
    const status = statusRaw === "removed" || statusRaw === "deleted" ? "removed" : statusRaw === "added" ? "added" : statusRaw === "renamed" ? "renamed" : "modified";
    return [{ path: redactText(path, 512).text, status: SCMFileStatusSchema.parse(status), additions: count(item.additions ?? item.lines_added), deletions: count(item.deletions ?? item.lines_removed), hunkCount: count(item.hunkCount ?? item.hunks ?? (typeof item.patch === "string" ? item.patch.split(/\r?\n(?=@@)/).filter(Boolean).length : 0), 100) }];
  }).sort((a, b) => a.path.localeCompare(b.path));
}

function normalizeLogs(raw: JsonRecord, jobs: ProviderNormalizedEvent["jobs"], max: number): ProviderNormalizedEvent["logs"] {
  const values = array(raw.logs).concat(array(raw.logReferences));
  const direct = typeof raw.log === "string" ? [{ jobId: jobs[0]?.id ?? "1", text: raw.log }] : [];
  return values.concat(direct).slice(0, max).flatMap((value, index) => {
    const item = typeof value === "string" ? { jobId: jobs[index]?.id ?? `${index + 1}`, text: value } : object(value);
    const text = typeof item.text === "string" ? item.text : typeof item.log === "string" ? item.log : "";
    const jobId = nativeId(item.jobId ?? item.id ?? jobs[index]?.id ?? `${index + 1}`);
    const sanitized = redactText(text, 64 * 1024).text;
    return [{ id: `log-${jobId}`, jobId, available: sanitized.length > 0, lineCount: sanitized.length === 0 ? 0 : Math.min(50, sanitized.split(/\r?\n/).length), sha256: sha256(sanitized), ...link(item.url ?? item.href) }];
  }).sort((a, b) => a.id.localeCompare(b.id));
}

function normalizeMetrics(raw: JsonRecord, max: number): ProviderNormalizedEvent["metrics"] {
  return array(raw.metrics).slice(0, max).flatMap((value) => {
    const item = object(value);
    const name = stringValue(item.name ?? item.metric, "");
    if (name.length === 0) return [];
    const state = ["normal", "degraded", "error", "unknown"].includes(String(item.state)) ? String(item.state) as "normal" | "degraded" | "error" | "unknown" : "unknown";
    return [{ name: redactText(name, 128).text, state, ...(number(item.value) === undefined ? {} : { value: number(item.value) }), ...(number(item.sampleCount) === undefined ? {} : { sampleCount: integer(item.sampleCount, 0) }), ...(typeof item.reference === "string" ? { reference: redactText(item.reference, 256).text } : {}) }];
  }).sort((a, b) => a.name.localeCompare(b.name));
}

function normalizeTraces(raw: JsonRecord, max: number): ProviderNormalizedEvent["traces"] {
  return array(raw.traces).slice(0, max).flatMap((value) => {
    const item = object(value);
    const digest = typeof item.spanDigest === "string" && /^[a-f0-9]{64}$/i.test(item.spanDigest) ? item.spanDigest.toLowerCase() : typeof item.id === "string" ? sha256(item.id) : "";
    if (digest.length === 0) return [];
    const status = ["ok", "error", "unknown"].includes(String(item.status)) ? String(item.status) as "ok" | "error" | "unknown" : "unknown";
    return [{ spanDigest: digest, durationMs: Math.min(86_400_000, Math.max(0, number(item.durationMs) ?? 0)), status, ...(typeof item.reference === "string" ? { reference: redactText(item.reference, 256).text } : {}) }];
  }).sort((a, b) => a.spanDigest.localeCompare(b.spanDigest));
}

function normalizeArtifact(raw: JsonRecord): ProviderNormalizedEvent["artifact"] {
  const direct = object(raw.artifact);
  const item = Object.keys(direct).length === 0 ? object(array(raw.artifacts)[0]) : direct;
  const digest = item.digest ?? item.artifact_digest ?? item.sha256;
  const digestBinding = digest === undefined ? { available: false as const, reason: "absent" as const } : typeof digest === "string" && /^(?:sha256:)?[a-f0-9]{64}$/i.test(digest) ? { available: true as const, value: digest.toLowerCase() } : { available: false as const, reason: "invalid" as const };
  return { ...(typeof item.name === "string" ? { name: redactText(item.name, 256).text } : {}), digest: digestBinding, ...urlField(item.reference ?? item.url ?? item.archive_download_url, "reference") };
}

function normalizeLinks(raw: JsonRecord, run: ProviderNormalizedEvent["run"]): ProviderNormalizedEvent["links"] {
  const links: ProviderNormalizedEvent["links"] = [];
  for (const value of array(raw.links)) {
    const item = object(value);
    const href = item.href ?? object(item.html).href ?? object(item.web).href;
    if (typeof href === "string" && safeUrl(href)) links.push({ kind: stringValue(item.kind, "run"), href });
  }
  const runLink = raw.html_url ?? raw.url ?? object(raw.links).html;
  if (typeof runLink === "string" && safeUrl(runLink)) links.push({ kind: "run", href: runLink });
  return links.filter((item, index, all) => all.findIndex((candidate) => candidate.kind === item.kind && candidate.href === item.href) === index).sort((a, b) => `${a.kind}:${a.href}`.localeCompare(`${b.kind}:${b.href}`)).slice(0, 10);
}

function capabilitiesFor(provider: ProviderKind, values: { jobs: unknown[]; diff: unknown[]; logs: unknown[]; metrics: unknown[]; traces: unknown[]; artifact: ProviderNormalizedEvent["artifact"]; links: unknown[] }): ProviderCapabilities {
  const providerMetrics = provider === "github-actions" || provider === "jenkins" || provider === "bitbucket-pipelines" ? "unsupported" as const : "unavailable" as const;
  return { status: "available", commit: "available", workflow: "available", jobs: values.jobs.length > 0 ? "available" : "unavailable", diff: values.diff.length > 0 ? "available" : "unavailable", logs: values.logs.length > 0 ? "available" : "unavailable", metrics: values.metrics.length > 0 ? "available" : providerMetrics, traces: values.traces.length > 0 ? "available" : providerMetrics, artifact: values.artifact.digest.available ? "available" : "unavailable", links: values.links.length > 0 ? "available" : "unavailable" };
}

function hasTruncatedProviderCollections(provider: ProviderKind, raw: JsonRecord, limits: ProviderCollectionLimits): boolean {
  const jobCount = provider === "github-actions" ? array(object(raw.jobs).jobs).length + array(raw.jobs).length : provider === "jenkins" ? Math.max(array(raw.jobs).length, jenkinsChangeJobs(raw).length) : array(raw.steps).length + array(raw.jobs).length;
  const diffCount = array(raw.files).length + array(raw.changes).length + array(raw.diffstat).length;
  const logCount = array(raw.logs).length + array(raw.logReferences).length + (typeof raw.log === "string" ? 1 : 0);
  return jobCount > limits.maxJobs || diffCount > limits.maxDiff || logCount > limits.maxLogs || array(raw.metrics).length > limits.maxMetrics || array(raw.traces).length > limits.maxTraces;
}

function normalizeConclusion(value: unknown, provider: ProviderKind): ProviderNormalizedEvent["run"]["conclusion"] {
  if (value === null || value === undefined || value === "") throw new ProviderEventAdapterError("malformed");
  const normalized = String(value).toLowerCase().replace(/[ -]/g, "_");
  if (["success", "successful", "passed", "pass"].includes(normalized)) return "success";
  if (["failure", "failed", "fail", "error", "unstable"].includes(normalized)) return "failure";
  if (["cancelled", "canceled", "aborted", "stopped", "halted"].includes(normalized)) return "cancelled";
  if (["timed_out", "timeout", "timedout"].includes(normalized)) return "timed_out";
  if (["skipped", "not_run"].includes(normalized)) return "skipped";
  if (["neutral"].includes(normalized)) return "neutral";
  if (["action_required", "manual", "paused"].includes(normalized)) return "action_required";
  if (normalized === "unknown") return "unknown";
  throw new ProviderEventAdapterError("malformed");
}

function normalizeRunStatus(value: string, provider: ProviderKind): ProviderNormalizedEvent["run"]["status"] {
  const normalized = value.toLowerCase().replace(/[ -]/g, "_");
  if (["queued", "pending", "created"].includes(normalized)) return "queued";
  if (["running", "in_progress", "waiting"].includes(normalized)) return "in_progress";
  if (["completed", "complete", "finished", "done"].includes(normalized)) return "completed";
  if (provider === "bitbucket-pipelines" && ["paused", "stopped", "halted"].includes(normalized)) return "completed";
  throw new ProviderEventAdapterError("malformed");
}

function nativeId(value: unknown): string { const id = typeof value === "number" || typeof value === "string" ? String(value) : ""; if (!CIProviderNativeIdSchema.safeParse(id).success) throw new ProviderEventAdapterError("malformed"); return id; }
function commit(value: unknown): string { if (typeof value !== "string" || !/^[a-f0-9]{40}$/i.test(value)) throw new ProviderEventAdapterError("malformed"); return value.toLowerCase(); }
function jenkinsSha(source: JsonRecord): unknown { for (const action of array(source.actions)) { const sha = object(object(action).lastBuiltRevision).SHA1; if (sha !== undefined) return sha; } return undefined; }
function jenkinsChangeJobs(raw: JsonRecord): unknown[] { return array(raw.changeSets).flatMap((set) => array(object(set).items).map((item) => ({ id: object(item).id ?? object(item).commitId ?? "change", name: "change-set", status: "completed", result: "success", steps: array(object(item).paths).map((path) => object(path).file) }))); }
function object(value: unknown): JsonRecord { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {}; }
function array(value: unknown): unknown[] { return Array.isArray(value) ? value : []; }
function stringValue(value: unknown, fallback: string): string { return typeof value === "string" && value.length > 0 ? value : fallback; }
function requiredString(value: unknown): string { if (typeof value !== "string" || value.length === 0) throw new ProviderEventAdapterError("malformed"); return value; }
function integer(value: unknown, fallback: number): number { return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 100 ? value : fallback; }
function requiredPositiveInteger(value: unknown): number { if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 100) throw new ProviderEventAdapterError("malformed"); return value; }
function count(value: unknown, max = 1_000_000): number { return typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.min(max, Math.floor(value)) : 0; }
function number(value: unknown): number | undefined { return typeof value === "number" && Number.isFinite(value) ? value : undefined; }
function requiredTimestamp(value: unknown): string { const date = typeof value === "number" ? new Date(value) : typeof value === "string" ? new Date(value) : new Date(Number.NaN); if (Number.isNaN(date.getTime())) throw new ProviderEventAdapterError("malformed"); return date.toISOString(); }
function iso(value: Date | string): string { const date = typeof value === "string" ? new Date(value) : value; if (Number.isNaN(date.getTime())) throw new ProviderEventAdapterError("malformed"); return date.toISOString(); }
function sha256(value: string): string { return createHash("sha256").update(value, "utf8").digest("hex"); }
function rawLogText(raw: JsonRecord, jobId: string): string { return array(raw.logs).concat(typeof raw.log === "string" ? [raw.log] : []).map((item) => typeof item === "string" ? item : object(item)).map((item) => typeof item === "string" ? item : String(object(item).text ?? object(item).log ?? "")).find((text) => text.length > 0 && jobId.length > 0) ?? ""; }
function logText(raw: JsonRecord, jobId: string): string { return redactText(rawLogText(raw, jobId), 64 * 1024).text; }
function safeUrl(value: string): boolean { try { const url = new URL(value); return (url.protocol === "https:" || url.protocol === "http:") && url.username === "" && url.password === ""; } catch { return false; } }
function link(value: unknown): { link?: string } { return typeof value === "string" && safeUrl(value) ? { link: value } : {}; }
function urlField(value: unknown, key: "reference"): { reference?: string } { return typeof value === "string" && safeUrl(value) ? { [key]: value } : {}; }
function workflowId(raw: JsonRecord, workflow: string): string { return nativeId(raw.workflow_id ?? raw.workflowId ?? raw.id ?? workflow); }
function firstLink(links: ProviderNormalizedEvent["links"], kind: string): { link?: string } { const found = links.find((item) => item.kind === kind); return found === undefined ? {} : { link: found.href }; }

function sanitizeProviderPayload(value: unknown, depth = 0): { value: unknown; redactionsApplied: boolean; truncated: boolean } {
  if (depth > 16) throw new ProviderEventAdapterError("malformed");
  if (typeof value === "string") {
    const result = redactText(value, 512);
    return { value: result.text, redactionsApplied: result.redactionsApplied, truncated: result.truncated };
  }
  if (Array.isArray(value)) {
    const children = value.map((child) => sanitizeProviderPayload(child, depth + 1));
    return { value: children.map((child) => child.value), redactionsApplied: children.some((child) => child.redactionsApplied), truncated: children.some((child) => child.truncated) };
  }
  if (value !== null && typeof value === "object") {
    const output: JsonRecord = {};
    let redactionsApplied = false;
    let truncated = false;
    for (const [key, child] of Object.entries(value)) {
      if (FORBIDDEN_PROVIDER_KEYS.has(key.toLowerCase())) throw new ProviderEventAdapterError("malformed");
      const sanitized = sanitizeProviderPayload(child, depth + 1);
      if (sanitized.value !== undefined) output[key] = sanitized.value;
      redactionsApplied ||= sanitized.redactionsApplied;
      truncated ||= sanitized.truncated;
    }
    return { value: output, redactionsApplied, truncated };
  }
  return { value, redactionsApplied: false, truncated: false };
}
