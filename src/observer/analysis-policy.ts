import { redactText } from "../ci/redaction.js";
import { z } from "zod";

/** The only tools an event-analysis callback may be given. This is data-only
 * policy metadata; the callback never receives a provider or an action port. */
export const ANALYSIS_TOOL_SURFACE = [
  "ci.workflow_status",
  "ci.failed_job_analysis",
  "ci.log_evidence",
  "ci.remediation_plan",
  "ci.rerun_failed_workflow",
] as const;

/** No action/provider ports are ever handed to recommendation analysis. */
export const ANALYSIS_ACTION_PORTS = [] as const;
export const ANALYSIS_RERUN_BOUNDARY = {
  tool: "ci.rerun_failed_workflow",
  available: false,
  reason: "approval-required-outside-analysis",
} as const;

export const AnalysisPolicyLimitsSchema = z.object({
  timeoutMs: z.number().int().min(1).max(30_000),
  maxBytes: z.number().int().min(1_024).max(64 * 1_024),
  maxDiffFiles: z.number().int().min(1).max(25),
  maxLogLines: z.number().int().min(1).max(100),
  maxMetrics: z.number().int().min(1).max(100),
  maxTraces: z.number().int().min(1).max(100),
  maxRecommendations: z.literal(1),
  maxText: z.number().int().min(32).max(512),
}).strict();
export type AnalysisPolicyLimits = z.infer<typeof AnalysisPolicyLimitsSchema>;

export const DEFAULT_ANALYSIS_POLICY_LIMITS: AnalysisPolicyLimits = {
  timeoutMs: 5_000,
  maxBytes: 32 * 1_024,
  maxDiffFiles: 10,
  maxLogLines: 50,
  maxMetrics: 20,
  maxTraces: 20,
  maxRecommendations: 1,
  maxText: 512,
};

const EventMetadataSchema = z.object({
  repository: z.string().min(1).max(200),
  workflow: z.string().min(1).max(200),
  runId: z.string().min(1).max(64),
  commitSha: z.string().max(128).optional(),
  deploymentId: z.string().max(128).optional(),
  traceId: z.string().max(128).optional(),
}).strict();

const DiffMetadataSchema = z.object({
  path: z.string().min(1).max(512),
  changeType: z.enum(["added", "modified", "deleted", "renamed", "unknown"]),
  additions: z.number().int().nonnegative().max(1_000_000),
  deletions: z.number().int().nonnegative().max(1_000_000),
  hunkCount: z.number().int().nonnegative().max(100),
}).strict();

const LogEvidenceSchema = z.object({ sequence: z.number().int().nonnegative().max(20_000), text: z.string().min(1).max(512) }).strict();
const MetricEvidenceSchema = z.object({ name: z.string().min(1).max(256), state: z.enum(["normal", "degraded", "error", "unknown"]), value: z.number().finite().optional(), sampleCount: z.number().int().nonnegative().max(1_440) }).strict();
const TraceEvidenceSchema = z.object({ spanDigest: z.string().regex(/^[a-f0-9]{64}$/), durationMs: z.number().finite().min(0).max(86_400_000), status: z.enum(["ok", "error", "unknown"]) }).strict();

export const BoundedAnalysisInputSchema = z.object({
  event: EventMetadataSchema,
  diff: z.array(DiffMetadataSchema).max(25),
  logs: z.array(LogEvidenceSchema).max(100),
  metrics: z.array(MetricEvidenceSchema).max(100),
  traces: z.array(TraceEvidenceSchema).max(100),
  allowedTools: z.array(z.enum(ANALYSIS_TOOL_SURFACE)).length(5),
}).strict();
export type BoundedAnalysisInput = z.infer<typeof BoundedAnalysisInputSchema>;

export interface AnalysisInput {
  readonly event: {
    readonly repository: string;
    readonly workflow: string;
    readonly runId: string;
    readonly commitSha?: string;
    readonly deploymentId?: string;
    readonly traceId?: string;
  };
  readonly diff?: readonly Partial<z.infer<typeof DiffMetadataSchema>>[];
  readonly logs?: readonly (string | { readonly sequence?: number; readonly text?: string })[];
  readonly metrics?: readonly { readonly name?: string; readonly state?: string; readonly value?: number; readonly sampleCount?: number }[];
  readonly traces?: readonly Partial<z.infer<typeof TraceEvidenceSchema>>[];
}

export function boundAnalysisInput(input: AnalysisInput, requestedLimits: Partial<AnalysisPolicyLimits> = {}): BoundedAnalysisInput {
  const limits = AnalysisPolicyLimitsSchema.parse({ ...DEFAULT_ANALYSIS_POLICY_LIMITS, ...requestedLimits });
  const event = {
    repository: safeText(input.event.repository, 200),
    workflow: safeText(input.event.workflow, 200),
    runId: safeText(input.event.runId, 64),
    ...(input.event.commitSha === undefined ? {} : { commitSha: safeText(input.event.commitSha, 128) }),
    ...(input.event.deploymentId === undefined ? {} : { deploymentId: safeText(input.event.deploymentId, 128) }),
    ...(input.event.traceId === undefined ? {} : { traceId: safeText(input.event.traceId, 128) }),
  };
  const diff = (input.diff ?? []).slice(0, limits.maxDiffFiles).map((item) => ({
    path: safeText(item.path ?? "unknown", 512),
    changeType: item.changeType === "added" || item.changeType === "modified" || item.changeType === "deleted" || item.changeType === "renamed" ? item.changeType : "unknown" as const,
    additions: boundedNumber(item.additions),
    deletions: boundedNumber(item.deletions),
    hunkCount: boundedNumber(item.hunkCount),
  }));
  const logs = (input.logs ?? []).slice(0, limits.maxLogLines).map((item, index) => ({
    sequence: boundedNumber(typeof item === "string" ? index + 1 : item.sequence ?? index + 1),
    text: safeText(typeof item === "string" ? item : item.text ?? "", limits.maxText),
  })).filter((item) => item.text.length > 0);
  const metrics = (input.metrics ?? []).slice(0, limits.maxMetrics).map((item) => ({
    name: safeText(item.name ?? "metric", 256),
    state: item.state === "normal" || item.state === "degraded" || item.state === "error" || item.state === "unknown" ? item.state : "unknown" as const,
    ...(typeof item.value === "number" && Number.isFinite(item.value) ? { value: item.value } : {}),
    sampleCount: boundedNumber(item.sampleCount),
  }));
  const traces = (input.traces ?? []).slice(0, limits.maxTraces).flatMap((item) => {
    const digest = typeof item.spanDigest === "string" && /^[a-f0-9]{64}$/.test(item.spanDigest) ? item.spanDigest : undefined;
    if (digest === undefined) return [];
    return [{ spanDigest: digest, durationMs: Math.max(0, Math.min(86_400_000, Number(item.durationMs) || 0)), status: item.status === "ok" || item.status === "error" ? item.status : "unknown" as const }];
  });
  const result = BoundedAnalysisInputSchema.parse({ event, diff, logs, metrics, traces, allowedTools: [...ANALYSIS_TOOL_SURFACE] });
  return fitInputBytes(result, limits.maxBytes);
}

export const RecommendationSchema = z.object({
  title: z.string().min(1).max(512),
  rationale: z.string().max(512).optional(),
  steps: z.array(z.string().min(1).max(512)).max(4),
  evidenceRefs: z.array(z.string().min(1).max(64)).max(10),
}).strict();
export type Recommendation = z.infer<typeof RecommendationSchema>;

export const RecommendationResultSchema = z.object({
  available: z.boolean(),
  reason: z.enum(["available", "unavailable", "timeout", "aborted", "malformed"]),
  recommendation: RecommendationSchema.optional(),
}).strict();
export type RecommendationResult = z.infer<typeof RecommendationResultSchema>;

export type AnalysisCallback = (input: BoundedAnalysisInput, context: {
  readonly signal: AbortSignal;
  /** Exact /mcp/ci surface metadata; this is not an invokable tool port. */
  readonly allowedTools: typeof ANALYSIS_TOOL_SURFACE;
  /** Deliberately empty: recommendations cannot mutate, deploy, rollback, or rerun. */
  readonly actionPorts: typeof ANALYSIS_ACTION_PORTS;
  readonly rerun: typeof ANALYSIS_RERUN_BOUNDARY;
}) => Promise<unknown>;

export async function runBoundedRecommendationAnalysis(options: {
  readonly input: AnalysisInput | BoundedAnalysisInput;
  readonly callback?: AnalysisCallback;
  readonly signal?: AbortSignal;
  readonly limits?: Partial<AnalysisPolicyLimits>;
}): Promise<RecommendationResult> {
  const limits = AnalysisPolicyLimitsSchema.parse({ ...DEFAULT_ANALYSIS_POLICY_LIMITS, ...options.limits });
  // Re-bound even schema-valid input: the schema caps item counts/text but does
  // not enforce the caller-selected byte and count budgets.
  let input: BoundedAnalysisInput;
  try {
    input = boundAnalysisInput(options.input as AnalysisInput, limits);
  } catch (error) {
    if (error instanceof AnalysisInputTooLargeError) return unavailable("malformed");
    throw error;
  }
  if (options.callback === undefined) return unavailable("unavailable");
  if (options.signal?.aborted) return unavailable("aborted");
  const controller = new AbortController();
  let rejectAbort: (() => void) | undefined;
  const onAbort = () => {
    controller.abort();
    rejectAbort?.();
  };
  options.signal?.addEventListener("abort", onAbort, { once: true });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const aborted = options.signal === undefined ? undefined : new Promise<never>((_, reject) => {
      rejectAbort = () => reject(new AnalysisAbortedError());
    });
    // Close the small gap between the initial check and listener setup.
    if (options.signal?.aborted) {
      onAbort();
      return unavailable("aborted");
    }
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new AnalysisTimeoutError()); }, limits.timeoutMs);
    });
    const callback = options.callback(input, {
      signal: controller.signal,
      allowedTools: ANALYSIS_TOOL_SURFACE,
      actionPorts: ANALYSIS_ACTION_PORTS,
      rerun: ANALYSIS_RERUN_BOUNDARY,
    });
    const value = await Promise.race(aborted === undefined ? [callback, timeout] : [callback, timeout, aborted]);
    return normalizeRecommendation(value, limits.maxText);
  } catch (error) {
    if (error instanceof AnalysisTimeoutError) return unavailable("timeout");
    if (error instanceof AnalysisAbortedError) return unavailable("aborted");
    if (options.signal?.aborted || controller.signal.aborted) return unavailable(options.signal?.aborted ? "aborted" : "timeout");
    return unavailable("malformed");
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    options.signal?.removeEventListener("abort", onAbort);
  }
}

export class AnalysisTimeoutError extends Error {
  constructor() { super("analysis timed out"); this.name = "AnalysisTimeoutError"; }
}

class AnalysisAbortedError extends Error {
  constructor() { super("analysis aborted"); this.name = "AnalysisAbortedError"; }
}

class AnalysisInputTooLargeError extends Error {
  constructor() { super("analysis input exceeds byte limit"); this.name = "AnalysisInputTooLargeError"; }
}

function normalizeRecommendation(value: unknown, maxText: number): RecommendationResult {
  const candidate = value !== null && typeof value === "object" ? value as Record<string, unknown> : {};
  const raw = candidate.recommendation ?? (Array.isArray(candidate.recommendations) ? candidate.recommendations[0] : candidate);
  if (raw === null || typeof raw !== "object") return unavailable("malformed");
  const item = raw as Record<string, unknown>;
  const title = typeof item.title === "string" ? safeText(item.title, maxText) : "";
  if (title.length === 0) return unavailable("malformed");
  let remainingText = maxText - title.length;
  const rawRationale = typeof item.rationale === "string" ? safeText(item.rationale, maxText) : undefined;
  const rationale = rawRationale === undefined ? undefined : takeRecommendationText(rawRationale, remainingText);
  remainingText -= rationale?.length ?? 0;
  const steps: string[] = [];
  if (Array.isArray(item.steps)) {
    for (const step of item.steps.filter((candidate): candidate is string => typeof candidate === "string").slice(0, 4)) {
      if (remainingText === 0) break;
      const bounded = takeRecommendationText(safeText(step, maxText), remainingText);
      if (bounded.length === 0) break;
      steps.push(bounded);
      remainingText -= bounded.length;
    }
  }
  const evidenceRefs: string[] = [];
  if (Array.isArray(item.evidenceRefs)) {
    for (const ref of item.evidenceRefs.filter((candidate): candidate is string => typeof candidate === "string").slice(0, 10)) {
      if (remainingText === 0) break;
      const bounded = takeRecommendationText(safeText(ref, 64), remainingText);
      if (bounded.length === 0) break;
      evidenceRefs.push(bounded);
      remainingText -= bounded.length;
    }
  }
  return RecommendationResultSchema.parse({ available: true, reason: "available", recommendation: { title, ...(rationale === undefined || rationale.length === 0 ? {} : { rationale }), steps, evidenceRefs } });
}

function unavailable(reason: RecommendationResult["reason"]): RecommendationResult { return { available: false, reason }; }
function safeText(value: string, maxLength: number): string { return redactText(value.replace(/[\u0000-\u001f\u007f]/g, " "), maxLength).text.trim(); }
function takeRecommendationText(value: string, remaining: number): string { return remaining > 0 ? value.slice(0, remaining) : ""; }
function boundedNumber(value: number | undefined): number { return typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.min(1_000_000, Math.floor(value))) : 0; }
function fitInputBytes(input: BoundedAnalysisInput, maxBytes: number): BoundedAnalysisInput {
  const result = { ...input, event: { ...input.event }, diff: [...input.diff], logs: [...input.logs], metrics: [...input.metrics], traces: [...input.traces] };
  while (Buffer.byteLength(JSON.stringify(result), "utf8") > maxBytes && (result.logs.length || result.metrics.length || result.traces.length || result.diff.length)) {
    if (result.logs.length) result.logs.pop();
    else if (result.metrics.length) result.metrics.pop();
    else if (result.traces.length) result.traces.pop();
    else result.diff.pop();
  }
  // Scalar event metadata can exceed a low byte budget even after evidence is
  // exhausted. Drop optional correlation fields, then trim required fields in
  // a stable order while preserving their schema-required nonempty values.
  for (const field of ["traceId", "deploymentId", "commitSha"] as const) {
    if (Buffer.byteLength(JSON.stringify(result), "utf8") <= maxBytes) break;
    const event = { ...result.event };
    delete event[field];
    result.event = event;
  }
  for (const field of ["repository", "workflow", "runId"] as const) {
    while (Buffer.byteLength(JSON.stringify(result), "utf8") > maxBytes && result.event[field].length > 1) {
      result.event = { ...result.event, [field]: result.event[field].slice(0, -1) };
    }
  }
  if (Buffer.byteLength(JSON.stringify(result), "utf8") > maxBytes) throw new AnalysisInputTooLargeError();
  return BoundedAnalysisInputSchema.parse(result);
}
