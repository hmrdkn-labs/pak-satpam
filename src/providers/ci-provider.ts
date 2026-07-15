import type {
  CIFailedJobAnalysisInput,
  CIFailedJobAnalysisResult,
  CILogEvidenceInput,
  CILogEvidenceResult,
  CIRerunFailedWorkflowInput,
  CIRerunFailedWorkflowResult,
  CIRemediationPlanInput,
  CIRemediationPlanResult,
  CIWorkflowRun,
  CIWorkflowStatusInput,
  CIWorkflowStatusResult,
} from "../domain/ci-schemas.js";
import type { CIProviderCapability, CIProviderName } from "../domain/ci-provider-contracts.js";
import type {
  SCMChangeEvidenceInput,
  SCMChangeEvidenceResult,
  TelemetryCorrelationInput,
  TelemetryCorrelationResult,
} from "../domain/forensics-schemas.js";

export type CIProviderErrorCode = "unavailable" | "malformed" | "permission" | "unsupported";

export class CIProviderError extends Error {
  constructor(readonly code: CIProviderErrorCode) {
    super(`CI provider ${code}`);
    this.name = "CIProviderError";
  }
}

export interface CIReadProvider {
  getWorkflowStatus(input: CIWorkflowStatusInput): Promise<CIWorkflowStatusResult>;
  listWorkflowRuns?(input: CIWorkflowRunListInput): Promise<CIWorkflowRunListResult>;
  getFailedJobAnalysis(input: CIFailedJobAnalysisInput): Promise<CIFailedJobAnalysisResult>;
  getLogEvidence(input: CILogEvidenceInput): Promise<CILogEvidenceResult>;
  getRemediationPlan(input: CIRemediationPlanInput): Promise<CIRemediationPlanResult>;
}

export interface CIRerunProvider {
  rerunFailedWorkflow(input: Omit<CIRerunFailedWorkflowInput, "requestId" | "approvalToken">): Promise<CIRerunFailedWorkflowResult>;
}

export type CIProviderRuntimeType = "github" | "jenkins" | "bitbucket";

export interface CIProviderIdentity {
  readonly ciProviderType?: CIProviderRuntimeType;
}

/** Compatibility shape for existing adapters that expose both ports. */
export interface CIProvider extends CIReadProvider, CIRerunProvider, CIProviderIdentity {}

/** Optional read-only evidence ports. Adapters may expose either capability. */
export interface SCMChangeEvidenceProvider {
  getChangeEvidence(input: SCMChangeEvidenceInput): Promise<SCMChangeEvidenceResult>;
}

export interface TelemetryCorrelationProvider {
  getTelemetryCorrelation(input: TelemetryCorrelationInput): Promise<TelemetryCorrelationResult>;
}

export interface ForensicsProviderSet {
  readonly scm?: SCMChangeEvidenceProvider;
  readonly telemetry?: TelemetryCorrelationProvider;
}

/** A partial or malformed set must never widen the MCP tool surface. */
export function isForensicsProviderSet(value: unknown): value is ForensicsProviderSet {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  const scm = candidate.scm;
  const telemetry = candidate.telemetry;
  if (scm === undefined && telemetry === undefined) return false;
  if (scm !== undefined && (scm === null || typeof scm !== "object" || typeof (scm as Record<string, unknown>).getChangeEvidence !== "function")) return false;
  if (telemetry !== undefined && (telemetry === null || typeof telemetry !== "object" || typeof (telemetry as Record<string, unknown>).getTelemetryCorrelation !== "function")) return false;
  return true;
}

export class CIUnsupportedCapabilityError extends CIProviderError {
  readonly providerName: CIProviderName;
  readonly capability: CIProviderCapability;

  constructor(providerName: CIProviderName, capability: CIProviderCapability) {
    super("unsupported");
    this.name = "CIUnsupportedCapabilityError";
    this.providerName = providerName;
    this.capability = capability;
  }
}

export interface CIWorkflowRunListInput {
  readonly repo: string;
  readonly workflow: string;
  readonly createdAfter?: string;
  readonly page: number;
  readonly perPage: number;
}

export interface CIWorkflowRunListResult {
  readonly runs: readonly CIWorkflowRun[];
  readonly hasMore: boolean;
  readonly nextPage?: number;
}

export interface CITokenProvider {
  getToken(repository: string): Promise<string>;
}
