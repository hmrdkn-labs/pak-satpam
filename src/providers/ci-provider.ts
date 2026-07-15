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

/** Compatibility shape for existing adapters that expose both ports. */
export interface CIProvider extends CIReadProvider, CIRerunProvider {}

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
