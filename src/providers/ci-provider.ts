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

export type CIProviderErrorCode = "unavailable" | "malformed" | "permission";

export class CIProviderError extends Error {
  constructor(readonly code: CIProviderErrorCode) {
    super(`CI provider ${code}`);
    this.name = "CIProviderError";
  }
}

export interface CIProvider {
  getWorkflowStatus(input: CIWorkflowStatusInput): Promise<CIWorkflowStatusResult>;
  listWorkflowRuns?(input: CIWorkflowRunListInput): Promise<CIWorkflowRunListResult>;
  getFailedJobAnalysis(input: CIFailedJobAnalysisInput): Promise<CIFailedJobAnalysisResult>;
  getLogEvidence(input: CILogEvidenceInput): Promise<CILogEvidenceResult>;
  getRemediationPlan(input: CIRemediationPlanInput): Promise<CIRemediationPlanResult>;
  rerunFailedWorkflow(input: Omit<CIRerunFailedWorkflowInput, "requestId" | "approvalToken">): Promise<CIRerunFailedWorkflowResult>;
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
