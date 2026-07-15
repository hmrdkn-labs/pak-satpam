import type { CIAllowlist } from "./policy.js";
import type { ApprovalTokenService } from "./approval.js";
import type { CIProvider } from "../providers/ci-provider.js";

export interface CIService {
  readonly provider: CIProvider;
  readonly policy: CIAllowlist;
  readonly approval: ApprovalTokenService;
  /** Explicit opt-in for exposing the approval-gated mutation tool. */
  readonly enableRerunTool?: boolean;
}
