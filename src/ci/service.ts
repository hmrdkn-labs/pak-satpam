import type { CIAllowlist } from "./policy.js";
import type { ApprovalTokenService } from "./approval.js";
import type { CIProvider } from "../providers/ci-provider.js";

export type CIProviderType = "github" | "jenkins" | "bitbucket";

export interface CIProviderRuntimeMetadata {
  readonly name: string;
  readonly type: CIProviderType;
  readonly capabilities: {
    readonly read: boolean;
    readonly rerun: boolean;
  };
  readonly approvalRequired: boolean;
}

export interface CIService {
  readonly provider: CIProvider;
  readonly policy: CIAllowlist;
  readonly approval?: ApprovalTokenService;
  /** Runtime-owned identity and capability declaration; absent means fail closed. */
  readonly runtimeMetadata?: CIProviderRuntimeMetadata;
}
