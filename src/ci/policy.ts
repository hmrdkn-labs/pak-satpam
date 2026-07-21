export interface CIAllowlist {
  readonly workflowsByRepository: Readonly<Record<string, readonly string[]>>;
}

/** Exact challenge repositories and their Jenkins multibranch job names. */
export const CHALLENGE_CI_ALLOWLIST: Readonly<Record<string, readonly string[]>> = {
  "academytools/planpal-backend-learner-6": ["planpal-backend-learner-6"],
  "academytools/planpal-web-client-learner-6": ["planpal-web-client-learner-6"],
  "academytools/planpal-config-6": ["planpalasix-config"],
  "academytools/planpal-infra-6": ["planpal-infra-6"],
};

export function createCIAllowlist(workflowsByRepository: Record<string, readonly string[]>): CIAllowlist {
  return {
    workflowsByRepository: Object.fromEntries(
      Object.entries(workflowsByRepository).map(([repo, workflows]) => [repo, [...new Set(workflows)]]),
    ),
  };
}

export function isCIResourceAllowed(
  policy: CIAllowlist,
  repo: string,
  workflow: string,
  matches: (allowlistEntry: string, workflow: string) => boolean,
): boolean {
  return policy.workflowsByRepository[repo]?.some((allowlistEntry) => matches(allowlistEntry, workflow)) ?? false;
}

export function assertCIResourceAllowed(
  policy: CIAllowlist,
  repo: string,
  workflow: string,
  matches: (allowlistEntry: string, workflow: string) => boolean,
): void {
  if (!isCIResourceAllowed(policy, repo, workflow, matches)) throw new Error("ci_policy_denied");
}
