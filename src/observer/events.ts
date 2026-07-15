import type { CIWorkflowRun } from "../domain/ci-schemas.js";
import { CIProviderError } from "../providers/ci-provider.js";

export type ObserverEventSourceKind = "poll" | "webhook";

export interface ObserverRunListInput {
  readonly repo: string;
  readonly workflow: string;
  readonly createdAfter?: string;
  readonly page: number;
  readonly perPage: number;
}

export interface ObserverRunListResult {
  readonly runs: readonly CIWorkflowRun[];
  readonly hasMore: boolean;
  readonly nextPage?: number;
}

export interface ObserverWebhookRequest {
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly body: string;
}

/** Provider adapters own signature checks and provider-payload parsing. */
export interface ObserverWebhookVerifier {
  verify(request: ObserverWebhookRequest): Promise<readonly unknown[]>;
}

/** The runtime consumes normalized runs and never interprets provider payloads. */
export interface ObserverEventSource {
  readonly providerClass?: string;
  readonly webhookVerifier?: ObserverWebhookVerifier;
  listTerminalRuns(input: ObserverRunListInput): Promise<ObserverRunListResult>;
}

export interface ObserverProviderPort {
  readonly providerClass?: string;
  readonly ciProviderType?: string;
  readonly listWorkflowRuns?: (input: ObserverRunListInput) => Promise<ObserverRunListResult>;
}

/** Build only the observer capabilities the provider actually implements. */
export function observerEventSourceFromProvider(provider: ObserverProviderPort): ObserverEventSource {
  const listWorkflowRuns = provider.listWorkflowRuns;
  return {
    ...(provider.providerClass === undefined ? {} : { providerClass: provider.providerClass }),
    listTerminalRuns: listWorkflowRuns === undefined
      ? async () => { throw new CIProviderError("unsupported"); }
      : (input) => listWorkflowRuns.call(provider, input),
  };
}
