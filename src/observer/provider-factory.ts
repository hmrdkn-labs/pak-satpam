import { CIProviderError } from "../providers/ci-provider.js";
import { GitHubActionsProvider } from "../providers/github-actions-provider.js";
import { MappedGitHubAppTokenProvider } from "../providers/mapped-github-app-token-provider.js";
import type { ObserverProvider } from "./runtime.js";
import { readObserverSecretFile, type ObserverAllowlistEntry, type ObserverFileConfig } from "./config.js";
import { observerEventSourceFromProvider, type ObserverEventSource } from "./events.js";

export type ObserverProviderConfiguration =
  | { readonly type: "github"; readonly github: ObserverFileConfig["github"]; readonly allowlist: readonly ObserverAllowlistEntry[] }
  | { readonly type: "jenkins" }
  | { readonly type: "bitbucket" };

/** Construct the configured observer adapter without sharing CI token state. */
export function createObserverProviderFromConfiguration(
  configuration: ObserverProviderConfiguration,
  options: { readonly repositories: readonly string[]; readonly fetch: typeof globalThis.fetch; readonly clock: () => Date },
): ObserverProvider {
  if (configuration.type !== "github") throw new CIProviderError("unsupported");
  const tokenProvider = MappedGitHubAppTokenProvider.fromFiles({
    appIdFile: configuration.github.app_id_file,
    pemKeyFile: configuration.github.pem_key_file,
    installations: configuration.github.installations.map((entry) => "repo" in entry
      ? { repo: entry.repo, installationIdFile: entry.installation_id_file }
      : { owner: entry.owner, installationIdFile: entry.installation_id_file }),
    repositories: options.repositories,
    fetch: options.fetch,
    clock: options.clock,
    apiBaseUrl: configuration.github.api_base_url,
    actionsPermission: "read",
  });
  return new GitHubActionsProvider({
    tokenProvider,
    fetch: options.fetch,
    clock: options.clock,
    apiBaseUrl: configuration.github.api_base_url,
  });
}

/** Build polling and webhook capabilities from the same provider configuration. */
export function createObserverEventSourceFromProviderConfiguration(
  configuration: ObserverProviderConfiguration,
  provider: ObserverProvider,
  createWebhookVerifier?: (secret: Uint8Array, allowlist: readonly ObserverAllowlistEntry[]) => ObserverEventSource["webhookVerifier"],
): ObserverEventSource {
  const source = observerEventSourceFromProvider(provider);
  if (configuration.type !== "github" || configuration.github.webhook_secret_file === undefined || createWebhookVerifier === undefined) return source;
  const verifier = createWebhookVerifier(
    readObserverSecretFile(configuration.github.webhook_secret_file),
    configuration.allowlist,
  );
  return verifier === undefined ? source : { ...source, webhookVerifier: verifier };
}
