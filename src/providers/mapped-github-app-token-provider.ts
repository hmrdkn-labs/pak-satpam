import { readFileSync, statSync } from "node:fs";

import type { CITokenProvider } from "./ci-provider.js";
import { GitHubAppTokenProvider } from "./github-app-token-provider.js";

export interface GitHubInstallationSelector {
  readonly repo?: string;
  readonly owner?: string;
  readonly installationIdFile: string;
}

export class MappedGitHubAppTokenProvider implements CITokenProvider {
  readonly #byRepository = new Map<string, GitHubAppTokenProvider>();
  readonly #byOwner = new Map<string, GitHubAppTokenProvider>();

  private constructor() {}

  static fromFiles(options: {
    appIdFile: string;
    pemKeyFile: string;
    installations: readonly GitHubInstallationSelector[];
    repositories: readonly string[];
    fetch: typeof globalThis.fetch;
    clock: () => Date;
    apiBaseUrl: string;
    actionsPermission?: "read" | "write";
  }): MappedGitHubAppTokenProvider {
    const appId = readNumericPrivateFile(options.appIdFile, "GitHub App ID");
    const provider = new MappedGitHubAppTokenProvider();
    const repositories = [...new Set(options.repositories)];
    const ownerProviders = new Map<string, GitHubAppTokenProvider>();
    const repositoryProviders = new Map<string, GitHubAppTokenProvider>();

    for (const selector of options.installations) {
      if ((selector.repo === undefined) === (selector.owner === undefined)) {
        throw new Error("Invalid GitHub installation mapping");
      }
      const key = selector.repo ?? selector.owner ?? "";
      const allowedRepositories = repositories.filter(
        (repository) => selector.repo === repository || selector.owner === repository.split("/")[0],
      );
      if (allowedRepositories.length === 0) throw new Error("Unused GitHub installation mapping");
      const tokenProvider = GitHubAppTokenProvider.fromPemFile({
        appId,
        installationId: readNumericPrivateFile(selector.installationIdFile, "GitHub installation ID"),
        pemKeyFile: options.pemKeyFile,
        allowedRepositories,
        fetch: options.fetch,
        clock: options.clock,
        apiBaseUrl: options.apiBaseUrl,
        ...(options.actionsPermission === undefined ? {} : { actionsPermission: options.actionsPermission }),
      });
      if (selector.repo !== undefined) {
        if (repositoryProviders.has(key)) throw new Error("Duplicate GitHub repository installation mapping");
        repositoryProviders.set(key, tokenProvider);
      } else {
        if (ownerProviders.has(key)) throw new Error("Duplicate GitHub owner installation mapping");
        ownerProviders.set(key, tokenProvider);
      }
    }

    for (const repository of repositories) {
      const owner = repository.split("/")[0] ?? "";
      const selected = repositoryProviders.get(repository) ?? ownerProviders.get(owner);
      if (selected === undefined) throw new Error(`Missing GitHub installation mapping for ${repository}`);
      if (repositoryProviders.has(repository)) provider.#byRepository.set(repository, selected);
      else provider.#byOwner.set(owner, selected);
    }
    return provider;
  }

  async getToken(repository: string): Promise<string> {
    const owner = repository.split("/")[0] ?? "";
    const provider = this.#byRepository.get(repository) ?? this.#byOwner.get(owner);
    if (provider === undefined) throw new Error("GitHub repository installation mapping unavailable");
    return provider.getToken(repository);
  }
}

function readNumericPrivateFile(path: string, label: string): string {
  let metadata;
  try { metadata = statSync(path); } catch { throw new Error(`${label} is unavailable`); }
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > 256 * 1_024 || (metadata.mode & 0o077) !== 0) {
    throw new Error(`${label} must be a regular 0600 file`);
  }
  const value = readFileSync(path, "utf8").trim();
  if (!/^\d+$/.test(value)) throw new Error(`${label} must be numeric`);
  return value;
}
