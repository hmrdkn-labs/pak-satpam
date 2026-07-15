import type { CITokenProvider } from "./ci-provider.js";
import {
  assertTrustedHost,
  assertResponseRef,
  boundedJson,
  boundedResponseText,
  commit,
  createSCMBudgetGuard,
  finalizeSCMEvidence,
  nativeId,
  prepareSCMInput,
  providerHttpError,
  ref,
  repository,
  resolveSCMUrl,
  type RawSCMFile,
} from "./scm-adapter-helpers.js";
import { redactSCMText } from "../scm/context.js";
import { SCMProviderError, type SCMReadProvider } from "../scm/provider.js";
import type { SCMChangeEvidenceInput, SCMChangeEvidenceResult, SCMPullRequest } from "../scm/schemas.js";

const GITHUB_PROVIDER_NAME = "github";
const GITHUB_API_VERSION = "2022-11-28";

export interface GitHubSCMProviderOptions {
  readonly token?: string;
  readonly tokenProvider?: CITokenProvider;
  readonly fetch: typeof globalThis.fetch;
  readonly clock?: () => Date;
  readonly apiBaseUrl?: string;
  readonly allowedRepositories: readonly string[];
  readonly allowedRefs: readonly string[];
  readonly allowedHosts?: readonly string[];
}

export class GitHubSCMProvider implements SCMReadProvider {
  readonly #tokenProvider: CITokenProvider;
  readonly #fetch: typeof globalThis.fetch;
  readonly #clock: () => Date;
  readonly #apiBaseUrl: URL;
  readonly #allowlists: Pick<GitHubSCMProviderOptions, "allowedRepositories" | "allowedRefs">;

  constructor(options: GitHubSCMProviderOptions) {
    if (options.allowedRepositories.length === 0 || options.allowedRefs.length === 0) throw new Error("GitHub SCM allowlists are required");
    if (options.token === undefined && options.tokenProvider === undefined) throw new Error("GitHub token provider is required");
    this.#tokenProvider = options.tokenProvider ?? { getToken: async () => options.token ?? "" };
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? (() => new Date());
    this.#apiBaseUrl = assertTrustedHost(options.apiBaseUrl ?? "https://api.github.com/", options.allowedHosts, "GitHub API base URL");
    if (this.#apiBaseUrl.protocol !== "https:") throw new Error("GitHub SCM credentials require HTTPS");
    if (this.#apiBaseUrl.hostname !== "api.github.com" && options.allowedHosts === undefined) throw new Error("GitHub API host is not allowlisted");
    if (this.#apiBaseUrl.hostname === "api.github.com" && this.#apiBaseUrl.port !== "" && this.#apiBaseUrl.port !== "443") throw new Error("GitHub API host must use the expected port");
    if (this.#apiBaseUrl.pathname !== "/" && !this.#apiBaseUrl.pathname.endsWith("/")) this.#apiBaseUrl.pathname += "/";
    this.#allowlists = options;
  }

  async getChangeEvidence(input: SCMChangeEvidenceInput): Promise<SCMChangeEvidenceResult> {
    const prepared = prepareSCMInput(input, this.#allowlists);
    const budgetGuard = createSCMBudgetGuard(prepared.budget, this.#clock);
    if (prepared.input.pullRequest !== undefined) {
      return this.pullRequestEvidence(prepared, budgetGuard);
    }
    if (prepared.input.compare !== undefined) return this.compareEvidence(prepared, budgetGuard);
    const selector = prepared.input.commit ?? prepared.input.ref;
    if (selector === undefined) throw new SCMProviderError("malformed");
    const value = await this.json(`/repos/${prepared.input.repository}/commits/${encodeURIComponent(selector)}?per_page=${prepared.budget.maxFiles}`, prepared.input.repository, budgetGuard);
    const responseRepository = repositoryFrom(value.repository);
    if (responseRepository !== prepared.input.repository) throw new SCMProviderError("malformed");
    const headSha = commit(value.sha);
    if (prepared.input.commit !== undefined && headSha !== prepared.input.commit.toLowerCase()) throw new SCMProviderError("malformed");
    if (prepared.input.ref !== undefined) assertResponseRef(prepared.input.ref, this.#allowlists.allowedRefs);
    const files = githubFiles(value.files, prepared.budget.maxFiles);
    const baseSha = firstParent(value.parents);
    return finalizeSCMEvidence({
      providerClass: GITHUB_PROVIDER_NAME,
      observedAt: this.#clock(),
      prepared,
      base: baseSha === undefined ? {} : { sha: baseSha },
      head: { ...(prepared.input.ref === undefined ? {} : { ref: prepared.input.ref }), sha: headSha },
      files,
      providerTruncated: Array.isArray(value.files) && value.files.length > prepared.budget.maxFiles,
      budgetGuard,
    });
  }

  getRepositoryEvidence(input: SCMChangeEvidenceInput): Promise<SCMChangeEvidenceResult> {
    return this.getChangeEvidence(input);
  }

  private async compareEvidence(prepared: ReturnType<typeof prepareSCMInput>, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<SCMChangeEvidenceResult> {
    const compare = prepared.input.compare;
    if (compare === undefined) throw new SCMProviderError("malformed");
    const repositoryName = prepared.input.repository;
    const raw = await this.json(`/repos/${repositoryName}/compare/${encodeURIComponent(`${compare.base}...${compare.head}`)}`, repositoryName, budgetGuard);
    if (repositoryFrom(raw.repository) !== repositoryName) throw new SCMProviderError("malformed");
    const baseCommit = commitRecord(raw.base_commit);
    const headCommit = commitRecord(raw.head_commit) ?? lastCommit(raw.commits);
    if (headCommit === undefined) throw new SCMProviderError("malformed");
    const files = githubFiles(raw.files, prepared.budget.maxFiles);
    return finalizeSCMEvidence({
      providerClass: GITHUB_PROVIDER_NAME,
      observedAt: this.#clock(),
      prepared,
      base: { ...(revisionRef(compare.base) === undefined ? {} : { ref: revisionRef(compare.base) }), ...(baseCommit === undefined ? {} : { sha: baseCommit }) },
      head: { ...(revisionRef(compare.head) === undefined ? {} : { ref: revisionRef(compare.head) }), sha: headCommit },
      files,
      providerTruncated: Array.isArray(raw.files) && raw.files.length > prepared.budget.maxFiles,
      budgetGuard,
    });
  }

  private async pullRequestEvidence(prepared: ReturnType<typeof prepareSCMInput>, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<SCMChangeEvidenceResult> {
    const repositoryName = prepared.input.repository;
    const pullRequestId = prepared.input.pullRequest;
    if (pullRequestId === undefined) throw new SCMProviderError("malformed");
    const raw = await this.json(`/repos/${repositoryName}/pulls/${encodeURIComponent(pullRequestId)}`, repositoryName, budgetGuard);
    const pullRequest = normalizePullRequest(raw, repositoryName, pullRequestId, this.#allowlists.allowedRefs);
    if (prepared.input.ref !== undefined && prepared.input.ref !== pullRequest.base.ref && prepared.input.ref !== pullRequest.head.ref) throw new SCMProviderError("permission");
    if (prepared.input.commit !== undefined && prepared.input.commit.toLowerCase() !== pullRequest.head.sha) throw new SCMProviderError("permission");
    const response = await this.request(`/repos/${repositoryName}/pulls/${encodeURIComponent(pullRequestId)}/files?per_page=${prepared.budget.maxFiles}`, repositoryName, budgetGuard);
    if (!response.ok) throw providerHttpError(response.status);
    const text = await boundedResponseText(response);
    let value: unknown;
    try { value = JSON.parse(text); } catch { throw new SCMProviderError("malformed"); }
    if (!Array.isArray(value)) throw new SCMProviderError("malformed");
    const files = githubFiles(value, prepared.budget.maxFiles);
    return finalizeSCMEvidence({
      providerClass: GITHUB_PROVIDER_NAME,
      observedAt: this.#clock(),
      prepared,
      base: pullRequest.base,
      head: { ...pullRequest.head, sha: pullRequest.head.sha ?? pullRequest.base.sha ?? "" },
      pullRequest,
      files,
      providerTruncated: value.length > prepared.budget.maxFiles,
      budgetGuard,
    });
  }

  private async json(path: string, repositoryName: string, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<Record<string, unknown>> {
    const response = await this.request(path, repositoryName, budgetGuard);
    return boundedJson(response);
  }

  private async request(path: string, repositoryName: string, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<Response> {
    let token: string;
    try { token = await this.#tokenProvider.getToken(repositoryName); } catch { throw new SCMProviderError("permission"); }
    if (token.length === 0 || token.length > 4 * 1_024) throw new SCMProviderError("permission");
    budgetGuard.beginRequest();
    try {
      const response = await this.#fetch(resolveSCMUrl(this.#apiBaseUrl, path), {
        method: "GET",
        headers: { accept: "application/vnd.github+json", authorization: `Bearer ${token}`, "x-github-api-version": GITHUB_API_VERSION },
        redirect: "error",
        signal: AbortSignal.timeout(Math.min(10_000, budgetGuard.remainingMs)),
      });
      budgetGuard.finishRequest();
      return response;
    } catch { throw new SCMProviderError("unavailable"); }
  }
}

function githubFiles(value: unknown, maxFiles = 100): RawSCMFile[] {
  if (!Array.isArray(value)) throw new SCMProviderError("malformed");
  return value.slice(0, maxFiles).map((item): RawSCMFile => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw new SCMProviderError("malformed");
    const raw = item as Record<string, unknown>;
    if (typeof raw.filename !== "string" || raw.filename.length === 0 || typeof raw.status !== "string") throw new SCMProviderError("malformed");
    return {
      path: raw.filename,
      status: githubStatus(raw.status),
      additions: count(raw.additions),
      deletions: count(raw.deletions),
      ...(typeof raw.patch === "string" ? { patch: raw.patch } : {}),
      binary: raw.patch === undefined,
    };
  });
}

function normalizePullRequest(raw: Record<string, unknown>, expectedRepository: string, expectedId: string, allowedRefs: readonly string[] | undefined): SCMPullRequest {
  const id = nativeId(raw.number);
  if (id !== expectedId) throw new SCMProviderError("malformed");
  const base = side(raw.base, expectedRepository, allowedRefs);
  const head = side(raw.head, undefined, allowedRefs);
  const title = typeof raw.title === "string" ? redactSCMText(raw.title, 512).text : undefined;
  return {
    id,
    ...(title === undefined ? {} : { title }),
    ...(typeof raw.state === "string" ? { state: raw.state.slice(0, 64) } : {}),
    base: { ref: base.ref, sha: base.sha },
    head: { ref: head.ref, sha: head.sha },
  };
}

function side(value: unknown, expectedRepository: string | undefined, allowedRefs: readonly string[] | undefined): { ref: string; sha: string } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new SCMProviderError("malformed");
  const raw = value as Record<string, unknown>;
  const branch = ref(raw.ref);
  const sha = commit(raw.sha);
  assertResponseRef(branch, allowedRefs ?? []);
  if (expectedRepository !== undefined && repositoryFrom(raw.repo) !== expectedRepository) throw new SCMProviderError("malformed");
  return { ref: branch, sha };
}

function repositoryFrom(value: unknown): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new SCMProviderError("malformed");
  const raw = value as Record<string, unknown>;
  return repository(raw.full_name);
}

function firstParent(value: unknown): string | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  const parent = value[0];
  if (parent === null || typeof parent !== "object" || Array.isArray(parent)) throw new SCMProviderError("malformed");
  return commit((parent as Record<string, unknown>).sha);
}

function commitRecord(value: unknown): string | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const sha = (value as Record<string, unknown>).sha;
  return typeof sha === "string" ? commit(sha) : undefined;
}

function lastCommit(value: unknown): string | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  return commitRecord(value[value.length - 1]);
}

function revisionRef(value: string): string | undefined {
  return /^[a-f0-9]{40}$/i.test(value) ? undefined : ref(value);
}

function githubStatus(value: string): RawSCMFile["status"] {
  if (["added", "modified", "removed", "renamed", "copied"].includes(value)) return value as RawSCMFile["status"];
  return "unknown";
}

function count(value: unknown): number {
  if (value === undefined) return 0;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 1_000_000_000) throw new SCMProviderError("malformed");
  return value;
}
