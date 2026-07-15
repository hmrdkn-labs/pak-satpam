import { readFileSync, statSync } from "node:fs";
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
import { redactSCMText, normalizeRepositoryFromUrl } from "../scm/context.js";
import { SCMProviderError, type SCMReadProvider } from "../scm/provider.js";
import type { SCMChangeEvidenceInput, SCMChangeEvidenceResult, SCMPullRequest } from "../scm/schemas.js";
import { assertCIProviderTransport, normalizeCIProviderEndpoint } from "../domain/ci-provider-contracts.js";

const BITBUCKET_PROVIDER_NAME = "bitbucket-cloud";

export interface BitbucketSCMProviderOptions {
  readonly baseUrl: string;
  readonly token?: string;
  readonly tokenFile?: string;
  readonly username?: string;
  readonly fetch: typeof globalThis.fetch;
  readonly clock?: () => Date;
  readonly allowedRepositories: readonly string[];
  readonly allowedRefs: readonly string[];
  readonly allowedHosts?: readonly string[];
}

export class BitbucketSCMProvider implements SCMReadProvider {
  readonly #baseUrl: URL;
  readonly #authorization: string;
  readonly #fetch: typeof globalThis.fetch;
  readonly #clock: () => Date;
  readonly #allowlists: Pick<BitbucketSCMProviderOptions, "allowedRepositories" | "allowedRefs">;

  constructor(options: BitbucketSCMProviderOptions) {
    if (options.allowedRepositories.length === 0 || options.allowedRefs.length === 0) throw new Error("Bitbucket SCM allowlists are required");
    this.#baseUrl = assertTrustedHost(options.baseUrl, options.allowedHosts, "Bitbucket API base URL");
    if (!this.#baseUrl.pathname.endsWith("/")) this.#baseUrl.pathname += "/";
    this.#authorization = basicAuthorization(options);
    assertCIProviderTransport(normalizeCIProviderEndpoint({ origin: this.#baseUrl.origin, path: this.#baseUrl.pathname }), { providerLabel: "Bitbucket", credentialed: true });
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? (() => new Date());
    this.#allowlists = options;
  }

  async getChangeEvidence(input: SCMChangeEvidenceInput): Promise<SCMChangeEvidenceResult> {
    const prepared = prepareSCMInput(input, this.#allowlists);
    const budgetGuard = createSCMBudgetGuard(prepared.budget, this.#clock);
    if (prepared.input.pullRequest !== undefined) return this.pullRequestEvidence(prepared, budgetGuard);
    if (prepared.input.compare !== undefined) return this.compareEvidence(prepared, budgetGuard);
    const selector = prepared.input.commit ?? prepared.input.ref;
    if (selector === undefined) throw new SCMProviderError("malformed");
    const repoPath = repositoryPath(prepared.input.repository);
    const commitValue = prepared.input.ref === undefined
      ? await this.json(`/repositories/${repoPath}/commit/${encodeURIComponent(selector)}`, budgetGuard)
      : await this.json(`/repositories/${repoPath}/commits/${encodeURIComponent(selector)}?pagelen=1`, budgetGuard);
    const raw = firstCommit(commitValue);
    if (repositoryFrom(raw.repository) !== prepared.input.repository) throw new SCMProviderError("malformed");
    const headSha = commit(raw.hash);
    if (prepared.input.commit !== undefined && headSha !== prepared.input.commit.toLowerCase()) throw new SCMProviderError("malformed");
    if (prepared.input.ref !== undefined) assertResponseRef(prepared.input.ref, this.#allowlists.allowedRefs);
    const files = await this.commitFiles(repoPath, headSha, prepared.budget.maxFiles, budgetGuard);
    return finalizeSCMEvidence({
      providerClass: BITBUCKET_PROVIDER_NAME,
      observedAt: this.#clock(),
      prepared,
      base: firstParent(raw.parents),
      head: { ...(prepared.input.ref === undefined ? {} : { ref: prepared.input.ref }), sha: headSha },
      files: files.files,
      providerTruncated: files.truncated,
      budgetGuard,
    });
  }

  getRepositoryEvidence(input: SCMChangeEvidenceInput): Promise<SCMChangeEvidenceResult> {
    return this.getChangeEvidence(input);
  }

  private async compareEvidence(prepared: ReturnType<typeof prepareSCMInput>, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<SCMChangeEvidenceResult> {
    const compare = prepared.input.compare;
    if (compare === undefined) throw new SCMProviderError("malformed");
    const repoPath = repositoryPath(prepared.input.repository);
    const head = /^[a-f0-9]{40}$/i.test(compare.head) ? commit(compare.head) : await this.resolveRevision(repoPath, compare.head, budgetGuard);
    const stats = await this.json(`/repositories/${repoPath}/diffstat/${encodeURIComponent(`${compare.base}..${compare.head}`)}?pagelen=${prepared.budget.maxFiles}`, budgetGuard);
    const values = arrayField(stats, "values");
    const diffResponse = await this.request(`/repositories/${repoPath}/diff/${encodeURIComponent(`${compare.base}..${compare.head}`)}`, budgetGuard);
    if (!diffResponse.ok) throw providerHttpError(diffResponse.status);
    const files = bitbucketFiles(values.slice(0, prepared.budget.maxFiles), parseDiff(await boundedResponseText(diffResponse)));
    return finalizeSCMEvidence({
      providerClass: BITBUCKET_PROVIDER_NAME,
      observedAt: this.#clock(),
      prepared,
      base: { ...(revisionRef(compare.base) === undefined ? {} : { ref: revisionRef(compare.base) }), ...(isCommit(compare.base) ? { sha: commit(compare.base) } : {}) },
      head: { ...(revisionRef(compare.head) === undefined ? {} : { ref: revisionRef(compare.head) }), sha: head },
      files,
      providerTruncated: values.length > prepared.budget.maxFiles,
      budgetGuard,
    });
  }

  private async pullRequestEvidence(prepared: ReturnType<typeof prepareSCMInput>, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<SCMChangeEvidenceResult> {
    const repositoryName = prepared.input.repository;
    const pullRequestId = prepared.input.pullRequest;
    if (pullRequestId === undefined) throw new SCMProviderError("malformed");
    const repoPath = repositoryPath(repositoryName);
    const raw = await this.json(`/repositories/${repoPath}/pullrequests/${encodeURIComponent(pullRequestId)}`, budgetGuard);
    const pullRequest = normalizePullRequest(raw, repositoryName, pullRequestId, this.#allowlists.allowedRefs);
    if (prepared.input.ref !== undefined && prepared.input.ref !== pullRequest.base.ref && prepared.input.ref !== pullRequest.head.ref) throw new SCMProviderError("permission");
    if (prepared.input.commit !== undefined && prepared.input.commit.toLowerCase() !== pullRequest.head.sha) throw new SCMProviderError("permission");
    const stats = await this.json(`/repositories/${repoPath}/pullrequests/${encodeURIComponent(pullRequestId)}/diffstat?pagelen=${prepared.budget.maxFiles}`, budgetGuard);
    const values = arrayField(stats, "values");
    const diffResponse = await this.request(`/repositories/${repoPath}/pullrequests/${encodeURIComponent(pullRequestId)}/diff`, budgetGuard);
    if (!diffResponse.ok) throw providerHttpError(diffResponse.status);
    const diff = parseDiff(await boundedResponseText(diffResponse));
    const files = bitbucketFiles(values.slice(0, prepared.budget.maxFiles), diff);
    return finalizeSCMEvidence({
      providerClass: BITBUCKET_PROVIDER_NAME,
      observedAt: this.#clock(),
      prepared,
      base: pullRequest.base,
      head: { ref: pullRequest.head.ref, sha: pullRequest.head.sha ?? "" },
      pullRequest,
      files,
      providerTruncated: values.length > prepared.budget.maxFiles,
      budgetGuard,
    });
  }

  private async commitFiles(repoPath: string, sha: string, maxItems: number, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<{ files: RawSCMFile[]; truncated: boolean }> {
    const stats = await this.json(`/repositories/${repoPath}/commit/${encodeURIComponent(sha)}/diffstat?pagelen=${maxItems}`, budgetGuard);
    const values = arrayField(stats, "values");
    const diffResponse = await this.request(`/repositories/${repoPath}/commit/${encodeURIComponent(sha)}/diff`, budgetGuard);
    if (!diffResponse.ok) throw providerHttpError(diffResponse.status);
    const diff = parseDiff(await boundedResponseText(diffResponse));
    return { files: bitbucketFiles(values.slice(0, maxItems), diff), truncated: values.length > maxItems };
  }

  private async resolveRevision(repoPath: string, revision: string, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<string> {
    const raw = firstCommit(await this.json(`/repositories/${repoPath}/commits/${encodeURIComponent(revision)}?pagelen=1`, budgetGuard));
    return commit(raw.hash);
  }

  private async json(path: string, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<Record<string, unknown>> {
    return boundedJson(await this.request(path, budgetGuard));
  }

  private async request(path: string, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<Response> {
    budgetGuard.beginRequest();
    try {
      const response = await this.#fetch(resolveSCMUrl(this.#baseUrl, path), {
        method: "GET",
        headers: { accept: "application/json, text/plain", authorization: this.#authorization },
        redirect: "error",
        signal: AbortSignal.timeout(Math.min(10_000, budgetGuard.remainingMs)),
      });
      budgetGuard.finishRequest();
      return response;
    } catch { throw new SCMProviderError("unavailable"); }
  }
}

function basicAuthorization(options: BitbucketSCMProviderOptions): string {
  let value = options.token;
  if (options.token !== undefined && options.tokenFile !== undefined) throw new Error("Configure one Bitbucket token source");
  if (options.tokenFile !== undefined) {
    const metadata = statSync(options.tokenFile);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > 4 * 1_024 || (metadata.mode & 0o077) !== 0) throw new Error("Invalid Bitbucket token file");
    value = readFileSync(options.tokenFile, "utf8").trim();
  }
  if (value === undefined || value.length === 0) throw new Error("Bitbucket token is required");
  if (options.username !== undefined) return `Basic ${Buffer.from(`${options.username}:${value}`, "utf8").toString("base64")}`;
  if (value.includes(":")) return `Basic ${Buffer.from(value, "utf8").toString("base64")}`;
  return `Bearer ${value}`;
}

function repositoryPath(value: string): string {
  const [workspace, slug, extra] = value.split("/");
  if (workspace === undefined || slug === undefined || extra !== undefined) throw new SCMProviderError("malformed");
  return `${encodeURIComponent(workspace)}/${encodeURIComponent(slug)}`;
}

function isCommit(value: string): boolean { return /^[a-f0-9]{40}$/i.test(value); }
function revisionRef(value: string): string | undefined { return isCommit(value) ? undefined : ref(value); }

function normalizePullRequest(raw: Record<string, unknown>, expectedRepository: string, expectedId: string, allowedRefs: readonly string[] | undefined): SCMPullRequest {
  const id = nativeId(raw.id);
  if (id !== expectedId || repositoryFrom(raw.repository) !== expectedRepository) throw new SCMProviderError("malformed");
  const base = side(raw.destination, allowedRefs);
  const head = side(raw.source, allowedRefs);
  const title = typeof raw.title === "string" ? redactSCMText(raw.title, 512).text : undefined;
  return {
    id,
    ...(title === undefined ? {} : { title }),
    ...(typeof raw.state === "string" ? { state: raw.state.slice(0, 64) } : {}),
    base: { ref: base.ref, sha: base.sha },
    head: { ref: head.ref, sha: head.sha },
  };
}

function side(value: unknown, allowedRefs: readonly string[] | undefined): { ref: string; sha: string } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new SCMProviderError("malformed");
  const raw = value as Record<string, unknown>;
  const branch = raw.branch;
  if (branch === null || typeof branch !== "object" || Array.isArray(branch)) throw new SCMProviderError("malformed");
  const branchRecord = branch as Record<string, unknown>;
  const branchName = ref(branchRecord.name);
  assertResponseRef(branchName, allowedRefs ?? []);
  const commitValue = raw.commit;
  if (commitValue === null || typeof commitValue !== "object" || Array.isArray(commitValue)) throw new SCMProviderError("malformed");
  return { ref: branchName, sha: commit((commitValue as Record<string, unknown>).hash) };
}

function repositoryFrom(value: unknown): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new SCMProviderError("malformed");
  const raw = value as Record<string, unknown>;
  if (typeof raw.full_name === "string") return repository(raw.full_name);
  const links = raw.links;
  if (links !== null && typeof links === "object" && !Array.isArray(links)) {
    const self = (links as Record<string, unknown>).self;
    if (self !== null && typeof self === "object" && !Array.isArray(self) && typeof (self as Record<string, unknown>).href === "string") {
      const parsed = normalizeRepositoryFromUrl((self as Record<string, unknown>).href as string);
      if (parsed !== undefined) return parsed;
    }
  }
  throw new SCMProviderError("malformed");
}

function firstCommit(raw: Record<string, unknown>): Record<string, unknown> {
  if (Array.isArray(raw.values)) {
    const first = raw.values[0];
    if (first === null || typeof first !== "object" || Array.isArray(first)) throw new SCMProviderError("malformed");
    return first as Record<string, unknown>;
  }
  return raw;
}

function firstParent(value: unknown): { sha?: string } {
  if (!Array.isArray(value) || value.length === 0) return {};
  const first = value[0];
  if (first === null || typeof first !== "object" || Array.isArray(first)) throw new SCMProviderError("malformed");
  return { sha: commit((first as Record<string, unknown>).hash) };
}

function arrayField(value: Record<string, unknown>, field: string): unknown[] {
  if (!Array.isArray(value[field])) throw new SCMProviderError("malformed");
  return value[field] as unknown[];
}

function bitbucketFiles(values: readonly unknown[], diffs: ReadonlyMap<string, string>): RawSCMFile[] {
  return values.map((value): RawSCMFile => {
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new SCMProviderError("malformed");
    const raw = value as Record<string, unknown>;
    const oldPath = filePath(raw.old);
    const newPath = filePath(raw.new);
    const path = newPath ?? oldPath;
    if (path === undefined) throw new SCMProviderError("malformed");
    const status = statusType(raw.status, oldPath, newPath);
    const patch = diffs.get(path);
    return { path, status, additions: count(raw.lines_added), deletions: count(raw.lines_removed), ...(patch === undefined ? {} : { patch }), binary: patch !== undefined && /(?:^Binary files|GIT binary patch)/im.test(patch) };
  });
}

function filePath(value: unknown): string | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const path = (value as Record<string, unknown>).path;
  return typeof path === "string" && path.length > 0 ? path : undefined;
}

function statusType(value: unknown, oldPath: string | undefined, newPath: string | undefined): RawSCMFile["status"] {
  const type = value !== null && typeof value === "object" && !Array.isArray(value) && typeof (value as Record<string, unknown>).type === "string" ? String((value as Record<string, unknown>).type).toLowerCase() : "";
  if (type === "added") return "added";
  if (type === "removed") return "removed";
  if (type === "renamed" || (oldPath !== undefined && newPath !== undefined && oldPath !== newPath)) return "renamed";
  if (type === "copied") return "copied";
  if (type === "modified") return "modified";
  return "unknown";
}

function parseDiff(value: string): Map<string, string> {
  const result = new Map<string, string>();
  const blocks = value.split(/(?=^diff --git )/m).filter((block) => block.startsWith("diff --git "));
  for (const block of blocks) {
    const header = block.split(/\r?\n/, 1)[0] ?? "";
    const match = header.match(/^diff --git a\/(.+) b\/(.+)$/);
    if (match === null) continue;
    result.set(match[2] ?? match[1] ?? "", block);
  }
  return result;
}

function count(value: unknown): number {
  if (value === undefined) return 0;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 1_000_000_000) throw new SCMProviderError("malformed");
  return value;
}
