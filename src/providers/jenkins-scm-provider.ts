import { readFileSync, statSync } from "node:fs";
import {
  assertTrustedHost,
  assertResponseRef,
  boundedJson,
  commit,
  createSCMBudgetGuard,
  finalizeSCMEvidence,
  prepareSCMInput,
  ref,
  repository,
  resolveSCMUrl,
  type RawSCMFile,
} from "./scm-adapter-helpers.js";
import { assertAllowedRef, normalizeRepositoryFromUrl } from "../scm/context.js";
import { SCMProviderError, type SCMReadProvider } from "../scm/provider.js";
import type { SCMChangeEvidenceInput, SCMChangeEvidenceResult, SCMPullRequest } from "../scm/schemas.js";
import { assertCIProviderTransport, normalizeCIProviderEndpoint } from "../domain/ci-provider-contracts.js";

const JENKINS_PROVIDER_NAME = "jenkins";

export interface JenkinsSCMProviderOptions {
  readonly baseUrl: string;
  readonly job: string;
  readonly branch?: string;
  readonly username?: string;
  readonly token?: string;
  readonly tokenFile?: string;
  readonly fetch: typeof globalThis.fetch;
  readonly clock?: () => Date;
  readonly allowedRepositories: readonly string[];
  readonly allowedRefs: readonly string[];
  readonly allowedHosts?: readonly string[];
  readonly allowInsecureHttp?: boolean;
}

export class JenkinsSCMProvider implements SCMReadProvider {
  readonly #baseUrl: URL;
  readonly #job: string;
  readonly #branch: string | undefined;
  readonly #authorization: string | undefined;
  readonly #fetch: typeof globalThis.fetch;
  readonly #clock: () => Date;
  readonly #allowlists: Pick<JenkinsSCMProviderOptions, "allowedRepositories" | "allowedRefs">;

  constructor(options: JenkinsSCMProviderOptions) {
    if (options.allowedRepositories.length === 0 || options.allowedRefs.length === 0) throw new Error("Jenkins SCM allowlists are required");
    this.#baseUrl = assertTrustedHost(options.baseUrl, options.allowedHosts, "Jenkins API base URL");
    if (!this.#baseUrl.pathname.endsWith("/")) this.#baseUrl.pathname += "/";
    this.#job = safeJob(options.job);
    this.#branch = options.branch;
    if (this.#branch !== undefined) ref(this.#branch);
    assertCIProviderTransport(normalizeCIProviderEndpoint({ origin: this.#baseUrl.origin, path: this.#baseUrl.pathname }), {
      providerLabel: "Jenkins",
      credentialed: options.username !== undefined || options.token !== undefined || options.tokenFile !== undefined,
      ...(options.allowInsecureHttp === undefined ? {} : { allowInsecureHttp: options.allowInsecureHttp }),
    });
    this.#authorization = basicAuthorization(options);
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? (() => new Date());
    this.#allowlists = options;
  }

  async getChangeEvidence(input: SCMChangeEvidenceInput): Promise<SCMChangeEvidenceResult> {
    const prepared = prepareSCMInput(input, this.#allowlists);
    if (prepared.input.compare !== undefined) throw new SCMProviderError("unsupported");
    const budgetGuard = createSCMBudgetGuard(prepared.budget, this.#clock);
    const branch = this.#branch ?? prepared.input.ref;
    if (branch === undefined) throw new SCMProviderError("malformed");
    try { assertAllowedRef(branch, this.#allowlists.allowedRefs); } catch { throw new SCMProviderError("permission"); }
    if (prepared.input.ref !== undefined && prepared.input.ref !== branch) throw new SCMProviderError("permission");
    const response = await this.request(buildPath(this.#job, branch), budgetGuard);
    const raw = await boundedJson(response);
    const reportedRepository = jenkinsRepository(raw);
    if (reportedRepository !== prepared.input.repository) throw new SCMProviderError("malformed");
    const reportedRef = ref(raw.branchName ?? raw.ref ?? raw.branch);
    if (reportedRef !== branch) throw new SCMProviderError("permission");
    assertResponseRef(reportedRef, this.#allowlists.allowedRefs);
    const headSha = jenkinsSha(raw);
    if (prepared.input.commit !== undefined && prepared.input.commit.toLowerCase() !== headSha) throw new SCMProviderError("malformed");
    const files = jenkinsFiles(raw.changeSets, prepared.budget.maxFiles);
    const pullRequest = prepared.input.pullRequest === undefined ? undefined : jenkinsPullRequest(raw.changeSets, prepared.input.pullRequest, reportedRef, headSha);
    return finalizeSCMEvidence({
      providerClass: JENKINS_PROVIDER_NAME,
      observedAt: this.#clock(),
      prepared,
      base: {},
      head: { ref: reportedRef, sha: headSha },
      ...(pullRequest === undefined ? {} : { pullRequest }),
      files: files.files,
      providerTruncated: files.truncated,
      budgetGuard,
    });
  }

  getRepositoryEvidence(input: SCMChangeEvidenceInput): Promise<SCMChangeEvidenceResult> {
    return this.getChangeEvidence(input);
  }

  private async request(path: string, budgetGuard: ReturnType<typeof createSCMBudgetGuard>): Promise<Response> {
    budgetGuard.beginRequest();
    try {
      const response = await this.#fetch(resolveSCMUrl(this.#baseUrl, path), {
        method: "GET",
        headers: { accept: "application/json", ...(this.#authorization === undefined ? {} : { authorization: this.#authorization }) },
        redirect: "error",
        signal: AbortSignal.timeout(Math.min(10_000, budgetGuard.remainingMs)),
      });
      budgetGuard.finishRequest();
      return response;
    } catch { throw new SCMProviderError("unavailable"); }
  }
}

function safeJob(value: string): string {
  const segments = value.split("/");
  if (segments.length === 0 || segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) throw new Error("Jenkins job path is unsafe");
  return value;
}

function buildPath(job: string, branch: string): string {
  return `/${[...job.split("/"), branch].map((segment) => `job/${encodeURIComponent(segment)}`).join("/")}/lastBuild/api/json`;
}

function basicAuthorization(options: JenkinsSCMProviderOptions): string | undefined {
  let token = options.token;
  if (options.token !== undefined && options.tokenFile !== undefined) throw new Error("Configure one Jenkins token source");
  if (options.tokenFile !== undefined) {
    const metadata = statSync(options.tokenFile);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > 4 * 1_024 || (metadata.mode & 0o077) !== 0) throw new Error("Invalid Jenkins token file");
    token = readFileSync(options.tokenFile, "utf8").trim();
  }
  if (token === undefined && options.username === undefined) return undefined;
  if (token === undefined || options.username === undefined || token.length === 0 || options.username.length === 0) throw new Error("Jenkins Basic auth requires username and token");
  return `Basic ${Buffer.from(`${options.username}:${token}`, "utf8").toString("base64")}`;
}

function jenkinsRepository(raw: Record<string, unknown>): string {
  const urls: string[] = [];
  const scm = raw.scm;
  if (scm !== null && typeof scm === "object" && !Array.isArray(scm)) {
    const configs = (scm as Record<string, unknown>).userRemoteConfigs;
    if (Array.isArray(configs)) {
      for (const config of configs) {
        if (config !== null && typeof config === "object" && !Array.isArray(config) && typeof (config as Record<string, unknown>).url === "string") urls.push((config as Record<string, unknown>).url as string);
      }
    }
  }
  const repositories = [...new Set(urls.map(normalizeRepositoryFromUrl).filter((value): value is string => value !== undefined))];
  if (repositories.length !== 1) throw new SCMProviderError("malformed");
  return repository(repositories[0]);
}

function jenkinsSha(raw: Record<string, unknown>): string {
  const actions = Array.isArray(raw.actions) ? raw.actions : [];
  for (const action of actions) {
    if (action === null || typeof action !== "object" || Array.isArray(action)) continue;
    const revision = (action as Record<string, unknown>).lastBuiltRevision;
    if (revision !== null && typeof revision === "object" && !Array.isArray(revision)) {
      const sha = (revision as Record<string, unknown>).SHA1;
      if (typeof sha === "string" && /^[a-f0-9]{40}$/i.test(sha)) return commit(sha);
    }
  }
  throw new SCMProviderError("malformed");
}

function jenkinsFiles(value: unknown, maxFiles: number): { files: RawSCMFile[]; truncated: boolean } {
  if (value === undefined) return { files: [], truncated: false };
  if (!Array.isArray(value)) throw new SCMProviderError("malformed");
  const files: RawSCMFile[] = [];
  for (const changeSet of value) {
    if (changeSet === null || typeof changeSet !== "object" || Array.isArray(changeSet)) throw new SCMProviderError("malformed");
    const items = (changeSet as Record<string, unknown>).items;
    if (items === undefined) continue;
    if (!Array.isArray(items)) throw new SCMProviderError("malformed");
    for (const item of items) {
      if (item === null || typeof item !== "object" || Array.isArray(item)) throw new SCMProviderError("malformed");
      const paths = (item as Record<string, unknown>).paths;
      if (paths === undefined) continue;
      if (!Array.isArray(paths)) throw new SCMProviderError("malformed");
      for (const path of paths) {
        if (path === null || typeof path !== "object" || Array.isArray(path) || typeof (path as Record<string, unknown>).file !== "string") throw new SCMProviderError("malformed");
        const file = path as Record<string, unknown>;
        const name = file.file as string;
        if (files.length >= maxFiles) return { files, truncated: true };
        files.push({ path: name, status: jenkinsStatus(file.editType), binary: binaryPath(name) });
      }
    }
  }
  return { files, truncated: files.length >= maxFiles };
}

function jenkinsPullRequest(value: unknown, expectedId: string, branch: string, sha: string): SCMPullRequest {
  if (!Array.isArray(value)) throw new SCMProviderError("malformed");
  const ids = value.flatMap((changeSet) => {
    if (changeSet === null || typeof changeSet !== "object" || Array.isArray(changeSet) || !Array.isArray((changeSet as Record<string, unknown>).items)) return [];
    return ((changeSet as Record<string, unknown>).items as unknown[]).flatMap((item) => item !== null && typeof item === "object" && !Array.isArray(item) && (typeof (item as Record<string, unknown>).id === "string" || typeof (item as Record<string, unknown>).id === "number") ? [String((item as Record<string, unknown>).id)] : []);
  });
  if (!ids.includes(expectedId)) throw new SCMProviderError("malformed");
  return { id: expectedId, base: {}, head: { ref: branch, sha } };
}

function jenkinsStatus(value: unknown): RawSCMFile["status"] {
  const status = typeof value === "string" ? value.toLowerCase() : "";
  if (status === "add" || status === "added") return "added";
  if (status === "delete" || status === "deleted" || status === "remove" || status === "removed") return "removed";
  if (status === "rename" || status === "renamed") return "renamed";
  if (status === "copy" || status === "copied") return "copied";
  if (status === "edit" || status === "edited" || status === "modify" || status === "modified") return "modified";
  return "unknown";
}

function binaryPath(path: string): boolean {
  return /\.(?:png|jpe?g|gif|webp|ico|pdf|zip|gz|tar|woff2?|ttf|bin|exe|dylib|so)$/i.test(path);
}
