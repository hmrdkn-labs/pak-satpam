import {
  SCMChangeEvidenceInputSchema,
  SCMProviderNativeIdSchema,
  SCMRepositorySchema,
  SCMRefSchema,
  makeSCMEvidence,
  resolveSCMBudget,
  type SCMChangeEvidenceInput,
  type SCMChangeEvidenceResult,
  type SCMBudget,
  type SCMFileChange,
  type SCMIdentity,
  type SCMPullRequest,
} from "../scm/schemas.js";
import { boundSCMItems, assertAllowedRef, assertAllowedRepository, redactSCMText, utf8Bytes, type SCMBoundedItems } from "../scm/context.js";
import { SCMProviderError } from "../scm/provider.js";

export const MAX_SCM_RESPONSE_BYTES = 2 * 1_024 * 1_024;

export interface SCMAllowlistOptions {
  readonly allowedRepositories?: readonly string[];
  readonly allowedRefs?: readonly string[];
  readonly allowedHosts?: readonly string[];
}

export interface SCMPreparedInput {
  readonly input: SCMChangeEvidenceInput;
  readonly budget: SCMBudget;
}

export function prepareSCMInput(value: unknown, options: SCMAllowlistOptions): SCMPreparedInput {
  let input: SCMChangeEvidenceInput;
  try {
    input = SCMChangeEvidenceInputSchema.parse(value);
    assertAllowedRepository(input.repository, options.allowedRepositories);
    assertAllowedRef(input.ref, options.allowedRefs);
  } catch (error) {
    if (error instanceof SCMProviderError) throw error;
    const message = error instanceof Error ? error.message : "invalid SCM input";
    throw new SCMProviderError(message.includes("allowlisted") ? "permission" : "malformed");
  }
  return { input, budget: resolveSCMBudget(input.budget) };
}

export function assertTrustedHost(value: string, allowedHosts: readonly string[] | undefined, label: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`${label} must be a URL`); }
  if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new Error(`${label} must not contain credentials or query data`);
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (allowedHosts !== undefined && !allowedHosts.some((host) => host.toLowerCase().replace(/\.$/, "") === hostname)) {
    throw new Error(`${label} host is not allowlisted`);
  }
  return url;
}

export function resolveSCMUrl(baseUrl: URL, path: string): URL {
  const url = new URL(path.replace(/^\/+/, ""), baseUrl);
  if (url.origin !== baseUrl.origin || !url.pathname.startsWith(baseUrl.pathname)) throw new SCMProviderError("permission");
  return url;
}

export async function boundedResponseText(response: Response): Promise<string> {
  const text = await response.text();
  if (utf8Bytes(text) > MAX_SCM_RESPONSE_BYTES) throw new SCMProviderError("malformed");
  return text;
}

export async function boundedJson(response: Response): Promise<Record<string, unknown>> {
  if (!response.ok) throw providerHttpError(response.status);
  const text = await boundedResponseText(response);
  try {
    const value: unknown = JSON.parse(text);
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch { throw new SCMProviderError("malformed"); }
}

export function providerHttpError(status: number): SCMProviderError {
  return new SCMProviderError(status === 401 || status === 403 ? "permission" : status === 404 ? "malformed" : "unavailable");
}

export function nativeId(value: unknown): string {
  const id = typeof value === "number" || typeof value === "string" ? String(value) : "";
  if (!SCMProviderNativeIdSchema.safeParse(id).success) throw new SCMProviderError("malformed");
  return id;
}

export function commit(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/i.test(value)) throw new SCMProviderError("malformed");
  return value.toLowerCase();
}

export function ref(value: unknown): string {
  if (typeof value !== "string" || !SCMRefSchema.safeParse(value).success) throw new SCMProviderError("malformed");
  return value;
}

export function assertResponseRef(value: unknown, allowlist: readonly string[]): string {
  const parsed = SCMRefSchema.safeParse(value);
  if (!parsed.success) throw new SCMProviderError("malformed");
  if (!allowlist.includes(parsed.data)) throw new SCMProviderError("permission");
  return parsed.data;
}

export function repository(value: unknown): string {
  if (typeof value !== "string" || !SCMRepositorySchema.safeParse(value).success) throw new SCMProviderError("malformed");
  return value;
}

export function identity(refValue: unknown, shaValue: unknown): SCMIdentity {
  const result: { ref?: string; sha?: string } = {};
  if (refValue !== undefined && refValue !== null) result.ref = ref(refValue);
  if (shaValue !== undefined && shaValue !== null) result.sha = commit(shaValue);
  return result;
}

export interface RawSCMFile {
  readonly path: string;
  readonly status: SCMFileChange["status"];
  readonly additions?: number;
  readonly deletions?: number;
  readonly patch?: string;
  readonly binary?: boolean;
}

export function normalizeFile(raw: RawSCMFile, budget: SCMBudget): { file: SCMFileChange; redacted: boolean } {
  if (raw.path.startsWith("/") || raw.path.split("/").some((segment) => segment === "..")) throw new SCMProviderError("malformed");
  const path = redactSCMText(raw.path, 1_024);
  if (path.binary) throw new SCMProviderError("malformed");
  const patchBudget = Math.max(64, Math.min(32 * 1_024, Math.floor(budget.maxBytes / 4)));
  let result: SCMFileChange = {
    path: path.text,
    status: raw.status,
    additions: boundedCount(raw.additions),
    deletions: boundedCount(raw.deletions),
    binary: raw.binary === true,
  };
  let redacted = path.redacted;
  if (result.binary) {
    result = { ...result, suppressedReason: "binary" };
  } else if (raw.patch !== undefined) {
    const patch = redactSCMText(raw.patch, patchBudget);
    redacted ||= patch.redacted;
    if (patch.binary) {
      result = { ...result, binary: true, suppressedReason: "binary" };
    } else {
      result = {
        ...result,
        patch: patch.text,
        ...(patch.truncated ? { suppressedReason: "budget" as const } : {}),
      };
    }
  } else {
    result = { ...result, suppressedReason: "provider-omitted" };
  }
  return { file: result, redacted };
}

export function finalizeSCMEvidence(args: {
  readonly providerClass: string;
  readonly observedAt: Date;
  readonly prepared: SCMPreparedInput;
  readonly base: SCMIdentity;
  readonly head: SCMIdentity & { readonly sha: string };
  readonly pullRequest?: SCMPullRequest;
  readonly files: readonly RawSCMFile[];
  readonly providerTruncated?: boolean;
  readonly providerRedactions?: boolean;
}): SCMChangeEvidenceResult {
  const normalized = args.files.map((file) => normalizeFile(file, args.prepared.budget));
  const bounded: SCMBoundedItems<SCMFileChange> = boundSCMItems(normalized.map((item) => item.file), args.prepared.budget);
  const additions = bounded.items.reduce((total, file) => total + file.additions, 0);
  const deletions = bounded.items.reduce((total, file) => total + file.deletions, 0);
  const data: SCMChangeEvidenceResult["data"] = {
    repository: args.prepared.input.repository,
    selector: {
      ...(args.prepared.input.ref === undefined ? {} : { ref: args.prepared.input.ref }),
      ...(args.prepared.input.commit === undefined ? {} : { commit: args.prepared.input.commit }),
      ...(args.prepared.input.pullRequest === undefined ? {} : { pullRequest: args.prepared.input.pullRequest }),
    },
    base: args.base,
    head: args.head,
    ...(args.pullRequest === undefined ? {} : { pullRequest: args.pullRequest }),
    files: [...bounded.items],
    summary: { files: bounded.items.length, additions, deletions },
  };
  return makeSCMEvidence(args.providerClass, args.observedAt, data, {
    freshness: "fresh",
    truncated: Boolean(args.providerTruncated) || bounded.truncated,
    redactionsApplied: Boolean(args.providerRedactions) || normalized.some((item) => item.redacted),
    budget: {
      ...args.prepared.budget,
      usedBytes: bounded.usage.bytes,
      usedItems: bounded.usage.items,
      usedTokens: bounded.usage.tokens,
    },
  });
}

function boundedCount(value: number | undefined): number {
  if (value === undefined) return 0;
  if (!Number.isInteger(value) || value < 0 || value > 1_000_000_000) throw new SCMProviderError("malformed");
  return value;
}
