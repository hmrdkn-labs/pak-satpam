import { redactText } from "../ci/redaction.js";
import { SCMRepositorySchema, SCMRefSchema, type SCMBudget } from "./schemas.js";

export interface RedactedSCMText {
  readonly text: string;
  readonly redacted: boolean;
  readonly binary: boolean;
  readonly truncated: boolean;
}

export interface SCMBoundedItems<T> {
  readonly items: readonly T[];
  readonly truncated: boolean;
  readonly usage: { readonly bytes: number; readonly items: number; readonly tokens: number; readonly hunks: number; readonly lines: number };
}

export function utf8Bytes(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

export function estimateSCMTokens(value: unknown): number {
  return Math.ceil(utf8Bytes(JSON.stringify(value) ?? "null") / 4);
}

export function redactSCMText(input: string, maxBytes: number): RedactedSCMText {
  if (isBinaryText(input)) return { text: "[BINARY_SUPPRESSED]", redacted: true, binary: true, truncated: false };
  const initial = redactText(input, Math.max(maxBytes, 1));
  let text = initial.text;
  let truncated = false;
  if (utf8Bytes(text) > maxBytes) {
    const suffix = "...[TRUNCATED]";
    text = utf8Bytes(suffix) > maxBytes
      ? truncateUtf8(suffix, maxBytes)
      : `${truncateUtf8(text, maxBytes - utf8Bytes(suffix))}${suffix}`;
    truncated = true;
  }
  return { text, redacted: initial.redacted || truncated, binary: false, truncated };
}

export function isBinaryText(value: string): boolean {
  return value.includes("\u0000") || /^(?:Binary files|GIT binary patch)/im.test(value);
}

type SCMItemBudget = Pick<SCMBudget, "maxBytes"> & Partial<Pick<SCMBudget, "maxFiles" | "maxHunks" | "maxLines">> & { readonly maxItems?: number; readonly maxTokens?: number };

export function boundSCMItems<T>(items: readonly T[], budget: SCMItemBudget): SCMBoundedItems<T> {
  const selected: T[] = [];
  let truncated = false;
  const maxFiles = budget.maxFiles ?? budget.maxItems ?? 100;
  const maxHunks = budget.maxHunks ?? Number.MAX_SAFE_INTEGER;
  const maxLines = budget.maxLines ?? Number.MAX_SAFE_INTEGER;
  const maxTokens = budget.maxTokens ?? Number.MAX_SAFE_INTEGER;
  for (const item of items) {
    if (selected.length >= maxFiles) {
      truncated = true;
      break;
    }
    const candidate = [...selected, item];
    const bytes = utf8Bytes(JSON.stringify(candidate) ?? "null");
    const tokens = Math.ceil(bytes / 4);
    const usage = scmPatchUsage(candidate);
    if (bytes > budget.maxBytes || tokens > maxTokens || usage.hunks > maxHunks || usage.lines > maxLines) {
      truncated = true;
      break;
    }
    selected.push(item);
  }
  if (selected.length < items.length) truncated = true;
  const serialized = JSON.stringify(selected) ?? "null";
  const bytes = utf8Bytes(serialized);
  const usage = scmPatchUsage(selected);
  return { items: selected, truncated, usage: { bytes, items: selected.length, tokens: Math.ceil(bytes / 4), ...usage } };
}

function scmPatchUsage(items: readonly unknown[]): { readonly hunks: number; readonly lines: number } {
  let hunks = 0;
  let lines = 0;
  for (const item of items) {
    if (item === null || typeof item !== "object" || typeof (item as { patch?: unknown }).patch !== "string") continue;
    const patchLines = ((item as { patch: string }).patch).split(/\r?\n/);
    hunks += patchLines.filter((line) => line.startsWith("@@")).length;
    lines += patchLines.filter((line) => !line.startsWith("@@")).length;
  }
  return { hunks, lines };
}

export function assertAllowedRepository(repository: string, allowlist: readonly string[] | undefined): void {
  SCMRepositorySchema.parse(repository);
  if (allowlist !== undefined && !allowlist.includes(repository)) throw new Error("repository is not allowlisted");
}

export function assertAllowedRef(ref: string | undefined, allowlist: readonly string[] | undefined): void {
  if (ref === undefined) return;
  SCMRefSchema.parse(ref);
  if (allowlist !== undefined && !allowlist.includes(ref)) throw new Error("ref is not allowlisted");
}

export function normalizeRepositoryFromUrl(value: string): string | undefined {
  const ssh = value.match(/^[^@]+@[^:]+:(.+)$/);
  const candidate = ssh?.[1] ?? (() => {
    try { return new URL(value).pathname.replace(/^\/+/, ""); } catch { return undefined; }
  })();
  if (candidate === undefined) return undefined;
  const normalized = candidate.replace(/\.git\/?$/, "").replace(/\/+$/, "");
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(normalized) ? normalized : undefined;
}

function truncateUtf8(value: string, maxBytes: number): string {
  if (maxBytes <= 0) return "";
  let end = Math.min(value.length, maxBytes);
  while (end > 0 && utf8Bytes(value.slice(0, end)) > maxBytes) end -= 1;
  return value.slice(0, end);
}
