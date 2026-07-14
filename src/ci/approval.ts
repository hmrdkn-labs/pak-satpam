import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";
import { CIRequestIdSchema, CIRunIdSchema, CIRepositorySchema, CIWorkflowSchema } from "../domain/ci-schemas.js";
import { redactMetadata } from "./redaction.js";

export const MAX_APPROVAL_TTL_SECONDS = 300;
const ApprovalBindingSchema = z.object({
  repo: CIRepositorySchema,
  workflow: CIWorkflowSchema,
  runId: CIRunIdSchema,
  requestId: CIRequestIdSchema,
  runAttempt: z.number().int().min(1).max(100),
  headSha: z.string().regex(/^[a-f0-9]{40}$/),
  nonce: z.string().min(16).max(128),
  expiresAt: z.number().int().positive(),
  issuedAt: z.number().int().positive(),
  version: z.literal(1),
}).strict();
export type ApprovalBinding = z.infer<typeof ApprovalBindingSchema>;
export type ApprovalRequest = Omit<ApprovalBinding, "nonce" | "expiresAt" | "issuedAt" | "version"> & {
  readonly ttlSeconds: number;
  readonly nonce?: string;
};
export type ApprovalErrorCode = "malformed" | "signature" | "binding" | "expired" | "replay" | "duplicate" | "policy";
export type ApprovalAuditEvent = Record<string, unknown>;
export type ApprovalConsumeResult = { ok: true } | { ok: false; code: "replay" | "duplicate" };
type ApprovalRequestBinding = Pick<ApprovalBinding, "repo" | "workflow" | "runId" | "runAttempt" | "headSha" | "requestId">;
type ApprovalUseRecord = ApprovalRequestBinding & Pick<ApprovalBinding, "nonce"> & { outcome: string; at: string };

export interface ApprovalAuditStore {
  hasNonce(nonce: string): boolean;
  hasRequest(binding: ApprovalRequestBinding): boolean;
  consumeApproval(record: ApprovalUseRecord): ApprovalConsumeResult;
  acquireActionLease(binding: Pick<ApprovalBinding, "repo" | "workflow" | "runId">): (() => void) | undefined;
  recordApprovalUse(record: ApprovalUseRecord): void;
  append(event: ApprovalAuditEvent): void;
}

export class InMemoryApprovalAuditStore implements ApprovalAuditStore {
  readonly events: ApprovalAuditEvent[] = [];
  readonly #nonces = new Set<string>();
  readonly #requests = new Set<string>();
  readonly #actions = new Set<string>();

  hasNonce(nonce: string): boolean { return this.#nonces.has(digest(nonce)); }
  hasRequest(binding: ApprovalRequestBinding): boolean {
    return this.#requests.has(requestKey(binding));
  }
  consumeApproval(record: ApprovalUseRecord): ApprovalConsumeResult {
    if (this.#nonces.has(digest(record.nonce))) return { ok: false, code: "replay" };
    if (this.#requests.has(requestKey(record))) return { ok: false, code: "duplicate" };
    this.recordApprovalUse(record);
    return { ok: true };
  }
  acquireActionLease(binding: Pick<ApprovalBinding, "repo" | "workflow" | "runId">): (() => void) | undefined {
    const key = actionKey(binding);
    if (this.#actions.has(key)) return undefined;
    this.#actions.add(key);
    return () => { this.#actions.delete(key); };
  }
  recordApprovalUse(record: ApprovalUseRecord): void {
    this.#nonces.add(digest(record.nonce));
    this.#requests.add(requestKey(record));
    this.append({ event: "approval_consumed", repo: record.repo, workflow: record.workflow, runId: record.runId, requestId: record.requestId, nonceDigest: digest(record.nonce), outcome: record.outcome, at: record.at });
  }
  append(event: ApprovalAuditEvent): void { this.events.push(redactMetadata(event) as ApprovalAuditEvent); }
}

export class FileApprovalAuditStore implements ApprovalAuditStore {
  readonly #replayPath: string;
  readonly #auditPath: string;

  constructor(options: { replayPath: string; auditPath: string }) {
    this.#replayPath = options.replayPath;
    this.#auditPath = options.auditPath;
  }
  hasNonce(nonce: string): boolean {
    return this.readReplay().some((record) => record.nonceDigest === digest(nonce));
  }
  hasRequest(binding: ApprovalRequestBinding): boolean {
    const key = requestKey(binding);
    return this.readReplay().some((record) => record.requestDigest === digest(key));
  }
  consumeApproval(record: ApprovalUseRecord): ApprovalConsumeResult {
    return withFileLock(this.#replayPath, () => {
      const replay = this.readReplay();
      if (replay.some((entry) => entry.nonceDigest === digest(record.nonce))) return { ok: false, code: "replay" };
      if (replay.some((entry) => entry.requestDigest === digest(requestKey(record)))) return { ok: false, code: "duplicate" };
      this.appendReplayRecord(record);
      this.append({
        event: "approval_consumed",
        repo: record.repo,
        workflow: record.workflow,
        runId: record.runId,
        requestId: record.requestId,
        nonceDigest: digest(record.nonce),
        outcome: record.outcome,
        at: record.at,
      });
      return { ok: true };
    });
  }
  acquireActionLease(binding: Pick<ApprovalBinding, "repo" | "workflow" | "runId">): (() => void) | undefined {
    const lockPath = `${this.#replayPath}.action-${digest(actionKey(binding))}.lock`;
    ensureParent(lockPath);
    let descriptor: number;
    try { descriptor = openSync(lockPath, "wx", 0o600); } catch (error) {
      if (isNodeError(error, "EEXIST")) {
        try {
          if (Date.now() - statSync(lockPath).mtimeMs > 10 * 60_000) {
            unlinkSync(lockPath);
            descriptor = openSync(lockPath, "wx", 0o600);
          } else return undefined;
        } catch (staleError) {
          if (isNodeError(staleError, "EEXIST")) return undefined;
          throw staleError;
        }
      } else throw error;
    }
    return () => {
      closeSync(descriptor);
      try { unlinkSync(lockPath); } catch (error) { if (!isNodeError(error, "ENOENT")) throw error; }
    };
  }
  recordApprovalUse(record: ApprovalUseRecord): void {
    withFileLock(this.#replayPath, () => {
      this.appendReplayRecord(record);
      this.append({ event: "approval_consumed", repo: record.repo, workflow: record.workflow, runId: record.runId, requestId: record.requestId, nonceDigest: digest(record.nonce), outcome: record.outcome, at: record.at });
    });
  }
  append(event: ApprovalAuditEvent): void {
    withFileLock(this.#auditPath, () => {
      ensurePrivateFile(this.#auditPath);
      appendFileSync(this.#auditPath, `${JSON.stringify(redactMetadata(event))}\n`, { encoding: "utf8", mode: 0o600 });
    });
  }
  private appendReplayRecord(record: ApprovalUseRecord): void {
    ensurePrivateFile(this.#replayPath);
    appendFileSync(this.#replayPath, `${JSON.stringify({
      nonceDigest: digest(record.nonce),
      requestDigest: digest(requestKey(record)),
      repo: record.repo,
      workflow: record.workflow,
      runId: record.runId,
      requestId: record.requestId,
      outcome: record.outcome,
      at: record.at,
    })}\n`, { encoding: "utf8", mode: 0o600 });
  }
  private readReplay(): Array<{ nonceDigest?: string; requestDigest?: string }> {
    try {
      return readFileSync(this.#replayPath, "utf8").split("\n").filter(Boolean).flatMap((line) => {
        try {
          const value: unknown = JSON.parse(line);
          return value !== null && typeof value === "object" ? [value as { nonceDigest?: string; requestDigest?: string }] : [];
        } catch { return []; }
      });
    } catch { return []; }
  }
}

export interface ApprovalTokenServiceOptions {
  readonly key: Uint8Array;
  readonly clock: () => Date;
  readonly audit: ApprovalAuditStore;
}

export class ApprovalTokenService {
  readonly #key: Uint8Array;
  readonly #clock: () => Date;
  readonly #audit: ApprovalAuditStore;

  constructor(options: ApprovalTokenServiceOptions) {
    if (options.key.byteLength < 32) throw new Error("approval key must be at least 32 bytes");
    this.#key = options.key;
    this.#clock = options.clock;
    this.#audit = options.audit;
  }

  issue(request: ApprovalRequest): string {
    if (!Number.isInteger(request.ttlSeconds) || request.ttlSeconds < 1 || request.ttlSeconds > MAX_APPROVAL_TTL_SECONDS) {
      throw new Error(`approval TTL must be between 1 and ${MAX_APPROVAL_TTL_SECONDS} seconds`);
    }
    const issuedAt = Math.floor(this.#clock().getTime() / 1_000);
    const payload: ApprovalBinding = {
      version: 1,
      repo: request.repo,
      workflow: request.workflow,
      runId: request.runId,
      runAttempt: request.runAttempt,
      headSha: request.headSha,
      requestId: request.requestId,
      nonce: request.nonce ?? randomBytes(18).toString("base64url"),
      issuedAt,
      expiresAt: issuedAt + request.ttlSeconds,
    };
    ApprovalBindingSchema.parse(payload);
    const encoded = encode(payload);
    return `${encoded}.${signature(this.#key, encoded)}`;
  }

  verifyAndConsume(token: string, binding: Omit<ApprovalBinding, "nonce" | "expiresAt" | "issuedAt" | "version">): { ok: true } | { ok: false; code: ApprovalErrorCode } {
    const parts = token.split(".");
    if (parts.length !== 2 || parts[0] === undefined || parts[1] === undefined) return { ok: false, code: "malformed" };
    const [encoded, suppliedSignature] = parts;
    let payload: ApprovalBinding;
    try {
      const parsed: unknown = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
      payload = ApprovalBindingSchema.parse(parsed);
    } catch { return { ok: false, code: "malformed" }; }
    const expected = signature(this.#key, encoded);
    const expectedBuffer = Buffer.from(expected);
    const suppliedBuffer = Buffer.from(suppliedSignature);
    if (expectedBuffer.length !== suppliedBuffer.length || !timingSafeEqual(expectedBuffer, suppliedBuffer)) return { ok: false, code: "signature" };
    if (payload.repo !== binding.repo || payload.workflow !== binding.workflow || payload.runId !== binding.runId || payload.runAttempt !== binding.runAttempt || payload.headSha !== binding.headSha || payload.requestId !== binding.requestId) return { ok: false, code: "binding" };
    const now = Math.floor(this.#clock().getTime() / 1_000);
    if (payload.expiresAt <= now || payload.expiresAt - payload.issuedAt > MAX_APPROVAL_TTL_SECONDS || payload.issuedAt > now + 1) return { ok: false, code: "expired" };
    return this.#audit.consumeApproval({ ...binding, nonce: payload.nonce, outcome: "consumed", at: this.#clock().toISOString() });
  }

  audit(event: ApprovalAuditEvent): void { this.#audit.append(event); }
  acquireActionLease(binding: Pick<ApprovalBinding, "repo" | "workflow" | "runId">): (() => void) | undefined {
    return this.#audit.acquireActionLease(binding);
  }

  static readKeyFile(path: string): Buffer {
    const metadata = statSync(path);
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) throw new Error("approval key file must be a regular 0600 file");
    const key = readFileSync(path);
    if (key.byteLength < 32) throw new Error("approval key must be at least 32 bytes");
    return key;
  }
}

function requestKey(binding: ApprovalRequestBinding): string {
  return [binding.repo, binding.workflow, binding.runId, binding.runAttempt, binding.headSha, binding.requestId].join("\u001f");
}
function actionKey(binding: Pick<ApprovalBinding, "repo" | "workflow" | "runId">): string { return [binding.repo, binding.workflow, binding.runId].join("\u001f"); }
function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function encode(payload: ApprovalBinding): string { return Buffer.from(JSON.stringify(payload)).toString("base64url"); }
function signature(key: Uint8Array, encoded: string): string { return createHmac("sha256", key).update(encoded).digest("base64url"); }
function ensureParent(path: string): void { mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); }

function ensurePrivateFile(path: string): void {
  try {
    const metadata = statSync(path);
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) throw new Error("approval metadata file must be private");
  } catch (error) {
    if (!isNodeError(error, "ENOENT")) throw error;
  }
}

function withFileLock<T>(path: string, operation: () => T): T {
  const lockPath = `${path}.lock`;
  ensureParent(lockPath);
  const descriptor = acquireFileLock(lockPath);
  try {
    ensurePrivateFile(path);
    return operation();
  } finally {
    closeSync(descriptor);
    try { unlinkSync(lockPath); } catch (error) { if (!isNodeError(error, "ENOENT")) throw error; }
  }
}

function acquireFileLock(path: string): number {
  const waitCell = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + 5_000;
  while (Date.now() <= deadline) {
    try {
      return openSync(path, "wx", 0o600);
    } catch (error) {
      if (!isNodeError(error, "EEXIST")) throw error;
      try {
        if (Date.now() - statSync(path).mtimeMs > 30_000) unlinkSync(path);
      } catch (staleError) {
        if (!isNodeError(staleError, "ENOENT")) throw staleError;
      }
      Atomics.wait(waitCell, 0, 0, 5);
    }
  }
  throw new Error("approval replay lock unavailable");
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === code;
}
