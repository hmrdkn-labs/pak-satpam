import { randomUUID } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export type ObserverDeliveryState = "pending" | "delivered";

export interface ObserverSeenRecord {
  readonly outcome: string;
  readonly observedAt: string;
  readonly delivery: ObserverDeliveryState;
  readonly deliveredAt?: string;
}

export interface ObserverTargetState {
  readonly cursor?: string;
  readonly page: number;
  readonly seen: Readonly<Record<string, ObserverSeenRecord>>;
}

export interface ObserverStateDocument {
  readonly version: 1;
  readonly targets: Readonly<Record<string, ObserverTargetState>>;
  readonly updatedAt: string;
}

export interface ObserverStateStore {
  acquireLease(): (() => void) | undefined;
  load(): ObserverStateDocument;
  save(state: ObserverStateDocument): void;
}

const EMPTY_STATE: ObserverStateDocument = { version: 1, targets: {}, updatedAt: new Date(0).toISOString() };

export class FileObserverStateStore implements ObserverStateStore {
  readonly #filePath: string;
  readonly #lockPath: string;
  readonly #leaseMs: number;
  readonly #clock: () => Date;

  constructor(options: { filePath: string; leaseMs: number; clock?: () => Date }) {
    this.#filePath = options.filePath;
    this.#lockPath = `${options.filePath}.lock`;
    this.#leaseMs = options.leaseMs;
    this.#clock = options.clock ?? (() => new Date());
  }

  acquireLease(): (() => void) | undefined {
    mkdirSync(dirname(this.#lockPath), { recursive: true, mode: 0o700 });
    let descriptor: number;
    try {
      descriptor = openSync(this.#lockPath, "wx", 0o600);
      writeFileSync(descriptor, "observer-lease\n", { encoding: "utf8" });
    } catch (error) {
      if (!isNodeError(error, "EEXIST")) throw new Error("observer lease unavailable");
      try {
        if (this.#clock().getTime() - statSync(this.#lockPath).mtimeMs <= this.#leaseMs) return undefined;
        unlinkSync(this.#lockPath);
        descriptor = openSync(this.#lockPath, "wx", 0o600);
        writeFileSync(descriptor, "observer-lease\n", { encoding: "utf8" });
      } catch (staleError) {
        if (isNodeError(staleError, "EEXIST")) return undefined;
        throw new Error("observer lease unavailable");
      }
    }
    return () => {
      try { closeSync(descriptor); } catch { /* already closed */ }
      try { unlinkSync(this.#lockPath); } catch (error) { if (!isNodeError(error, "ENOENT")) throw error; }
    };
  }

  load(): ObserverStateDocument {
    if (!existsSync(this.#filePath)) return cloneState(EMPTY_STATE);
    try {
      const metadata = statSync(this.#filePath);
      if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) throw new Error();
      const parsed: unknown = JSON.parse(readFileSync(this.#filePath, "utf8"));
      if (!isStateDocument(parsed)) throw new Error();
      return parsed;
    } catch {
      throw new Error("observer_state_malformed");
    }
  }

  save(state: ObserverStateDocument): void {
    if (!isStateDocument(state)) throw new Error("observer_state_malformed");
    mkdirSync(dirname(this.#filePath), { recursive: true, mode: 0o700 });
    const temporary = `${this.#filePath}.${process.pid}.${randomUUID()}.tmp`;
    const descriptor = openSync(temporary, "wx", 0o600);
    try {
      writeFileSync(descriptor, `${JSON.stringify(state)}\n`, { encoding: "utf8" });
      fsyncSync(descriptor);
      closeSync(descriptor);
      renameSync(temporary, this.#filePath);
    } catch (error) {
      try { closeSync(descriptor); } catch { /* best effort cleanup */ }
      try { unlinkSync(temporary); } catch { /* best effort cleanup */ }
      throw error;
    }
  }
}

export class InMemoryObserverStateStore implements ObserverStateStore {
  #state: ObserverStateDocument = cloneState(EMPTY_STATE);
  #leased = false;

  acquireLease(): (() => void) | undefined {
    if (this.#leased) return undefined;
    this.#leased = true;
    return () => { this.#leased = false; };
  }

  load(): ObserverStateDocument { return cloneState(this.#state); }
  save(state: ObserverStateDocument): void { this.#state = cloneState(state); }
}

function isStateDocument(value: unknown): value is ObserverStateDocument {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  if (candidate.version !== 1 || typeof candidate.updatedAt !== "string" || candidate.targets === null || typeof candidate.targets !== "object" || Array.isArray(candidate.targets)) return false;
  for (const target of Object.values(candidate.targets as Record<string, unknown>)) {
    if (target === null || typeof target !== "object" || Array.isArray(target)) return false;
    const record = target as Record<string, unknown>;
    if (record.page !== undefined && (typeof record.page !== "number" || !Number.isInteger(record.page) || record.page < 1)) return false;
    if (record.cursor !== undefined && typeof record.cursor !== "string") return false;
    if (record.seen === null || typeof record.seen !== "object" || Array.isArray(record.seen)) return false;
    for (const seen of Object.values(record.seen as Record<string, unknown>)) {
      if (seen === null || typeof seen !== "object" || Array.isArray(seen)) return false;
      const item = seen as Record<string, unknown>;
      if (typeof item.outcome !== "string" || typeof item.observedAt !== "string" || !["pending", "delivered"].includes(String(item.delivery))) return false;
    }
  }
  return true;
}

function cloneState(state: ObserverStateDocument): ObserverStateDocument {
  return JSON.parse(JSON.stringify(state)) as ObserverStateDocument;
}

function isNodeError(error: unknown, code: string): boolean {
  return error !== null && typeof error === "object" && "code" in error && (error as { code?: unknown }).code === code;
}
