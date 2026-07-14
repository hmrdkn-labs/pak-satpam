import { readFileSync, statSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

import { CIRepositorySchema, CIWorkflowSchema } from "../domain/ci-schemas.js";
import { isTrustedHermesUrl } from "./delivery.js";

const MAX_OBSERVER_CONFIG_BYTES = 256 * 1_024;
const MAX_OBSERVER_SECRET_BYTES = 256 * 1_024;

const ObserverAllowlistSchema = z.object({
  repo: CIRepositorySchema,
  workflows: z.array(CIWorkflowSchema).min(1).max(50),
}).strict();

const ObserverFileConfigSchema = z.object({
  version: z.literal(1),
  allowlist: z.array(ObserverAllowlistSchema).min(1).max(100),
  state_file: z.string().min(1).max(1_024),
  github: z.object({
    app_id_file: z.string().min(1).max(1_024),
    pem_key_file: z.string().min(1).max(1_024),
    installations: z.array(z.union([
      z.object({ repo: CIRepositorySchema, installation_id_file: z.string().min(1).max(1_024) }).strict(),
      z.object({ owner: z.string().min(1).max(100).regex(/^[A-Za-z0-9_.-]+$/), installation_id_file: z.string().min(1).max(1_024) }).strict(),
    ])).min(1).max(100),
    api_base_url: z.literal("https://api.github.com").default("https://api.github.com"),
  }).strict(),
  hermes: z.object({
    success_url: z.url().optional(),
    status_url: z.url().optional(),
    analysis_url: z.url(),
    trusted_internal_hosts: z.array(z.string().min(1).max(253).refine((value) => !value.includes("*") && !value.includes("/"))).max(20).default([]),
    hmac_key_file: z.string().min(1).max(1_024),
  }).strict().superRefine((value, context) => {
    if (value.success_url === undefined && value.status_url === undefined) context.addIssue({ code: "custom", path: ["success_url"], message: "success_url or status_url is required" });
  }),
  poll: z.object({
    interval_ms: z.number().int().min(1_000).max(86_400_000).default(30_000),
    overlap_ms: z.number().int().min(0).max(86_400_000).default(300_000),
    initial_lookback_ms: z.number().int().min(0).max(30 * 86_400_000).default(86_400_000),
    stale_after_ms: z.number().int().min(1_000).max(7 * 86_400_000).default(3_600_000),
    page_size: z.number().int().min(1).max(100).default(100),
    max_pages: z.number().int().min(1).max(10).default(2),
  }).strict().default({ interval_ms: 30_000, overlap_ms: 300_000, initial_lookback_ms: 86_400_000, stale_after_ms: 3_600_000, page_size: 100, max_pages: 2 }),
  limits: z.object({
    max_failed_jobs: z.number().int().min(0).max(20).default(5),
    max_log_lines: z.number().int().min(1).max(200).default(80),
    max_payload_bytes: z.number().int().min(1_024).max(512 * 1_024).default(128 * 1_024),
  }).strict().default({ max_failed_jobs: 5, max_log_lines: 80, max_payload_bytes: 128 * 1_024 }),
  lease_seconds: z.number().int().min(5).max(3_600).default(60),
  retry: z.object({
    attempts: z.number().int().min(1).max(8).default(4),
    backoff_ms: z.number().int().min(1).max(60_000).default(500),
    timeout_ms: z.number().int().min(100).max(30_000).default(10_000),
  }).strict().default({ attempts: 4, backoff_ms: 500, timeout_ms: 10_000 }),
  health: z.object({
    host: z.string().min(1).max(253).default("127.0.0.1"),
    port: z.number().int().min(1).max(65_535).optional(),
  }).strict().default({ host: "127.0.0.1" }),
}).strict();

export type ObserverFileConfig = z.infer<typeof ObserverFileConfigSchema>;

export interface ObserverAllowlistEntry {
  readonly repo: string;
  readonly workflows: readonly string[];
}

export interface ObserverConfig {
  readonly allowlist: readonly ObserverAllowlistEntry[];
  readonly stateFile: string;
  readonly hermesUrl?: string;
  readonly successUrl?: string;
  readonly analysisUrl?: string;
  readonly trustedHermesHosts?: readonly string[];
  readonly hmacKey: Uint8Array;
  readonly pollIntervalMs: number;
  readonly overlapMs: number;
  readonly initialLookbackMs?: number;
  readonly staleAfterMs: number;
  readonly pageSize: number;
  readonly maxPages: number;
  readonly maxFailedJobs: number;
  readonly maxLogLines: number;
  readonly maxPayloadBytes: number;
  readonly leaseMs: number;
  readonly deliveryAttempts: number;
  readonly deliveryBackoffMs: number;
  readonly deliveryTimeoutMs: number;
  readonly healthHost?: string;
  readonly healthPort?: number;
}

export function loadObserverConfiguration(path: string): ObserverFileConfig {
  const document = readPrivateFile(path, MAX_OBSERVER_CONFIG_BYTES, "observer configuration");
  try {
    const raw: unknown = parseYaml(document);
    const parsed = ObserverFileConfigSchema.safeParse(raw);
    if (!parsed.success) throw new Error();
    for (const entry of parsed.data.allowlist) {
      if (new Set(entry.workflows).size !== entry.workflows.length) throw new Error();
    }
    const successUrl = parsed.data.hermes.success_url ?? parsed.data.hermes.status_url;
    if (successUrl === undefined || !isTrustedHermesUrl(successUrl, parsed.data.hermes.trusted_internal_hosts) || !isTrustedHermesUrl(parsed.data.hermes.analysis_url, parsed.data.hermes.trusted_internal_hosts)) throw new Error();
    return parsed.data;
  } catch {
    throw new Error("Invalid observer configuration");
  }
}

export function readObserverSecretFile(path: string, minimumBytes = 32): Buffer {
  const value = readPrivateFile(path, MAX_OBSERVER_SECRET_BYTES, "observer secret").trim();
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength < minimumBytes) throw new Error("Observer secret is missing or too short");
  return bytes;
}

export function observerRuntimeConfig(file: ObserverFileConfig, hmacKey: Uint8Array): ObserverConfig {
  const successUrl = file.hermes.success_url ?? file.hermes.status_url;
  if (successUrl === undefined) throw new Error("Invalid observer configuration");
  const duplicateRepositories = new Set<string>();
  for (const entry of file.allowlist) {
    if (duplicateRepositories.has(entry.repo)) throw new Error("Invalid observer configuration");
    duplicateRepositories.add(entry.repo);
  }
  return {
    allowlist: file.allowlist.map((entry) => ({ repo: entry.repo, workflows: [...entry.workflows] })),
    stateFile: file.state_file,
    successUrl,
    analysisUrl: file.hermes.analysis_url,
    trustedHermesHosts: [...file.hermes.trusted_internal_hosts],
    hmacKey,
    pollIntervalMs: file.poll.interval_ms,
    overlapMs: file.poll.overlap_ms,
    initialLookbackMs: file.poll.initial_lookback_ms,
    staleAfterMs: file.poll.stale_after_ms,
    pageSize: file.poll.page_size,
    maxPages: file.poll.max_pages,
    maxFailedJobs: file.limits.max_failed_jobs,
    maxLogLines: file.limits.max_log_lines,
    maxPayloadBytes: file.limits.max_payload_bytes,
    leaseMs: file.lease_seconds * 1_000,
    deliveryAttempts: file.retry.attempts,
    deliveryBackoffMs: file.retry.backoff_ms,
    deliveryTimeoutMs: file.retry.timeout_ms,
    ...(file.health.host === undefined ? {} : { healthHost: file.health.host }),
    ...(file.health.port === undefined ? {} : { healthPort: file.health.port }),
  };
}

export function readObserverPrivateFile(path: string): string {
  return readPrivateFile(path, MAX_OBSERVER_SECRET_BYTES, "observer file");
}

function readPrivateFile(path: string, maxBytes: number, label: string): string {
  let metadata;
  try {
    metadata = statSync(path);
  } catch {
    throw new Error(`${label} is unavailable`);
  }
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > maxBytes || (metadata.mode & 0o077) !== 0) {
    throw new Error(`${label} must be a regular 0600 file`);
  }
  try {
    return readFileSync(path, "utf8");
  } catch {
    throw new Error(`${label} is unavailable`);
  }
}
