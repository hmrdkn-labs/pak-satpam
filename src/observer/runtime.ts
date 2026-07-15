import { createServer, type Server } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";

import { CIRepositorySchema, CIRunIdSchema, CIWorkflowSchema, type CIWorkflowRun } from "../domain/ci-schemas.js";
import { redactMetadata } from "../ci/redaction.js";
import { CIProviderError, type CIProvider } from "../providers/ci-provider.js";
import { assembleFailureAnalysis, buildAgentNotificationPayload, makeUnavailableFailureAnalysis, type AgentNotificationPayload } from "../ci/forensics.js";
import type { ForensicsProviderSet } from "../providers/ci-provider.js";
import { loadObserverConfiguration, observerRuntimeConfig, readObserverSecretFile, type ObserverConfig } from "./config.js";
import { z } from "zod";
import { HttpDeliverySink, type ObserverDeliveryRoute, type ObserverDeliverySink } from "./delivery.js";
import { observerEventSourceFromProvider, type ObserverEventSource, type ObserverEventSourceKind, type ObserverRunListInput, type ObserverWebhookRequest } from "./events.js";
import { createObserverEventSourceFromProviderConfiguration, createObserverProviderFromConfiguration } from "./provider-factory.js";
import { FileObserverStateStore, type ObserverSeenRecord, type ObserverStateDocument, type ObserverStateStore, type ObserverTargetState } from "./state.js";

export type ObserverOutcome = "success" | "failure" | "cancelled" | "timed_out" | "action_required" | "skipped" | "neutral" | "stale" | "unavailable" | "malformed";

export type ObserverProvider = CIProvider & {
  readonly providerClass?: string;
  readonly forensics?: ForensicsProviderSet;
  listWorkflowRuns(input: ObserverRunListInput): Promise<{ runs: readonly CIWorkflowRun[]; hasMore: boolean; nextPage?: number }>;
};

export interface ObserverEvent {
  readonly schemaVersion: "1.0";
  readonly type: "ci.run.observed";
  readonly eventId: string;
  readonly observedAt: string;
  readonly source: ObserverEventSourceKind;
  readonly providerClass?: string;
  readonly repo: string;
  readonly workflow: string;
  readonly runId: string;
  readonly runAttempt: number;
  readonly terminalConclusion: CIWorkflowRun["conclusion"];
  readonly outcome: ObserverOutcome;
  readonly freshness: "fresh" | "stale";
  readonly updatedAt: string;
  readonly analysis?: unknown;
  readonly evidence?: readonly unknown[];
  readonly remediation?: unknown;
  readonly warnings: readonly { code: string; message: string }[];
}

export interface ObserverPollSummary {
  readonly skipped: boolean;
  readonly observed: readonly { eventId: string; runId: string; outcome: ObserverOutcome }[];
  readonly delivered: number;
  readonly errors: readonly { repo: string; workflow: string; outcome: "unavailable" | "malformed" }[];
  readonly truncatedTargets: number;
}

export interface ObserverWebhookSummary extends ObserverPollSummary {
  readonly accepted: boolean;
}

export interface ObserverMetricsSnapshot {
  readonly polls: number;
  readonly deliveries: number;
  readonly deliveryFailures: number;
  readonly targetErrors: number;
  readonly observations: number;
  readonly suppressed: number;
  readonly outcomes: Readonly<Record<ObserverOutcome, number>>;
  readonly targetCount: number;
  readonly truncatedTargets: number;
  readonly lastPollDegraded: boolean;
  readonly lastPollAt?: string;
  readonly lastError?: "unavailable" | "malformed";
}

type MutableObserverState = {
  version: 1;
  targets: Record<string, ObserverTargetState>;
  updatedAt: string;
};

interface ReconcileResult {
  readonly target: ObserverTargetState;
  readonly failed: boolean;
  readonly delivered: number;
  readonly deliveryFailures: number;
}

const PROVIDER_BACKOFF_BASE_MS = 5_000;
const BACKOFF_MAX_MS = 5 * 60_000;
const DEFAULT_INITIAL_LOOKBACK_MS = 24 * 60 * 60_000;

export class InMemoryObserverMetrics {
  #polls = 0;
  #deliveries = 0;
  #deliveryFailures = 0;
  #targetErrors = 0;
  #observations = 0;
  #suppressed = 0;
  #targetCount = 0;
  #truncatedTargets = 0;
  #lastPollDegraded = false;
  #lastPollAt: string | undefined;
  #lastError: "unavailable" | "malformed" | undefined;
  readonly #outcomes: Record<ObserverOutcome, number> = {
    success: 0, failure: 0, cancelled: 0, timed_out: 0, action_required: 0, skipped: 0, neutral: 0, stale: 0, unavailable: 0, malformed: 0,
  };

  recordPoll(targetCount: number, at: string): void { this.#polls += 1; this.#targetCount = targetCount; this.#lastPollAt = at; }
  recordObservation(outcome: ObserverOutcome): void { this.#observations += 1; this.#outcomes[outcome] += 1; }
  recordSuppressed(): void { this.#suppressed += 1; }
  recordDelivery(): void { this.#deliveries += 1; }
  recordDeliveryFailure(): void { this.#deliveryFailures += 1; }
  recordTargetError(outcome: "unavailable" | "malformed"): void { this.#targetErrors += 1; this.#lastError = outcome; this.#outcomes[outcome] += 1; }
  finishPoll(options: { targetErrors: number; truncatedTargets: number; deliveryFailures: number }): void {
    this.#truncatedTargets = options.truncatedTargets;
    this.#lastPollDegraded = options.targetErrors > 0 || options.truncatedTargets > 0 || options.deliveryFailures > 0;
    if (options.targetErrors === 0) this.#lastError = undefined;
  }
  snapshot(): ObserverMetricsSnapshot {
    return {
      polls: this.#polls,
      deliveries: this.#deliveries,
      deliveryFailures: this.#deliveryFailures,
      targetErrors: this.#targetErrors,
      observations: this.#observations,
      suppressed: this.#suppressed,
      outcomes: { ...this.#outcomes },
      targetCount: this.#targetCount,
      truncatedTargets: this.#truncatedTargets,
      lastPollDegraded: this.#lastPollDegraded,
      ...(this.#lastPollAt === undefined ? {} : { lastPollAt: this.#lastPollAt }),
      ...(this.#lastError === undefined ? {} : { lastError: this.#lastError }),
    };
  }
}

export class ObserverRuntime {
  readonly #config: ObserverConfig;
  readonly #provider: ObserverProvider;
  readonly #source: ObserverEventSource;
  readonly #state: ObserverStateStore;
  readonly #deliver: (body: string, eventId: string, route?: ObserverDeliveryRoute) => Promise<unknown>;
  readonly #clock: () => Date;
  readonly #metrics: InMemoryObserverMetrics;
  #timer: ReturnType<typeof setInterval> | undefined;
  #polling = false;

  constructor(options: {
    config: ObserverConfig;
    provider: ObserverProvider;
    source?: ObserverEventSource;
    state: ObserverStateStore;
    deliver?: (body: string, eventId: string, route?: ObserverDeliveryRoute) => Promise<unknown>;
    sink?: ObserverDeliverySink;
    clock?: () => Date;
    metrics?: InMemoryObserverMetrics;
  }) {
    this.#config = options.config;
    this.#provider = options.provider;
    this.#source = options.source ?? observerEventSourceFromProvider(options.provider);
    this.#state = options.state;
    if (options.deliver === undefined && options.sink === undefined) throw new Error("Observer delivery sink is required");
    this.#deliver = options.deliver ?? ((body, eventId, route) => options.sink!.deliver(body, eventId, route));
    this.#clock = options.clock ?? (() => new Date());
    this.#metrics = options.metrics ?? new InMemoryObserverMetrics();
  }

  get metrics(): InMemoryObserverMetrics { return this.#metrics; }

  async pollOnce(): Promise<ObserverPollSummary> {
    const release = this.#state.acquireLease();
    if (release === undefined) return { skipped: true, observed: [], delivered: 0, errors: [], truncatedTargets: 0 };
    const now = this.#clock();
    this.#metrics.recordPoll(this.targetCount(), now.toISOString());
    const observed: Array<{ eventId: string; runId: string; outcome: ObserverOutcome }> = [];
    const errors: Array<{ repo: string; workflow: string; outcome: "unavailable" | "malformed" }> = [];
    let delivered = 0;
    let truncatedTargets = 0;
    let pollDeliveryFailures = 0;
    try {
      const state = this.#state.load();
      const mutableState = cloneState(state);
      for (const target of targets(this.#config)) {
        const targetKey = targetKeyFor(target.repo, target.workflow);
        const previous = mutableState.targets[targetKey] ?? { page: 1, seen: {} };
        const initialPage = previous.page ?? 1;
        const scanCursor = previous.cursor ?? new Date(now.getTime() - (this.#config.initialLookbackMs ?? DEFAULT_INITIAL_LOOKBACK_MS)).toISOString();
        const backoffUntil = previous.backoffUntil === undefined ? undefined : Date.parse(previous.backoffUntil);
        if (backoffUntil !== undefined && Number.isFinite(backoffUntil) && backoffUntil > now.getTime()) {
          this.#metrics.recordTargetError("unavailable");
          errors.push({ repo: target.repo, workflow: target.workflow, outcome: "unavailable" });
          continue;
        }
        const deliveryBackoffUntil = previous.deliveryBackoffUntil === undefined ? undefined : Date.parse(previous.deliveryBackoffUntil);
        if (deliveryBackoffUntil !== undefined && Number.isFinite(deliveryBackoffUntil) && deliveryBackoffUntil > now.getTime()) {
          this.#metrics.recordTargetError("unavailable");
          errors.push({ repo: target.repo, workflow: target.workflow, outcome: "unavailable" });
          continue;
        }

        let backlogPage = initialPage;
        let backlogPagesFetched = 0;
        let backlogHasMore = false;
        let targetFailedDelivery = false;
        let targetTruncated = false;
        let currentTarget: ObserverTargetState = { ...previous, page: backlogPage, cursor: scanCursor };
        try {
          // The hot lane is always unfiltered page one. A provider may not
          // expose a creation-time filter that sees a long-running run which
          // only became terminal recently.
          const hotResult = await this.#source.listTerminalRuns({
            repo: target.repo,
            workflow: target.workflow,
            page: 1,
            perPage: this.#config.pageSize,
          });
          const hotReconciliation = await this.reconcileRuns({
            runs: hotResult.runs,
            source: "poll",
            target,
            targetKey,
            currentTarget,
            state: mutableState,
            now,
            observed,
            errors,
          });
          currentTarget = hotReconciliation.target;
          targetFailedDelivery = hotReconciliation.failed;
          delivered += hotReconciliation.delivered;
          pollDeliveryFailures += hotReconciliation.deliveryFailures;

          // The backlog lane owns durable page/cursor state. Its filter is
          // computed once and reused unchanged across every page in the scan.
          const backlogCreatedAfter = createdAfterWithOverlap(scanCursor, this.#config.overlapMs);
          while (!targetFailedDelivery && backlogPagesFetched < this.#config.maxPages) {
            currentTarget = { ...currentTarget, page: backlogPage, cursor: scanCursor };
            mutableState.targets[targetKey] = currentTarget;
            this.#state.save(withUpdatedAt(mutableState, now));
            const listInput: {
              repo: string;
              workflow: string;
              page: number;
              perPage: number;
              createdAfter?: string;
            } = {
              repo: target.repo,
              workflow: target.workflow,
              page: backlogPage,
              perPage: this.#config.pageSize,
            };
            if (backlogCreatedAfter !== undefined) listInput.createdAfter = backlogCreatedAfter;
            const result = await this.#source.listTerminalRuns(listInput);
            backlogPagesFetched += 1;
            backlogHasMore = result.hasMore;
            const nextPage = result.nextPage ?? backlogPage + 1;
            if (backlogHasMore && (!Number.isInteger(nextPage) || nextPage <= backlogPage)) throw new CIProviderError("malformed");
            const backlogReconciliation = await this.reconcileRuns({
              runs: result.runs,
              source: "poll",
              target,
              targetKey,
              currentTarget,
              state: mutableState,
              now,
              observed,
              errors,
            });
            currentTarget = backlogReconciliation.target;
            targetFailedDelivery = backlogReconciliation.failed;
            delivered += backlogReconciliation.delivered;
            pollDeliveryFailures += backlogReconciliation.deliveryFailures;
            if (targetFailedDelivery || !backlogHasMore) break;
            backlogPage = nextPage;
          }
          if (targetFailedDelivery) {
            mutableState.targets[targetKey] = { ...currentTarget, page: backlogPage };
            this.#state.save(withUpdatedAt(mutableState, now));
          } else if (backlogHasMore) {
            targetTruncated = true;
            mutableState.targets[targetKey] = { ...currentTarget, page: backlogPage };
            this.#state.save(withUpdatedAt(mutableState, now));
          } else {
            const cleanTarget = withoutBackoff({ ...currentTarget, cursor: now.toISOString(), page: 1 });
            mutableState.targets[targetKey] = pruneSeen(cleanTarget);
            this.#state.save(withUpdatedAt(mutableState, now));
          }
        } catch (error) {
          const outcome = providerErrorOutcome(error);
          this.#metrics.recordTargetError(outcome);
          errors.push({ repo: target.repo, workflow: target.workflow, outcome });
          const persisted = { ...currentTarget, page: backlogPage };
          mutableState.targets[targetKey] = isProviderBackoffError(error)
            ? withProviderBackoff(persisted, now)
            : persisted;
          this.#state.save(withUpdatedAt(mutableState, now));
          continue;
        }
        if (targetTruncated) truncatedTargets += 1;
      }
      this.#metrics.finishPoll({ targetErrors: errors.length, truncatedTargets, deliveryFailures: pollDeliveryFailures });
      return { skipped: false, observed, delivered, errors, truncatedTargets };
    } finally {
      release();
    }
  }

  async ingestWebhook(request: ObserverWebhookRequest): Promise<ObserverWebhookSummary> {
    const release = this.#state.acquireLease();
    if (release === undefined) return { accepted: false, skipped: true, observed: [], delivered: 0, errors: [], truncatedTargets: 0 };
    const observed: Array<{ eventId: string; runId: string; outcome: ObserverOutcome }> = [];
    const errors: Array<{ repo: string; workflow: string; outcome: "unavailable" | "malformed" }> = [];
    let delivered = 0;
    let deliveryFailures = 0;
    try {
      const verifier = this.#source.webhookVerifier;
      if (verifier === undefined) {
        this.#metrics.recordTargetError("malformed");
        errors.push({ repo: "unknown", workflow: "unknown", outcome: "malformed" });
        this.#metrics.finishPoll({ targetErrors: errors.length, truncatedTargets: 0, deliveryFailures: 0 });
        return { accepted: false, skipped: false, observed, delivered, errors, truncatedTargets: 0 };
      }

      let candidates: readonly unknown[];
      try {
        candidates = await verifier.verify(request);
      } catch {
        this.#metrics.recordTargetError("malformed");
        errors.push({ repo: "unknown", workflow: "unknown", outcome: "malformed" });
        this.#metrics.finishPoll({ targetErrors: errors.length, truncatedTargets: 0, deliveryFailures: 0 });
        return { accepted: false, skipped: false, observed, delivered, errors, truncatedTargets: 0 };
      }

      const grouped = new Map<string, { repo: string; workflow: string; runs: CIWorkflowRun[] }>();
      for (const candidate of candidates) {
        const parsed = ObserverRunSchema.safeParse(candidate);
        if (!parsed.success || !isAllowedTarget(this.#config, parsed.success ? parsed.data.repository : undefined, parsed.success ? parsed.data.workflow : undefined)) {
          this.#metrics.recordTargetError("malformed");
          errors.push({
            repo: parsed.success ? parsed.data.repository : "unknown",
            workflow: parsed.success ? parsed.data.workflow : "unknown",
            outcome: "malformed",
          });
          continue;
        }
        const run = parsed.data;
        const key = targetKeyFor(run.repository, run.workflow);
        const entry = grouped.get(key) ?? { repo: run.repository, workflow: run.workflow, runs: [] };
        entry.runs.push(run);
        grouped.set(key, entry);
      }

      const state = cloneState(this.#state.load());
      const now = this.#clock();
      for (const group of grouped.values()) {
        const targetKey = targetKeyFor(group.repo, group.workflow);
        const previous = state.targets[targetKey] ?? { page: 1, seen: {} };
        const reconciliation = await this.reconcileRuns({
          runs: group.runs,
          source: "webhook",
          target: group,
          targetKey,
          currentTarget: previous,
          state,
          now,
          observed,
          errors,
        });
        state.targets[targetKey] = reconciliation.target;
        delivered += reconciliation.delivered;
        deliveryFailures += reconciliation.deliveryFailures;
      }
      this.#metrics.finishPoll({ targetErrors: errors.length, truncatedTargets: 0, deliveryFailures });
      return { accepted: true, skipped: false, observed, delivered, errors, truncatedTargets: 0 };
    } finally {
      release();
    }
  }

  async start(): Promise<() => Promise<void>> {
    await this.pollOnce();
    this.#timer = setInterval(() => {
      if (this.#polling) return;
      this.#polling = true;
      void this.pollOnce().finally(() => { this.#polling = false; });
    }, this.#config.pollIntervalMs);
    return async () => {
      if (this.#timer !== undefined) clearInterval(this.#timer);
      this.#timer = undefined;
    };
  }

  health(): { status: "ok" | "degraded"; metrics: ObserverMetricsSnapshot } {
    const metrics = this.#metrics.snapshot();
    return { status: metrics.lastPollDegraded ? "degraded" : "ok", metrics };
  }

  private async reconcileRuns(options: {
    runs: readonly unknown[];
    source: ObserverEventSourceKind;
    target: { repo: string; workflow: string };
    targetKey: string;
    currentTarget: ObserverTargetState;
    state: MutableObserverState;
    now: Date;
    observed: Array<{ eventId: string; runId: string; outcome: ObserverOutcome }>;
    errors: Array<{ repo: string; workflow: string; outcome: "unavailable" | "malformed" }>;
  }): Promise<ReconcileResult> {
    let currentTarget = options.currentTarget;
    let delivered = 0;
    let deliveryFailures = 0;
    const deliveryBackoffUntil = currentTarget.deliveryBackoffUntil === undefined ? undefined : Date.parse(currentTarget.deliveryBackoffUntil);
    const attempted = new Set<string>();
    for (const candidate of options.runs) {
      const parsed = ObserverRunSchema.safeParse(candidate);
      if (!parsed.success) {
        this.#metrics.recordTargetError("malformed");
        options.errors.push({ repo: options.target.repo, workflow: options.target.workflow, outcome: "malformed" });
        continue;
      }
      const run = parsed.data;
      if (run.repository !== options.target.repo || run.workflow !== options.target.workflow || run.status !== "completed") {
        if (run.repository !== options.target.repo || run.workflow !== options.target.workflow) {
          this.#metrics.recordTargetError("malformed");
          options.errors.push({ repo: options.target.repo, workflow: options.target.workflow, outcome: "malformed" });
        }
        continue;
      }
      const eventId = observerEventId(run);
      if (attempted.has(eventId)) continue;
      attempted.add(eventId);
      const prior = (options.state.targets[options.targetKey] ?? currentTarget).seen[eventId];
      const statusDelivered = isSettledDelivery(prior?.statusDelivery) || isSettledDelivery(prior?.delivery);
      const analysisRequired = isAnalysisConclusion(run.conclusion);
      const analysisDelivered = !analysisRequired || isSettledDelivery(prior?.analysisDelivery);
      if (statusDelivered && analysisDelivered) continue;

      const outcome = outcomeForRun(run, options.now, this.#config.staleAfterMs);
      this.#metrics.recordObservation(outcome);
      options.observed.push({ eventId, runId: run.id, outcome });
      if (outcome === "stale") {
        currentTarget = markSeen(options.state.targets[options.targetKey] ?? currentTarget, eventId, {
          outcome,
          observedAt: options.now.toISOString(),
          delivery: "suppressed",
          statusDelivery: "suppressed",
          ...(analysisRequired ? { analysisDelivery: "suppressed" as const } : {}),
        });
        options.state.targets[options.targetKey] = currentTarget;
        this.#state.save(withUpdatedAt(options.state, options.now));
        this.#metrics.recordSuppressed();
        continue;
      }
      if (deliveryBackoffUntil !== undefined && Number.isFinite(deliveryBackoffUntil) && deliveryBackoffUntil > options.now.getTime()) {
        this.#metrics.recordTargetError("unavailable");
        options.errors.push({ repo: options.target.repo, workflow: options.target.workflow, outcome: "unavailable" });
        return { target: currentTarget, failed: true, delivered, deliveryFailures };
      }

      if (!statusDelivered) {
        const statusEvent = await this.buildEvent(run, outcome, options.now, false, options.source);
        currentTarget = markSeen(options.state.targets[options.targetKey] ?? currentTarget, eventId, { outcome, observedAt: statusEvent.observedAt, delivery: "pending", statusDelivery: "pending" });
        options.state.targets[options.targetKey] = currentTarget;
        this.#state.save(withUpdatedAt(options.state, options.now));
        try {
          await this.#deliver(serializeObserverEvent(statusEvent, this.#config.maxPayloadBytes), deliveryEventId(eventId, "status"), "success");
          currentTarget = markSeen(options.state.targets[options.targetKey] ?? currentTarget, eventId, { outcome, observedAt: statusEvent.observedAt, delivery: "delivered", deliveredAt: options.now.toISOString(), statusDelivery: "delivered", statusDeliveredAt: options.now.toISOString() });
          options.state.targets[options.targetKey] = currentTarget;
          this.#state.save(withUpdatedAt(options.state, options.now));
          this.#metrics.recordDelivery();
          delivered += 1;
        } catch {
          this.#metrics.recordDeliveryFailure();
          deliveryFailures += 1;
          currentTarget = withDeliveryBackoff(currentTarget, options.now, this.#config.deliveryBackoffMs);
          options.state.targets[options.targetKey] = currentTarget;
          this.#state.save(withUpdatedAt(options.state, options.now));
          return { target: currentTarget, failed: true, delivered, deliveryFailures };
        }
      }

      if (analysisRequired && !analysisDelivered) {
        const analysisEvent = await this.buildEvent(run, outcome, options.now, true, options.source);
        currentTarget = markSeen(options.state.targets[options.targetKey] ?? currentTarget, eventId, { outcome, observedAt: analysisEvent.observedAt, analysisDelivery: "pending" });
        options.state.targets[options.targetKey] = currentTarget;
        this.#state.save(withUpdatedAt(options.state, options.now));
        try {
          await this.#deliver(serializeObserverEvent(analysisEvent, this.#config.maxPayloadBytes), deliveryEventId(eventId, "analysis"), "analysis");
          currentTarget = markSeen(options.state.targets[options.targetKey] ?? currentTarget, eventId, { outcome, observedAt: analysisEvent.observedAt, analysisDelivery: "delivered", analysisDeliveredAt: options.now.toISOString() });
          options.state.targets[options.targetKey] = currentTarget;
          this.#state.save(withUpdatedAt(options.state, options.now));
          this.#metrics.recordDelivery();
          delivered += 1;
        } catch {
          this.#metrics.recordDeliveryFailure();
          deliveryFailures += 1;
          currentTarget = withDeliveryBackoff(currentTarget, options.now, this.#config.deliveryBackoffMs);
          options.state.targets[options.targetKey] = currentTarget;
          this.#state.save(withUpdatedAt(options.state, options.now));
          return { target: currentTarget, failed: true, delivered, deliveryFailures };
        }
      }

    }
    return { target: currentTarget, failed: false, delivered, deliveryFailures };
  }

  private targetCount(): number { return targets(this.#config).length; }

  private async buildEvent(run: CIWorkflowRun, outcome: ObserverOutcome, now: Date, includeAnalysis: boolean, source: ObserverEventSourceKind): Promise<ObserverEvent | AgentNotificationPayload> {
    const warnings: Array<{ code: string; message: string }> = [];
    if (includeAnalysis && isAnalysisConclusion(run.conclusion)) {
      const input = { repo: run.repository, workflow: run.workflow, runId: run.id };
      try {
        const observerStatusProvider = {
          ...this.#provider,
          getWorkflowStatus: async () => ({
            schemaVersion: "1.0" as const,
            observedAt: now.toISOString(),
            providerClass: this.#source.providerClass ?? this.#provider.providerClass ?? "observer",
            freshness: "fresh" as const,
            truncated: false,
            redactionsApplied: false,
            warnings: [],
            data: { run },
          }),
        };
        const assembled = await assembleFailureAnalysis({
          provider: observerStatusProvider,
          ...(this.#provider.forensics === undefined ? {} : { evidence: this.#provider.forensics }),
          input: { ...input, maxJobs: this.#config.maxFailedJobs, maxLogLines: this.#config.maxLogLines },
          clock: () => now,
        });
        return buildAgentNotificationPayload({ analysis: assembled, eventId: observerEventId(run), source, maxBytes: this.#config.maxPayloadBytes });
      } catch (error) {
        const fallback = makeUnavailableFailureAnalysis({ run: { ...run, status: "completed" }, observedAt: now, ...(this.#source.providerClass === undefined ? {} : { providerClass: this.#source.providerClass }), code: providerErrorOutcome(error) });
        return buildAgentNotificationPayload({ analysis: fallback, eventId: observerEventId(run), source, maxBytes: this.#config.maxPayloadBytes });
      }
    }
    return {
      schemaVersion: "1.0",
      type: "ci.run.observed",
      eventId: observerEventId(run),
      observedAt: now.toISOString(),
      source,
      ...(this.#source.providerClass === undefined ? {} : { providerClass: this.#source.providerClass }),
      repo: run.repository,
      workflow: run.workflow,
      runId: run.id,
      runAttempt: run.runAttempt,
      terminalConclusion: run.conclusion,
      outcome,
      freshness: outcome === "stale" ? "stale" : "fresh",
      updatedAt: run.updatedAt,
      warnings,
    };
  }
}

export function createObserverRuntimeFromFiles(options: {
  configPath: string;
  fetch: typeof globalThis.fetch;
  clock?: () => Date;
  sleep?: (milliseconds: number) => Promise<void>;
}): ObserverRuntime {
  const fileConfig = loadObserverConfiguration(options.configPath);
  const hmacKey = readObserverSecretFile(fileConfig.hermes.hmac_key_file);
  const config = observerRuntimeConfig(fileConfig, hmacKey);
  const clock = options.clock ?? (() => new Date());
  const providerConfiguration = { type: "github" as const, github: fileConfig.github, allowlist: config.allowlist };
  const provider = createObserverProviderFromConfiguration(providerConfiguration, {
    repositories: fileConfig.allowlist.map((entry) => entry.repo),
    fetch: options.fetch,
    clock,
  });
  const state = new FileObserverStateStore({ filePath: config.stateFile, leaseMs: config.leaseMs, clock });
  const delivery = new HttpDeliverySink({
    routes: {
      success: config.successUrl ?? config.hermesUrl ?? "",
      ...(config.analysisUrl === undefined ? {} : { analysis: config.analysisUrl }),
    },
    ...(config.trustedHermesHosts === undefined ? {} : { trustedInternalHosts: config.trustedHermesHosts }),
    key: hmacKey,
    fetch: options.fetch,
    clock,
    ...(options.sleep === undefined ? {} : { sleep: options.sleep }),
    maxAttempts: config.deliveryAttempts,
    backoffMs: config.deliveryBackoffMs,
    timeoutMs: config.deliveryTimeoutMs,
  });
  const source = createObserverEventSourceFromProviderConfiguration(
    providerConfiguration,
    provider,
    (secret, allowlist) => createGitHubWebhookVerifier(secret, allowlist),
  );
  return new ObserverRuntime({ config, provider, source, state, sink: delivery, clock });
}

export function createGitHubWebhookVerifier(
  secret: Uint8Array,
  allowlist: readonly { repo: string; workflows: readonly string[] }[],
): ObserverEventSource["webhookVerifier"] {
  if (secret.byteLength < 32) throw new Error("Webhook secret is missing or too short");
  return {
    async verify(request) {
      if (request.body.length > 2 * 1_024 * 1_024) throw new Error("Invalid webhook");
      if (headerValue(request.headers, "x-github-event") !== "workflow_run") throw new Error("Invalid webhook");
      const supplied = headerValue(request.headers, "x-hub-signature-256");
      if (supplied === undefined || !/^sha256=[a-f0-9]{64}$/.test(supplied)) throw new Error("Invalid webhook");
      const expected = `sha256=${createHmac("sha256", secret).update(request.body, "utf8").digest("hex")}`;
      const suppliedBytes = Buffer.from(supplied, "utf8");
      const expectedBytes = Buffer.from(expected, "utf8");
      if (suppliedBytes.length !== expectedBytes.length || !timingSafeEqual(suppliedBytes, expectedBytes)) throw new Error("Invalid webhook");

      let payload: unknown;
      try { payload = JSON.parse(request.body); } catch { throw new Error("Invalid webhook"); }
      const normalized = normalizeGitHubWorkflowRun(payload, allowlist);
      return normalized === undefined ? [] : [normalized];
    },
  };
}

function headerValue(headers: Readonly<Record<string, string | readonly string[] | undefined>>, name: string): string | undefined {
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name);
  const value = entry?.[1];
  if (typeof value === "string") return value;
  return value?.length === 1 ? value[0] : undefined;
}

function normalizeGitHubWorkflowRun(payload: unknown, allowlist: readonly { repo: string; workflows: readonly string[] }[]): Record<string, unknown> | undefined {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) throw new Error("Invalid webhook");
  const root = payload as Record<string, unknown>;
  const workflowRun = root.workflow_run;
  const repository = root.repository;
  if (workflowRun === null || typeof workflowRun !== "object" || Array.isArray(workflowRun) || repository === null || typeof repository !== "object" || Array.isArray(repository)) throw new Error("Invalid webhook");
  const run = workflowRun as Record<string, unknown>;
  const repo = (repository as Record<string, unknown>).full_name;
  const workflow = workflowName(run, root.workflow);
  if (typeof repo !== "string" || typeof workflow !== "string" || !allowlist.some((entry) => entry.repo === repo && entry.workflows.includes(workflow))) return undefined;
  if (run.status !== "completed") return undefined;
  const id = typeof run.id === "number" ? String(run.id) : run.id;
  const conclusion = run.conclusion;
  const runAttempt = run.run_attempt;
  const event = run.event;
  const ref = run.head_branch;
  const sha = run.head_sha;
  const createdAt = run.created_at;
  const updatedAt = run.updated_at;
  if (typeof id !== "string" || typeof runAttempt !== "number" || typeof event !== "string" || typeof ref !== "string" || typeof sha !== "string" || typeof createdAt !== "string" || typeof updatedAt !== "string") throw new Error("Invalid webhook");
  if (conclusion !== null && conclusion !== "success" && conclusion !== "failure" && conclusion !== "cancelled" && conclusion !== "timed_out" && conclusion !== "skipped" && conclusion !== "neutral" && conclusion !== "action_required" && conclusion !== "unknown") throw new Error("Invalid webhook");
  return { id, repository: repo, workflow, status: "completed", conclusion: conclusion as string | null, runAttempt, event, ref, sha: sha.toLowerCase(), createdAt, updatedAt };
}

function workflowName(run: Record<string, unknown>, workflow: unknown): string | undefined {
  const candidates = [run.path, workflow !== null && typeof workflow === "object" && !Array.isArray(workflow) ? (workflow as Record<string, unknown>).path : undefined, run.name];
  for (const candidate of candidates) {
    if (typeof candidate !== "string" || candidate.length === 0) continue;
    return candidate.replace(/^\/?\.github\/workflows\//, "");
  }
  return undefined;
}

export { observerEventSourceFromProvider } from "./events.js";

export function observerEventId(run: Pick<CIWorkflowRun, "repository" | "workflow" | "id" | "runAttempt">): string {
  return `${run.repository}:${run.workflow}:${run.id}:${run.runAttempt}`;
}

export function outcomeForRun(run: Pick<CIWorkflowRun, "status" | "conclusion" | "updatedAt">, now: Date, staleAfterMs: number): ObserverOutcome {
  if (run.status !== "completed") return "malformed";
  const updated = Date.parse(run.updatedAt);
  if (!Number.isFinite(updated)) return "malformed";
  if (now.getTime() - updated > staleAfterMs) return "stale";
  switch (run.conclusion) {
    case "success": return "success";
    case "failure": return "failure";
    case "cancelled": return "cancelled";
    case "timed_out": return "timed_out";
    case "action_required": return "action_required";
    case "skipped": return "skipped";
    case "neutral": return "neutral";
    default: return "malformed";
  }
}

export function renderObserverMetrics(snapshot: ObserverMetricsSnapshot): string {
  const lines = [
    `observer_polls_total ${snapshot.polls}`,
    `observer_deliveries_total ${snapshot.deliveries}`,
    `observer_delivery_failures_total ${snapshot.deliveryFailures}`,
    `observer_target_errors_total ${snapshot.targetErrors}`,
    `observer_observations_total ${snapshot.observations}`,
    `observer_suppressed_total ${snapshot.suppressed}`,
    `observer_targets ${snapshot.targetCount}`,
    `observer_truncated_targets ${snapshot.truncatedTargets}`,
  ];
  for (const outcome of Object.keys(snapshot.outcomes).sort()) lines.push(`observer_outcomes_total{outcome="${outcome}"} ${snapshot.outcomes[outcome as ObserverOutcome]}`);
  return `${lines.join("\n")}\n`;
}

export function createObserverHealthServer(runtime: ObserverRuntime, options: { host: string; port: number }): Server {
  const server = createServer((request, response) => {
    if (request.url === "/healthz") {
      const health = runtime.health();
      response.writeHead(health.status === "ok" ? 200 : 503, { "content-type": "application/json" });
      response.end(JSON.stringify({ status: health.status, metrics: health.metrics }));
      return;
    }
    if (request.url === "/metrics") {
      response.writeHead(200, { "content-type": "text/plain; version=0.0.4" });
      response.end(renderObserverMetrics(runtime.metrics.snapshot()));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  server.listen(options.port, options.host);
  return server;
}

function targets(config: ObserverConfig): Array<{ repo: string; workflow: string }> {
  return config.allowlist.flatMap((entry) => entry.workflows.map((workflow) => ({ repo: entry.repo, workflow })));
}

function isAllowedTarget(config: ObserverConfig, repo: string | undefined, workflow: string | undefined): boolean {
  return repo !== undefined && workflow !== undefined && targets(config).some((target) => target.repo === repo && target.workflow === workflow);
}

function targetKeyFor(repo: string, workflow: string): string { return `${repo}\u001f${workflow}`; }

function createdAfterWithOverlap(cursor: string, overlapMs: number): string | undefined {
  const cursorMs = Date.parse(cursor);
  return Number.isFinite(cursorMs) ? new Date(cursorMs - overlapMs).toISOString() : undefined;
}

function isAnalysisConclusion(conclusion: CIWorkflowRun["conclusion"]): boolean {
  return conclusion === "failure" || conclusion === "cancelled" || conclusion === "timed_out" || conclusion === "action_required";
}

function outcomeForProviderError(error: unknown): "unavailable" | "malformed" {
  return error instanceof CIProviderError && error.code === "malformed" || error !== null && typeof error === "object" && (error as { code?: unknown }).code === "malformed" ? "malformed" : "unavailable";
}

const providerErrorOutcome = outcomeForProviderError;

function isProviderBackoffError(error: unknown): boolean {
  if (error instanceof CIProviderError) return error.code === "unavailable";
  if (error === null || typeof error !== "object") return false;
  const value = error as { code?: unknown; status?: unknown };
  return value.code === "unavailable" || value.code === "rate_limited" || value.code === "too_many_requests" || value.status === 429;
}

function withProviderBackoff(target: ObserverTargetState, now: Date): ObserverTargetState {
  const delay = Math.min(BACKOFF_MAX_MS, Math.max(PROVIDER_BACKOFF_BASE_MS, (target.backoffMs ?? PROVIDER_BACKOFF_BASE_MS / 2) * 2));
  return {
    ...target,
    backoffMs: delay,
    backoffUntil: new Date(now.getTime() + delay).toISOString(),
  };
}

function withDeliveryBackoff(target: ObserverTargetState, now: Date, configuredMs: number): ObserverTargetState {
  const delay = Math.min(BACKOFF_MAX_MS, Math.max(configuredMs, (target.deliveryBackoffMs ?? Math.max(1, configuredMs / 2)) * 2));
  return {
    ...target,
    deliveryBackoffMs: delay,
    deliveryBackoffUntil: new Date(now.getTime() + delay).toISOString(),
  };
}

function withoutBackoff(target: ObserverTargetState): ObserverTargetState {
  const next = { ...target };
  delete next.backoffMs;
  delete next.backoffUntil;
  delete next.deliveryBackoffMs;
  delete next.deliveryBackoffUntil;
  return next;
}

function serializeObserverEvent(event: ObserverEvent | AgentNotificationPayload, maxBytes: number): string {
  const redacted = redactMetadata(event) as Record<string, unknown>;
  let body = JSON.stringify(redacted);
  if (Buffer.byteLength(body, "utf8") <= maxBytes) return body;
  if (event.type === "ci.failure.analysis") {
    return JSON.stringify({
      schemaVersion: "1.0",
      type: event.type,
      eventId: event.eventId,
      dedupeKey: event.dedupeKey,
      source: event.source,
      observedAt: event.observedAt,
      outcome: event.outcome,
      truncated: true,
      warnings: [{ code: "payload_truncated", message: "Bounded analysis omitted" }],
    });
  }
  delete redacted.evidence;
  redacted.warnings = [...(Array.isArray(redacted.warnings) ? redacted.warnings : []), { code: "payload_truncated", message: "Bounded evidence omitted" }];
  body = JSON.stringify(redacted);
  if (Buffer.byteLength(body, "utf8") <= maxBytes) return body;
  return JSON.stringify({
    schemaVersion: "1.0",
    type: "ci.run.observed",
    eventId: event.eventId,
    observedAt: event.observedAt,
    source: event.source,
    ...(event.providerClass === undefined ? {} : { providerClass: event.providerClass }),
    repo: event.repo,
    workflow: event.workflow,
    runId: event.runId,
    runAttempt: event.runAttempt,
    terminalConclusion: event.terminalConclusion,
    outcome: event.outcome,
    freshness: event.freshness,
    updatedAt: event.updatedAt,
    warnings: [{ code: "payload_truncated", message: "Bounded evidence omitted" }],
  });
}

function deliveryEventId(eventId: string, route: "status" | "analysis"): string {
  return `${eventId}:${route}`;
}

function isSettledDelivery(state: ObserverSeenRecord["statusDelivery"]): boolean {
  return state === "delivered" || state === "suppressed";
}

function markSeen(target: ObserverTargetState, eventId: string, record: Pick<ObserverSeenRecord, "outcome" | "observedAt"> & Partial<ObserverSeenRecord>): ObserverTargetState {
  const previous = target.seen[eventId];
  const merged: ObserverSeenRecord = {
    ...previous,
    ...record,
    outcome: record.outcome,
    observedAt: record.observedAt,
    delivery: record.delivery ?? previous?.delivery ?? "pending",
  };
  return { ...target, seen: { ...target.seen, [eventId]: merged } };
}

function pruneSeen(target: ObserverTargetState): ObserverTargetState {
  const entries = Object.entries(target.seen);
  if (entries.length <= 1_000) return target;
  const retained = entries.filter(([, record]) => record.delivery === "pending" || record.analysisDelivery === "pending").concat(entries.filter(([, record]) => record.delivery === "delivered" && record.analysisDelivery !== "pending").slice(-900));
  return { ...target, seen: Object.fromEntries(retained) };
}

function withUpdatedAt(state: ObserverStateDocument, now: Date): ObserverStateDocument {
  return { ...state, updatedAt: now.toISOString() };
}

function cloneState(state: ObserverStateDocument): MutableObserverState {
  return JSON.parse(JSON.stringify(state)) as MutableObserverState;
}

const ObserverRunSchema = z.object({
  id: CIRunIdSchema,
  repository: CIRepositorySchema,
  workflow: CIWorkflowSchema,
  status: z.literal("completed"),
  conclusion: z.enum(["success", "failure", "cancelled", "timed_out", "skipped", "neutral", "action_required", "unknown"]).nullable(),
  runAttempt: z.number().int().min(1).max(100),
  event: z.string().min(1).max(64),
  ref: z.string().min(1).max(256),
  sha: z.string().regex(/^[a-f0-9]{40}$/),
  createdAt: z.iso.datetime({ offset: true }).refine((value) => value.endsWith("Z")),
  updatedAt: z.iso.datetime({ offset: true }).refine((value) => value.endsWith("Z")),
}).strict();
