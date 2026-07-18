import { createServer, type Server } from "node:http";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import { CIRepositorySchema, CIRunIdSchema, CIWorkflowSchema, type CIWorkflowRun } from "../domain/ci-schemas.js";
import { redactMetadata } from "../ci/redaction.js";
import { CIProviderError, type CIProvider } from "../providers/ci-provider.js";
import { normalizeGitHubActionsEvent } from "../providers/provider-event-adapters.js";
import { assembleFailureAnalysis, buildAgentNotificationPayload, makeUnavailableFailureAnalysis, type AgentNotificationPayload } from "../ci/forensics.js";
import type { ForensicsProviderSet } from "../providers/ci-provider.js";
import { loadObserverConfiguration, observerRuntimeConfig, readObserverSecretFile, type ObserverConfig } from "./config.js";
import { z } from "zod";
import { HttpDeliverySink, type ObserverDeliveryRoute, type ObserverDeliverySink } from "./delivery.js";
import { observerEventSourceFromProvider, type ObserverEventSource, type ObserverEventSourceKind, type ObserverRunListInput, type ObserverWebhookRequest } from "./events.js";
import { createObserverEventSourceFromProviderConfiguration, createObserverProviderFromConfiguration } from "./provider-factory.js";
import { FileObserverStateStore, type ObserverSeenRecord, type ObserverStateDocument, type ObserverStateStore, type ObserverTargetState } from "./state.js";
import { createObserverEventEnvelope, observerReplayKey, serializeObserverEventEnvelope, type EventCorrelation } from "./event-envelope.js";
import type { CIFailureAnalysisResult } from "../domain/forensics-schemas.js";
import { DEFAULT_ANALYSIS_POLICY_LIMITS, runBoundedRecommendationAnalysis, type AnalysisCallback, type AnalysisPolicyLimits } from "./analysis-policy.js";

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
  readonly dedupeKey: string;
  readonly replayKey: string;
  readonly identity: { readonly dedupeKey: string; readonly replayKey: string };
  readonly observedAt: string;
  readonly source: ObserverEventSourceKind;
  readonly providerClass?: string;
  readonly repo: string;
  readonly workflow: string;
  readonly runId: string;
  readonly runAttempt: number;
  readonly terminalConclusion: CIWorkflowRun["conclusion"];
  readonly outcome: ObserverOutcome;
  readonly status: { readonly state: "completed"; readonly conclusion: Exclude<CIWorkflowRun["conclusion"], null>; readonly outcome: ObserverOutcome };
  readonly notification: "failure" | "recovery";
  readonly severity: "red" | "green";
  readonly threadId: string;
  readonly freshness: "fresh" | "stale";
  readonly updatedAt: string;
  readonly correlation: EventCorrelation;
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
  readonly #recommendationAnalysis: AnalysisCallback | undefined;
  readonly #recommendationLimits: Partial<AnalysisPolicyLimits> | undefined;
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
    recommendationAnalysis?: AnalysisCallback;
    recommendationLimits?: Partial<AnalysisPolicyLimits>;
  }) {
    this.#config = options.config;
    this.#provider = options.provider;
    this.#source = options.source ?? observerEventSourceFromProvider(options.provider);
    this.#state = options.state;
    if (options.deliver === undefined && options.sink === undefined) throw new Error("Observer delivery sink is required");
    this.#deliver = options.deliver ?? ((body, eventId, route) => options.sink!.deliver(body, eventId, route));
    this.#clock = options.clock ?? (() => new Date());
    this.#metrics = options.metrics ?? new InMemoryObserverMetrics();
    this.#recommendationAnalysis = options.recommendationAnalysis;
    this.#recommendationLimits = options.recommendationLimits;
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
    if (currentTarget.incidentActive === undefined) currentTarget = { ...currentTarget, incidentActive: hasDeliveredNonSuccess(currentTarget) };
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
      const legacyEventId = legacyObserverEventId(run);
      const existingTarget = options.state.targets[options.targetKey] ?? currentTarget;
      const prior = existingTarget.seen[eventId] ?? existingTarget.seen[legacyEventId];
      if (prior !== undefined && existingTarget.seen[eventId] === undefined) {
        currentTarget = markSeen(currentTarget, eventId, {
          ...prior,
          ...(prior.analysisAttempted === undefined && prior.analysisDelivery !== undefined ? { analysisAttempted: true } : {}),
        });
        options.state.targets[options.targetKey] = currentTarget;
      }
      const currentRecord = currentTarget.seen[eventId];
      const statusDelivered = isSettledDelivery(currentRecord?.statusDelivery) || isSettledDelivery(currentRecord?.delivery);
      const analysisRequired = isAnalysisConclusion(run.conclusion);
      const analysisAttempted = currentRecord?.analysisAttempted === true || currentRecord?.analysisDelivery !== undefined;
      const outcome = outcomeForRun(run, options.now, this.#config.staleAfterMs);
      if (statusDelivered && (!analysisRequired || analysisAttempted) && (outcome !== "success" || (currentTarget.incidentActive !== true && currentTarget.recoveryEventId === undefined))) continue;
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

      if (outcome === "success") {
        if (currentTarget.incidentActive !== true && currentTarget.recoveryEventId === undefined) {
          if (currentRecord === undefined) {
            currentTarget = markSeen(currentTarget, eventId, { outcome, observedAt: options.now.toISOString(), delivery: "suppressed", statusDelivery: "suppressed" });
            options.state.targets[options.targetKey] = currentTarget;
            this.#state.save(withUpdatedAt(options.state, options.now));
            this.#metrics.recordSuppressed();
          }
          continue;
        }

        const hasRecoveryIdentity = currentTarget.recoveryEventId !== undefined;
        const recoveryEventId = currentTarget.recoveryEventId ?? eventId;
        currentTarget = { ...currentTarget, recoveryEventId };
        const recoveryRecord = currentTarget.seen[recoveryEventId];
        const recoveryDelivered = hasRecoveryIdentity && (recoveryRecord?.statusDelivery === "delivered" || recoveryRecord?.delivery === "delivered");
        if (recoveryDelivered) {
          const cleared = { ...currentTarget };
          delete cleared.recoveryEventId;
          currentTarget = { ...cleared, incidentActive: false };
          options.state.targets[options.targetKey] = currentTarget;
          this.#state.save(withUpdatedAt(options.state, options.now));
          continue;
        }
        if (deliveryBackoffUntil !== undefined && Number.isFinite(deliveryBackoffUntil) && deliveryBackoffUntil > options.now.getTime()) {
          this.#metrics.recordTargetError("unavailable");
          options.errors.push({ repo: options.target.repo, workflow: options.target.workflow, outcome: "unavailable" });
          return { target: currentTarget, failed: true, delivered, deliveryFailures };
        }
        const recoveryEvent = await this.buildEvent(run, outcome, options.now, false, options.source, "recovery", recoveryEventId);
        currentTarget = markSeen(currentTarget, recoveryEventId, { outcome, observedAt: recoveryEvent.observedAt, delivery: "pending", statusDelivery: "pending" });
        options.state.targets[options.targetKey] = currentTarget;
        this.#state.save(withUpdatedAt(options.state, options.now));
        try {
          await this.#deliver(serializeObserverEvent(recoveryEvent, this.#config.maxPayloadBytes), deliveryEventId(recoveryEventId, "status"), "success");
          const cleared = { ...currentTarget };
          delete cleared.recoveryEventId;
          currentTarget = markSeen({ ...cleared, incidentActive: false }, recoveryEventId, { outcome, observedAt: recoveryEvent.observedAt, delivery: "delivered", deliveredAt: options.now.toISOString(), statusDelivery: "delivered", statusDeliveredAt: options.now.toISOString() });
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
        continue;
      }

      if (!analysisRequired) {
        currentTarget = markSeen(currentTarget, eventId, { outcome, observedAt: options.now.toISOString(), delivery: "suppressed", statusDelivery: "suppressed" });
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
        const statusEvent = await this.buildEvent(run, outcome, options.now, false, options.source, "failure", eventId);
        currentTarget = markSeen(options.state.targets[options.targetKey] ?? currentTarget, eventId, { outcome, observedAt: statusEvent.observedAt, delivery: "pending", statusDelivery: "pending" });
        options.state.targets[options.targetKey] = currentTarget;
        this.#state.save(withUpdatedAt(options.state, options.now));
        try {
          await this.#deliver(serializeObserverEvent(statusEvent, this.#config.maxPayloadBytes), deliveryEventId(eventId, "status"), "success");
          currentTarget = markSeen(options.state.targets[options.targetKey] ?? currentTarget, eventId, { outcome, observedAt: statusEvent.observedAt, delivery: "delivered", deliveredAt: options.now.toISOString(), statusDelivery: "delivered", statusDeliveredAt: options.now.toISOString() });
          currentTarget = { ...currentTarget, incidentActive: true };
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
      } else {
        currentTarget = { ...currentTarget, incidentActive: true };
      }

      const latestRecord = currentTarget.seen[eventId];
      if (!latestRecord?.analysisAttempted && latestRecord?.analysisDelivery === undefined) {
        currentTarget = markSeen(options.state.targets[options.targetKey] ?? currentTarget, eventId, { outcome, observedAt: options.now.toISOString(), analysisAttempted: true, analysisDelivery: "pending" });
        options.state.targets[options.targetKey] = currentTarget;
        this.#state.save(withUpdatedAt(options.state, options.now));
        const analysisEvent = await this.buildEvent(run, outcome, options.now, true, options.source);
        currentTarget = markSeen(options.state.targets[options.targetKey] ?? currentTarget, eventId, { outcome, observedAt: analysisEvent.observedAt, analysisAttempted: true, analysisDelivery: "pending" });
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

  private async buildEvent(run: CIWorkflowRun, outcome: ObserverOutcome, now: Date, includeAnalysis: boolean, source: ObserverEventSourceKind, notification: "failure" | "recovery" = "failure", eventId = observerEventId(run)): Promise<ObserverEvent | AgentNotificationPayload> {
    const warnings: Array<{ code: string; message: string }> = [];
    if (includeAnalysis && isAnalysisConclusion(run.conclusion)) {
      const input = { repo: run.repository, workflow: run.workflow, runId: run.id };
      const timeoutMs = this.#recommendationLimits?.timeoutMs ?? DEFAULT_ANALYSIS_POLICY_LIMITS.timeoutMs;
      const deadline = Date.now() + timeoutMs;
      const deadlineController = new AbortController();
      let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
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
        const deadlineFailure = new Promise<never>((_, reject) => {
          deadlineTimer = setTimeout(() => {
            deadlineController.abort();
            reject(new Error("failure analysis deadline exceeded"));
          }, timeoutMs);
        });
        let assembled: CIFailureAnalysisResult;
        try {
          assembled = await Promise.race([
            assembleFailureAnalysis({
              provider: observerStatusProvider,
              ...(this.#provider.forensics === undefined ? {} : { evidence: this.#provider.forensics }),
              input: { ...input, maxJobs: this.#config.maxFailedJobs, maxLogLines: this.#config.maxLogLines },
              clock: () => now,
            }),
            deadlineFailure,
          ]);
        } catch (error) {
          assembled = makeUnavailableFailureAnalysis({ run: { ...run, status: "completed" }, observedAt: now, ...(this.#source.providerClass === undefined ? {} : { providerClass: this.#source.providerClass }), code: providerErrorOutcome(error) });
        }

        const payload = buildAgentNotificationPayload({ analysis: assembled, eventId, source, maxBytes: this.#config.maxPayloadBytes });
        if (this.#recommendationAnalysis === undefined) return payload;

        const remainingMs = deadline - Date.now();
        if (remainingMs <= 0) {
          deadlineController.abort();
          return { ...payload, recommendation: { available: false, reason: "timeout" } } as AgentNotificationPayload;
        }
        const recommendation = await runBoundedRecommendationAnalysis({
          input: recommendationInputForAnalysis(assembled),
          callback: this.#recommendationAnalysis,
          signal: deadlineController.signal,
          limits: { ...this.#recommendationLimits, timeoutMs: Math.max(1, Math.min(timeoutMs, remainingMs)) },
        });
        // This controller is private to the shared analysis deadline, so an
        // aborted callback here is always the deterministic timeout fallback.
        const boundedRecommendation = recommendation.reason === "aborted"
          ? { ...recommendation, reason: "timeout" as const }
          : recommendation;
        return { ...payload, recommendation: boundedRecommendation } as AgentNotificationPayload;
      } finally {
        if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
      }
    }
    const event = {
      schemaVersion: "1.0",
      type: "ci.run.observed",
      eventId,
      observedAt: now.toISOString(),
      source,
      ...(this.#source.providerClass === undefined ? {} : { providerClass: this.#source.providerClass }),
      repo: run.repository,
      workflow: run.workflow,
      runId: run.id,
      runAttempt: run.runAttempt,
      terminalConclusion: run.conclusion,
      outcome,
      status: { state: "completed" as const, conclusion: run.conclusion ?? "unknown", outcome },
      notification,
      severity: notification === "recovery" ? "green" : "red",
      threadId: observerThreadId(run),
      freshness: outcome === "stale" ? "stale" : "fresh",
      updatedAt: run.updatedAt,
      dedupeKey: eventId,
      replayKey: observerReplayKey({ repo: run.repository, workflow: run.workflow, runId: run.id, runAttempt: run.runAttempt }),
      identity: {
        dedupeKey: eventId,
        replayKey: observerReplayKey({ repo: run.repository, workflow: run.workflow, runId: run.id, runAttempt: run.runAttempt }),
      },
      correlation: {
        deploymentId: { available: false as const, reason: "absent" as const },
        commitSha: { available: true as const, value: run.sha },
        artifactDigest: { available: false as const, reason: "absent" as const },
        traceId: { available: false as const, reason: "absent" as const },
      },
      warnings,
    };
    return createObserverEventEnvelope(event as unknown as import("./event-envelope.js").ObserverEventEnvelopeInput) as unknown as ObserverEvent;
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
  let run: CIWorkflowRun;
  try {
    run = normalizeGitHubActionsEvent(payload, { source: "webhook", includeGoal23Envelope: false }).run;
  } catch {
    throw new Error("Invalid webhook");
  }
  if (!allowlist.some((entry) => entry.repo === run.repository && entry.workflows.includes(run.workflow))) return undefined;
  return run.status === "completed" ? run : undefined;
}

export { observerEventSourceFromProvider } from "./events.js";

export function observerEventId(run: Pick<CIWorkflowRun, "repository" | "workflow" | "sha" | "conclusion">): string {
  return `${run.repository}:${run.workflow}:${run.sha}:${run.conclusion ?? "unknown"}`;
}

export function observerThreadId(run: Pick<CIWorkflowRun, "repository" | "workflow">): string {
  return `${run.repository}:${run.workflow}`;
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

function legacyObserverEventId(run: Pick<CIWorkflowRun, "repository" | "workflow" | "id" | "runAttempt">): string {
  return `${run.repository}:${run.workflow}:${run.id}:${run.runAttempt}`;
}

function hasDeliveredNonSuccess(target: ObserverTargetState): boolean {
  return Object.values(target.seen).some((record) => isAnalysisConclusion(record.outcome as CIWorkflowRun["conclusion"]) && (record.statusDelivery === "delivered" || record.delivery === "delivered"));
}

function outcomeForProviderError(error: unknown): "unavailable" | "malformed" {
  return error instanceof CIProviderError && error.code === "malformed" || error !== null && typeof error === "object" && (error as { code?: unknown }).code === "malformed" ? "malformed" : "unavailable";
}

const providerErrorOutcome = outcomeForProviderError;

function recommendationInputForAnalysis(analysis: CIFailureAnalysisResult) {
  return {
    event: {
      repository: analysis.data.subject.repo,
      workflow: analysis.data.subject.workflow,
      runId: analysis.data.subject.runId,
      commitSha: analysis.data.subject.headSha,
    },
    diff: analysis.data.scmChanges.map((change) => ({
      path: change.path,
      changeType: change.changeType,
      additions: change.additions,
      deletions: change.deletions,
      hunkCount: change.hunks.length,
    })),
    logs: analysis.data.ciEvidence.map((evidence, sequence) => ({
      sequence,
      text: `CI log evidence ${evidence.evidenceRef} (${evidence.lineCount} lines)`,
    })),
    metrics: analysis.data.telemetrySignals
      .filter((signal) => signal.kind === "metric")
      .map((signal) => ({ name: signal.id, state: signal.state })),
    traces: analysis.data.telemetrySignals
      .filter((signal) => signal.kind === "trace")
      .map((signal) => ({
        spanDigest: createHash("sha256").update(signal.reference ?? signal.id, "utf8").digest("hex"),
        durationMs: 0,
        status: (signal.state === "error" ? "error" : signal.state === "normal" ? "ok" : "unknown") as "error" | "ok" | "unknown",
      })),
  };
}

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
  if ((event as { type?: string }).type === "ci.run.observed") {
    // Runtime validation is the final boundary before a status delivery. The
    // serializer rejects malformed, secret-bearing, or oversized envelopes.
    return serializeObserverEventEnvelope(event as unknown as import("./event-envelope.js").ObserverEventEnvelopeInput, maxBytes);
  }
  const analysisEvent = event as AgentNotificationPayload;
  const redacted = redactMetadata(analysisEvent) as Record<string, unknown>;
  let body = JSON.stringify(redacted);
  if (Buffer.byteLength(body, "utf8") <= maxBytes) return body;
  if (analysisEvent.type === "ci.failure.analysis") {
    return JSON.stringify({
      schemaVersion: "1.0",
      type: analysisEvent.type,
      eventId: analysisEvent.eventId,
      dedupeKey: analysisEvent.dedupeKey,
      source: analysisEvent.source,
      observedAt: analysisEvent.observedAt,
      outcome: analysisEvent.outcome,
      truncated: true,
      warnings: [{ code: "payload_truncated", message: "Bounded analysis omitted" }],
    });
  }
  delete redacted.evidence;
  redacted.warnings = [...(Array.isArray(redacted.warnings) ? redacted.warnings : []), { code: "payload_truncated", message: "Bounded evidence omitted" }];
  body = JSON.stringify(redacted);
  if (Buffer.byteLength(body, "utf8") <= maxBytes) return body;
  const statusEvent = event as ObserverEvent;
  return JSON.stringify({
    schemaVersion: "1.0",
    type: "ci.run.observed",
    eventId: statusEvent.eventId,
    observedAt: statusEvent.observedAt,
    source: statusEvent.source,
    ...(statusEvent.providerClass === undefined ? {} : { providerClass: statusEvent.providerClass }),
    repo: statusEvent.repo,
    workflow: statusEvent.workflow,
    runId: statusEvent.runId,
    runAttempt: statusEvent.runAttempt,
    terminalConclusion: statusEvent.terminalConclusion,
    outcome: statusEvent.outcome,
    notification: statusEvent.notification,
    severity: statusEvent.severity,
    threadId: statusEvent.threadId,
    freshness: statusEvent.freshness,
    updatedAt: statusEvent.updatedAt,
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
  const retained = entries.filter(([, record]) => record.delivery === "pending" || (record.analysisDelivery === "pending" && record.analysisAttempted !== true)).concat(entries.filter(([, record]) => record.delivery === "delivered" && record.analysisDelivery !== "pending").slice(-900));
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
