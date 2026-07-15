import type { TelemetryCorrelation } from "../domain/telemetry-schemas.js";

/** Stable, human-auditable identity for evidence from one requested window. */
export function buildTelemetryCorrelationKey(input: TelemetryCorrelation): string {
  return [
    `run=${input.runId}`,
    `job=${input.jobId}`,
    `commit=${input.commitSha}`,
    `service=${input.serviceId}`,
    `from=${input.from}`,
    `to=${input.to}`,
  ].join("|");
}
