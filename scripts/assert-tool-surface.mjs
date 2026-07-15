import assert from "node:assert/strict";

const BASE_TOOLS = [
  "observability.capabilities",
  "observability.health_snapshot",
  "observability.active_alerts",
  "observability.query_metrics",
  "observability.render_panel",
  "observability.render_dashboard",
  "observability.incident_context",
];

const CI_TOOLS = [
  "ci.workflow_status",
  "ci.failed_job_analysis",
  "ci.log_evidence",
  "ci.remediation_plan",
  "ci.rerun_failed_workflow",
];
const CI_READ_TOOLS = CI_TOOLS.slice(0, 4);
const FORENSICS_TOOLS = [
  "ci.failure_analysis",
  "ci.scm_change_evidence",
  "ci.telemetry_correlation",
];
const COMBINED_TOOLS = [...BASE_TOOLS, ...CI_TOOLS];

export function assertToolSurface(tools) {
  const names = tools.map((tool) => tool.name);
  const ciNames = names.filter((name) => name.startsWith("ci."));
  assert.deepEqual(names.filter((name) => !name.startsWith("ci.")), BASE_TOOLS);
  assert(ciNames.length === 0 || ciNames.length >= CI_READ_TOOLS.length, `unexpected optional CI tool count: ${ciNames.length}`);
  assert(ciNames.every((name) => CI_TOOLS.includes(name) || FORENSICS_TOOLS.includes(name)), "unexpected CI tool");
  if (ciNames.length > 0) {
    const legacyNames = ciNames.filter((name) => !FORENSICS_TOOLS.includes(name));
    assert.deepEqual(legacyNames, legacyNames.includes("ci.rerun_failed_workflow") ? CI_TOOLS : CI_READ_TOOLS);
    const rerun = tools.find((tool) => tool.name === "ci.rerun_failed_workflow");
    if (rerun !== undefined) {
      assert.deepEqual(rerun.annotations, {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      });
    }
  }
}

export function assertProfileToolSurface(tools, profile) {
  const names = tools.map((tool) => tool.name);
  assert.deepEqual(names, profile === "combined" ? COMBINED_TOOLS : CI_TOOLS);
}
