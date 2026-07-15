import { readFileSync, statSync } from "node:fs";
import { parse as parseYaml } from "yaml";

import {
  parseRuntimeConfiguration,
  RUNTIME_PROFILES,
  runtimeProviderMetadata,
  type RuntimeProviderMetadata,
  type RuntimeConfiguration,
  type RuntimeProfile,
} from "../runtime/load-runtime-configuration.js";

const MAX_CONFIG_BYTES = 256 * 1_024;
const MIN_MCP_TOKEN_BYTES = 16;
const MIN_CI_KEY_BYTES = 32;

export type RuntimeDiagnosticCode =
  | "RUNTIME_CONFIG_OK"
  | "RUNTIME_CONFIG_MISSING"
  | "RUNTIME_CONFIG_INVALID"
  | "RUNTIME_MCP_TOKEN_MISSING"
  | "RUNTIME_MCP_TOKEN_INSECURE"
  | "RUNTIME_MCP_TOKEN_INVALID"
  | "RUNTIME_GRAFANA_TOKEN_MISSING"
  | "RUNTIME_GRAFANA_TOKEN_INSECURE"
  | "RUNTIME_GRAFANA_TOKEN_INVALID"
  | "RUNTIME_CI_SECRET_MISSING"
  | "RUNTIME_CI_SECRET_INSECURE"
  | "RUNTIME_CI_SECRET_INVALID";

export interface RuntimeDiagnostic {
  readonly code: RuntimeDiagnosticCode;
  readonly severity: "info" | "error";
}

export interface RuntimeConfigurationDiagnostic {
  readonly ok: boolean;
  readonly profile?: RuntimeProfile;
  readonly runtimeMetadata?: RuntimeProviderMetadata;
  readonly diagnostics: readonly RuntimeDiagnostic[];
}

export interface DiagnoseRuntimeConfigurationOptions {
  readonly configPath: string;
  readonly mcpTokenPath: string;
  readonly grafanaTokenPath?: string;
}

type FileStatus = "ok" | "missing" | "insecure" | "invalid";

export function diagnoseRuntimeConfiguration(
  options: DiagnoseRuntimeConfigurationOptions,
): RuntimeConfigurationDiagnostic {
  const diagnostics: RuntimeDiagnostic[] = [];
  const configStatus = inspectConfigFile(options.configPath);
  if (configStatus !== "ok") {
    diagnostics.push({ code: configCode(configStatus), severity: "error" });
    return { ok: false, diagnostics };
  }

  let configuration: RuntimeConfiguration;
  try {
    configuration = parseRuntimeConfiguration(readFileSync(options.configPath, "utf8"));
  } catch {
    diagnostics.push({ code: "RUNTIME_CONFIG_INVALID", severity: "error" });
    return { ok: false, diagnostics };
  }

  const profile = configuration.profile;
  const runtimeMetadata = runtimeProviderMetadata(configuration);
  const profileDiagnostics: RuntimeDiagnostic[] = [];
  appendFileDiagnostic(profileDiagnostics, inspectSecretFile(options.mcpTokenPath, MIN_MCP_TOKEN_BYTES), "mcp");
  if (profile !== "ci-only") {
    appendFileDiagnostic(profileDiagnostics, inspectSecretFile(options.grafanaTokenPath, MIN_MCP_TOKEN_BYTES), "grafana");
  }
  if (profile === "ci-only" || profile === "combined") {
    inspectCIFiles(configuration, profileDiagnostics, runtimeMetadata.ci);
  }

  diagnostics.push(...profileDiagnostics);
  if (diagnostics.length === 0) diagnostics.push({ code: "RUNTIME_CONFIG_OK", severity: "info" });
  return { ok: diagnostics.every((diagnostic) => diagnostic.severity !== "error"), profile, runtimeMetadata, diagnostics };
}

function inspectConfigFile(path: string): FileStatus {
  try {
    const metadata = statSync(path);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_CONFIG_BYTES) return "invalid";
    return "ok";
  } catch {
    return "missing";
  }
}

function inspectSecretFile(path: string | undefined, minimumBytes: number): FileStatus {
  if (path === undefined) return "missing";
  try {
    const metadata = statSync(path);
    if (!metadata.isFile()) return "invalid";
    if ((metadata.mode & 0o077) !== 0) return "insecure";
    if (metadata.size < minimumBytes || metadata.size > MAX_CONFIG_BYTES) return "invalid";
    return "ok";
  } catch {
    return "missing";
  }
}

function inspectCIFiles(configuration: RuntimeConfiguration, diagnostics: RuntimeDiagnostic[], metadata: RuntimeProviderMetadata["ci"]): void {
  const ci = configuration.ci;
  if (ci === undefined) return;
  const selected = ci.providers === undefined || ci.provider_name === undefined
    ? ci
    : ci.providers[ci.provider_name];
  const files: Array<{ path: string; minimumBytes: number }> = [];
  if (metadata?.type === "github" && ci.approval !== undefined) files.push({ path: ci.approval.key_file, minimumBytes: MIN_CI_KEY_BYTES });
  if (metadata?.type === "bitbucket" && selected?.bitbucket !== undefined) files.push({ path: selected.bitbucket.token_file, minimumBytes: 1 });
  const app = selected?.github?.app;
  if (app !== undefined) {
    files.push({ path: app.app_id_file, minimumBytes: 1 }, { path: app.pem_key_file, minimumBytes: 1 });
    if (app.installation_id_file !== undefined) files.push({ path: app.installation_id_file, minimumBytes: 1 });
    for (const installation of app.installations ?? []) files.push({ path: installation.installation_id_file, minimumBytes: 1 });
  }
  for (const file of files) appendFileDiagnostic(diagnostics, inspectSecretFile(file.path, file.minimumBytes), "ci");
}

function appendFileDiagnostic(diagnostics: RuntimeDiagnostic[], status: FileStatus, kind: "mcp" | "grafana" | "ci"): void {
  if (status === "ok") return;
  const prefix = kind === "mcp" ? "RUNTIME_MCP_TOKEN" : kind === "grafana" ? "RUNTIME_GRAFANA_TOKEN" : "RUNTIME_CI_SECRET";
  const suffix = status === "missing" ? "MISSING" : status === "insecure" ? "INSECURE" : "INVALID";
  diagnostics.push({ code: `${prefix}_${suffix}` as RuntimeDiagnosticCode, severity: "error" });
}

function configCode(status: Exclude<FileStatus, "ok">): RuntimeDiagnosticCode {
  return status === "missing" ? "RUNTIME_CONFIG_MISSING" : "RUNTIME_CONFIG_INVALID";
}

export function isRuntimeProfile(value: unknown): value is RuntimeProfile {
  return typeof value === "string" && (RUNTIME_PROFILES as readonly string[]).includes(value);
}

export function readRuntimeProfileMetadata(document: string): RuntimeProfile | undefined {
  try {
    const raw: unknown = parseYaml(document);
    if (raw !== null && typeof raw === "object" && "profile" in raw && isRuntimeProfile(raw.profile)) return raw.profile;
  } catch {
    return undefined;
  }
  return undefined;
}
