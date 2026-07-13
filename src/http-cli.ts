#!/usr/bin/env node
import process from "node:process";

import { createObservabilityHttpApp } from "./http/create-http-app.js";
import { loadRuntimeConfiguration } from "./runtime/load-runtime-configuration.js";

const host = process.env.MCP_HTTP_HOST ?? "127.0.0.1";
const port = parsePort(process.env.MCP_HTTP_PORT ?? "8765");
const allowedHosts = requiredEnvironment("MCP_HTTP_ALLOWED_HOSTS")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const runtime = loadRuntimeConfiguration({
  configPath: requiredEnvironment("OBSERVABILITY_PROVIDER_CONFIG"),
  grafanaTokenPath: requiredEnvironment("GRAFANA_TOKEN_FILE"),
  mcpTokenPath: requiredEnvironment("MCP_TOKEN_FILE"),
  fetch: globalThis.fetch.bind(globalThis),
});
const app = createObservabilityHttpApp({
  provider: runtime.provider,
  visualProvider: runtime.visualProvider,
  visualAllowlist: runtime.visualAllowlist,
  ...(runtime.ci === undefined ? {} : { ci: runtime.ci }),
  bearerToken: runtime.bearerToken,
  host,
  allowedHosts,
});

const listener = app.listen(port, host, (error?: Error) => {
  if (error !== undefined) {
    process.stderr.write("observability-agent-mcp HTTP startup failed\n");
    process.exitCode = 1;
    return;
  }
  process.stderr.write("observability-agent-mcp HTTP transport ready\n");
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    listener.close(() => process.exit(0));
  });
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function parsePort(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65_535) {
    throw new Error("MCP_HTTP_PORT must be an integer between 1 and 65535");
  }
  return parsed;
}
