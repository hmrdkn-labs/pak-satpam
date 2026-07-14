#!/usr/bin/env node

import process from "node:process";

import { loadObserverConfiguration } from "./config.js";
import { createObserverHealthServer, createObserverRuntimeFromFiles } from "./runtime.js";

const configPath = requiredEnvironment("OBSERVER_CONFIG_FILE");
const fileConfig = loadObserverConfiguration(configPath);
const runtime = createObserverRuntimeFromFiles({ configPath, fetch: globalThis.fetch.bind(globalThis) });
const healthPort = process.env.OBSERVER_HEALTH_PORT === undefined
  ? fileConfig.health.port
  : parsePort(process.env.OBSERVER_HEALTH_PORT);
const healthServer = healthPort === undefined ? undefined : createObserverHealthServer(runtime, {
  host: process.env.OBSERVER_HEALTH_HOST?.trim() || fileConfig.health.host,
  port: healthPort,
});
const stop = await runtime.start();

await new Promise<void>((resolve) => {
  const shutdown = async (): Promise<void> => {
    await stop();
    healthServer?.close();
    resolve();
  };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
});

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function parsePort(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65_535) throw new Error("OBSERVER_HEALTH_PORT must be an integer between 1 and 65535");
  return parsed;
}
