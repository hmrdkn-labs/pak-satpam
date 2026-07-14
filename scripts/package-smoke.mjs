import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { assertToolSurface } from "./assert-tool-surface.mjs";

const root = process.cwd();
const temporary = mkdtempSync(join(tmpdir(), "observability-agent-mcp-package-"));

try {
  const packed = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--pack-destination", temporary], {
      cwd: root,
      encoding: "utf8",
    }),
  );
  const tarball = join(temporary, packed[0].filename);
  writeFileSync(join(temporary, "package.json"), '{"private":true,"type":"module"}\n');
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", tarball], {
    cwd: temporary,
    stdio: "ignore",
  });

  const installedRoot = join(
    temporary,
    "node_modules",
    "@hamardikan",
    "observability-agent-mcp",
  );
  const module = await import(pathToFileURL(join(installedRoot, "dist", "index.js")).href);
  assert.equal(typeof module.createObservabilityServer, "function");
  assert(readFileSync(join(installedRoot, "dist", "index.d.ts"), "utf8").includes("createObservabilityServer"));
  const observerModule = await import(pathToFileURL(join(installedRoot, "dist", "observer", "index.js")).href);
  assert.equal(typeof observerModule.ObserverRuntime, "function");

  const bin = join(temporary, "node_modules", ".bin", "observability-agent-mcp");
  assert(statSync(bin).isFile());
  assert(statSync(join(temporary, "node_modules", ".bin", "observability-agent-mcp-observer")).isFile());
  const transport = new StdioClientTransport({ command: bin, stderr: "pipe" });
  const client = new Client({ name: "installed-package-smoke", version: "1.0.0" });
  try {
    await client.connect(transport);
    const tools = await client.listTools();
    assertToolSurface(tools.tools);
  } finally {
    await client.close();
  }

  process.stdout.write("installed_package_smoke=ok\n");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
