import {
  RenderDashboardInputSchema,
  RenderPanelInputSchema,
  type RenderDashboardInput,
  type RenderPanelInput,
} from "../domain/tool-schemas.js";
import type { ObservabilityVisualProvider, VisualRenderResult } from "./observability-provider.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 8 * 1_024 * 1_024;

export interface GrafanaVisualProviderOptions {
  readonly baseUrl: string;
  readonly token: string;
  readonly fetch: typeof globalThis.fetch;
  /** Keys are `${dashboardId}:${panelId}` and values are pre-approved Grafana /render paths. */
  readonly panels: Readonly<Record<string, string>>;
  /** Keys are logical dashboard IDs and values are pre-approved Grafana /render paths. */
  readonly dashboards: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
}

/** Deliberately generic: upstream status, body, URL, and credentials never escape. */
export class VisualProviderError extends Error {
  constructor(message: "Visual route is not allowlisted" | "Visual evidence is unavailable") {
    super(message);
    this.name = "VisualProviderError";
  }
}

/** Read-only Grafana renderer backed exclusively by injected allowlisted routes. */
export class GrafanaVisualProvider implements ObservabilityVisualProvider {
  readonly #options: GrafanaVisualProviderOptions;
  private readonly baseUrl: URL;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;

  constructor(options: GrafanaVisualProviderOptions) {
    this.#options = options;
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    if (!Number.isInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 30_000) {
      throw new Error("timeoutMs must be between 1 and 30000");
    }
    if (!Number.isInteger(this.maxBytes) || this.maxBytes < 1 || this.maxBytes > DEFAULT_MAX_BYTES) {
      throw new Error("maxBytes must be between 1 and 8388608");
    }
  }

  async renderPanel(input: RenderPanelInput): Promise<VisualRenderResult> {
    const request = RenderPanelInputSchema.parse(input);
    const route = this.#options.panels[`${request.dashboardId}:${request.panelId}`];
    if (route === undefined) throw new VisualProviderError("Visual route is not allowlisted");
    return this.render(route, request);
  }

  async renderDashboard(input: RenderDashboardInput): Promise<VisualRenderResult> {
    const request = RenderDashboardInputSchema.parse(input);
    const route = this.#options.dashboards[request.dashboardId];
    if (route === undefined) throw new VisualProviderError("Visual route is not allowlisted");
    return this.render(route, request);
  }

  private async render(route: string, request: RenderPanelInput | RenderDashboardInput): Promise<VisualRenderResult> {
    let url: URL;
    try {
      url = allowlistedRenderUrl(this.baseUrl, route, request);
    } catch {
      throw new VisualProviderError("Visual route is not allowlisted");
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.#options.fetch(url, {
        method: "GET",
        redirect: "error",
        headers: { Accept: "image/png", Authorization: `Bearer ${this.#options.token}` },
        signal: controller.signal,
      });
      const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
      const contentLength = Number(response.headers.get("content-length"));
      if (!response.ok || contentType !== "image/png" || (Number.isFinite(contentLength) && contentLength > this.maxBytes)) {
        throw new VisualProviderError("Visual evidence is unavailable");
      }
      const data = await readBoundedBody(response, this.maxBytes);
      if (data.byteLength === 0 || !isPng(data)) {
        throw new VisualProviderError("Visual evidence is unavailable");
      }
      return {
        mimeType: "image/png",
        data,
        rawByteSize: data.byteLength,
        width: request.width,
        height: request.height,
      };
    } catch (error) {
      if (error instanceof VisualProviderError) throw error;
      throw new VisualProviderError("Visual evidence is unavailable");
    } finally {
      clearTimeout(timeout);
    }
  }
}

async function readBoundedBody(response: Response, maxBytes: number): Promise<Uint8Array> {
  if (response.body === null) throw new VisualProviderError("Visual evidence is unavailable");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new VisualProviderError("Visual evidence is unavailable");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function normalizeBaseUrl(value: string): URL {
  const url = new URL(value);
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || url.search || url.hash) {
    throw new Error("baseUrl must be an absolute HTTP(S) URL without credentials, query, or fragment");
  }
  if (!url.pathname.endsWith("/")) url.pathname = `${url.pathname}/`;
  return url;
}

function allowlistedRenderUrl(
  baseUrl: URL,
  route: string,
  request: RenderPanelInput | RenderDashboardInput,
): URL {
  if (!route.startsWith("/") || route.includes("#")) {
    throw new Error("invalid route");
  }
  const basePath = baseUrl.pathname.replace(/\/+$/, "");
  const routePath = route.replace(/^\/+/, "");
  const url = new URL(
    basePath !== "" && (route === basePath || route.startsWith(`${basePath}/`))
      ? route.replace(/^\/+/, "")
      : routePath,
    basePath !== "" && (route === basePath || route.startsWith(`${basePath}/`)) ? new URL(baseUrl.origin) : baseUrl,
  );
  const renderPrefix = `${basePath === "" ? "" : `${basePath}/`}render/`;
  if (url.origin !== baseUrl.origin || !url.pathname.startsWith(renderPrefix)) throw new Error("invalid route");
  const configuredKeys = [...url.searchParams.keys()];
  if (
    configuredKeys.some((key) => key !== "panelId") ||
    configuredKeys.length > 1 ||
    (url.searchParams.has("panelId") && !/^\d{1,9}$/.test(url.searchParams.get("panelId") ?? ""))
  ) {
    throw new Error("invalid route");
  }
  url.searchParams.set("from", request.from);
  url.searchParams.set("to", request.to);
  url.searchParams.set("width", String(request.width));
  url.searchParams.set("height", String(request.height));
  url.searchParams.set("theme", request.theme);
  return url;
}

function isPng(data: Uint8Array): boolean {
  const signature = [137, 80, 78, 71, 13, 10, 26, 10];
  return signature.every((value, index) => data[index] === value);
}
