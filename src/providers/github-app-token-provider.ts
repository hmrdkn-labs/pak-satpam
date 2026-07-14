import { createPrivateKey, createSign } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { CIProviderError, type CITokenProvider } from "./ci-provider.js";

const GITHUB_API_VERSION = "2022-11-28";
const TOKEN_REFRESH_SKEW_MS = 60_000;

export interface GitHubAppTokenProviderOptions {
  readonly appId: string;
  readonly installationId: string;
  readonly privateKeyPem: string;
  readonly allowedRepositories: readonly string[];
  readonly fetch: typeof globalThis.fetch;
  readonly clock?: () => Date;
  readonly apiBaseUrl?: string;
  readonly actionsPermission?: "read" | "write";
}

export class StaticGitHubTokenProvider implements CITokenProvider {
  constructor(private readonly token: string) {
    if (token.length < 16) throw new Error("GitHub token is too short");
  }
  async getToken(_repository: string): Promise<string> { return this.token; }
}

export class GitHubAppTokenProvider implements CITokenProvider {
  readonly #appId: string;
  readonly #installationId: string;
  readonly #privateKey: ReturnType<typeof createPrivateKey>;
  readonly #allowedRepositories: ReadonlySet<string>;
  readonly #fetch: typeof globalThis.fetch;
  readonly #clock: () => Date;
  readonly #apiBaseUrl: string;
  readonly #actionsPermission: "read" | "write";
  readonly #cached = new Map<string, { token: string; expiresAt: number }>();

  constructor(options: GitHubAppTokenProviderOptions) {
    if (!/^\d+$/.test(options.appId) || !/^\d+$/.test(options.installationId)) {
      throw new Error("GitHub App IDs must be numeric");
    }
    this.#appId = options.appId;
    this.#installationId = options.installationId;
    try {
      this.#privateKey = createPrivateKey(options.privateKeyPem);
    } catch {
      throw new Error("Invalid GitHub App private key");
    }
    this.#allowedRepositories = new Set(options.allowedRepositories);
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? (() => new Date());
    this.#apiBaseUrl = trustedGitHubApiBase(options.apiBaseUrl);
    this.#actionsPermission = options.actionsPermission ?? "write";
  }

  static fromPemFile(options: Omit<GitHubAppTokenProviderOptions, "privateKeyPem"> & { pemKeyFile: string }): GitHubAppTokenProvider {
    const metadata = statSync(options.pemKeyFile);
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) throw new Error("GitHub App PEM file must be a regular 0600 file");
    return new GitHubAppTokenProvider({ ...options, privateKeyPem: readFileSync(options.pemKeyFile, "utf8") });
  }

  async getToken(repository: string): Promise<string> {
    if (!this.#allowedRepositories.has(repository)) throw new CIProviderError("permission");
    const now = this.#clock().getTime();
    const cached = this.#cached.get(repository);
    if (cached !== undefined && cached.expiresAt - TOKEN_REFRESH_SKEW_MS > now) return cached.token;

    const jwt = this.createJwt();
    const response = await this.#fetch(
      `${this.#apiBaseUrl}/app/installations/${encodeURIComponent(this.#installationId)}/access_tokens`,
      {
        method: "POST",
        headers: {
          accept: "application/vnd.github+json",
          authorization: `Bearer ${jwt}`,
          "x-github-api-version": GITHUB_API_VERSION,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          repositories: [repository.split("/")[1]],
          permissions: { actions: this.#actionsPermission },
        }),
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      },
    ).catch(() => { throw new CIProviderError("unavailable"); });
    if (response.status === 401 || response.status === 403) throw new CIProviderError("permission");
    if (!response.ok) throw new CIProviderError("unavailable");
    let value: unknown;
    try { value = await response.json(); } catch { throw new CIProviderError("malformed"); }
    if (!isTokenResponse(value)) throw new CIProviderError("malformed");
    const expiresAt = Date.parse(value.expires_at);
    if (!Number.isFinite(expiresAt) || expiresAt <= now) throw new CIProviderError("malformed");
    this.#cached.set(repository, { token: value.token, expiresAt });
    return value.token;
  }

  private createJwt(): string {
    const now = Math.floor(this.#clock().getTime() / 1_000);
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const header = encode({ alg: "RS256", typ: "JWT" });
    const payload = encode({ iat: now - 60, exp: now + 540, iss: this.#appId });
    const input = `${header}.${payload}`;
    const signer = createSign("RSA-SHA256");
    signer.update(input);
    return `${input}.${signer.sign(this.#privateKey).toString("base64url")}`;
  }
}

function trustedGitHubApiBase(value: string | undefined): string {
  const url = new URL(value ?? "https://api.github.com");
  if (url.protocol !== "https:" || url.hostname !== "api.github.com" || url.port !== "" || url.username !== "" || url.password !== "" || (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("GitHub API base URL is not trusted");
  }
  return "https://api.github.com";
}

function isTokenResponse(value: unknown): value is { token: string; expires_at: string } {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return typeof record.token === "string" && record.token.length >= 16 && typeof record.expires_at === "string";
}
