import { readFileSync, statSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

import { LogicalIdSchema } from "../domain/tool-schemas.js";
import { CIProviderEndpointSchema, CIProviderNameSchema } from "../domain/ci-provider-contracts.js";
import type { VisualAllowlist } from "../domain/visual-policy.js";
import { GrafanaVisualProvider } from "../providers/grafana-visual-provider.js";
import type {
  Clock,
  ObservabilityProvider,
  ObservabilityVisualProvider,
} from "../providers/observability-provider.js";
import { VictoriaMetricsProvider } from "../providers/victoriametrics-provider.js";
import { JenkinsProvider } from "../providers/jenkins-provider.js";
import { BitbucketProvider } from "../providers/bitbucket-provider.js";
import { CIRepositorySchema, CIWorkflowSchema } from "../domain/ci-schemas.js";
import { ApprovalTokenService, FileApprovalAuditStore } from "../ci/approval.js";
import { createCIAllowlist } from "../ci/policy.js";
import type { CIProviderRuntimeMetadata, CIService, CIProviderType } from "../ci/service.js";
import { GitHubActionsProvider } from "../providers/github-actions-provider.js";
import { GitHubAppTokenProvider } from "../providers/github-app-token-provider.js";
import { MappedGitHubAppTokenProvider } from "../providers/mapped-github-app-token-provider.js";
import { BitbucketSCMProvider, GitHubSCMProvider, JenkinsSCMProvider } from "../scm/index.js";
import type { SCMReadProvider } from "../scm/provider.js";
import type { ForensicsProviderSet } from "../providers/ci-provider.js";
import { SCMChangeEvidenceResultSchema as SCMAdapterResultSchema } from "../scm/schemas.js";
import { SCMChangeEvidenceResultSchema as ForensicsSCMResultSchema } from "../domain/forensics-schemas.js";
import { CIProviderRegistry } from "../providers/ci-provider-registry.js";
import { READ_ONLY_CI_PROVIDER_CAPABILITIES, APPROVAL_GATED_CI_PROVIDER_CAPABILITIES } from "../domain/ci-provider-contracts.js";

const MAX_CONFIG_BYTES = 256 * 1_024;

interface BuiltForensics {
  readonly scm?: SCMReadProvider;
  readonly forensics?: ForensicsProviderSet;
}

export const RUNTIME_PROFILES = ["observability-only", "ci-only", "combined"] as const;
export type RuntimeProfile = (typeof RUNTIME_PROFILES)[number];

const HttpProviderSchema = z
  .object({
    type: z.string().min(1).max(64),
    base_url: z.url(),
  })
  .strict();

const QuerySchema = z
  .object({
    expression: z.string().min(1).max(4_096),
    label_keys: z.array(LogicalIdSchema).max(20).default([]),
  })
  .strict();

const NumericMatchSchema = z
  .object({
    operator: z.enum(["eq", "gt", "gte", "lt", "lte"]),
    value: z.number().finite(),
  })
  .strict();

const ServiceHealthSchema = z
  .object({
    query_template: LogicalIdSchema,
    healthy_when: NumericMatchSchema,
    degraded_when: NumericMatchSchema.optional(),
    summary: z.string().min(1).max(512).refine((value) => !/[<>]/.test(value)),
  })
  .strict();

const DashboardSchema = z
  .object({
    uid: LogicalIdSchema,
    slug: LogicalIdSchema,
    title: z.string().min(1).max(256).refine((value) => !/[<>]/.test(value)),
    panels: z
      .record(
        LogicalIdSchema,
        z.object({ id: z.number().int().min(1).max(999_999_999) }).strict(),
      )
      .refine((panels) => Object.keys(panels).length <= 50),
  })
  .strict();

const CIAllowlistEntrySchema = z
  .object({ repo: CIRepositorySchema, workflows: z.array(CIWorkflowSchema).min(1).max(50) })
  .strict();
const GitHubInstallationSchema = z.union([
  z.object({ repo: CIRepositorySchema, installation_id_file: z.string().min(1).max(1_024) }).strict(),
  z.object({ owner: z.string().min(1).max(100).regex(/^[A-Za-z0-9_.-]+$/), installation_id_file: z.string().min(1).max(1_024) }).strict(),
]);
const GitHubAppSchema = z
  .object({
    app_id_file: z.string().min(1).max(1_024),
    installation_id_file: z.string().min(1).max(1_024).optional(),
    installations: z.array(GitHubInstallationSchema).min(1).max(100).optional(),
    pem_key_file: z.string().min(1).max(1_024),
  })
  .strict()
  .superRefine((value, context) => {
    if ((value.installation_id_file === undefined) === (value.installations === undefined)) {
      context.addIssue({ code: "custom", path: ["installations"], message: "configure one installation mode" });
    }
  });
const CIProviderTypeSchema = z.enum(["github", "jenkins", "bitbucket"]);
const CIProviderBaseUrlSchema = z.string().min(1).max(2_048).url().refine((value) => {
  const url = new URL(value);
  return (url.protocol === "http:" || url.protocol === "https:") && url.username === "" && url.password === "" && url.search === "" && url.hash === "";
}, "must be an HTTP(S) base URL without credentials, query, or fragment");
const JenkinsConfigSchema = z
  .object({ base_url: CIProviderBaseUrlSchema.optional(), endpoint: CIProviderEndpointSchema.optional(), allow_insecure_http: z.boolean().default(false) })
  .strict()
  .superRefine((value, context) => {
    if ((value.base_url === undefined) === (value.endpoint === undefined)) {
      context.addIssue({ code: "custom", path: ["endpoint"], message: "configure exactly one base_url or endpoint" });
      return;
    }
    const url = new URL(value.endpoint?.origin ?? value.base_url as string);
    if (url.protocol === "http:" && (value.allow_insecure_http !== true || !["127.0.0.1", "::1"].includes(url.hostname.toLowerCase().replace(/^\[|\]$/g, "")))) {
      context.addIssue({ code: "custom", path: ["base_url"], message: "cleartext HTTP requires explicit loopback opt-in" });
    }
  });
const BitbucketConfigSchema = z
  .object({ base_url: CIProviderBaseUrlSchema.optional(), endpoint: CIProviderEndpointSchema.optional(), token_file: z.string().min(1).max(1_024), username: z.string().min(1).max(256).optional() })
  .strict()
  .superRefine((value, context) => {
    if ((value.base_url === undefined) === (value.endpoint === undefined)) {
      context.addIssue({ code: "custom", path: ["endpoint"], message: "configure exactly one base_url or endpoint" });
      return;
    }
    if (new URL(value.endpoint?.origin ?? value.base_url as string).protocol !== "https:") context.addIssue({ code: "custom", path: ["base_url"], message: "Bitbucket credentials require HTTPS" });
  });
const GitHubConfigSchema = z
  .object({
    api_base_url: CIProviderBaseUrlSchema.optional(),
    api_endpoint: CIProviderEndpointSchema.optional(),
    app: GitHubAppSchema.optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.api_base_url !== undefined && value.api_endpoint !== undefined) {
      context.addIssue({ code: "custom", path: ["api_endpoint"], message: "configure exactly one api_base_url or api_endpoint" });
    }
    const origin = value.api_endpoint?.origin ?? value.api_base_url;
    if (origin !== undefined) {
      const url = new URL(origin);
      if (url.protocol !== "https:" || url.hostname !== "api.github.com" || url.port !== "") {
        context.addIssue({ code: "custom", path: ["api_base_url"], message: "GitHub API base URL is not trusted" });
      }
    }
  });
const SCMForensicsSchema = z
  .object({
    enabled: z.boolean().default(true),
    provider: CIProviderTypeSchema.optional(),
    base_url: CIProviderBaseUrlSchema.optional(),
    endpoint: CIProviderEndpointSchema.optional(),
    token_file: z.string().min(1).max(1_024).optional(),
    username: z.string().min(1).max(256).optional(),
    job: z.string().min(1).max(512).optional(),
    branch: z.string().min(1).max(256).regex(/^[^\s?#]+$/).optional(),
    allowed_refs: z.array(z.string().min(1).max(256).regex(/^[^\s?#]+$/)).min(1).max(100).default(["main"]),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.base_url !== undefined && value.endpoint !== undefined) context.addIssue({ code: "custom", path: ["endpoint"], message: "configure one base_url or endpoint" });
  });
const TelemetryForensicsSchema = z
  .object({
    enabled: z.boolean().default(true),
    query_template: LogicalIdSchema,
  })
  .strict();
const ForensicsConfigSchema = z
  .object({ scm: SCMForensicsSchema.optional(), telemetry: TelemetryForensicsSchema.optional() })
  .strict();
const NamedCIProviderSchema = z
  .object({
    type: CIProviderTypeSchema,
    github: GitHubConfigSchema.optional(),
    jenkins: JenkinsConfigSchema.optional(),
    bitbucket: BitbucketConfigSchema.optional(),
    forensics: ForensicsConfigSchema.optional(),
  })
  .strict()
  .superRefine((value, context) => {
    const configured = value.type === "github" ? value.github : value.type === "jenkins" ? value.jenkins : value.bitbucket;
    if (configured === undefined) context.addIssue({ code: "custom", path: [value.type], message: "provider configuration is required" });
  });
const CIConfigSchema = z
  .object({
    enabled: z.boolean().default(false),
    provider: CIProviderTypeSchema.default("github"),
    provider_name: CIProviderNameSchema.optional(),
    providers: z.record(CIProviderNameSchema, NamedCIProviderSchema).refine((providers) => Object.keys(providers).length <= 20).optional(),
    allowlist: z.array(CIAllowlistEntrySchema).max(100).default([]),
    github: GitHubConfigSchema.optional(),
    jenkins: JenkinsConfigSchema.optional(),
    bitbucket: BitbucketConfigSchema.optional(),
    approval: z
      .object({
        key_file: z.string().min(1).max(1_024),
        replay_file: z.string().min(1).max(1_024),
        audit_file: z.string().min(1).max(1_024),
      })
      .strict()
      .optional(),
    forensics: ForensicsConfigSchema.optional(),
    max_freshness_seconds: z.number().int().min(1).max(3_600).default(300),
  })
  .strict();

const ObservabilityProvidersSchema = z
  .object({
    metrics: HttpProviderSchema.extend({ type: z.literal("prometheus-compatible") }).strict(),
    alerts: HttpProviderSchema.extend({ type: z.enum(["vmalert", "grafana-alertmanager"]) }).strict(),
    grafana: HttpProviderSchema.extend({ type: z.literal("grafana") }).strict(),
  })
  .strict();

const ObservabilityPolicySchema = z
  .object({
    named_queries: z.record(LogicalIdSchema, QuerySchema),
    service_health: z.record(LogicalIdSchema, ServiceHealthSchema),
    dashboards: z.record(LogicalIdSchema, DashboardSchema),
  })
  .strict();

export const RuntimeConfigSchema = z
  .object({
    version: z.literal(1),
    profile: z.enum(RUNTIME_PROFILES),
    providers: ObservabilityProvidersSchema.optional(),
    policy: ObservabilityPolicySchema.optional(),
    ci: CIConfigSchema.optional(),
  })
  .strict()
  .superRefine((configuration, context) => {
    const needsObservability = configuration.profile !== "ci-only";
    if (needsObservability && (configuration.providers === undefined || configuration.policy === undefined)) {
      context.addIssue({ code: "custom", path: ["providers"], message: "observability configuration is required for this profile" });
    }
    if (configuration.profile === "observability-only" && configuration.ci?.enabled === true) {
      context.addIssue({ code: "custom", path: ["ci"], message: "CI requires the combined profile" });
    }
    if ((configuration.profile === "ci-only" || configuration.profile === "combined") && configuration.ci?.enabled !== true) {
      context.addIssue({ code: "custom", path: ["ci"], message: "enabled CI configuration is required for this profile" });
    }
    if (configuration.ci?.providers !== undefined) {
      if (configuration.ci.provider_name === undefined) {
        context.addIssue({ code: "custom", path: ["ci", "provider_name"], message: "named provider selection is required" });
      } else if (configuration.ci.providers[configuration.ci.provider_name] === undefined) {
        context.addIssue({ code: "custom", path: ["ci", "provider_name"], message: "selected provider is not configured" });
      }
    } else if (configuration.ci?.provider_name !== undefined) {
      context.addIssue({ code: "custom", path: ["ci", "provider_name"], message: "named providers are not configured" });
    }
    if (configuration.ci?.enabled === true) {
      const ci = configuration.ci;
      const configuredProviders = ci.providers === undefined
        ? [[ci.provider, { type: ci.provider, github: ci.github, jenkins: ci.jenkins, bitbucket: ci.bitbucket }] as const]
        : Object.entries(ci.providers);
      for (const [name, candidate] of configuredProviders) {
        const providerConfig = candidate.type === "github" ? candidate.github : candidate.type === "jenkins" ? candidate.jenkins : candidate.bitbucket;
        if (providerConfig === undefined) {
          context.addIssue({ code: "custom", path: ["ci", "providers", name], message: "provider configuration is required" });
        }
        if (candidate.type === "github" && candidate.github?.app === undefined) {
          context.addIssue({ code: "custom", path: ["ci", "providers", name, "github", "app"], message: "GitHub App configuration is required" });
        }
      }
      const selected = ci.providers === undefined || ci.provider_name === undefined
        ? { type: ci.provider, github: ci.github, jenkins: ci.jenkins, bitbucket: ci.bitbucket }
        : ci.providers[ci.provider_name];
      if (selected !== undefined) {
        const providerConfig = selected.type === "github" ? selected.github : selected.type === "jenkins" ? selected.jenkins : selected.bitbucket;
        if (providerConfig === undefined) {
          context.addIssue({ code: "custom", path: ["ci", selected.type], message: "selected provider configuration is required" });
        }
        if (selected.type === "github") {
          if (ci.approval === undefined) context.addIssue({ code: "custom", path: ["ci", "approval"], message: "approval configuration is required for rerun capability" });
        }
      }
    }
    if (configuration.policy !== undefined) {
      for (const [serviceId, health] of Object.entries(configuration.policy.service_health)) {
        if (configuration.policy.named_queries[health.query_template] === undefined) {
          context.addIssue({
            code: "custom",
            path: ["policy", "service_health", serviceId, "query_template"],
            message: "must reference a named query",
          });
        }
      }
    }
  });

export type RuntimeConfiguration = z.infer<typeof RuntimeConfigSchema>;

export interface RuntimeProviderMetadata {
  readonly observability?: {
    readonly metrics: string;
    readonly alerts: string;
    readonly grafana: string;
  };
  readonly ci?: CIProviderRuntimeMetadata;
}

export function parseRuntimeConfiguration(document: string): RuntimeConfiguration {
  let raw: unknown;
  try {
    raw = parseYaml(document);
  } catch {
    throw new Error("Invalid runtime configuration");
  }
  const parsed = RuntimeConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error("Invalid runtime configuration");
  }
  return parsed.data;
}

export function runtimeProviderMetadata(configuration: RuntimeConfiguration): RuntimeProviderMetadata {
  const observability = configuration.providers === undefined
    ? undefined
    : {
        metrics: configuration.providers.metrics.type,
        alerts: configuration.providers.alerts.type,
        grafana: configuration.providers.grafana.type,
      };
  const ci = configuration.ci?.enabled === true ? resolveCIProvider(configuration.ci).metadata : undefined;
  return {
    ...(observability === undefined ? {} : { observability }),
    ...(ci === undefined ? {} : { ci }),
  };
}

export interface LoadRuntimeConfigurationOptions {
  readonly configPath: string;
  readonly grafanaTokenPath?: string;
  readonly mcpTokenPath: string;
  readonly fetch: typeof globalThis.fetch;
  readonly clock?: Clock;
}

export class LoadedRuntimeConfiguration {
  readonly #bearerToken: string;

  constructor(
    public readonly profile: RuntimeProfile,
    public readonly provider: ObservabilityProvider | undefined,
    public readonly visualProvider: ObservabilityVisualProvider | undefined,
    public readonly visualAllowlist: VisualAllowlist | undefined,
    bearerToken: string,
    public readonly ci: CIService | undefined = undefined,
    public readonly runtimeMetadata: RuntimeProviderMetadata = {},
  ) {
    this.#bearerToken = bearerToken;
  }

  get bearerToken(): string {
    return this.#bearerToken;
  }
}

export function loadRuntimeConfiguration(
  options: LoadRuntimeConfigurationOptions,
): LoadedRuntimeConfiguration {
  const document = readBoundedFile(options.configPath, false);
  const bearerToken = readBoundedFile(options.mcpTokenPath, true).trim();
  if (bearerToken.length < 16) {
    throw new Error("Runtime secret is missing or too short");
  }

  const configuration = parseRuntimeConfiguration(document);
  const runtimeMetadata = runtimeProviderMetadata(configuration);

  let provider: ObservabilityProvider | undefined;
  let visualProvider: ObservabilityVisualProvider | undefined;
  let visualAllowlist: VisualAllowlist | undefined;
  if (configuration.profile !== "ci-only") {
    const providers = configuration.providers;
    const policy = configuration.policy;
    if (providers === undefined || policy === undefined) throw new Error("Invalid runtime configuration");
    const grafanaToken = options.grafanaTokenPath === undefined
      ? ""
      : readBoundedFile(options.grafanaTokenPath, true).trim();
    if (grafanaToken.length < 16) throw new Error("Runtime secret is missing or too short");
    const queryTemplates = Object.fromEntries(
      Object.entries(policy.named_queries).map(([name, query]) => [
        name,
        { expression: query.expression, labelKeys: query.label_keys },
      ]),
    );
    const serviceHealth = Object.fromEntries(
      Object.entries(policy.service_health).map(([name, health]) => [
        name,
        {
          queryTemplate: health.query_template,
          healthyWhen: health.healthy_when,
          ...(health.degraded_when === undefined ? {} : { degradedWhen: health.degraded_when }),
          summary: health.summary,
        },
      ]),
    );
    provider = new VictoriaMetricsProvider({
      baseUrl: providers.metrics.base_url,
      alertsBaseUrl: providers.alerts.base_url,
      alertsProvider: providers.alerts.type,
      fetch: options.fetch,
      queryTemplates,
      serviceHealth,
      visualsEnabled: true,
      dashboardRefs: Object.entries(policy.dashboards).map(
        ([dashboardId, dashboard]) => ({ dashboardId, title: dashboard.title }),
      ),
      ...(options.clock === undefined ? {} : { clock: options.clock }),
    });

    const panels: Record<string, string> = {};
    const dashboards: Record<string, string> = {};
    const allowlistDashboards: Record<string, { panels: string[] }> = {};
    for (const [dashboardId, dashboard] of Object.entries(policy.dashboards)) {
      const basePath = `${encodeURIComponent(dashboard.uid)}/${encodeURIComponent(dashboard.slug)}`;
      dashboards[dashboardId] = `/render/d/${basePath}`;
      allowlistDashboards[dashboardId] = { panels: Object.keys(dashboard.panels) };
      for (const [panelId, panel] of Object.entries(dashboard.panels)) {
        panels[`${dashboardId}:${panelId}`] = `/render/d-solo/${basePath}?panelId=${String(panel.id)}`;
      }
    }
    visualAllowlist = { dashboards: allowlistDashboards };
    visualProvider = new GrafanaVisualProvider({
      baseUrl: providers.grafana.base_url,
      token: grafanaToken,
      fetch: options.fetch,
      panels,
      dashboards,
    });
  }

  const ci = buildCIConfiguration(configuration.ci, options, provider);

  return new LoadedRuntimeConfiguration(
    configuration.profile,
    provider,
    visualProvider,
    visualAllowlist,
    bearerToken,
    ci,
    runtimeMetadata,
  );
}

type CIConfiguration = z.infer<typeof CIConfigSchema>;

interface ResolvedCIProviderConfiguration {
  readonly name: string;
  readonly type: CIProviderType;
  readonly github?: CIConfiguration["github"];
  readonly jenkins?: CIConfiguration["jenkins"];
  readonly bitbucket?: CIConfiguration["bitbucket"];
  readonly forensics?: CIConfiguration["forensics"];
}

interface ResolvedCIProvider {
  readonly configuration: ResolvedCIProviderConfiguration;
  readonly metadata: CIProviderRuntimeMetadata;
}

function resolveCIProviders(configuration: CIConfiguration): readonly ResolvedCIProvider[] {
  if (configuration.providers !== undefined) {
    return Object.entries(configuration.providers).map(([name, selected]) => ({
      configuration: { name, type: selected.type, github: selected.github, jenkins: selected.jenkins, bitbucket: selected.bitbucket, forensics: selected.forensics },
      metadata: {
        name,
        type: selected.type,
        capabilities: { read: true, rerun: selected.type === "github" },
        approvalRequired: selected.type === "github",
      },
    }));
  }
  return [{
    configuration: { name: configuration.provider, type: configuration.provider, github: configuration.github, jenkins: configuration.jenkins, bitbucket: configuration.bitbucket, forensics: configuration.forensics },
    metadata: {
      name: configuration.provider,
      type: configuration.provider,
      capabilities: { read: true, rerun: configuration.provider === "github" },
      approvalRequired: configuration.provider === "github",
    },
  }];
}

function resolveCIProvider(configuration: CIConfiguration): ResolvedCIProvider {
  const selectedName = configuration.providers === undefined ? configuration.provider : configuration.provider_name;
  if (selectedName === undefined) throw new Error("Invalid CI runtime configuration");
  const selected = resolveCIProviders(configuration).find((entry) => entry.metadata.name === selectedName);
  if (selected === undefined) throw new Error("Invalid CI runtime configuration");
  return selected;
}

function buildCIConfiguration(
  configuration: CIConfiguration | undefined,
  options: LoadRuntimeConfigurationOptions,
  observabilityProvider: ObservabilityProvider | undefined,
): CIService | undefined {
  if (configuration?.enabled !== true) return undefined;
  if (configuration.allowlist.length === 0) {
    throw new Error("Invalid CI runtime configuration");
  }
  const selected = resolveCIProvider(configuration);
  const repositories = configuration.allowlist.map((entry) => entry.repo);
  const clock = options.clock ?? (() => new Date());
  const built = resolveCIProviders(configuration).map((entry) => {
    const provider = buildCIProvider(entry, repositories, options, clock, configuration.max_freshness_seconds);
    const builtForensics = buildForensics(entry.configuration, provider, repositories, options, observabilityProvider, clock);
    return {
      name: entry.metadata.name,
      kind: entry.metadata.type,
      capabilities: entry.metadata.capabilities.rerun
        ? APPROVAL_GATED_CI_PROVIDER_CAPABILITIES
        : READ_ONLY_CI_PROVIDER_CAPABILITIES,
      provider,
      ...(builtForensics?.scm === undefined ? {} : { scm: builtForensics.scm }),
      ...(builtForensics?.forensics === undefined ? {} : { forensics: builtForensics.forensics }),
    };
  });
  const providerRegistry = new CIProviderRegistry(built);
  const active = providerRegistry.select(selected.metadata.name);
  const activeProvider = active.provider as CIService["provider"];
  const approval = selected.metadata.approvalRequired
    ? configuration.approval === undefined
      ? (() => { throw new Error("Invalid CI runtime configuration"); })()
      : (() => {
          const key = ApprovalTokenService.readKeyFile(configuration.approval.key_file);
          const audit = new FileApprovalAuditStore({
            replayPath: configuration.approval.replay_file,
            auditPath: configuration.approval.audit_file,
          });
          return new ApprovalTokenService({ key, clock, audit });
        })()
    : undefined;
  return {
    provider: activeProvider,
    policy: createCIAllowlist(Object.fromEntries(configuration.allowlist.map((entry) => [entry.repo, entry.workflows]))),
    runtimeMetadata: selected.metadata,
    providerRegistry,
    ...(active.scm === undefined ? {} : { scm: active.scm }),
    ...(active.forensics === undefined ? {} : { forensics: active.forensics }),
    ...(approval === undefined ? {} : { approval }),
  };
}

function buildCIProvider(
  selected: ResolvedCIProvider,
  repositories: readonly string[],
  options: LoadRuntimeConfigurationOptions,
  clock: Clock,
  maxFreshnessSeconds: number,
): CIService["provider"] {
  if (selected.configuration.type === "jenkins") {
    const jenkins = selected.configuration.jenkins;
    if (jenkins === undefined) throw new Error("Invalid CI runtime configuration");
    return new JenkinsProvider({
      ...(jenkins.endpoint === undefined ? { baseUrl: jenkins.base_url! } : { endpoint: jenkins.endpoint }),
      allowInsecureHttp: jenkins.allow_insecure_http,
      fetch: options.fetch,
      providerName: selected.metadata.name,
      ...(options.clock === undefined ? {} : { clock }),
      maxFreshnessMs: maxFreshnessSeconds * 1_000,
    });
  }
  if (selected.configuration.type === "bitbucket") {
    const bitbucket = selected.configuration.bitbucket;
    if (bitbucket === undefined) throw new Error("Invalid CI runtime configuration");
    return new BitbucketProvider({
      ...(bitbucket.endpoint === undefined ? { baseUrl: bitbucket.base_url! } : { endpoint: bitbucket.endpoint }),
      tokenFile: bitbucket.token_file,
      ...(bitbucket.username === undefined ? {} : { username: bitbucket.username }),
      fetch: options.fetch,
      providerName: selected.metadata.name,
      ...(options.clock === undefined ? {} : { clock }),
      maxFreshnessMs: maxFreshnessSeconds * 1_000,
    });
  }
  return buildGitHubProvider(selected.configuration, repositories, options, clock, maxFreshnessSeconds);
}

function buildForensics(
  configuration: ResolvedCIProviderConfiguration,
  provider: CIService["provider"],
  repositories: readonly string[],
  options: LoadRuntimeConfigurationOptions,
  observabilityProvider: ObservabilityProvider | undefined,
  clock: Clock,
): BuiltForensics | undefined {
  const configured = configuration.forensics;
  if (configured === undefined) return undefined;
  const result: { scm?: SCMReadProvider; forensicsSCM?: NonNullable<ForensicsProviderSet["scm"]>; telemetry?: ForensicsProviderSet["telemetry"] } = {};
  if (configured.scm?.enabled === true) {
    const type = configured.scm.provider ?? configuration.type;
    if (type !== configuration.type) throw new Error("Invalid CI runtime configuration");
    const selected = type === "github" ? configuration.github : type === "jenkins" ? configuration.jenkins : configuration.bitbucket;
    const baseUrl = configured.scm.endpoint === undefined
      ? configured.scm.base_url ?? providerBaseUrl(selected)
      : new URL(configured.scm.endpoint.path, configured.scm.endpoint.origin).toString();
    if (baseUrl === undefined) throw new Error("Invalid CI runtime configuration");
    const allowedRefs = configured.scm.allowed_refs;
    const bitbucketTokenFile = configured.scm.token_file ?? configuration.bitbucket?.token_file;
    const scmAdapter = type === "github"
      ? new GitHubSCMProvider({ tokenProvider: buildGitHubReadTokenProvider(configuration, repositories, options, clock), fetch: options.fetch, clock, apiBaseUrl: baseUrl, allowedRepositories: repositories, allowedRefs })
      : type === "jenkins"
        ? configured.scm.job === undefined
          ? (() => { throw new Error("Invalid CI runtime configuration"); })()
          : new JenkinsSCMProvider({ baseUrl, job: configured.scm.job, ...(configured.scm.branch === undefined ? {} : { branch: configured.scm.branch }), ...(configured.scm.token_file === undefined ? {} : { tokenFile: configured.scm.token_file }), ...(configured.scm.username === undefined ? {} : { username: configured.scm.username }), fetch: options.fetch, clock, allowedRepositories: repositories, allowedRefs })
        : new BitbucketSCMProvider({ baseUrl, ...(bitbucketTokenFile === undefined ? {} : { tokenFile: bitbucketTokenFile }), ...(configured.scm.username === undefined ? {} : { username: configured.scm.username }), fetch: options.fetch, clock, allowedRepositories: repositories, allowedRefs });
    result.scm = scmAdapter;
    result.forensicsSCM = wrapSCMProvider(scmAdapter);
  }
  if (configured.telemetry?.enabled === true) {
    if (observabilityProvider === undefined) throw new Error("Invalid CI runtime configuration");
    const telemetry = configured.telemetry;
    result.telemetry = {
      async getTelemetryCorrelation(_input) {
        const metrics = await observabilityProvider.queryMetrics({ queryTemplate: telemetry.query_template });
        const signals = metrics.data.series.slice(0, 20).map((series, index) => ({
          id: `metric-${index + 1}`,
          kind: "metric" as const,
          state: series.samples.length === 0 ? "unknown" as const : "normal" as const,
          summary: "Configured metrics evidence available",
          observedAt: metrics.observedAt,
        }));
        return {
          schemaVersion: "1.0" as const,
          observedAt: metrics.observedAt,
          providerClass: metrics.providerClass,
          freshness: metrics.freshness,
          truncated: metrics.truncated || metrics.data.series.length > signals.length,
          redactionsApplied: metrics.redactionsApplied,
          warnings: metrics.warnings,
          data: signals.length === 0
            ? { available: false as const, unavailable: { code: "no-metrics", message: "Configured metrics evidence unavailable" } }
            : { available: true as const, signals },
        };
      },
    };
  }
  if (result.scm === undefined && result.telemetry === undefined) return undefined;
  const forensics = result.forensicsSCM === undefined && result.telemetry === undefined
    ? undefined
    : {
        ...(result.forensicsSCM === undefined ? {} : { scm: result.forensicsSCM }),
        ...(result.telemetry === undefined ? {} : { telemetry: result.telemetry }),
      };
  return {
    ...(result.scm === undefined ? {} : { scm: result.scm }),
    ...(forensics === undefined ? {} : { forensics }),
  };
}

function providerBaseUrl(configuration: unknown): string | undefined {
  if (configuration === null || typeof configuration !== "object") return undefined;
  const value = configuration as Record<string, unknown>;
  const endpoint = value.api_endpoint ?? value.endpoint;
  if (endpoint !== null && typeof endpoint === "object" && !Array.isArray(endpoint)) {
    const configured = endpoint as { origin?: unknown; path?: unknown };
    if (typeof configured.origin === "string" && typeof configured.path === "string") return new URL(configured.path, configured.origin).toString();
  }
  const baseUrl = value.api_base_url ?? value.base_url;
  return typeof baseUrl === "string" ? baseUrl : undefined;
}

function wrapSCMProvider(adapter: {
  getChangeEvidence(input: Parameters<SCMReadProvider["getChangeEvidence"]>[0]): Promise<unknown>;
}): NonNullable<ForensicsProviderSet["scm"]> {
  return {
    async getChangeEvidence(input) {
      const raw = SCMAdapterResultSchema.parse(await adapter.getChangeEvidence({
        repository: input.repo,
        commit: input.headSha,
        budget: {
          maxBytes: 512 * 1_024,
          maxFiles: input.maxChanges,
          maxHunks: input.maxChanges,
          maxLines: input.maxHunkLines,
          maxProviderRequests: 4,
          maxDurationMs: 10_000,
        },
      }));
      const changes = raw.data.files.slice(0, input.maxChanges).map((file) => ({
        path: file.path,
        changeType: file.status === "removed" ? "deleted" as const : file.status === "renamed" ? "renamed" as const : file.status === "added" ? "added" as const : "modified" as const,
        additions: file.additions,
        deletions: file.deletions,
        hunks: file.patch === undefined ? [] : [{
          header: "@@",
          lines: file.patch.split(/\r?\n/).slice(0, input.maxHunkLines),
        }],
      }));
      return ForensicsSCMResultSchema.parse({
        schemaVersion: "1.0",
        observedAt: raw.observedAt,
        providerClass: raw.providerClass,
        freshness: raw.freshness,
        truncated: raw.truncated || raw.data.files.length > changes.length,
        redactionsApplied: raw.redactionsApplied,
        warnings: raw.warnings,
        data: changes.length === 0
          ? { available: false, unavailable: { code: "no-changes", message: "Configured SCM evidence unavailable" } }
          : { available: true, changes },
      });
    },
  };
}

function buildGitHubReadTokenProvider(
  configuration: ResolvedCIProviderConfiguration,
  repositories: readonly string[],
  options: LoadRuntimeConfigurationOptions,
  clock: Clock,
) {
  const github = configuration.github;
  const app = github?.app;
  if (github === undefined || app === undefined) throw new Error("Invalid CI runtime configuration");
  return app.installations !== undefined
    ? MappedGitHubAppTokenProvider.fromFiles({
        appIdFile: app.app_id_file,
        pemKeyFile: app.pem_key_file,
        installations: app.installations.map((entry) => "repo" in entry ? { repo: entry.repo, installationIdFile: entry.installation_id_file } : { owner: entry.owner, installationIdFile: entry.installation_id_file }),
        repositories,
        fetch: options.fetch,
        clock,
        ...(github.api_endpoint === undefined ? { apiBaseUrl: github.api_base_url ?? "https://api.github.com" } : { apiEndpoint: github.api_endpoint }),
        actionsPermission: "read",
      })
    : GitHubAppTokenProvider.fromPemFile({
        appId: readNumericSecretFile(app.app_id_file),
        installationId: readNumericSecretFile(app.installation_id_file ?? ""),
        pemKeyFile: app.pem_key_file,
        allowedRepositories: repositories,
        fetch: options.fetch,
        clock,
        ...(github.api_endpoint === undefined ? { apiBaseUrl: github.api_base_url ?? "https://api.github.com" } : { apiEndpoint: github.api_endpoint }),
        actionsPermission: "read",
      });
}

function buildGitHubProvider(
  configuration: ResolvedCIProviderConfiguration,
  repositories: readonly string[],
  options: LoadRuntimeConfigurationOptions,
  clock: Clock,
  maxFreshnessSeconds: number,
): GitHubActionsProvider {
  if (configuration.github === undefined) throw new Error("Invalid CI runtime configuration");
  const app = configuration.github.app;
  const readTokenProvider = app === undefined
    ? undefined
    : app.installations !== undefined
      ? MappedGitHubAppTokenProvider.fromFiles({
          appIdFile: app.app_id_file,
          pemKeyFile: app.pem_key_file,
          installations: app.installations.map((entry) => "repo" in entry
            ? { repo: entry.repo, installationIdFile: entry.installation_id_file }
            : { owner: entry.owner, installationIdFile: entry.installation_id_file }),
          repositories,
          fetch: options.fetch,
          clock,
          ...(configuration.github.api_endpoint === undefined
            ? { apiBaseUrl: configuration.github.api_base_url ?? "https://api.github.com" }
            : { apiEndpoint: configuration.github.api_endpoint }),
          actionsPermission: "read",
        })
      : GitHubAppTokenProvider.fromPemFile({
          appId: readNumericSecretFile(app.app_id_file),
          installationId: readNumericSecretFile(app.installation_id_file ?? ""),
          pemKeyFile: app.pem_key_file,
          allowedRepositories: repositories,
          fetch: options.fetch,
          clock,
          ...(configuration.github.api_endpoint === undefined
            ? { apiBaseUrl: configuration.github.api_base_url ?? "https://api.github.com" }
            : { apiEndpoint: configuration.github.api_endpoint }),
          actionsPermission: "read",
        });
  const writeTokenProvider = app === undefined
    ? undefined
    : app.installations !== undefined
      ? MappedGitHubAppTokenProvider.fromFiles({
          appIdFile: app.app_id_file,
          pemKeyFile: app.pem_key_file,
          installations: app.installations.map((entry) => "repo" in entry
            ? { repo: entry.repo, installationIdFile: entry.installation_id_file }
            : { owner: entry.owner, installationIdFile: entry.installation_id_file }),
          repositories,
          fetch: options.fetch,
          clock,
          ...(configuration.github.api_endpoint === undefined
            ? { apiBaseUrl: configuration.github.api_base_url ?? "https://api.github.com" }
            : { apiEndpoint: configuration.github.api_endpoint }),
          actionsPermission: "write",
        })
      : GitHubAppTokenProvider.fromPemFile({
          appId: readNumericSecretFile(app.app_id_file),
          installationId: readNumericSecretFile(app.installation_id_file ?? ""),
          pemKeyFile: app.pem_key_file,
          allowedRepositories: repositories,
          fetch: options.fetch,
          clock,
          ...(configuration.github.api_endpoint === undefined
            ? { apiBaseUrl: configuration.github.api_base_url ?? "https://api.github.com" }
            : { apiEndpoint: configuration.github.api_endpoint }),
          actionsPermission: "write",
        });
  if (readTokenProvider === undefined || writeTokenProvider === undefined) throw new Error("CI runtime configuration requires a GitHub App or token file");
  return new GitHubActionsProvider({
    tokenProvider: readTokenProvider,
    writeTokenProvider,
    fetch: options.fetch,
    ...(options.clock === undefined ? {} : { clock }),
    ...(configuration.github.api_endpoint === undefined
      ? { apiBaseUrl: configuration.github.api_base_url ?? "https://api.github.com" }
      : { endpoint: configuration.github.api_endpoint }),
    maxFreshnessMs: maxFreshnessSeconds * 1_000,
    providerName: configuration.name,
  });
}

function readNumericSecretFile(path: string): string {
  const value = readBoundedFile(path, true).trim();
  if (!/^\d+$/.test(value)) throw new Error("Invalid CI runtime configuration");
  return value;
}

function readBoundedFile(path: string, secret: boolean): string {
  const metadata = statSync(path);
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_CONFIG_BYTES) {
    throw new Error(secret ? "Invalid secret file" : "Invalid runtime configuration");
  }
  if (secret && (metadata.mode & 0o077) !== 0) {
    throw new Error("Secret file permissions are too broad");
  }
  return readFileSync(path, "utf8");
}
