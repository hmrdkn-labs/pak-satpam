import {
  CIProviderDescriptorSchema,
  CIProviderNameSchema,
  supportsCIProviderCapability,
  type CIProviderCapability,
  type CIProviderCapabilities,
  type CIProviderDescriptor,
  type CIProviderKind,
  type CIProviderName,
} from "../domain/ci-provider-contracts.js";
import {
  CIUnsupportedCapabilityError,
  type CIReadProvider,
  type CIRerunProvider,
  type ForensicsProviderSet,
} from "./ci-provider.js";
import type { SCMReadProvider } from "../scm/provider.js";

const REQUIRED_READ_PORTS = [
  "getWorkflowStatus",
  "getFailedJobAnalysis",
  "getLogEvidence",
  "getRemediationPlan",
] as const satisfies readonly (keyof CIReadProvider)[];

export function hasCIReadPorts(provider: unknown): provider is CIReadProvider {
  if (provider === null || typeof provider !== "object") return false;
  return REQUIRED_READ_PORTS.every((port) => typeof (provider as Record<string, unknown>)[port] === "function");
}

export type CIProviderImplementation = CIReadProvider & Partial<CIRerunProvider>;

export interface CIProviderRegistration {
  readonly name: CIProviderName;
  readonly kind: CIProviderKind;
  readonly capabilities: CIProviderCapabilities;
  readonly provider: CIProviderImplementation;
  readonly endpoint?: CIProviderDescriptor["endpoint"];
  readonly scm?: SCMReadProvider;
  readonly forensics?: ForensicsProviderSet;
}

/** Named provider registry with capability checks at the contract boundary. */
export class CIProviderRegistry {
  readonly #providers: ReadonlyMap<CIProviderName, CIProviderRegistration>;

  constructor(registrations: readonly CIProviderRegistration[]) {
    const providers = new Map<CIProviderName, CIProviderRegistration>();
    for (const registration of registrations) {
      const descriptor = CIProviderDescriptorSchema.parse({
        name: registration.name,
        kind: registration.kind,
        capabilities: registration.capabilities,
        ...(registration.endpoint === undefined ? {} : { endpoint: registration.endpoint }),
      });
      if (providers.has(descriptor.name)) throw new Error(`Duplicate CI provider name: ${descriptor.name}`);
      if (descriptor.capabilities.read && !hasCIReadPorts(registration.provider)) {
        const missing = REQUIRED_READ_PORTS.find((port) => typeof (registration.provider as unknown as Record<string, unknown>)[port] !== "function");
        throw new Error(`CI provider ${descriptor.name} declares read without port ${missing ?? "unknown"}`);
      }
      if (
        descriptor.capabilities.rerun === "approval-gated" &&
        typeof registration.provider.rerunFailedWorkflow !== "function"
      ) {
        throw new Error(`CI provider ${descriptor.name} declares rerun without a rerun port`);
      }
      providers.set(descriptor.name, Object.freeze({
        ...registration,
        name: descriptor.name,
        kind: descriptor.kind,
        capabilities: descriptor.capabilities,
        ...(descriptor.endpoint === undefined ? {} : { endpoint: descriptor.endpoint }),
      }));
    }
    this.#providers = providers;
  }

  get size(): number {
    return this.#providers.size;
  }

  has(name: string): boolean {
    return this.#providers.has(name);
  }

  get(name: string): CIProviderRegistration | undefined {
    return this.#providers.get(name);
  }

  /** Resolve the explicitly selected provider without selecting by iteration order. */
  select(name: string): CIProviderRegistration {
    const providerName = CIProviderNameSchema.parse(name);
    const registration = this.#providers.get(providerName);
    if (registration === undefined) throw new CIUnsupportedCapabilityError(providerName, "read");
    return registration;
  }

  list(): readonly CIProviderDescriptor[] {
    return [...this.#providers.values()].map(({ name, kind, capabilities, endpoint }) => ({
      name,
      kind,
      capabilities,
      ...(endpoint === undefined ? {} : { endpoint }),
    }));
  }

  supports(name: string, capability: CIProviderCapability): boolean {
    const registration = this.#providers.get(name);
    return registration !== undefined && supportsCIProviderCapability(registration.capabilities, capability);
  }

  require(name: string, capability: CIProviderCapability): CIProviderImplementation {
    const providerName = CIProviderNameSchema.parse(name);
    const registration = this.#providers.get(providerName);
    if (registration === undefined || !supportsCIProviderCapability(registration.capabilities, capability)) {
      throw new CIUnsupportedCapabilityError(providerName, capability);
    }
    return registration.provider;
  }

  requireRead(name: string): CIReadProvider {
    return this.require(name, "read");
  }

  requireRerun(name: string): CIRerunProvider {
    const provider = this.require(name, "rerun");
    if (typeof provider.rerunFailedWorkflow !== "function") {
      const providerName = CIProviderNameSchema.parse(name);
      throw new CIUnsupportedCapabilityError(providerName, "rerun");
    }
    return provider as CIRerunProvider;
  }

  async invokeRead<T>(name: string, operation: (provider: CIReadProvider) => Promise<T>): Promise<T> {
    return operation(this.requireRead(name));
  }

  async invokeRerun<T>(name: string, operation: (provider: CIRerunProvider) => Promise<T>): Promise<T> {
    return operation(this.requireRerun(name));
  }
}
