const SECRET_PATTERNS: readonly RegExp[] = [
  /(?:authorization|token|password|secret|api[_-]?key)\s*[:=]\s*(?:(?:Bearer|Basic)\s+)?[^\s,;]+/gi,
  /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /\b(?:gh[pousr]_\w+|github_pat_\w+|glpat-\w+)/gi,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]+\b/g,
  /\b[A-Z][A-Z0-9_]*(?:TOKEN|PASSWORD|SECRET|API_KEY|ACCESS_KEY(?:_ID)?)\s*[:=]\s*[^\s,;]+/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /https?:\/\/[^\s/@]+:[^\s/@]+@/gi,
];

export interface RedactedText {
  readonly text: string;
  /** True when a secret was replaced or the value was shortened. */
  readonly redacted: boolean;
  /** True only when a secret pattern was replaced. */
  readonly redactionsApplied: boolean;
  readonly truncated: boolean;
}

export function redactText(input: string, maxLength = 1_024): RedactedText {
  let text = input;
  let redactionsApplied = false;
  for (const pattern of SECRET_PATTERNS) {
    const next = text.replace(pattern, "[REDACTED]");
    redactionsApplied ||= next !== text;
    text = next;
  }
  let truncated = false;
  if (text.length > maxLength) {
    text = `${text.slice(0, Math.max(0, maxLength - 15))}...[TRUNCATED]`;
    truncated = true;
  }
  return { text, redacted: redactionsApplied || truncated, redactionsApplied, truncated };
}

export function redactMetadata(value: unknown): unknown {
  if (typeof value === "string") return redactText(value, 512).text;
  if (Array.isArray(value)) return value.slice(0, 20).map(redactMetadata);
  if (value !== null && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value).slice(0, 40)) {
      output[redactText(key, 64).text] = redactMetadata(child);
    }
    return output;
  }
  return value;
}
