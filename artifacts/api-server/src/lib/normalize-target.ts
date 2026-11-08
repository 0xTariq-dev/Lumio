import { isIP } from "node:net";

const MAX_TARGET_LENGTH = 2048;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const EXPLICIT_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Normalize user-supplied domains and IPs to HTTPS before URL policy checks.
 * Absolute HTTP(S) URLs retain their requested scheme.
 */
export function normalizeScanTargetInput(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const input = value.trim();
  if (
    !input ||
    input.length > MAX_TARGET_LENGTH ||
    CONTROL_CHARACTERS.test(input) ||
    input.startsWith("//")
  ) {
    return undefined;
  }

  let candidate = input;
  if (EXPLICIT_SCHEME.test(input)) {
    if (!/^https?:\/\//i.test(input)) return undefined;
  } else {
    const delimiter = input.search(/[/?#]/);
    const host = delimiter < 0 ? input : input.slice(0, delimiter);
    const suffix = delimiter < 0 ? "/" : input.slice(delimiter);
    const unwrappedHost =
      host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;

    if (isIP(unwrappedHost) === 6) {
      const ipv6Authority = host.startsWith("[") ? host : `[${host}]`;
      candidate = `https://${ipv6Authority}${suffix}`;
    } else {
      if (host.includes(":")) return undefined;
      candidate = `https://${input}`;
    }
  }

  try {
    const url = new URL(candidate);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      (url.port && url.port !== (url.protocol === "https:" ? "443" : "80"))
    ) {
      return undefined;
    }
    const normalized = url.toString();
    return normalized.length <= MAX_TARGET_LENGTH ? normalized : undefined;
  } catch {
    return undefined;
  }
}
