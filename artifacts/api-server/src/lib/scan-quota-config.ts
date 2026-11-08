export const SCAN_LIMITS = {
  startsPerMinute: 2,
  startsPerDay: 15,
  lifetimeStartsPerIp: 15,
} as const;

/**
 * The environment switch controls the per-client daily and lifetime caps.
 * The per-minute burst guard remains enabled regardless of this setting.
 * Only an explicit "false" disables the caps, so missing or invalid values
 * fail closed.
 */
export function areScanQuotaLimitsEnabled(
  value: string | undefined = process.env.SCAN_QUOTA_LIMITS_ENABLED,
): boolean {
  return value?.trim().toLowerCase() !== "false";
}
