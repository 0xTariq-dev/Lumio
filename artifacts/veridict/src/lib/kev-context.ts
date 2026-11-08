import snapshot from './kev-snapshot.json' with { type: 'json' };

export type SoftwareEvidence = {
  product: string;
  version?: string | null;
  evidenceStrength: 'strong' | 'weak' | 'ambiguous';
  evidenceSource:
    | 'html_generator_and_wp_asset_path'
    | 'html_generator_only'
    | 'wp_asset_path_only';
};

type AffectedRange = {
  from: string;
  through?: string;
  lessThan?: string;
};

export type KevEntry = {
  cveId: string;
  product: string;
  summary: string;
  affectedRanges: AffectedRange[];
  kevStatus: string;
  kevDate: string;
  fixedVersion: string;
  branchNote: string;
  cisaUrl: string;
  cveRecordUrl: string;
  vendorAdvisoryUrl: string;
};

export type KevSnapshot = {
  version: string;
  checkedAt: string;
  cisaReleasedAt: string;
  entries: KevEntry[];
};
export const LOCAL_KEV_SNAPSHOT = snapshot as KevSnapshot;
export const KEV_SNAPSHOT_MAX_AGE_DAYS = 30;

export type KevContextResult = {
  status: 'matched' | 'no-match' | 'insufficient';
  evidence?: SoftwareEvidence;
  matches: KevEntry[];
  reason?: 'missing' | 'weak' | 'ambiguous' | 'unknown-version';
  snapshotStale: boolean;
  snapshotAgeDays: number | null;
};

function compareVersions(left: string, right: string): number | null {
  const pattern = /^\d+\.\d+\.\d+$/;
  if (!pattern.test(left) || !pattern.test(right)) return null;

  const leftParts = left.split('.').map(Number);
  const rightParts = right.split('.').map(Number);
  if (
    [...leftParts, ...rightParts].some(
      (part) => !Number.isSafeInteger(part) || part < 0,
    )
  ) {
    return null;
  }

  for (let index = 0; index < 3; index += 1) {
    const difference = leftParts[index] - rightParts[index];
    if (difference !== 0) return difference;
  }
  return 0;
}

export function matchKevContext(
  evidence: SoftwareEvidence[] | undefined,
  source: KevSnapshot = LOCAL_KEV_SNAPSHOT,
  now: Date = new Date(),
): KevContextResult {
  const checkedAt = Date.parse(source.checkedAt);
  const cisaReleasedAt = Date.parse(source.cisaReleasedAt);
  const validDates = Number.isFinite(checkedAt) && Number.isFinite(cisaReleasedAt);
  const oldestSourceDate = validDates
    ? Math.min(checkedAt, cisaReleasedAt)
    : Number.POSITIVE_INFINITY;
  const ageMs = Number.isFinite(oldestSourceDate)
    ? Math.max(0, now.getTime() - oldestSourceDate)
    : Number.POSITIVE_INFINITY;
  const snapshotAgeDays = Number.isFinite(ageMs)
    ? Math.floor(ageMs / (24 * 60 * 60 * 1000))
    : null;
  const snapshotStale =
    snapshotAgeDays === null ||
    ageMs > KEV_SNAPSHOT_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
  const result = (
    status: KevContextResult['status'],
    details: {
      evidence?: SoftwareEvidence;
      matches?: KevEntry[];
      reason?: KevContextResult['reason'];
    } = {},
  ): KevContextResult => ({
    status,
    matches: [],
    ...details,
    snapshotStale,
    snapshotAgeDays,
  });

  if (!evidence?.length) {
    return result('insufficient', { matches: [], reason: 'missing' });
  }

  if (evidence.length !== 1) {
    return result('insufficient', { matches: [], reason: 'ambiguous' });
  }

  const observed = evidence[0];
  if (observed.evidenceStrength !== 'strong') {
    return result('insufficient', {
      evidence: observed,
      matches: [],
      reason: observed.evidenceStrength === 'ambiguous' ? 'ambiguous' : 'weak',
    });
  }

  if (!observed.version || !/^\d+\.\d+\.\d+$/.test(observed.version)) {
    return result('insufficient', {
      evidence: observed,
      matches: [],
      reason: 'unknown-version',
    });
  }

  const matchingEntries = source.entries.filter((entry) => {
    if (entry.product !== observed.product) return false;
    return entry.affectedRanges.some((range) => {
      const afterStart = compareVersions(observed.version!, range.from);
      const upperBound = range.lessThan ?? range.through;
      const beforeEnd = upperBound ? compareVersions(observed.version!, upperBound) : null;
      if (afterStart === null || beforeEnd === null || afterStart < 0) return false;
      return range.lessThan ? beforeEnd < 0 : beforeEnd <= 0;
    });
  });

  return result(matchingEntries.length ? 'matched' : 'no-match', {
    evidence: observed,
    matches: matchingEntries,
  });
}

export function kevStatusLabel(result: KevContextResult) {
  if (result.snapshotStale) {
    return result.status === 'matched'
      ? 'Possible match in a stale local snapshot'
      : 'Local vulnerability data is stale';
  }
  if (result.status === 'matched') return 'Possible match in the local snapshot';
  if (result.status === 'no-match') return 'No matching entry in this snapshot';
  if (result.reason === 'weak') return 'Evidence was too weak to match';
  if (result.reason === 'ambiguous') return 'Evidence was ambiguous, so no match was made';
  if (result.reason === 'unknown-version') return 'No exact version was available for matching';
  return 'No product and version evidence was available';
}

export function evidenceSourceLabel(source: SoftwareEvidence['evidenceSource']) {
  switch (source) {
    case 'html_generator_and_wp_asset_path':
      return 'HTML generator metadata and same-origin WordPress asset path';
    case 'html_generator_only':
      return 'HTML generator metadata only';
    case 'wp_asset_path_only':
      return 'Same-origin WordPress asset path only';
  }
}
