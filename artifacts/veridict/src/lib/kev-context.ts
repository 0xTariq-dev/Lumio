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
  through: string;
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

export const LOCAL_KEV_SNAPSHOT: {
  version: string;
  checkedAt: string;
  entries: KevEntry[];
} = {
  version: '2026-11-08',
  checkedAt: '2026-11-08',
  entries: [
    {
      cveId: 'CVE-2026-119977',
      product: 'WordPress',
      summary:
        'WordPress Core has a remote-code-execution vulnerability during the upgrade window.',
      affectedRanges: [
        { from: '4.7.0', through: '4.7.38' },
        { from: '4.8.0', through: '4.8.33' },
        { from: '4.9.0', through: '4.9.34' },
        { from: '5.0.0', through: '5.0.30' },
        { from: '5.1.0', through: '5.1.27' },
        { from: '5.2.0', through: '5.2.29' },
        { from: '5.3.0', through: '5.3.26' },
        { from: '5.4.0', through: '5.4.24' },
        { from: '5.5.0', through: '5.5.23' },
        { from: '5.6.0', through: '5.6.22' },
        { from: '5.7.0', through: '5.7.20' },
        { from: '5.8.0', through: '5.8.18' },
        { from: '5.9.0', through: '5.9.19' },
        { from: '6.0.0', through: '6.0.17' },
        { from: '6.1.0', through: '6.1.15' },
        { from: '6.2.0', through: '6.2.14' },
        { from: '6.3.0', through: '6.3.13' },
        { from: '6.4.0', through: '6.4.13' },
        { from: '6.5.0', through: '6.5.13' },
        { from: '6.6.0', through: '6.6.10' },
        { from: '6.7.0', through: '6.7.10' },
        { from: '6.8.0', through: '6.8.11' },
        { from: '6.9.0', through: '6.9.10' },
        { from: '7.0.0', through: '7.0.7' },
        { from: '7.1.0', through: '7.1.3' },
      ],
      kevStatus: 'Listed in CISA Known Exploited Vulnerabilities Catalog',
      kevDate: '2026-11-03',
      fixedVersion: '7.1.4',
      branchNote:
        'The vendor advisory notes security backports for eligible branches; confirm the fixed release for the installed branch.',
      cisaUrl:
        'https://www.cisa.gov/news-events/alerts/2026/11/03/cisa-adds-one-known-exploited-vulnerability-catalog',
      cveRecordUrl: 'https://cveawg.mitre.org/api/cve/CVE-2026-119977',
      vendorAdvisoryUrl: 'https://wordpress.org/news/2026/10/wordpress-7-1-4/',
    },
  ],
};

export type KevContextResult = {
  status: 'matched' | 'no-match' | 'insufficient';
  evidence?: SoftwareEvidence;
  matches: KevEntry[];
  reason?: 'missing' | 'weak' | 'ambiguous' | 'unknown-version';
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
): KevContextResult {
  if (!evidence?.length) {
    return { status: 'insufficient', matches: [], reason: 'missing' };
  }

  if (evidence.length !== 1) {
    return { status: 'insufficient', matches: [], reason: 'ambiguous' };
  }

  const observed = evidence[0];
  if (observed.evidenceStrength !== 'strong') {
    return {
      status: 'insufficient',
      evidence: observed,
      matches: [],
      reason: observed.evidenceStrength === 'ambiguous' ? 'ambiguous' : 'weak',
    };
  }

  if (!observed.version || !/^\d+\.\d+\.\d+$/.test(observed.version)) {
    return {
      status: 'insufficient',
      evidence: observed,
      matches: [],
      reason: 'unknown-version',
    };
  }

  const matchingEntries = LOCAL_KEV_SNAPSHOT.entries.filter((entry) => {
    if (entry.product !== observed.product) return false;
    return entry.affectedRanges.some((range) => {
      const afterStart = compareVersions(observed.version!, range.from);
      const beforeEnd = compareVersions(observed.version!, range.through);
      return afterStart !== null && beforeEnd !== null && afterStart >= 0 && beforeEnd <= 0;
    });
  });

  return {
    status: matchingEntries.length ? 'matched' : 'no-match',
    evidence: observed,
    matches: matchingEntries,
  };
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
