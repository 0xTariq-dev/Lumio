import { rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_CVE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const OUTPUT_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../src/lib/kev-snapshot.json',
);
const REQUEST_TIMEOUT_MS = 20_000;
const NO_KEY_DELAY_MS = 6_500;
const NVD_API_KEY = process.env.NVD_API_KEY;
const USER_AGENT = 'Lumio-KEV-refresh/1.0';

function isAllowedVendorAdvisoryUrl(value) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:') return false;
    if (parsed.hostname === 'wordpress.org') return true;
    return parsed.hostname === 'github.com' &&
      /^\/WordPress\/wordpress-develop\/security\/advisories\/[A-Za-z0-9-]+\/?$/.test(parsed.pathname);
  } catch {
    return false;
  }
}

async function getJson(url, headers = {}) {
  const response = await fetch(url, {
    headers: { accept: 'application/json', 'user-agent': USER_AGENT, ...headers },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`Source request failed with HTTP ${response.status}`);
  return response.json();
}

function cisaCoreEntries(catalog) {
  if (!Array.isArray(catalog.vulnerabilities) || typeof catalog.dateReleased !== 'string') {
    throw new Error('CISA KEV catalog shape is invalid');
  }
  return catalog.vulnerabilities.filter((item) => {
    const vendor = String(item.vendorProject ?? '').toLowerCase();
    const product = String(item.product ?? '').toLowerCase();
    return vendor === 'wordpress' && (product === 'core' || product === 'wordpress core');
  });
}

function versionRanges(cve) {
  const ranges = [];
  for (const affectedProduct of cve.affected ?? []) {
    for (const product of affectedProduct.affectedData ?? []) {
      const vendor = String(product.vendor ?? '').toLowerCase();
      const name = String(product.product ?? '').toLowerCase();
      if (!vendor.includes('wordpress') && !name.includes('wordpress')) continue;
      for (const version of product.versions ?? []) {
        if (version.status !== 'affected' || version.versionType !== 'semver') continue;
        const range = {
          from: version.version === '0' ? '0.0.0' : version.version,
        };
        if (version.lessThan) range.lessThan = version.lessThan;
        else if (version.lessThanOrEqual) range.through = version.lessThanOrEqual;
        else range.through = range.from;
        if (/^\d+\.\d+\.\d+$/.test(range.from) &&
            (range.through ? /^\d+\.\d+\.\d+$/.test(range.through) : /^\d+\.\d+\.\d+$/.test(range.lessThan))) {
          ranges.push(range);
        }
      }
    }
  }
  const unique = new Map(ranges.map((range) => [`${range.from}|${range.through ?? ''}|${range.lessThan ?? ''}`, range]));
  return [...unique.values()];
}

function vendorAdvisory(cisaEntry, cve) {
  const references = (cve.references ?? [])
    .filter((item) => Array.isArray(item.tags) && item.tags.includes('Vendor Advisory'))
    .map((item) => item.url)
    .filter(isAllowedVendorAdvisoryUrl);
  const cisaNotes = String(cisaEntry.notes ?? '')
    .match(/https:\/\/[^\s;,"<>]+/g) ?? [];
  const preferred = [
    ...references,
    ...cisaNotes.filter(isAllowedVendorAdvisoryUrl),
  ];
  return preferred.find(isAllowedVendorAdvisoryUrl) ?? `https://nvd.nist.gov/vuln/detail/${cisaEntry.cveID}`;
}

function releaseReference(notes) {
  const value = String(notes ?? '');
  const match = value.match(/wordpress[-/](\d+\.\d+\.\d+)/i);
  return match ? `${match[1]} (release reference; verify branch-specific backports)` : '';
}

async function nvdRecord(cveId, index) {
  if (index > 0) await new Promise((resolveDelay) =>
    setTimeout(resolveDelay, NVD_API_KEY ? 500 : NO_KEY_DELAY_MS),
  );
  const headers = NVD_API_KEY ? { apiKey: NVD_API_KEY } : {};
  const url = new URL(NVD_CVE_URL);
  url.searchParams.set('cveId', cveId);
  const result = await getJson(url, headers);
  const cve = result.vulnerabilities?.[0]?.cve;
  if (result.totalResults !== 1 || !cve || cve.id !== cveId) {
    throw new Error(`NVD did not return one record for ${cveId}`);
  }
  return cve;
}

function entryFromSources(cisaEntry, cve) {
  const description = cve.descriptions?.find((item) => item.lang === 'en')?.value;
  const affectedRanges = versionRanges(cve);
  if (!description || affectedRanges.length === 0) {
    throw new Error(`Required NVD description or affected ranges are missing for ${cve.id}`);
  }
  const boundaries = [...new Set(affectedRanges.map((range) => range.lessThan).filter(Boolean))].sort();
  const cveRecordUrl = `https://nvd.nist.gov/vuln/detail/${cve.id}`;
  const cisaUrl = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${encodeURIComponent(cve.id)}`;
  const release = releaseReference(cisaEntry.notes);
  const fixedVersion = [
    release ? `Vendor release reference: ${release}` : '',
    boundaries.length ? `NVD unaffected-range boundaries: ${boundaries.join(', ')}` : '',
  ].filter(Boolean).join('; ') ||
    'No single fixed release is listed; consult the vendor advisory.';
  return {
    cveId: cve.id,
    product: 'WordPress',
    summary: description.slice(0, 800),
    affectedRanges,
    kevStatus: 'Listed in CISA Known Exploited Vulnerabilities Catalog',
    kevDate: cisaEntry.dateAdded,
    fixedVersion,
    branchNote: 'Version fingerprints cannot reveal vendor backports. This is possible, unverified context; confirm the installed branch with the vendor.',
    cisaUrl,
    cveRecordUrl,
    vendorAdvisoryUrl: vendorAdvisory(cisaEntry, cve),
  };
}

async function main() {
  const catalog = await getJson(CISA_KEV_URL);
  if (!Number.isFinite(Date.parse(catalog.dateReleased))) {
    throw new Error('CISA KEV release date is invalid');
  }
  const cisaEntries = cisaCoreEntries(catalog);
  if (cisaEntries.length === 0) throw new Error('CISA KEV contains no WordPress Core entries');
  const entries = [];
  for (const [index, item] of cisaEntries.entries()) {
    if (!/^CVE-\d{4}-\d{4,}$/.test(String(item.cveID ?? ''))) {
      throw new Error('CISA KEV contains an invalid CVE identifier');
    }
    const cve = await nvdRecord(item.cveID, index);
    entries.push(entryFromSources(item, cve));
  }
  const checkedAt = new Date().toISOString();
  const snapshot = {
    version: checkedAt.slice(0, 10),
    checkedAt,
    cisaReleasedAt: catalog.dateReleased,
    entries: entries.sort((left, right) => left.cveId.localeCompare(right.cveId)),
  };
  const serialized = `${JSON.stringify(snapshot, null, 2)}\n`;
  const temporaryPath = `${OUTPUT_PATH}.tmp`;
  await writeFile(temporaryPath, serialized, { mode: 0o644 });
  await rename(temporaryPath, OUTPUT_PATH);
  process.stdout.write(`Updated local KEV snapshot: ${entries.length} WordPress Core entries; CISA feed ${catalog.dateReleased}.\n`);
}

main().catch((error) => {
  process.stderr.write(`KEV refresh failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
  process.exitCode = 1;
});
