import assert from 'node:assert/strict';
import test from 'node:test';
import {
  KEV_SNAPSHOT_MAX_AGE_DAYS,
  LOCAL_KEV_SNAPSHOT,
  kevStatusLabel,
  matchKevContext,
} from './kev-context.ts';

const strong = (version) => ({
  product: 'WordPress',
  version,
  evidenceStrength: 'strong',
  evidenceSource: 'html_generator_and_wp_asset_path',
});

test('matches an exact strong version inside a listed affected range', () => {
  const result = matchKevContext([strong('7.1.3')]);

  assert.equal(result.status, 'matched');
  assert.equal(result.matches[0].cveId, 'CVE-2026-119977');
});

test('does not match an exact strong version outside listed ranges', () => {
  const result = matchKevContext([strong('7.1.4')]);

  assert.equal(result.status, 'no-match');
  assert.deepEqual(result.matches, []);
});

test('does not match when the version is unknown', () => {
  const result = matchKevContext([strong(null)]);

  assert.equal(result.status, 'insufficient');
  assert.equal(result.reason, 'unknown-version');
});

test('does not match weak or ambiguous evidence', () => {
  const weak = matchKevContext([
    {
      ...strong('7.1.3'),
      evidenceStrength: 'weak',
      evidenceSource: 'html_generator_only',
    },
  ]);
  const ambiguous = matchKevContext([
    {
      ...strong(null),
      evidenceStrength: 'ambiguous',
    },
  ]);

  assert.equal(weak.status, 'insufficient');
  assert.equal(weak.reason, 'weak');
  assert.equal(ambiguous.status, 'insufficient');
  assert.equal(ambiguous.reason, 'ambiguous');
});

test('uses an exclusive NVD upper version boundary correctly', () => {
  const snapshot = {
    ...LOCAL_KEV_SNAPSHOT,
    entries: [{
      ...LOCAL_KEV_SNAPSHOT.entries[0],
      affectedRanges: [{ from: '6.9.0', lessThan: '6.9.5' }],
    }],
  };
  assert.equal(matchKevContext([strong('6.9.4')], snapshot).status, 'matched');
  assert.equal(matchKevContext([strong('6.9.5')], snapshot).status, 'no-match');
  assert.equal(matchKevContext([strong('6.8.9')], snapshot).status, 'no-match');
});

test('does not report an unsupported product as a CVE match', () => {
  const result = matchKevContext([{
    ...strong('7.1.3'),
    product: 'Unknown CMS',
  }]);
  assert.equal(result.status, 'no-match');
  assert.deepEqual(result.matches, []);
});

test('marks stale or invalid snapshots and never labels them current', () => {
  const now = new Date('2027-01-01T00:00:00.000Z');
  const snapshot = {
    ...LOCAL_KEV_SNAPSHOT,
    checkedAt: '2026-11-08T00:00:00.000Z',
  };
  const matched = matchKevContext([strong('7.1.3')], snapshot, now);
  assert.equal(matched.snapshotStale, true);
  assert.ok(matched.snapshotAgeDays > KEV_SNAPSHOT_MAX_AGE_DAYS);
  assert.equal(kevStatusLabel(matched), 'Possible match in a stale local snapshot');
  const invalid = matchKevContext([strong('7.1.3')], {
    ...snapshot,
    checkedAt: 'not-a-date',
  }, now);
  assert.equal(invalid.snapshotStale, true);
  assert.equal(invalid.snapshotAgeDays, null);
});

test('marks data stale immediately after the 30-day source-data limit', () => {
  const snapshot = {
    ...LOCAL_KEV_SNAPSHOT,
    checkedAt: '2026-11-01T00:00:00.000Z',
    cisaReleasedAt: '2026-11-01T00:00:00.000Z',
  };
  const atLimit = matchKevContext([], snapshot, new Date('2026-12-01T00:00:00.000Z'));
  const pastLimit = matchKevContext(
    [],
    snapshot,
    new Date('2026-12-01T00:00:00.001Z'),
  );
  assert.equal(atLimit.snapshotStale, false);
  assert.equal(pastLimit.snapshotStale, true);
});

test('keeps no-match wording caveated and visibly reports stale data', () => {
  const current = matchKevContext([strong('7.1.4')], LOCAL_KEV_SNAPSHOT, new Date('2026-11-08T23:59:00Z'));
  assert.equal(kevStatusLabel(current), 'No matching entry in this snapshot');
  const stale = matchKevContext([strong('7.1.4')], {
    ...LOCAL_KEV_SNAPSHOT,
    checkedAt: '2026-09-01T00:00:00.000Z',
  }, new Date('2026-11-08T23:59:00Z'));
  assert.equal(kevStatusLabel(stale), 'Local vulnerability data is stale');
  assert.match(LOCAL_KEV_SNAPSHOT.entries[0].branchNote, /backports/i);
});
