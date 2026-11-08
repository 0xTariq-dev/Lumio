import assert from 'node:assert/strict';
import test from 'node:test';
import { matchKevContext } from './kev-context.ts';

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
