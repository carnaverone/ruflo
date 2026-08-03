import assert from 'node:assert/strict';
import test from 'node:test';
import {
  evaluateMemoryTrust,
  filterMemoryRecordsByTrust,
  normalizeMemoryTrust,
} from '../lib/memory-trust-policy.mjs';

const verifiedAt = new Date().toISOString();

function verified(overrides = {}) {
  return {
    source_ref: 'urn:example:source:123',
    license: 'MIT',
    verified_at: verifiedAt,
    confidence: 0.9,
    clearance_level: 'internal',
    status: 'verified',
    ...overrides,
  };
}

test('normalization defaults legacy metadata to unverified and fail-closed confidence', () => {
  const trust = normalizeMemoryTrust({});
  assert.equal(trust.status, 'unverified');
  assert.equal(trust.confidence, 0);
  assert.equal(trust.verified_at, null);
});

test('verified records pass the default retrieval policy', () => {
  assert.equal(evaluateMemoryTrust(verified()).accepted, true);
});

test('unverified records are excluded by default', () => {
  const result = evaluateMemoryTrust({ ...verified(), status: 'unverified', verified_at: null });
  assert.equal(result.accepted, false);
  assert.ok(result.reasons.includes('status_not_allowed'));
});

test('low-confidence records are excluded', () => {
  const result = evaluateMemoryTrust(verified({ confidence: 0.4 }));
  assert.ok(result.reasons.includes('confidence_below_threshold'));
});

test('restricted records are excluded from an internal retrieval scope', () => {
  const result = evaluateMemoryTrust(verified({ clearance_level: 'restricted' }));
  assert.ok(result.reasons.includes('clearance_exceeds_policy'));
});

test('license allowlists are enforced', () => {
  const result = evaluateMemoryTrust(verified({ license: 'Proprietary' }), {
    allowed_licenses: ['MIT', 'Apache-2.0'],
  });
  assert.ok(result.reasons.includes('license_not_allowed'));
});

test('retrieval filtering returns accepted records separately from rejected reasons', () => {
  const records = [
    { id: 'trusted', trust: verified() },
    { id: 'unknown', trust: {} },
    { id: 'restricted', trust: verified({ clearance_level: 'restricted' }) },
  ];
  const result = filterMemoryRecordsByTrust(records);
  assert.deepEqual(result.accepted.map((record) => record.id), ['trusted']);
  assert.deepEqual(result.rejected.map(({ record }) => record.id), ['unknown', 'restricted']);
});

test('verified status without verified_at is invalid metadata', () => {
  const result = evaluateMemoryTrust({ ...verified(), verified_at: null });
  assert.equal(result.accepted, false);
  assert.deepEqual(result.reasons, ['invalid_trust_metadata']);
});
