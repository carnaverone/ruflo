import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createExecutionProof,
  digestCommand,
  verifyExecutionProof,
} from '../lib/execution-proof.mjs';

const executedAt = '2026-08-03T20:00:00.000Z';
const sourceCommit = 'a'.repeat(40);

function validProof(overrides = {}) {
  return createExecutionProof({
    command: 'npm test -- --runInBand',
    exitCode: 0,
    sourceCommit,
    executedAt,
    claimId: 'example-claim',
    ...overrides,
  });
}

test('creates a privacy-preserving proof without persisting the raw command', () => {
  const proof = validProof();
  assert.equal('command' in proof, false);
  assert.equal(proof.commandDigest, digestCommand('npm test -- --runInBand'));
  assert.equal(verifyExecutionProof(proof).verified, true);
});

test('non-zero exit codes can never produce a verified success', () => {
  const proof = validProof({ exitCode: 1 });
  const result = verifyExecutionProof(proof);
  assert.equal(result.status, 'unverified');
  assert.deepEqual(result.reasons, ['nonzero_exit_code']);
});

test('tampering with the commit invalidates the evidence digest', () => {
  const proof = validProof();
  proof.sourceCommit = 'b'.repeat(40);
  assert.deepEqual(verifyExecutionProof(proof).reasons, ['digest_mismatch']);
});

test('missing proof fields are reported as unverified rather than trusted', () => {
  const result = verifyExecutionProof({ schema: 'ruflo-execution-proof/v1', exitCode: 0 });
  assert.equal(result.verified, false);
  assert.ok(result.reasons.includes('invalid_command_digest'));
  assert.ok(result.reasons.includes('invalid_source_commit'));
  assert.ok(result.reasons.includes('invalid_executed_at'));
  assert.ok(result.reasons.includes('invalid_evidence_digest'));
});

test('a future timestamp fails closed', () => {
  const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const proof = validProof({ executedAt: future });
  assert.ok(verifyExecutionProof(proof, { maxFutureSkewMs: 0 }).reasons.includes('timestamp_in_future'));
});

test('an input status field cannot self-declare success', () => {
  const proof = validProof({ exitCode: 7 });
  proof.status = 'verified';
  const result = verifyExecutionProof(proof);
  assert.equal(result.status, 'unverified');
  assert.ok(result.reasons.includes('nonzero_exit_code'));
});
