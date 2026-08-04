import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  createExecutionAttestation,
  digestArgv,
  digestBytes,
  verifyExecutionAttestation,
} from '../lib/execution-attestation.mjs';

const RUNNER = fileURLToPath(new URL('../run-and-attest.mjs', import.meta.url));
const VERIFIER = fileURLToPath(new URL('../verify-execution-attestation.mjs', import.meta.url));
const SOURCE_COMMIT = 'a'.repeat(40);

function keys() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKey,
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

function validBody(overrides = {}) {
  const now = new Date();
  return {
    commandDigest: digestArgv(['node', '--version']),
    stdoutDigest: digestBytes('v22.0.0\n'),
    stderrDigest: digestBytes(''),
    exitCode: 0,
    signal: null,
    sourceCommit: SOURCE_COMMIT,
    startedAt: new Date(now.getTime() - 50).toISOString(),
    completedAt: now.toISOString(),
    claimId: 'unit-test',
    ...overrides,
  };
}

test('signs and verifies against a separately supplied trusted key', () => {
  const pair = keys();
  const attestation = createExecutionAttestation(validBody(), pair.privateKey);
  const result = verifyExecutionAttestation(attestation, pair.publicKey);
  assert.equal(result.verified, true);
  assert.equal(result.authenticated, true);
  assert.equal(result.status, 'verified');
});

test('a different trusted key cannot verify the attestation', () => {
  const signer = keys();
  const other = keys();
  const attestation = createExecutionAttestation(validBody(), signer.privateKey);
  const result = verifyExecutionAttestation(attestation, other.publicKey);
  assert.equal(result.verified, false);
  assert.ok(result.reasons.includes('signer_key_mismatch'));
});

test('tampering with observed execution data invalidates the signature', () => {
  const pair = keys();
  const attestation = createExecutionAttestation(validBody(), pair.privateKey);
  attestation.exitCode = 1;
  const result = verifyExecutionAttestation(attestation, pair.publicKey);
  assert.equal(result.authenticated, false);
  assert.ok(result.reasons.includes('invalid_signature'));
});

test('an authenticated non-zero execution remains failed', () => {
  const pair = keys();
  const attestation = createExecutionAttestation(validBody({ exitCode: 7 }), pair.privateKey);
  const result = verifyExecutionAttestation(attestation, pair.publicKey);
  assert.equal(result.authenticated, true);
  assert.equal(result.verified, false);
  assert.equal(result.status, 'failed');
  assert.ok(result.reasons.includes('nonzero_exit_code'));
});

test('served public-key fields are rejected instead of self-pinning trust', () => {
  const pair = keys();
  const attestation = createExecutionAttestation(validBody(), pair.privateKey);
  attestation.publicKey = pair.publicPem.toString();
  const result = verifyExecutionAttestation(attestation, pair.publicKey);
  assert.equal(result.verified, false);
  assert.ok(result.reasons.includes('unexpected_field:publicKey'));
});

test('future and stale timestamps fail closed', () => {
  const pair = keys();
  const future = new Date(Date.now() + 60_000).toISOString();
  const futureAttestation = createExecutionAttestation(validBody({
    startedAt: future,
    completedAt: future,
  }), pair.privateKey);
  assert.ok(
    verifyExecutionAttestation(futureAttestation, pair.publicKey, { maxFutureSkewMs: 0 })
      .reasons.includes('timestamp_in_future'),
  );

  const old = new Date(Date.now() - 10_000).toISOString();
  const oldAttestation = createExecutionAttestation(validBody({ startedAt: old, completedAt: old }), pair.privateKey);
  assert.ok(
    verifyExecutionAttestation(oldAttestation, pair.publicKey, { maxAgeMs: 1 })
      .reasons.includes('attestation_too_old'),
  );
});

test('runner executes without a shell and persists only digests', () => {
  const pair = keys();
  const directory = mkdtempSync(path.join(tmpdir(), 'ruflo-attestation-'));
  const privatePath = path.join(directory, 'private.pem');
  const publicPath = path.join(directory, 'public.pem');
  const outputPath = path.join(directory, 'attestation.json');
  writeFileSync(privatePath, pair.privatePem, { mode: 0o600 });
  writeFileSync(publicPath, pair.publicPem, { mode: 0o644 });

  const source = 'process.stdout.write("VISIBLE_OUTPUT"); process.stderr.write("VISIBLE_ERROR")';
  const run = spawnSync(process.execPath, [
    RUNNER,
    '--private-key', privatePath,
    '--source-commit', SOURCE_COMMIT,
    '--output', outputPath,
    '--claim-id', 'integration-pass',
    '--', process.execPath, '-e', source,
  ], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /VISIBLE_OUTPUT/);
  assert.match(run.stderr, /VISIBLE_ERROR/);

  const serialized = readFileSync(outputPath, 'utf8');
  assert.doesNotMatch(serialized, /VISIBLE_OUTPUT|VISIBLE_ERROR/);
  assert.doesNotMatch(serialized, /process\.stdout|process\.stderr/);

  const verify = spawnSync(process.execPath, [
    VERIFIER,
    '--trusted-public-key', publicPath,
    outputPath,
  ], { encoding: 'utf8' });
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(JSON.parse(verify.stdout).verified, true);
});

test('runner preserves the command exit code and signs the failure', () => {
  const pair = keys();
  const directory = mkdtempSync(path.join(tmpdir(), 'ruflo-attestation-fail-'));
  const privatePath = path.join(directory, 'private.pem');
  const outputPath = path.join(directory, 'attestation.json');
  writeFileSync(privatePath, pair.privatePem, { mode: 0o600 });

  const run = spawnSync(process.execPath, [
    RUNNER,
    '--private-key', privatePath,
    '--source-commit', SOURCE_COMMIT,
    '--output', outputPath,
    '--', process.execPath, '-e', 'process.exit(7)',
  ], { encoding: 'utf8' });
  assert.equal(run.status, 7, run.stderr);
  const result = verifyExecutionAttestation(JSON.parse(readFileSync(outputPath, 'utf8')), pair.publicKey);
  assert.equal(result.authenticated, true);
  assert.equal(result.verified, false);
  assert.ok(result.reasons.includes('nonzero_exit_code'));
});

test('runner rejects symlinked private-key files', { skip: process.platform === 'win32' }, () => {
  const pair = keys();
  const directory = mkdtempSync(path.join(tmpdir(), 'ruflo-attestation-link-'));
  const privatePath = path.join(directory, 'private.pem');
  const linkPath = path.join(directory, 'private-link.pem');
  const outputPath = path.join(directory, 'attestation.json');
  writeFileSync(privatePath, pair.privatePem, { mode: 0o600 });
  symlinkSync(privatePath, linkPath);

  const run = spawnSync(process.execPath, [
    RUNNER,
    '--private-key', linkPath,
    '--source-commit', SOURCE_COMMIT,
    '--output', outputPath,
    '--', process.execPath, '--version',
  ], { encoding: 'utf8' });
  assert.equal(run.status, 2);
  assert.match(run.stderr, /non-symlink/);
});

test('command digest binds argument boundaries', () => {
  assert.notEqual(digestArgv(['ab', 'c']), digestArgv(['a', 'bc']));
});
