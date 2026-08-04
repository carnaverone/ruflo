#!/usr/bin/env node
import { lstatSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyExecutionAttestation } from './lib/execution-attestation.mjs';

const MAX_KEY_BYTES = 16 * 1024;
const MAX_ATTESTATION_BYTES = 128 * 1024;

function usage(message) {
  if (message) console.error(message);
  console.error(
    'usage: node scripts/verify-execution-attestation.mjs ' +
    '--trusted-public-key <key.pem> [--max-age-ms <milliseconds>] <attestation.json>',
  );
  process.exit(2);
}

function readRegularFile(path, maxBytes, label) {
  const resolved = resolve(path);
  const stat = lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`);
  if (stat.size > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`);
  const data = readFileSync(resolved);
  if (data.byteLength > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes after read`);
  return data;
}

const argv = process.argv.slice(2);
let publicKeyPath;
let maxAgeMs;
let attestationPath;
for (let index = 0; index < argv.length; index += 1) {
  const value = argv[index];
  if (value === '--trusted-public-key') {
    publicKeyPath = argv[++index];
  } else if (value === '--max-age-ms') {
    maxAgeMs = Number(argv[++index]);
  } else if (!value.startsWith('--') && !attestationPath) {
    attestationPath = value;
  } else {
    usage(`invalid argument: ${value}`);
  }
}
if (!publicKeyPath) usage('missing --trusted-public-key');
if (!attestationPath) usage('missing attestation path');
if (maxAgeMs !== undefined && (!Number.isFinite(maxAgeMs) || maxAgeMs < 0)) usage('invalid --max-age-ms');

try {
  const trustedPublicKey = readRegularFile(publicKeyPath, MAX_KEY_BYTES, 'trusted public key').toString('utf8');
  const source = readRegularFile(attestationPath, MAX_ATTESTATION_BYTES, 'attestation').toString('utf8');
  const attestation = JSON.parse(source);
  const result = verifyExecutionAttestation(attestation, trustedPublicKey, {
    ...(maxAgeMs === undefined ? {} : { maxAgeMs }),
  });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.verified ? 0 : 1);
} catch (error) {
  console.error(JSON.stringify({
    status: 'invalid',
    verified: false,
    authenticated: false,
    reasons: ['attestation_read_or_parse_failed'],
    error: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exit(2);
}
