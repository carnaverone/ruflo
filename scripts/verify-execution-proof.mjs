#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyExecutionProof } from './lib/execution-proof.mjs';

const MAX_PROOF_BYTES = 64 * 1024;
const file = process.argv[2];

if (!file) {
  console.error('usage: node scripts/verify-execution-proof.mjs <proof.json>');
  process.exit(2);
}

try {
  const path = resolve(file);
  const stat = statSync(path);
  if (!stat.isFile()) throw new Error('proof path is not a regular file');
  if (stat.size > MAX_PROOF_BYTES) throw new Error(`proof exceeds ${MAX_PROOF_BYTES} bytes`);

  const proof = JSON.parse(readFileSync(path, 'utf8'));
  const result = verifyExecutionProof(proof);
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.verified ? 0 : 1);
} catch (error) {
  console.error(JSON.stringify({
    status: 'unverified',
    verified: false,
    reasons: ['proof_read_or_parse_failed'],
    error: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exit(2);
}
