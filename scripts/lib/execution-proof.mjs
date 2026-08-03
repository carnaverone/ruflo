import { createHash, timingSafeEqual } from 'node:crypto';

export const EXECUTION_PROOF_SCHEMA = 'ruflo-execution-proof/v1';

const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const SHA256_DIGEST_RE = /^sha256:[0-9a-f]{64}$/i;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function stablePayload(proof) {
  return JSON.stringify({
    schema: EXECUTION_PROOF_SCHEMA,
    commandDigest: proof.commandDigest.toLowerCase(),
    exitCode: proof.exitCode,
    sourceCommit: proof.sourceCommit.toLowerCase(),
    executedAt: proof.executedAt,
    claimId: proof.claimId ?? null,
  });
}

function safeDigestEqual(actual, expected) {
  if (!SHA256_DIGEST_RE.test(actual) || !SHA256_DIGEST_RE.test(expected)) return false;
  const a = Buffer.from(actual.slice('sha256:'.length), 'hex');
  const b = Buffer.from(expected.slice('sha256:'.length), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

function isValidIsoTimestamp(value) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 40) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

export function digestCommand(command) {
  if (typeof command !== 'string' || command.trim().length === 0) {
    throw new TypeError('command must be a non-empty string');
  }
  return `sha256:${sha256(command)}`;
}

export function createExecutionProof(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('input must be an object');
  }

  const hasCommand = typeof input.command === 'string' && input.command.trim().length > 0;
  const hasCommandDigest = typeof input.commandDigest === 'string' && input.commandDigest.length > 0;
  if (hasCommand === hasCommandDigest) {
    throw new TypeError('provide exactly one of command or commandDigest');
  }

  const commandDigest = hasCommand ? digestCommand(input.command) : input.commandDigest.toLowerCase();
  if (!SHA256_DIGEST_RE.test(commandDigest)) {
    throw new TypeError('commandDigest must be sha256:<64 hex>');
  }
  if (!Number.isInteger(input.exitCode)) {
    throw new TypeError('exitCode must be an integer');
  }
  if (typeof input.sourceCommit !== 'string' || !SHA_RE.test(input.sourceCommit)) {
    throw new TypeError('sourceCommit must be a 40- or 64-character hexadecimal commit id');
  }
  if (!isValidIsoTimestamp(input.executedAt)) {
    throw new TypeError('executedAt must be a canonical ISO-8601 timestamp');
  }
  if (input.claimId !== undefined && (typeof input.claimId !== 'string' || input.claimId.length > 200)) {
    throw new TypeError('claimId must be a string of at most 200 characters');
  }

  const proof = {
    schema: EXECUTION_PROOF_SCHEMA,
    commandDigest,
    exitCode: input.exitCode,
    sourceCommit: input.sourceCommit.toLowerCase(),
    executedAt: input.executedAt,
    ...(input.claimId ? { claimId: input.claimId } : {}),
  };

  return {
    ...proof,
    evidenceDigest: `sha256:${sha256(stablePayload(proof))}`,
  };
}

export function verifyExecutionProof(input, options = {}) {
  const reasons = [];
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { status: 'unverified', verified: false, reasons: ['proof_not_object'] };
  }

  if (input.schema !== EXECUTION_PROOF_SCHEMA) reasons.push('unsupported_schema');
  if (typeof input.commandDigest !== 'string' || !SHA256_DIGEST_RE.test(input.commandDigest)) {
    reasons.push('invalid_command_digest');
  }
  if (!Number.isInteger(input.exitCode)) reasons.push('invalid_exit_code');
  else if (input.exitCode !== 0) reasons.push('nonzero_exit_code');
  if (typeof input.sourceCommit !== 'string' || !SHA_RE.test(input.sourceCommit)) {
    reasons.push('invalid_source_commit');
  }
  if (!isValidIsoTimestamp(input.executedAt)) {
    reasons.push('invalid_executed_at');
  } else {
    const maxFutureSkewMs = options.maxFutureSkewMs ?? 5 * 60 * 1000;
    if (Date.parse(input.executedAt) > Date.now() + maxFutureSkewMs) {
      reasons.push('timestamp_in_future');
    }
  }
  if (input.claimId !== undefined && (typeof input.claimId !== 'string' || input.claimId.length > 200)) {
    reasons.push('invalid_claim_id');
  }
  if (typeof input.evidenceDigest !== 'string' || !SHA256_DIGEST_RE.test(input.evidenceDigest)) {
    reasons.push('invalid_evidence_digest');
  }

  if (reasons.length === 0) {
    const expected = `sha256:${sha256(stablePayload(input))}`;
    if (!safeDigestEqual(input.evidenceDigest, expected)) reasons.push('digest_mismatch');
  }

  const verified = reasons.length === 0;
  return {
    status: verified ? 'verified' : 'unverified',
    verified,
    reasons,
    summary: {
      schema: input.schema ?? null,
      commandDigest: typeof input.commandDigest === 'string' ? input.commandDigest : null,
      sourceCommit: typeof input.sourceCommit === 'string' ? input.sourceCommit : null,
      executedAt: typeof input.executedAt === 'string' ? input.executedAt : null,
      claimId: typeof input.claimId === 'string' ? input.claimId : null,
    },
  };
}
