import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

export const EXECUTION_ATTESTATION_SCHEMA = 'ruflo-execution-attestation/v1';

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const COMMIT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22,128}$/;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{86,128}$/;
const ALLOWED_FIELDS = new Set([
  'schema',
  'commandDigest',
  'stdoutDigest',
  'stderrDigest',
  'exitCode',
  'signal',
  'sourceCommit',
  'startedAt',
  'completedAt',
  'nonce',
  'claimId',
  'signerKeyId',
  'signature',
]);

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 40) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  const canonical = new Date(parsed).toISOString();
  return canonical === value ? canonical : null;
}

function toPrivateKey(key) {
  const object = key?.type === 'private' ? key : createPrivateKey(key);
  if (object.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('private key must be Ed25519');
  }
  return object;
}

function toPublicKey(key) {
  const object = key?.type === 'public' ? key : createPublicKey(key);
  if (object.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('trusted public key must be Ed25519');
  }
  return object;
}

export function digestArgv(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((value) => typeof value !== 'string')) {
    throw new TypeError('argv must be a non-empty array of strings');
  }
  return sha256(Buffer.from(JSON.stringify(argv), 'utf8'));
}

export function digestBytes(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array) && typeof value !== 'string') {
    throw new TypeError('value must be bytes or a string');
  }
  return sha256(value);
}

export function publicKeyId(key) {
  const publicKey = toPublicKey(key?.type === 'private' ? createPublicKey(key) : key);
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return sha256(der);
}

function canonicalBody(input) {
  return {
    schema: EXECUTION_ATTESTATION_SCHEMA,
    commandDigest: input.commandDigest,
    stdoutDigest: input.stdoutDigest,
    stderrDigest: input.stderrDigest,
    exitCode: input.exitCode,
    signal: input.signal ?? null,
    sourceCommit: input.sourceCommit,
    startedAt: input.startedAt,
    completedAt: input.completedAt,
    nonce: input.nonce,
    claimId: input.claimId ?? null,
    signerKeyId: input.signerKeyId,
  };
}

function canonicalBytes(input) {
  return Buffer.from(JSON.stringify(canonicalBody(input)), 'utf8');
}

function validateStructure(input, options = {}) {
  const reasons = [];
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return ['attestation_not_object'];
  }

  for (const key of Object.keys(input)) {
    if (!ALLOWED_FIELDS.has(key)) reasons.push(`unexpected_field:${key}`);
  }

  if (input.schema !== EXECUTION_ATTESTATION_SCHEMA) reasons.push('unsupported_schema');
  for (const field of ['commandDigest', 'stdoutDigest', 'stderrDigest']) {
    if (typeof input[field] !== 'string' || !DIGEST_RE.test(input[field])) {
      reasons.push(`invalid_${field}`);
    }
  }
  if (!Number.isInteger(input.exitCode) || input.exitCode < 0 || input.exitCode > 255) {
    reasons.push('invalid_exit_code');
  }
  if (input.signal !== null && input.signal !== undefined) {
    if (typeof input.signal !== 'string' || !/^[A-Z0-9]{1,32}$/.test(input.signal)) {
      reasons.push('invalid_signal');
    }
  }
  if (typeof input.sourceCommit !== 'string' || !COMMIT_RE.test(input.sourceCommit)) {
    reasons.push('invalid_source_commit');
  }

  const startedAt = canonicalTimestamp(input.startedAt);
  const completedAt = canonicalTimestamp(input.completedAt);
  if (!startedAt) reasons.push('invalid_started_at');
  if (!completedAt) reasons.push('invalid_completed_at');
  if (startedAt && completedAt && Date.parse(completedAt) < Date.parse(startedAt)) {
    reasons.push('negative_duration');
  }

  const maxFutureSkewMs = options.maxFutureSkewMs ?? 5 * 60 * 1000;
  if (completedAt && Date.parse(completedAt) > Date.now() + maxFutureSkewMs) {
    reasons.push('timestamp_in_future');
  }
  if (completedAt && options.maxAgeMs !== undefined) {
    if (!Number.isFinite(options.maxAgeMs) || options.maxAgeMs < 0) {
      reasons.push('invalid_max_age_option');
    } else if (Date.now() - Date.parse(completedAt) > options.maxAgeMs) {
      reasons.push('attestation_too_old');
    }
  }

  if (typeof input.nonce !== 'string' || !NONCE_RE.test(input.nonce)) reasons.push('invalid_nonce');
  if (input.claimId !== null && input.claimId !== undefined) {
    if (typeof input.claimId !== 'string' || input.claimId.length === 0 || input.claimId.length > 200) {
      reasons.push('invalid_claim_id');
    }
  }
  if (typeof input.signerKeyId !== 'string' || !DIGEST_RE.test(input.signerKeyId)) {
    reasons.push('invalid_signer_key_id');
  }
  if (typeof input.signature !== 'string' || !SIGNATURE_RE.test(input.signature)) {
    reasons.push('invalid_signature_encoding');
  }
  return reasons;
}

export function createExecutionAttestation(input, privateKeyInput) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('input must be an object');
  }
  const privateKey = toPrivateKey(privateKeyInput);
  const publicKey = createPublicKey(privateKey);
  const body = canonicalBody({
    ...input,
    schema: EXECUTION_ATTESTATION_SCHEMA,
    nonce: input.nonce ?? randomBytes(16).toString('base64url'),
    signerKeyId: publicKeyId(publicKey),
  });
  const provisional = { ...body, signature: 'A'.repeat(86) };
  const reasons = validateStructure(provisional, { maxFutureSkewMs: Number.MAX_SAFE_INTEGER });
  if (reasons.length > 0) {
    throw new TypeError(`invalid execution attestation input: ${reasons.join(', ')}`);
  }
  const signature = cryptoSign(null, canonicalBytes(body), privateKey).toString('base64url');
  return { ...body, signature };
}

export function verifyExecutionAttestation(input, trustedPublicKeyInput, options = {}) {
  const reasons = validateStructure(input, options);
  let authenticated = false;
  let trustedKeyId = null;

  try {
    const trustedPublicKey = toPublicKey(trustedPublicKeyInput);
    trustedKeyId = publicKeyId(trustedPublicKey);
    if (typeof input?.signerKeyId === 'string' && input.signerKeyId !== trustedKeyId) {
      reasons.push('signer_key_mismatch');
    }
    if (reasons.length === 0) {
      authenticated = cryptoVerify(
        null,
        canonicalBytes(input),
        trustedPublicKey,
        Buffer.from(input.signature, 'base64url'),
      );
      if (!authenticated) reasons.push('invalid_signature');
    }
  } catch {
    reasons.push('invalid_trusted_public_key');
  }

  const executionSucceeded = input?.exitCode === 0 && (input?.signal === null || input?.signal === undefined);
  if (authenticated && !executionSucceeded) {
    if (input?.exitCode !== 0) reasons.push('nonzero_exit_code');
    if (input?.signal) reasons.push('terminated_by_signal');
  }

  const verified = authenticated && executionSucceeded && reasons.length === 0;
  return {
    status: verified ? 'verified' : (authenticated ? 'failed' : 'invalid'),
    verified,
    authenticated,
    executionSucceeded,
    reasons,
    summary: {
      schema: input?.schema ?? null,
      commandDigest: typeof input?.commandDigest === 'string' ? input.commandDigest : null,
      sourceCommit: typeof input?.sourceCommit === 'string' ? input.sourceCommit : null,
      startedAt: typeof input?.startedAt === 'string' ? input.startedAt : null,
      completedAt: typeof input?.completedAt === 'string' ? input.completedAt : null,
      claimId: typeof input?.claimId === 'string' ? input.claimId : null,
      signerKeyId: typeof input?.signerKeyId === 'string' ? input.signerKeyId : null,
      trustedKeyId,
    },
  };
}
