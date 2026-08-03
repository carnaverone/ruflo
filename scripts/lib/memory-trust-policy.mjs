export const MEMORY_TRUST_SCHEMA = 'ruflo-memory-trust/v1';
export const TRUST_STATUSES = ['verified', 'unverified', 'rejected'];
export const CLEARANCE_LEVELS = ['public', 'internal', 'restricted'];

const CLEARANCE_RANK = new Map(CLEARANCE_LEVELS.map((level, index) => [level, index]));

function isCanonicalIsoTimestamp(value) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 40) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function safeString(value, field, maxLength = 512) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || /[\u0000-\u001f]/.test(value)) {
    throw new TypeError(`${field} must be a non-empty printable string of at most ${maxLength} characters`);
  }
  return value;
}

export function normalizeMemoryTrust(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('trust metadata must be an object');
  }

  const status = input.status ?? 'unverified';
  if (!TRUST_STATUSES.includes(status)) throw new TypeError('invalid trust status');

  const confidence = input.confidence ?? 0;
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new TypeError('confidence must be a finite number between 0 and 1');
  }

  const clearanceLevel = input.clearance_level ?? 'internal';
  if (!CLEARANCE_LEVELS.includes(clearanceLevel)) throw new TypeError('invalid clearance_level');

  const verifiedAt = input.verified_at ?? null;
  if (verifiedAt !== null && !isCanonicalIsoTimestamp(verifiedAt)) {
    throw new TypeError('verified_at must be null or a canonical ISO-8601 timestamp');
  }

  if (status === 'verified' && verifiedAt === null) {
    throw new TypeError('verified entries require verified_at');
  }

  return {
    schema: MEMORY_TRUST_SCHEMA,
    source_ref: safeString(input.source_ref, 'source_ref'),
    license: safeString(input.license, 'license', 200),
    verified_at: verifiedAt,
    confidence,
    clearance_level: clearanceLevel,
    status,
  };
}

export function evaluateMemoryTrust(input, policy = {}) {
  let trust;
  try {
    trust = normalizeMemoryTrust(input);
  } catch (error) {
    return {
      accepted: false,
      status: 'rejected',
      reasons: ['invalid_trust_metadata'],
      error: error instanceof Error ? error.message : String(error),
    };
  }

  const reasons = [];
  const allowedStatuses = policy.allowed_statuses ?? ['verified'];
  const minConfidence = policy.min_confidence ?? 0.75;
  const maxClearance = policy.max_clearance ?? 'internal';
  const requireVerifiedAt = policy.require_verified_at ?? true;
  const maxAgeMs = policy.max_age_ms ?? null;
  const allowedLicenses = policy.allowed_licenses ?? null;

  if (!CLEARANCE_RANK.has(maxClearance)) reasons.push('invalid_policy_clearance');
  if (!Array.isArray(allowedStatuses) || allowedStatuses.some((status) => !TRUST_STATUSES.includes(status))) {
    reasons.push('invalid_policy_statuses');
  }
  if (typeof minConfidence !== 'number' || minConfidence < 0 || minConfidence > 1) {
    reasons.push('invalid_policy_confidence');
  }

  if (trust.status === 'rejected') reasons.push('entry_rejected');
  if (!allowedStatuses.includes(trust.status)) reasons.push('status_not_allowed');
  if (trust.confidence < minConfidence) reasons.push('confidence_below_threshold');
  if (CLEARANCE_RANK.has(maxClearance) && CLEARANCE_RANK.get(trust.clearance_level) > CLEARANCE_RANK.get(maxClearance)) {
    reasons.push('clearance_exceeds_policy');
  }
  if (requireVerifiedAt && trust.verified_at === null) reasons.push('verification_timestamp_required');

  if (maxAgeMs !== null) {
    if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) {
      reasons.push('invalid_policy_max_age');
    } else if (trust.verified_at === null || Date.now() - Date.parse(trust.verified_at) > maxAgeMs) {
      reasons.push('verification_expired');
    }
  }

  if (allowedLicenses !== null) {
    if (!Array.isArray(allowedLicenses) || allowedLicenses.some((license) => typeof license !== 'string')) {
      reasons.push('invalid_policy_licenses');
    } else if (trust.license === null || !allowedLicenses.includes(trust.license)) {
      reasons.push('license_not_allowed');
    }
  }

  return {
    accepted: reasons.length === 0,
    status: trust.status,
    reasons,
    trust,
  };
}

export function filterMemoryRecordsByTrust(records, policy = {}, getTrust = defaultTrustSelector) {
  if (!Array.isArray(records)) throw new TypeError('records must be an array');
  if (typeof getTrust !== 'function') throw new TypeError('getTrust must be a function');

  const accepted = [];
  const rejected = [];
  for (const record of records) {
    const result = evaluateMemoryTrust(getTrust(record), policy);
    if (result.accepted) accepted.push(record);
    else rejected.push({ record, reasons: result.reasons });
  }
  return { accepted, rejected };
}

function defaultTrustSelector(record) {
  if (!record || typeof record !== 'object') return {};
  return record.trust ?? record.metadata?.trust ?? {};
}
