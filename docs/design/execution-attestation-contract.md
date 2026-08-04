# Signed execution-attestation contract

`ruflo-execution-attestation/v1` records the result observed by a dedicated command runner and authenticates that record with Ed25519.

## Trust boundary

The runner launches the command directly with `shell: false`, streams stdout and stderr to their normal destinations, hashes those byte streams, observes the process exit code, and signs the resulting envelope. The verifier accepts a public key supplied separately by the operator or CI policy.

The private key must be controlled by the trusted runner and must not be available to the agent whose claim is being checked. If the agent can read the signing key or replace the runner, it can forge an attestation.

A valid signature authenticates what that runner observed. It does not prove that the command was the correct test, that coverage was sufficient, or that the signing host itself was uncompromised. Those properties require policy, sandboxing, and CI isolation above this primitive.

## Signed fields

The fixed canonical body includes:

- schema identifier;
- SHA-256 digest of the argument vector, preserving argument boundaries;
- SHA-256 digests of stdout and stderr bytes;
- observed exit code and termination signal;
- source commit;
- canonical start and completion timestamps;
- a random nonce;
- optional claim identifier;
- fingerprint of the signing public key.

The raw command, output, environment variables, working directory, credentials, source files, and local paths are not stored. Digests are identifiers, not encryption, and low-entropy values may still be guessable.

## Verification rules

Verification fails closed when:

- the envelope contains unknown fields;
- required fields are malformed;
- timestamps are invalid, future-dated, or older than an operator-selected maximum age;
- the signer fingerprint does not match the separately pinned public key;
- the Ed25519 signature is invalid;
- the process exited non-zero or was terminated by a signal.

The attestation never carries a public key that can become its own trust anchor. This avoids the self-signed-key failure mode covered by CWE-347.

## CLI

```bash
node scripts/run-and-attest.mjs \
  --private-key ./runner-ed25519-private.pem \
  --source-commit "$GITHUB_SHA" \
  --output ./test-attestation.json \
  -- npm test

node scripts/verify-execution-attestation.mjs \
  --trusted-public-key ./runner-ed25519-public.pem \
  ./test-attestation.json
```

The runner returns the executed command's exit code. The verifier returns `0` only for an authenticated zero-exit execution, `1` for a failed or invalid attestation, and `2` for usage or file-read errors.

Related architecture problem: #640.
