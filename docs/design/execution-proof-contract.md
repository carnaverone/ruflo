# Execution-proof contract

A task or agent claim must not be promoted to `verified` from self-reported text alone.
The `ruflo-execution-proof/v1` contract derives status from machine-checkable evidence:

- a SHA-256 digest identifying the executed command without persisting the raw command;
- an integer exit code equal to `0`;
- the source commit used for execution;
- a canonical ISO-8601 execution timestamp;
- a SHA-256 digest covering the complete proof payload.

Missing, malformed, non-zero, future-dated, or modified evidence is always returned as
`unverified`. An input `status` field is ignored, so callers cannot self-assert success.

The verifier returns only an evidence summary and reason codes. It does not print command
text, stdout, stderr, local paths, environment variables, credentials, or repository data.
