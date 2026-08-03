# Memory trust-governance policy

Typed provenance identifies who or what produced a memory. Trust governance adds a
separate decision layer that controls whether the record may be retrieved for a task.

The `ruflo-memory-trust/v1` metadata contract supports:

- `source_ref`: an opaque source identifier; callers should prefer a URN or digest over a local path;
- `license`: the source-use license or policy label;
- `verified_at`: canonical ISO-8601 verification time;
- `confidence`: a bounded value from `0` to `1`;
- `clearance_level`: `public`, `internal`, or `restricted`;
- `status`: `verified`, `unverified`, or `rejected`.

Default retrieval is fail-closed: only verified records with a verification timestamp,
confidence of at least `0.75`, and clearance no higher than `internal` are accepted.
Policies may additionally impose a maximum verification age and a license allowlist.

Legacy or incomplete records normalize to `unverified` with zero confidence. The filter
returns rejected records with reason codes, allowing audit without silently widening trust.
No source content, credentials, local paths, or private repository identifiers are required.
