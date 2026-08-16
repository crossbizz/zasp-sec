# M1-10 Neon Schema Baseline Design

## Decision

Add one dependency-free `services/platform/migrations` package with an embedded,
versioned initial migration. The migration creates the product-owned
`public.zasp_schema_versions` ledger and records its own exact version, name,
and SHA-256 checksum. A small transaction interface keeps the package independent
of pgx; M1-11 will own the pooled database wrapper.

The reviewed `proofs/neon-pooled` lifecycle remains the sole Neon provider
boundary. A narrow adapter will run the product migration on its exact
proof-owned disposable branch, verify version 1, roll it back, compare the
branch database fingerprint with its pre-migration baseline, and then prove the
branch absent. Product code does not call the Neon API or read credentials.

## Migration contract

The initial migration is immutable and ordered:

- version: `1`;
- name: `schema_versions`;
- up asset: create `public.zasp_schema_versions` with a bigint primary key,
  unique bounded name, exact lowercase SHA-256 checksum, and transaction-time
  application timestamp;
- ledger write: insert the exact version, name, and checksum inside the same
  transaction;
- down asset: only after the exact single ledger row is re-read, delete that row
  and drop the ledger table inside one transaction.

The checksum covers the exact embedded up and down assets with an unambiguous
separator. It is computed by product code and never accepted from a caller.

## Transaction and failure behavior

`Runner.Up` and `Runner.Down` each use one database transaction. They reject a
nil or canceled context, malformed transaction/row results, a pre-existing
baseline table, missing or additional version rows, and any identity or checksum
drift. Every failure maps to one fixed package error and triggers an independent,
bounded rollback. Commit happens only after exact post-state verification.

The runner exposes a read-only `State` query so the disposable proof and later
startup code can require either exact version 1 or exact absence. It does not
silently repair, skip, reorder, or auto-adopt migrations. Panics are not converted
to success; the deferred rollback remains armed.

## Safety and scope

- SQL identifiers are fixed literals; callers provide no SQL or identifier.
- The package retains no connection string, credential, provider ID, query
  result, or customer value.
- Up and down are intentionally strict rather than idempotent: unexpected state
  needs explicit operator reconciliation.
- M1-10 adds no pool, health statistics, query-timeout wrapper, schema for later
  product entities, ORM integration, startup auto-migration, or production
  deployment behavior.
- M1-11 remains Pending until the exact live up/down proof, cleanup, gates,
  scans, and independent review for M1-10 pass.

## Verification

Hermetic tests cover metadata/checksum stability, exact transaction order,
strict state validation, rollback and error precedence, cancellation, typed-nil
boundaries, and hostile database responses. The live root command uses the
ignored Neon inputs only through the existing proof boundary and must emit one
fixed success line after fresh up, exact version verification, down, baseline
restoration, and branch deletion.
