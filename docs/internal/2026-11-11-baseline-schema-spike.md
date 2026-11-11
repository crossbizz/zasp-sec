# Baseline schema spike, 2026-11-11

Decision (user, 2026-11-11): replace the 80-release migration chain with one baseline schema that installs as a non-superuser owner, and retire the historical releases and their pinned artifacts. This note records what a first spike measured. Nothing in the product changed.

## Why the chain cannot be kept

See [the readiness report](launch-readiness-2026-11-11.md), blocker 1. In short: PostgreSQL 16+ gives a non-superuser a membership in every role it creates and will not let it revoke that membership, and the schema's readiness predicates reject any membership outside a fixed list. Confirmed on a Neon branch.

## What was measured

Source: the current-profile schema installed by `agentsec-migrate up-authorization-runtime-profile` as a superuser on PostgreSQL 18.3, then dumped with `pg_dump` (115,338 lines; 72 roles, 41 of them NOLOGIN authority roles; 2,735 ownership statements).

| Test | Result |
| --- | --- |
| Create all 41 authority roles and their 67 grants as a non-superuser owner (`CREATEROLE`, `BYPASSRLS`) | Works, once `GRANTED BY` is dropped and the operator's self-grant is skipped |
| Restore the full schema as that owner | **0 errors in about 6 seconds**, in two passes: objects and registry data first, then ownership |
| Temporary grants the restore needs | The operator needs a `SET` membership in each owning role, and each owning role needs `CREATE` on the schemas. Both are revoked afterwards without error, because the operator is their grantor |
| Unmodified `agentsec-api` against the restored database | Passes PostgreSQL, Temporal/OpenFGA and current-authorization; refuses at `dependency:authorization-readiness` |
| Zero-argument readiness predicates that change value, non-superuser restore vs the original install | 65 of 127 |
| Control: the same dump restored by a **superuser** | 30 of 127 change value |

Two conclusions:

1. Installing the schema's objects and roles on a Neon-style database is mechanically fine. The DDL is not the problem.
2. The self-verification layer is the problem, twice over. 30 predicates do not survive a plain dump and restore even as a superuser, so they are tied to the install sequence itself (catalog fingerprints, recorded predecessor functions, registration rows). A further 35 fail only for a non-superuser, which is the membership rule.

## What the baseline therefore has to be

A dump of today's schema is not a baseline, because it carries the layer that fails. The baseline needs:

- the tables, policies, functions and grants as they are today;
- role provisioning written for a non-superuser: roles created by the operator, temporary `SET` and `CREATE` grants around ownership transfer, both revoked at the end;
- a readiness layer redesigned for it: one version and registration check per runtime principal, a membership rule that accepts the creator's automatic ADMIN-only membership, and no catalog fingerprints of historical releases;
- the Go readiness call sites moved to that layer (the API and each worker mode pass release checksums to dozens of per-release readiness functions today);
- the worker gate decided in the same change: `zasp_authorization80_worker.runtime_ready()` is `... AND false` today.

The existing chain stays in the repository until the baseline passes the real stack end to end, then is retired.

## Not yet known

- Which of the 30 restore-unstable predicates the API and workers actually consult at runtime. That sets how much of the readiness layer is rewritten rather than deleted.
- Whether any function body depends on object identifiers recorded at install time.
- Neon-specific limits beyond role semantics. Only role creation and the self-grant were tested on Neon; the product binaries cannot reach Neon over TCP from this environment.
