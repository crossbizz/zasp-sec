# SDK checksum audit correction

The real installed-SDK checksum rejection now reaches the durable integrity audit. This corrects the one Important finding in `docs/internal/compliance-api-task4-20260918/task-4-final-fix-review.md`. Telemetry was already accepted and is untouched.

I followed receiving-review, systematic-debugging, TDD and verification. The first final-fix tests stopped at a plain SDK-client substitute, which missed checksum middleware converting EOF into a read error. This round replaces only HTTP transport and keeps the installed S3 SDK running.

## The bounded adapter

The installed S3 version is `v1.107.2`, with `service/internal/checksum v1.9.30`. In that module's `algorithms.go`, `validateChecksumReader.Read` checks the digest only when the underlying read returns EOF. It returns the private concrete `checksum.validationError`; other body errors pass through without that type.

There is no exported sentinel or marker interface, and Go's internal-package boundary prevents importing its type. I rejected diagnostic-text matching because a provider/body error can copy that text. Disabling SDK validation would weaken the read path; adding another middleware/validation stack would expand this correction.

The isolated adapter checks the exact package path and concrete type name using reflection. No diagnostic text is inspected or returned. A recognized mismatch returns the existing safe `ErrGet` plus `artifactstore.ErrIntegrity`. Request cancellation and cancellation/deadline from body Close win over integrity classification. Existing Store and HTTP handling then produce generic denial and the SQL terminal integrity audit, with no successful consume or attachment.

This depends on the pinned SDK's private type identity. That dependency is explicit in the source comment. An SDK upgrade that changes the error type must fail the real-SDK behavioral regression until the adapter is reviewed; it must not silently update expected results.

## What proved it

Five real-SDK transport scenarios now run through driver, Store and mounted HTTP, and through the existing actual-session/registered-SQL fixture:

| Scenario | Required result |
| --- | --- |
| Successful pinned HTTP response, wrong body checksum | Safe integrity category, one committed safe audit, terminal grant, no disclosure/replay. |
| Interrupted body before EOF | Generic read failure; no corruption audit, unchanged bounded read lease. |
| Full advertised bytes followed by checksum-looking error text | Still generic. A string cannot impersonate the SDK type. |
| Cancellation when corrupt body reaches EOF | Cancellation wins even when SDK checksum validation also rejects; no audit or lease extension. |
| Valid pinned body | Exact stored bytes, verified consume, no integrity audit. |

Transport asserts the bucket/key, immutable version, owner and enabled checksum mode. It uses an anonymous SDK client and an in-process HTTP transport, never a live provider. All 11 earlier classification cases remain. The mounted checks assert exact read/audit/consume operations and no attachment/provider-secret exposure; SQL checks audit metadata/count, used_at, read_expires_at and replay behavior.

Focused RED 60172 exited 1 for the real SDK checksum case at driver, Store and HTTP; all four controls passed. Focused GREEN 28685 exited 0 after the 12-line production change.

The grouped boundary passed:

- Race 40010: exit 0, 52 exact non-SQL/non-process names, enumerated first by 72643. Storage, SDK driver and affected API cases ran together.
- Owned cached Docker 70698: exit 0, five top-level SQL tests. Classification has 16 cases now, including the five SDK scenarios. Current authorization/post-wait checks, audit-write-failure rollback, exact historical worker replay and runtime interruption/recovery all passed.
- Fresh Linux/arm64 API build 87369 and worker build 46662: exit 0. The grouped SQL run used these rebuilt binaries.

Full commands/results are in `task-4-final-fix-2-red-green.log.md`, `task-4-final-fix-2-enumeration.log.md` and `task-4-final-fix-2-verification.log.md`. No output truncation. Docker removed the owned container; all database/worker children joined normally. No host PostgreSQL.

## Frozen delta

Three existing files only. Fresh BEFORE and AFTER blobs are in `task-4-final-fix-2-blobs.json`; the patch compares those blobs, never the inherited HEAD diff. I reviewed the complete incremental diff after verification. Prior final-fix artifacts are unchanged.

Accepted telemetry identities remain:
`production_runtime.go = 328c3ec8c8ff4f96902ee9c4251567b36078dc9b`;
`compliance_composition_test.go = 223a8038e0a1a7bc4bca3cb522f00c628a94b86d`.
Release55 and56 SQL files are unchanged. No OpenAPI/client/UI, dependency, environment-switch or production-storage-interface edits.

UI/browser evidence remains historical and was not rerun. No staging, commit, push, live provider/advisory calls, image downloads or ledger edits. The 728-task scope and external gates are unchanged.

Ready for the controller's scoped re-review.
