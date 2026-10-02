# Original queue contract: repaired, locally verified, unpublished

September18 follow-up: the separate staging Terraform queue correction is now
locally implemented and independently reviewed, including explicit canonical
settings for the original queue/DLQ pairs. See
[fix report](staging-original-queue-20260918/fix-1-report.md) and
[review](staging-original-queue-20260918/fix-1-review.md). Account Terraform-plan
acceptance and the compliance56 deployment gap remain open. Historical counts
and the September15 checkpoint below are preserved; the current status ledger
is authoritative.

September 15, 2026. M1-33 remains component-only. The source repair and a fresh
disposable LocalStack run passed; no production deployment or new push occurred.

The repair restores `agentsec-tests`, `agentsec-tests-dlq` and
`agentsec.tests.v1`. Distinct Red Team production bindings are unchanged.
The proof module's three stale AWS dependencies were reconciled. Its job SDK
now requests and propagates the actual bounded `ApproximateReceiveCount` system
attribute; missing or invalid counts reject, without a default count of one.

Focused behavioral RED/GREEN, the affected Go proof race suite, original queue
definition checks, three distinct Red Team checks, seven runner protocol tests
and the 31-test status checker passed. Initial module setup failure, four real
negative-control failures, the stale ledger footer and six full-proof failures
are retained with their corrections. They aren't counted as passing runs.

Independent SPEC/QUALITY review approved the twelve-file repair without findings.
Root read the complete report and verified all fourteen source/data hashes before
the subsequent evidence-only ledger edits. The review SHA-256 is
`f7e7fc07e5708e6e266afb1fab401eb5008e868e03d9e9ccdba1c9a02a8cf884`.
Review and implementation reports are retained in
`.superpowers/sdd/2026-08-18-m1-33-sqs-queue-definitions-design/`.
Raw focused/grouped evidence is in `/tmp/zasp-m1-33-repair.29RHky/`.

## Fresh disposable provider run

The existing reviewed runner was used without code changes. Read-only image
inspection confirmed the locally installed pinned LocalStack 4.7.0 image:
`localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c`.
Its image ID was `sha256:ad4f76a02108f52479a33bbe0de40690d63ef51713971731f21f1de1e4eedb85`.
The toolchain was Go 1.25.6 darwin/arm64 and Node 22.23.1.

Working directory: `/tmp/zasp-daemon-replay.GUTSRq/worktree`.

```sh
env PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node proofs/localstack-sqs/run-queue-definitions.mjs
```

Root observed exec session 72976 through terminal exit 0. Its exact output was:

```text
LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true container_cleanup=true.
```

The runner creates a fresh random proof-owned container with only SQS enabled,
disabled persistence and a numeric-loopback port. Child/build environments are
allowlisted. It verifies all six queues, settings/tags/redrive policies, deletes
only proven-owned resources, audits absence and removes its owned build root
and container. No ambient AWS credentials, shared endpoint or old failed
resource was supplied. This is actual local-provider acceptance, not a mocked
SDK result or live AWS proof. The current run did not separately capture a
before/after fingerprint of a known shared LocalStack instance.

Still open: the remaining original full-release checks and shared-infrastructure
evidence, whole-range review, verified publication and exact-SHA UI CI. Staging
Terraform still needs its separate original queue correction. The current
availability counts stay 536 production-available, 131 component-only and 61
external gates across all 728 original tasks.
