# P4C checkpoint: one proof gap before acceptance

Spec verdict: the implementation matches the bounded admission/accounting design in source, but checkpoint acceptance needs the focused INSERT-boundary evidence below. Full P4C remains incomplete by agreement.

Quality verdict: with fixes to the checkpoint test coverage. I found no confirmed production-code defect in this scoped review. I would not treat the present tests as proof that the new shared guard protects every retained admission caller.

## What I reviewed

The review used the Superpowers requesting-code-review template, without another agent, implementation edits, git mutations, suite reruns or runtime activation. This report is the sole write.

I read `p4c-checkpoint-review-brief.md`, `p4c-brief.md`, the P4 parent brief, the frozen implementation report and all 751 lines of `p4c-scoped.diff`. The baseline is the captured dirty overlay on HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`, not HEAD~1. I independently checked the manifest SHA-256: `a5fd6aa756ede51b948b347ac0584406d69c54dd230a1ab12eee34183ba06384`. I relied on the controller's prior verification of the nine changed hashes, 15 logs, three packet references, 205 unchanged historical SQL files and reverse-check result.

For specific risks, I traced the unchanged existing-test admission/selector fragment, installed70 copies and worker dispatch, the manual admission test helper, accounting68 RLS, ownership66 restrictions, Temporal68 effect/test/cleanup settlement, and the inherited68/69/70 fingerprint recipe. I inspected the final log tails: API 50.555s on the expanded final test, CLI 27.682s on unchanged production and CLI-test bytes. Both show joined PostgreSQL shutdown. Those are existing results, not tests I reran.

## Strengths worth keeping

The two capacity checks consume one scoped all-owner count, while the accounting role still has no login or members. The trigger adds a separate serialized check at parent INSERT; its organization try-lock avoids waiting behind another holder after a retained caller has already acquired a definition lock. Read-committed enforcement and the exact current definition/version lookup are explicit.

The copy boundary is tight. The installer requires accepted72, saves both exact installed70 definitions and ACLs, checks the expected replacement occurrences, and fingerprints the resulting functions, private tables, constraints, policies and public capacity trigger. The inherited fingerprint recipe includes private immutability triggers and foreign-key triggers. CLI tests exercise the registered dispatcher, reject wrong principal configuration before installation, repeat installation, and reject four catalog changes.

Admission and revision1 start insertion occur inside the copied admission transaction, after parent insertion. The surrounding source checks, receipt identities, audit writes and final rechecks survive the copy. Failed candidate subtransactions roll back their product records. The final expanded test proves hidden-owner candidate filtering before LIMIT, same-ID tenant separation, selector competition in both connection orders, rollback/retry and duplicate wakeups.

The report also keeps its claims bounded. It does not call an unconsumed start row successful orchestration, and it distinguishes controlled historical rows from provider or terminal-parent execution evidence.

## Issues

### Critical

None identified.

### Important: [P2] Exercise rejection at the new shared INSERT guard

Primary location: `services/platform/apiserver/security_agent_temporal_admission_postgres_test.go:130` (the manual-path coverage at lines 130-133). Related implementation: `services/platform/migrations/sql/0073_production_temporal_admission.up.sql:63`, particularly lines 68-70. The selector race coverage is at test lines 201-218.

Every full-capacity refusal in this test goes through the new selector, which can reject the candidate before calling `admit`, and the overlapping selector test can skip it at the selector's organization try-lock. The manual helper admits a different definition and repeats that exact request. Neither case forces a retained caller past its old RLS-visible precheck and into a rejecting `capacity_guard` invocation. The successful admissions execute the trigger, but only below capacity. Disabling the trigger in the CLI test proves fingerprint rejection, not its behavioral contract.

This matters now. The checkpoint's new guard applies to every parent INSERT, including caller families that have not migrated to73, and it is the protection against their old owner-limited counts. A guard that always returned NEW, with a correspondingly compiled catalog pin, would preserve the capacity rejection assertions currently supplied. No oversubscription bug is demonstrated; the claimed cross-caller safety boundary lacks a regression test.

Add one focused installed-boundary group before accepting this foundation. A concrete route is the still-installed, worker-authorized `zasp_temporal70.op02` with an otherwise eligible definition at capacity solely because of an RLS-hidden Temporal parent. Its old selector/precheck can reach parent INSERT, so the73 trigger must reject and leave no parent, trigger receipt, audit, admission or start for the candidate. Prove admission after verified release. In the same focused group, force the row-boundary organization contention path and verify rollback/retry without waiting in the reverse lock order; retain the existing full-capacity replay assertion. The test should fail if the trigger's rejection logic is removed even when the replacement catalog is internally consistent.

This is checkpoint verification work. It does not require migrating every trigger family or rerunning the broad predecessor suites.

### Minor

None worth blocking this packet on.

## Controller follow-through

Resolve the P2 proof gap before calling the shared INSERT invariant accepted. The current concurrency evidence is selector-versus-selector, not a mixed retained/new caller matrix.

Keep the wider occupancy matrix explicit. Only the private68 provider reservation and its never-dispatched release have direct unresolved-owner assertions here. Effects, cleanup, retained controls, test links/invocations, webhook, export and Attack Lab obligations need their planned family evidence; I did not infer successful safe release for those branches from the provider fixture. In the source inspected, Temporal cleanup completion does set its effect to `cleaned`, and stopped tests retain an unsettled link, so neither trace established an immediate missed-owner defect.

The minimum lease-free run_test/rerun_test executor must consume the existing73 identity and produce actual child/parent settlement. Keep start delivery disabled until its current-authority, cancellation/deadline, approval, budgets and unknown-outcome contracts are proved. The retained70 claim path has not been fenced by this checkpoint; a future consumer must account for that coexistence before it can execute the same run.

Full trigger routing, separate service/human authority, the configured whole-second Temporal selector Schedule with shipped1s, source-revocation/deadline races, event/SQS/DLQ mappings, P4D family settlement, P8 broad acceptance, P9 retirement/equivalence and deployed authorization gates remain open. This review does not reduce any original728 acceptance requirement.

## Ready to merge?

With fixes, for the bounded checkpoint only. Source review found a coherent accounting implementation and no confirmed code defect; the untested cross-caller INSERT rejection is important enough to close before building the executor on an accepted accounting guarantee. Production activation and full P4C acceptance are not approved.
