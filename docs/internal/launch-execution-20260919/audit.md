# Launch plan audit

Reviewed 2026-09-19 against the original728-task plan, current availability TSV,
task-card Markdown and machine-readable dependency data. This is a self-review
of the scheduling plan, not independent product-code review or launch approval.
No agents were used or contacted by this side-conversation audit.

## Findings and corrections

1. **Local verification was unnecessarily serialized.** The first draft attached
   nearest pending upstream acceptance to each local verify step. That could
   leave almost the entire queue waiting on early historical gates even when
   code and test inputs already exist. Moved those dependencies to original-task
   release/acceptance; local verify now depends on its delivered behavior. Exact
   runtime/provider prerequisites still apply. No original edge was removed.
2. **Cards could be mistaken for dispatch-ready coding plans.** Four broad stages
   and shared source directories do not identify safe concurrent edits or actual
   missing interfaces. Added a per-packet DISPATCH-GATE for exact write sets,
   consumed/produced contracts, focused/batch tests, ownership and authorization.
   It runs once for a coherent feature packet, not808 times. Broad directory
   assignments alone are not permission for concurrent writes.
3. **Supplemental journey dependencies were ambiguous.** R4 now consumes local
   action verification artifacts, not completion/publication of every action's
   acceptance chain. R4/R5 explicitly name live deployment/provider inputs. An
   external gate ID means an authorized input package, not completion of every
   task with that external owner. Original live acceptance criteria remain.
4. **Publication and full launch needed separation.** Defined SHIP-GATE as the
   exact packet/candidate's mandatory publication checks, not a recursive wait
   for M8-54. Verified packets can ship while other original work continues.
   Product availability is not promoted merely because a packet was pushed.

## Execution recommendation

Use three non-overlapping implementer slots and one integration/review seat when
those slots are available. Start with the current agent execution packet, one
UI/composition packet against its agreed contracts, and a deployment/security
prerequisite packet. Rotate blocked work out; do not create new workers merely
to fill lanes. Reconcile existing live work before dispatching anything.

Keep one writer for SQL catalog/pins, one OpenAPI/generated-client integrator,
and one release publisher. Run one affected feature test/review batch, then only
the checks invalidated by corrections. Record long-running job IDs and inspect
those jobs instead of restarting them.

Do not use the202 cards as a sequential checklist or rebuild components already
supported by matching evidence. The main task owns actual implementation,
independent product review, ledger updates and publication.

## Acceptance of this plan

Structural validation passed on 2026-09-19 using Node v22.23.1:

```sh
node docs/internal/launch-execution-20260919/validate.mjs
```

The read-only validator confirmed all 728 original nodes, exact coverage of 202
pending tasks (141 component-only and 61 external), 808 coordination stages,
five connected packets, zero dependency cycles and zero missing references.
All 202 local verification stages are free of publication dependencies. Source
snapshot hashes and Markdown/JSON dependency consistency also passed. These
checks validate plan structure, not product behavior or live availability.

The corrected plan is suitable for execution coordination. Each selected packet still needs its exact
file/interface/test binding at DISPATCH-GATE. This review does not claim every
future implementation detail is already designed, that all provider access is
available, or that the product is production-ready.

Audit scope is confined to this plan directory. Product code, authoritative
status classifications, git index/branches and running work are unchanged.
