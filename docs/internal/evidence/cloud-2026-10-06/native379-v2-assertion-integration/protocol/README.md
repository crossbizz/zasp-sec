# Private zero-row role/session assertion protocol

This directory is an owned candidate outside the repository. It does not replace
native379 source rosters, populate anchors, change roles, activate runtime_ready,
change existing controls/limits, or establish native/deployed acceptance.

The fixed SQL uses three bound parameters: the declared expected role, the
session_user observed when the owned session was bootstrapped, and that session's
backend PID. pg_catalog-qualified types, functions and operators retain their
meaning under a hostile search_path. Match returns SELECT 0 with no tuples;
wrong or NULL expectations evaluate division by zero and return SQLSTATE 22012.
The adapter requires stream exhaustion, no Rows.Err, a live context and exact
SELECT 0 completion before it creates a server-role-session-assertion receipt.
AssertedRole is explicitly an asserted value, never fabricated observedRole.

Successful receipts contain the exact SQL SHA256 and the SHA256 of UTF-8 JSON
array parameter bytes, role/session/PID binding, placement, SQLSTATE 00000,
zero rows, SELECT 0 completion and timed_out=false. Receipt JSON bytes and elapsed
time are charged to the supplied budget. Failure cannot return a success receipt.
The tiny-budget test refuses even a successful server assertion when its receipt
cannot be retained. The private Budget is a protocol harness; integration must
use the existing aggregate receipt/time/buffer limits unchanged.

Real owned PostgreSQL 18.3 / Go 1.25.13 race tests cover normal/read-only
transactions, wrong role/session/PID and SQL NULL, invalid client values,
restricted role plus hostile search_path, declared poison and 25P02 behavior,
rollback/recovery, server statement timeout, cancelled context, cancellation of
an actual server request, and refusal to borrow old PID authority on a fresh
connection. Each run initializes its own socket-only database and performs
normal fast stop plus process Wait before deleting the owned fixture.

Evidence:
- red.log is the real protocol RED against a parameter-bound row-producing
  observation baseline in assertion-red.go.snapshot. Five top-level controls
  and ten immediate subcases fail, two controls pass; no skips; worker 0.595s.
- red-observation-arity.log is an earlier baseline failure with incompatible
  binding arity. It is preserved, but is not the primary zero-row-contract RED.
- green.log passes seven controls and ten immediate subcases (1.593s).
- green-final.log adds actual request cancellation/session identity protection;
  eight controls and ten immediate subcases pass (1.646s), zero failures/skips.
- evidence-summary.json pins candidate, baseline and log bytes.

Future integration requirements:
1. Independently review this SQL, receipt shape and evidence accounting. Reuse
   bootstrap-observed session identity without permitting caller-selected PID.
2. Extend the native379 result/schema/validator to represent explicit server
   assertion evidence; do not manufacture observedRole/session SELECT rows.
3. Declare before-poison assertion provenance. Skip new assertions inside
   deliberately aborted transactions before the declared 25P02 probe/rollback;
   assert immediately after rollback/recovery, including recover-probe.
4. Preserve the 589 declared programs, original role transitions, stream counts,
   error continuation, existing SQLSTATE controls and all aggregate limits.
   New receipts must be charged and bound to exact SQL/parameter/placement bytes.
5. Record resulting source/pin changes in a separate reviewed batch. Run the
   complete original native379 acceptance and fresh/upgrade/readback controls.
6. Seven missing anchors and other readiness gates remain external to this
   private protocol. No empty-to-populated anchor update is authorized here.

Independent review correction:
The first hostile-path case omitted explicit pg_catalog ordering and schema
USAGE, so it did not establish effective shadow resistance. The strengthened
case grants hostile schema USAGE, sets hostile,pg_catalog explicitly, and
installs hostile text/int equality, integer division and pg_backend_pid objects.
An unqualified lookup witness proves all four hostile objects actually win.
Wrong/NULL expectations still error under the qualified protocol, each followed
by savepoint rollback and a fresh zero-row assertion.
shadow-red.log rejects an unqualified protocol variant at the hostile-path
wrong/NULL assertion: 1 failed / 7 passed top-level controls (0.683s).
green-reviewed.log passes the final strengthened group: 8 top-level controls,
10 immediate subcases, zero failures/skips (1.652s), normal owned stop/join.
Earlier green-final.log is retained as superseded coverage, not final shadow proof.
