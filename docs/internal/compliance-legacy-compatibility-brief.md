# Preserve compliance reads when the complete service is disabled

This bounded compatibility task follows the connected fix wave. Its three
original findings are addressed; do not reopen them. Read
compliance-connected-fix-20260918/connected-fix-review.md for the residual
load-bearing regression and original design for disabled-service compatibility.

Use an explicit supported-mode/legacy signal to choose unfiltered legacy reads
versus independent SOC2/HIPAA cursor chains. Inspect existing validated response
and runtime capability signals before adding a new public contract. Never use
arbitrary errors/401/403/409 as a downgrade signal, silently switch scopes, claim
current freshness for legacy seeds, or enable exports based on client guesses.
Preserve current-service long cursors, both frameworks and effect/page aborts.

Write a failing regression crossing the real adapter and retained legacy query
contract with populated controls/evidence. Cover complete service enabled and
disabled/absent, authorization failures, scope/principal replacement, and no
legacy-to-current freshness fabrication. Test through actual composition where
possible rather than only a stub API interface. Explain the selected signal and
empty/mixed-response behavior in the report. Keep strict query validation.

Focused RED/GREEN, then affected integration tests and one assembled UI/types/
lint/build/browser boundary for changed behavior. Reuse unchanged SQL/storage
evidence by identity. No new dependency, provider or live infrastructure is needed.

Record pre-existing long-ID detail overflow separately; it does not authorize
unrelated visual redesign. The task is compatibility, not another broad review
or reimplementation of the three closed defects.

Capture fresh BEFORE/AFTER and scoped patch as legacy-compatibility-* under the
existing plan workspace; report exact commands/output, source identities and
joined cleanup. Root owns one task-scoped independent review. No staging, commit,
push, ledger edits, subagents, downloads/pulls/builds of images, host PostgreSQL,
live-provider/advisory calls. Preserve inherited changes and prior artifacts.
