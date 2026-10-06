# Gateway permission fixture — October 6, 2026

This bounded component evidence preserves a fresh full verification failure
and the correction of one test fixture. It is not a full-suite, hosted UI,
native379, deployment or security-gate acceptance receipt.

`focused-umask077-red.log` is the actual behavioral RED. The initial wrong-cwd
Go module-discovery error is retained separately and is not behavioral RED.
The grouped race-test JSONL logs each contain 13 top-level and six child passes,
zero failures/skips, under explicit umasks 077 and 022. Exact tool invocations
and their metadata limits are recorded in `execution-receipt.json`.

Only the intended group-readable database file setup now explicitly chmods
0640 after successful creation. The production exact-0600 refusal guard and
all existing assertions are unchanged. `source-identity.json` and
`source-change.patch` bind this delta. Independent review is separate evidence.

The full verify began at 8f537fec and ended at d466887f after a separate
companion/documentation change. It failed after 398 seconds, with worker PASS
376.043 seconds and gateway fixture FAIL. UI verification was not reached.
The private raw log was scanned with Gitleaks 8.30.1 (zero findings), inspected
for actual credential/signed-URL content, and deterministically compressed.
That scoped inspection does not clear the historical full-history security gate.

`historical-git-object-restoration-redacted.json` separately preserves exact
object-restoration attempts: four unavailable objects, zero restored, one
already-local introduction commit. Missing object/artifact provenance and
security clearance remain unproven. All previous evidence is preserved.
