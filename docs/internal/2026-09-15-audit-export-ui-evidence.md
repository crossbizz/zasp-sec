# Audit export UI: local verification checkpoint

September18 control-path recheck: browser extension control and owned-tab focus
now work, but native Save dialog controls remain inconsistent. The small
loopback probe was closed and its server joined without a save. No large export
retry or native saved-byte proof. See
[probe evidence](2026-09-18-audit-native-control-probe.md).

September 15, 2026. The two independent review findings and related lane test
are fixed locally: queued create rechecks freshness after acquiring its lane,
permission loss has neutral unavailable copy, and the successor test queues an
actual request. The five-file fix is frozen and scoped SPEC/QUALITY re-review
approved all three findings with no outstanding issue.
Original M7-36 remains component-only and unpublished.

The panel now calls the accepted private generated export adapter through
current session authority. It retains identity-bound create keys/job IDs,
polls with a finite foreground budget, verifies one canonical page at a time,
and writes closed chunks before the final manifest. Visible audit filters stay
independent of the organization-wide snapshot. No backend or provider contract
changed in this UI batch.

For the initial handoff, root read the complete implementer report, command/exit manifest, final grouped
test output and build tail. All twelve current source hashes matched the frozen
manifest. Initial report SHA-256 before the retained fix appendix:
`97629a40da75190ab05fe00de9ed6fc5879cc250f94aff973038bbe8343d7760`.
Snapshot-relative U20 delta SHA-256:
`417bf6e6e9d4b8d9f34ecbf08f2395f7f2550387a5a6fd1b8dea2cdf30dff8d3`.
The full local report and raw logs are retained in this worktree under
`.superpowers/sdd/2026-09-12-audit-export-plan/ui-save-evidence/`, with the report
at `audit-ui-save-batch-report.md` in its parent. These ignored local artifacts
must remain available for review; this document isn't a replacement for them.

The final affected group passed 159 tests across twelve files in 2.90 seconds.
Final typecheck and affected lint exited0. The five-stage production UI build
exited0; afterward only an explicit type annotation in an injected-directory
test changed, followed by the affected tests/typecheck/lint rerun. No production
build input changed after that build. Every implementer process is terminal.

Failures are retained, not rewritten as success: initial absent-action RED;
missing-module setup errors (not behavioral RED); real retry, bootstrap,
StrictMode cleanup and freshness regressions; initial timer-warning fixture;
lint issues; and the grouped test's type-inference failure. Corrected runs and
exact terminal exits are in the command manifest.

Controlled HTTP tests exercise the real adapter, APIProvider and SessionProvider,
including generic403 followed by current bootstrap authority. Injected directory
tests cover byte verification, collision refusal, read retry, writer errors and
joined final-close outcomes. These are component tests, not native filesystem
or deployed-provider evidence.

Fix1 has retained behavioral RED (four failures), focused GREEN (six passes),
one affected group (30 passes), typecheck, five-file lint and one fresh build.
All processes are terminal. Root verified all twelve current source hashes.
The fix delta SHA-256 is
`62e2af81cccb21f7f8a7bff70c113b82fdf4ade8165b086ed81fc5601a415ef0`;
raw commands and logs are in the same SDD workspace's `ui-save-fix1-evidence/`.
Unchanged test suites were not repeated.

Root read the complete fix review and command manifest, inspected the grouped
test and fresh-build outputs, and verified the review SHA-256:
`666d3a234e851afbc0e1b771ab735c3343119502c3b2a94a60e7c0a70c7999d8`.
The report is `audit-ui-save-fix1-review.md` in the same SDD workspace.

The full API's private storage-factory prerequisite now also has local
SPEC/QUALITY approval with no findings. Its three-file change preserves normal
production entry points and strict configuration while allowing a test-only
owned token/TLS adapter to use the actual cached STS/S3 providers. Focused
behavioral RED/GREEN and one 20-top-level-test API race group passed (session
99858, exit0, 2.205s). Root verified the complete source/evidence hash manifest
and read the independent review, SHA-256
`94800a61785df5538b1cc70b387f7d28b7062a278465ca4982ac8996bc482993`.
Reports are `audit-browser-factory-report.md` and
`audit-browser-factory-review.md` in the same SDD workspace. This is not a
successful database-backed full API build or browser-save result.

The existing large-export expected-byte checker only reads administration rows
and explicitly rejects policy/test rows. The new test-only mixed-producer checker
has independent SPEC/QUALITY approval with no findings. Root read the full
review, SHA256 `bfdf4434f50bffc03cd3dc56e3fa862f10c18e3141a4c16973f2ba6f0019e410`,
and verified its four source hashes and
retained ten-test affected race output (48.979s, session65376 exit0). It reads
raw committed producer rows in a separate snapshot; actual browser integration
is still pending. Existing administration-only checks were included in the group.

The later combined `npm test` run (root session66518) exited1. It reported two
stale repository-contract assertions outside the export component tests: the
old SQS proof core AWS SDK pin and the old exact README staging-status phrase.
Root checked both against the reviewed module repair and current source-audited
README. The two-file assertion correction now has independent SPEC/QUALITY
approval with no findings; root read the full review, SHA256
`ecc7fba85989b4662b44ea174552d21aa46c451633214c8edbc4c541df351716`.
Root read its report and focused output: seven tests passed in1.44s, session59462
exit0; affected lint session57076 exit0. Both final source hashes match the
report, with README/module inputs unchanged. This is focused repair evidence,
not a repeated full-suite run. The full UI suite is not currently recorded as
green at that historical checkpoint. The later dependency integration below
supersedes that full-suite status; publication gates remain required.
Its complete output is `frozen-ui-suite-2026-09-15.log` in the same SDD workspace.

The nested dependency integration now has a frozen report, SHA256
`306865db2d73f3cd6d79727e5934458fd57289a6b7bfa230b710d2bac3bc52a4`.
Root read it and verified all32 retained evidence checksums (85d2dd, exit0).
Pinned Node22.23.1/npm10.9.8 project installation completed; the full UI suite
passed208 files/1,625 tests, with typecheck, lint and production build also
passing. The actual installed production SBOM passes the unchanged license
gate, and the full dependency audit reports zero vulnerabilities. Independent
SPEC/QUALITY review of this seven-file integration approved it with no findings.
Root read the complete review and matched SHA256
`f8b4852b25e8362e412ba37c0fd49b2d8942b4d61aee46d8df43dd1af2e211b5`.
The reviewer reconstructed all seven files from incoming snapshots and patch,
checked actual consumer paths and the unchanged installed-license policy, and
reused the recorded suites. Actual native browser integration is now dispatched.

The affected group retained171 passes and one failed module import. Correcting
that test's transitive dependency resolution produced8 focused passes and clean
affected lint. The unchanged full UI/build were not rerun for this test-only
correction. A bounded owned standalone process served HTML and JavaScript with
HTTP200, then shut down and joined. This proves local startup, not authenticated
browser behavior, native saving, container readiness or deployed-provider use.
Exact logs and incoming-relative delta are in
`dependency-nested-integration-evidence/` in the same SDD workspace. Both prior
node_modules backups remain recoverable. No task promotion or push follows
from this checkpoint.

Still required: selected actual API/outbox/worker browser
composition; actual SSO/configuration/policy/test mutations; native directory
picker and saved-file verification; real reload and authentication interruption;
more than64 MiB and at least100,001-event saves with measured renderer memory;
whole-branch release checks and verified publication. No supported browser
version, live-provider acceptance or production readiness is certified here.

## Native handoff checkpoint, not save acceptance

Root inspected `audit-native-browser-evidence/native-vertical-7.log` and
`native-vertical-7-repaired-click-2.log` in the retained SDD directory
(`5a73ca`). The owned local full-API browser run recorded policy, SSO,
configuration and test mutations with raw producer witnesses. Its registered
outbox and export worker subprocesses passed in0.82s and4.05s. The identity
and storage providers were owned fixtures, not live external services.

The run did not complete native saving. Handle64794 ended with a ten-minute
native-selection/save timeout and logged cleanup. The first handoff contained
a stale target ID; a later hit-tested trusted click used the current owned
target. Neither a handoff record nor an input dispatch proves an OS picker
opened or any file was saved.

Root's native Chrome control call took845.1204s and returned an unrelated user
Chrome window after the owned run expired. Root performed no UI actions in
that window and observed no picker. The implementer reported the owned Chrome
process gone and the destination empty. Native saving, saved-byte comparison,
large native saves and native fault/recovery acceptance remain unproved.

Do not rerun an unchanged ten-minute handoff until the owned native window can
be targeted reliably. Non-picker composition and source tests can continue,
but cannot replace filesystem acceptance. No task classification or production
claim changes at this checkpoint. Verification stays grouped by feature batch,
with unchanged valid evidence reused and all required pre-push checks retained.

## Large preparation checkpoint, still no native save

Root verified all12 frozen source checksums and71 retained artifact checksums
for the native harness batch (049366, exit0). The integration report hash is
`4942c190838024b562753c3b03c4f531dae5c447c41fb6c4d83222cf5ee43c53`.
Independent review of this partial batch is requested; this isn't acceptance
of the unfinished native workflow.

Root read the retained fourth large-preparation log and readonly database
diagnostic. Run80219 exited1 at the near-limit response-envelope assertion.
Before that failure, the browser performed the four mutation families and
actual lost-create-response reload/replay with the same key. The registered
outbox and worker passed in1.15s and158.58s. The database diagnostic recorded
a ready captured export with100,008 events,101 chunks,99,431,964 chunk bytes,
102 intents and102 receipts. These are owned local-provider results.

The required envelope remains greater than1,000,000 and at most1,064,960 bytes.
The run didn't meet that assertion; final maximum-envelope and memory samples
weren't printed before failure. The512-byte fixture payload reaches the
event-count limit before the intended byte boundary. The next preparation
change should adjust fixture density and print bounded measurements before
asserting, without weakening the acceptance limit. Don't repeat the unchanged
large run.

The retained final Node group has51 passes and2 opt-in skips, not53 passes.
No saved-file oracle, native directory selection, measured memory during an
actual save, live provider acceptance or complete native fault matrix is proved.
M7-36 stays component-only; all original task classifications are unchanged.

## Harness review correction

Independent review of the frozen native batch found two additional harness
issues: provider termination was logged without rejecting a nonzero/signal
outcome, and the new Node browser regressions weren't in normal CI/package
commands. Root read the full review, hash
`bbced08f24d568c25df8d8ced3c2ddb2592f7f375ce3c5920bf8d9b5890d16cd`.

Both terminal branches now require joined status0 and no signal. Actual child
exit0/exit1/SIGTERM tests and extracted branch checks cover the fix. CI and the
package command now select both browser and volume regression files. The
fixture payload is1024 bytes; numeric diagnostics precede the unchanged size
assertions. Node verification has57 unique passes and2 opt-in skips across the
sandbox run and five permission-scoped loopback reruns, not a single all-green
59-test invocation. Workflow checks passed248 tests; affected lint and
whitespace passed. Scoped independent follow-up review returned SPEC compliant
and QUALITY approved with no new findings. Root read the full report and
matched its hash90816f7c815e3f6a9515b45487d2f5503069e32a46a5f1e410c320c233635816.
That approval covers the correction's source, not successful native acceptance.

The corrected preparation attempt50594 exited1 before export generation,
waiting for the created policy to appear. Its log records cleanup. This run
does not prove the new payload meets the near-limit wire criterion. The next
diagnosis concerns the harness click reporting success on a disabled control;
the failed run didn't retain that button's state, so the precise cause remains
unconfirmed. Full evidence and terminal accounting are in
`audit-native-browser-fix1-progress.md` in the retained SDD directory. No
unchanged large retry, native-save claim, task promotion or push follows.

## Corrected large preparation passed

The disabled-click helper now waits for an enabled button. Its actual-helper
regression failed before the guard and passed after it. Failed policy diagnostics
also preserve the original error if the browser connection closes. Independent
source review approved both corrections. The earlier policy-startup failure's
exact cause remains unconfirmed; the next observed readiness state was enabled.

The first1024-character padding correction violated the existing512-character
metadata-value contract and failed the audit page before export. Product limits
were correct and remain unchanged. The fixture now uses two legal512-character
fields. Its real audit-page adapter regression reproduced the rejection before
the fix, then all44 adapter tests passed. Typecheck and affected lint passed.
Independent follow-up review has no findings; root read and hash-verified
`0012c21577fbf70221f040dfbcd18a8bab2e8a4a2ed55ffdbd5ff28127e778f7`.

Corrected run81115 finished with exit0 (f8ff2a). It exercised real local browser
mutations, lost-response reload/replay, registered outbox and export workers,
and authenticated traversal of146 pages containing100,008 events and
151,954,163 chunk bytes. The largest actual response was1,050,064 bytes,
satisfying the unchanged near-limit criterion. No response was incomplete.
The export worker passed217.38s; the provider exited status0 with no signal and
reported its listener/control joined. Parent cleanup stages completed.

Preparation measured147 samples: heap9,948,044 initial/13,629,508 peak bytes;
renderer RSS194,117,632 initial/197,902,336 peak; provider RSS77,758,464 peak.
These measurements cover API-page reading, not filesystem writing. The log
explicitly records nativePickerInvoked=false and nativeSavedBytesVerified=false.
The owned read-only database diagnostic also found ready/captured, attempt1,
146chunks,147intents and147receipts with no failure code.

Retained evidence: `audit-native-browser-fix2-progress.md` and
`audit-native-browser-evidence/native-preparation-bounded-metadata.log` in the
same SDD directory. Log SHA256:
`af1979f1c16a576b11e7b5302429bab112f3c3eb19a2a1c035d16b59a56c93ec`.
Actual native saving, independent saved-byte/SQL comparison, native-save memory
and the remaining fault/recovery matrix are still required. All three B01 rows
remain component-only and unpublished.

### Native control remains unavailable

The next bounded native-control probe called `cua.getState()` with a 10-second
timeout. It returned after 10.0832 seconds with an execution timeout and kernel
reset, before identifying any browser window. No picker was operated and no
personal browser tab was touched. This is a control-path blocker, not a failure
of the export API or evidence of a completed native save. Do not repeat the
large preparation until the owned browser's native dialog can be targeted.
Independent tenant-security work continues while this acceptance gate stays open.
