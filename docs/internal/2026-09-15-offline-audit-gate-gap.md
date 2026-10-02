# Offline npm audit does not prove advisory clearance

## Active bounded exception-policy correction

Local correction is now independently approved. Five focused tests and eleven
affected race tests pass after public-wrapper and deterministic-boundary RED.
The exact three-file source, commands and review are retained in
`vulnerability-exception-20260918/`. Root verified the current source hashes.
This supersedes the implementation-pending statements in the history below;
scanner acceptance and publication remain blocked, with no gate bypass.

After local M2-33 acceptance, the expired-exception defect below is the next
active implementation batch. The public evaluator keeps its signature and
uses current UTC time; a private evaluation-time helper supports deterministic
tests. Chosen expiry semantics are exclusive00:00UTC at the start of the stored
YYYY-MM-DD date. Approved critical exceptions require a valid owner and expiry
strictly later than evaluation time; equality, expiry and invalid evaluation
time fail closed. Existing noncritical policy is unchanged.

Focused RED/GREEN, affected CLI unit/race tests and independent review are
required. No frontend or scanner interface changes are planned; unchanged
frontend evidence is reusable until publication. This policy correction cannot
clear M8-47 or the release gate: actual dependency and image scans still require
an approved advisory source and trustworthy exact-input evidence. No online
audit, alternate source, CI bypass or live infrastructure is authorized here.

## September18 current source audit

The shipping worktree still unconditionally throws after local release checks;
there is no approved scanner acceptance path. This inspection did not run the
whole release gate, npm audit, an alternate endpoint or a scanner. Original
M8-47 explicitly requires dependency/image scanning and severity/exception policy;
a dependency-only receipt validator would not close the image requirement.

A separate local policy bug is confirmed in cmd/agentsecctl/security_release.go:
EvaluateVulnerabilities parses ExceptionExpires as a date but never compares it
with current/evaluation time. TestSigningAndVulnerabilityGatesRejectUnsafeRelease
expects a critical finding with expiry2026-09-01 to be accepted. The following
focused offline command joined exit0 on September18, after that expiry:

```text
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -C cmd/agentsecctl -run '^TestSigningAndVulnerabilityGatesRejectUnsafeRelease$' -count=1 -v
=== RUN   TestSigningAndVulnerabilityGatesRejectUnsafeRelease
--- PASS: TestSigningAndVulnerabilityGatesRejectUnsafeRelease (0.00s)
PASS
ok github.com/zasp-ai/zasp-sec/cmd/agentsecctl 0.647s
```

This passing test proves the existing fixture accepts an expired exception;
it is not desired-policy GREEN or scanner evidence. A correction needs explicit
evaluation-time semantics and deterministic before/at/after expiry tests, then
binding the policy to actual approved exact-input scan evidence. Source search
found this evaluator called only by its tests. No production behavior changed
during this audit. M8-47 remains component-only; publication remains blocked.

## September 16 containment update

The recovered candidate now removes the offline audit invocation and rejects
release after the existing local checks with an explicit audit-evidence-unavailable
error. It no longer emits dependency-clearance success. This is intentional
fail-closed containment, not a completed scanner or M8-47 acceptance. No network
audit, alternate endpoint, permission retry or CI bypass was performed.

Root rechecked installed Arborist's offline return and zero initialization
(0472fc). Executable orchestration regression4466e8 failed because the previous
gate accepted zero counters; after containment63a7af passes all3 tests, including
no audit invocation, no clearance claim and fail-stop on earlier rollout failure.
Independent read-only review found no Critical/Important issue for containment.
The tests substitute external command execution; they do not prove vulnerability
clearance or full release success. The remaining scan must use an approved source,
bind evidence to the exact lockfile, enforce freshness and severity, and reject
skipped/error/stale/mismatched reports. No passing audit path is implemented yet.

The diagnosis below is historical; its unchanged-candidate statement describes
September15. Current availability remains534 production/133 component/61 external.

September15 source inspection. No npm audit command or network request ran for
this diagnosis. The publication disclosure request remains unanswered.

`scripts/production-release-gate.mjs` on current main runs npm audit with
`--omit=dev --offline --audit-level=high --json`, then accepts zero high and
critical counters. Pinned npm10.9.8's installed Arborist source contradicts
using that result as advisory-clearance proof:

- In `@npmcli/arborist/lib/audit-report.js`, `_getReport` returns null immediately
  when options.offline is true, before either registry fetch or any advisory
  initialization.
- `run` initializes vulnerability entries only when that report is truthy.
- `toJSON` starts all severity counters at zero and fills them from those
  entries. Zero counters can consequently mean that no advisory lookup ran.

Root inspected those exact installed source paths through local commands
f84860, b8aabe and e077fe. This is a source-proven evidence gap in main's
pre-existing gate, not a newly executed vulnerable-package experiment or a
regression caused by the dependency projection. The candidate leaves main's
gate file unchanged. Existing same-lock online audit evidence remains historical
and must not be relabeled as a fresh selected-state lookup.

Independent source review confirmed the causal chain, SHA256
`1fba4e1c0c5a22f8e9b3d69e1bc113d97fdacb2de9930f3c55750c6ceb6a4a64`.
One configuration distinction matters: pinned explicit npm audit forces
audit:true, so inherited audit=false does not suppress that command. It can
suppress installation-triggered audit. Inherited offline mode still skips the
explicit command's lookup; simply removing the hardcoded flag is insufficient.
Installation advisory output is not an independent mandatory severity gate.

Original M8-47 requires an actual dependency/image scan and an unaccepted
critical finding blocking release. Independent wiring review found only
fixture callers of the separate Go policy evaluator, with no alternative
scanner closing this gap. The authoritative ledger now records M8-47 as
component-only under T15-deployment, preserving historical Complete. The
535production/132component/61external counts retain all728 original IDs.

The same inspection checked the denied command's disclosure. The bulk request
excludes the root and sends dependency names/versions. If that request fails,
the quick-audit fallback includes the project name/version, dependency metadata
and Node/npm/platform/architecture/NODE_ENV metadata. This does not establish
that ordinary npm audit avoids private project information. No retry, alternate
endpoint, indirect invocation or workflow modification is authorized by this
diagnosis. User disclosure consent remains required by the permission decision.

Required correction before trusting this gate as security clearance: reject
missing/skipped advisory evidence, bind any accepted report to the exact lock
and an explicit freshness rule, preserve the severity policy, and behaviorally
test skipped/offline/error/stale/mismatched evidence. An approved online scan or
an explicitly selected trustworthy local advisory source is needed; an empty
offline report is insufficient. This correction is not implemented or verified
by this note. Keep publication and the corresponding security acceptance open.

No original728-task status is promoted, no fresh audit is claimed, and this
does not block unrelated local browser integration.
