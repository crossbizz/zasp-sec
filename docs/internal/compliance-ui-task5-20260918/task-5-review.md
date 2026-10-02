# Task5 independent review

Reviewer: /root/compliance_ui_review. Spec compliance: issues found.
Code quality: Needs fixes. No Critical finding established.

## Important findings

1. Obsolete list requests can invalidate the replacement session.
   ComplianceEvidenceView.tsx:78 calls listControls/listEvidence without its
   effect AbortSignal; cleanup84 aborts a controller those calls never receive.
   SessionsComplianceView.tsx:35/42 and pagination.ts:23 continue uncancellable
   cursor requests. The view's valid() guard prevents rendering but not the
   shared client.ts:210 authentication_required callback. Pass authority-bound
   cancellation through both lists and every page. Test delayed scope/principal
   replacement, no further pages, and no obsolete authentication error clearing
   replacement authority. Existing late-response test checks rendered data only.
   This is a diagnostic lead, not confirmed cause of the screenshot sign-in.

2. Browser success allows an unauthenticated final state.
   production-combined-e2e.mjs:2219–2225 checks404s/storage strings then captures
   without asserting continuity or mounted controls. Reviewer inspected the
   final screenshot and confirmed Sign in to Zasp. Diagnose with safe finalURL,
   response status/code, console and scope/session checkpoints. Require correct
   principal/scope after each denial, subsequent authorized evidence read and
   mounted controls/export screenshot. Never log credentials or grant tokens.

## Deferred Task4 Minors

- compliance_http.go:136 records integrity_failure for all reader errors;
  compliance_download.go:90 and underlying storage collapse categories. Preserve
  internal provider/cancellation/integrity distinctions through actual stack,
  retain generic public errors and test durable audit/consume behavior.
- production_runtime.go:129/412 use stdout. Accepted inspected logs have no new
  actionable warning, but fixture telemetry-noise issue remains open.

## Positive checks and limits

Strict source selectors and dedicated compliance route, authoritative freshness,
legacy labeling, transient body-only grants, current-authority download checks,
production-default storage seam and unchanged Sessions/Data Controls were
confirmed. Reviewer read the1180-line scoped patch, matched23 AFTER hashes,
read spec/original requirements and retained evidence. No mutations, suite
reruns, provider calls or subagents. Named outside-diff checks: decoder grammar,
authority generations, pagination cancellation, browser helper behavior,
storage error categories and telemetry. List-adapter inspection was required
because the integration diff omitted its cancellation contract.

Evidence confirms2086UI tests,79connected tests,80Node pass/2opt-in skips,
build/lint,3enumerated nonSQL race cases and SQL PASS. Typecheck log contains
only reported exit status. Browser assertions prove their earlier operations,
not final session continuity or visual acceptance. Live AWS/IAM/KMS/lifecycle,
deployed readiness and advisory gates remain separate. All728 tasks retained.
