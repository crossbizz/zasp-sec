# Task4 independent review

Reviewer: /root/compliance_api_review. Spec compliance: issues found.
Task quality: Needs fixes. No Critical finding.

## Important findings (reviewer text)

1. **Public controls lose authoritative freshness.** compliance_http.go:269
fetches only100 preview records; compliance_http.go:347 discards c.Freshness
and reconstructs fresh_until from that preview. A fresh record beyond the first
page produces a false stale result. Missing and stale also collapse into the
legacy deadline representation. Evidence wrappers at line311 describe
individual-record freshness, so they don't repair control-level semantics.

Add an authoritative control freshness field through OpenAPI, generated types
and strict decoders. Preserve the direct-control response shape. If fresh_until
remains a control-level deadline, calculate it across eligible sources in SQL;
don't derive it from preview records. Cover a fresh101st record, missing
controls, all-stale controls and migration-seeded-only configuration.

2. **Valid large exports fail in the default client.** client.ts:187 limits
attachments with Math.min(maximumBytes,4MiB), but the default at line8 is1MiB.
Valid downloads between1 and4MiB fail after the server has consumed their
grants. Retrying with another grant repeats the failure.

Give compliance attachments a separate4MiB default while preserving existing
JSON limits and deliberate caller restrictions. Add default-client tests above
1MiB, at4MiB and above4MiB.

## Minor findings

- compliance_download.go:90 collapses provider failures and integrity failures;
  compliance_http.go:136 audits all as artifact_integrity, potentially creating
  a false corruption incident. Keep internal categories distinct and public
  errors generic. Deferred for final connected review.
- Routine production-composition telemetry floods accepted logs. Capture or
  discard expected telemetry in the fixture, retaining it on failure. Deferred.

## Cannot verify and controller disposition

- Missing explicit audit-write-failure injection. Handler visibly denies on
  bookkeeping error, but add a focused regression that forces write failure
  and asserts safe denial, no attachment and no successful consume. Root
  confirms this coverage gap and includes it in fix1.
- Task5 UI/composed-browser and liveIAM/KMS/lifecycle/deployment remain later
  gates, not proved by this component review.
- Reviewer relied on root's release55 preservation evidence; no55 file occurs
  in scoped manifest. Root must retain exact historical blob verification.

## Strengths and method

Mounted session/S/origin/CSRF/freshness protections, complete route composition,
pinned-byte verification before consume, optional captured-scope compatibility,
committed durable integrity-denial audit and replay check, reader-only storage
authority, and exact source-conflict classification were confirmed.
Read complete scoped patch, manifest, design, constraints, report and logs.
Named outside-diff checks: SQL grant locks/auth/clocks, aggregate freshness,
shared-client limits/error behavior and runtime ordering/readiness/ownership.
No suites, network calls, mutations or subagents. Rejected host-PG run excluded.
