# Ordered readiness: scoped review

SPEC: PASS for this bounded task. QUALITY: APPROVED, with one minor evidence-hygiene finding. No Critical or Important findings.

I reviewed the four-path dirty-baseline diff, not HEAD. The final diff SHA256 is `2f49ee00697be2bd4592d62c754ded24fa5bed1585ef63e1bfb2da21a1aebf3b`; current manifest SHA256 is `28c3aa2621221364762533cf3812391638c8e5d09fc1726355d3f5df5f9be538`. All 18 packet artifacts and all four owned current source hashes matched in my read-only check. The controller separately verified all 2324 current source hashes. HEAD is the unchanged `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`, not the task baseline.

Paths below are relative to this worktree. Evidence packet: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-ordered-readiness/`.

## What holds

`services/platform/apiserver/security_agent_ordered_production.go:18` defines a closed statement with independent80 readiness and the actual public62 API deployment call. Line37 binds only the compiled80 checksum and compiled62 checksum/fingerprint. Lines28-43 keep mode selection under the adapter read lock, check closed/nil state, preserve the exact legacy route and never fall back after a current-route failure. Lines24 and49 retain the five-second context, cancellation check, 128-byte ceiling and strict62 response contract. This is installed capability, not an actor grant.

The new behavioral tests exercise the real adapter and actual handler builder. `services/platform/apiserver/ordered_readiness_test.go:90` covers exact pins/body, both result requirements, malformed/null/duplicate/unknown/trailing data, the 128/129-byte boundary and generic SQL refusal. Line139 covers seven lifecycle cases, including cancellation after scanning. Line178 covers enabled success/refusal and the unchanged disabled control. `services/platform/agentsec-api/ordered_readiness_routing_characterization_test.go:18` deliberately changes the real traced-wrapper expectation to success, while retaining the non-current control; the earlier defect's source and raw run remain in the separate routing packet.

The installed test is substantive. `services/platform/apiserver/ordered_readiness_postgres_test.go:43` verifies the actual registered, nonsuperuser, non-RLS-bypass API login. Line73 calls public62 directly before using the typed adapter. Lines129-156 exercise absent schemas, missing/drifted registration, ACL changes, allow-valued API/ready replacements and68/profile/audit drift, with restored positives. Lines156-180 cover cancellation while the schema lock is held. Lines51-67 check that product runs, receipts, executor effects and admin audit counts don't change. This does not prove the query reached that lock before cancellation; the report states that limit accurately.

## One minor item

P3 / Minor: `p7-ordered-readiness/native-first.log:4` through line32 contains repeated routine false-predicate and successful fingerprint diagnostics before the useful readiness evidence. The unchanged helper emits these at `services/platform/apiserver/temporal_policy_response_lineage_postgres_test.go:232` and `:281`. That noise makes a clean installed run harder to scan. Defer a shared-helper cleanup that prints these details on failure or explicit diagnostic mode; keep this retained raw log intact. This is evidence hygiene, not a failed migration or a defect in the new production method.

## Checks beyond the diff

The production hunk ends mid-method, so I read its unchanged validation tail and handler-builder context. I made three focused boundary checks:

- Lock/close and mode-transition risk: `services/platform/apiserver/postgres_database.go:457` and `:530`, plus `authorization_transaction.go:20`. They use the same mutex. The new current route holds its read lock through I/O; the legacy branch releases it before entering QueryJSON, avoiding recursive read-lock acquisition. A concurrent enable transition can refuse the legacy attempt but cannot grant generic current-mode access.
- Strict decode. `services/platform/apiserver/security_agent_public62_decoder.go:16` through `:80` rejects missing, duplicate, unknown, null and trailing values. The method imposes its smaller 128-byte cap first.
- Wrapper error/context propagation: `services/platform/agentsec-api/ordered_http_runtime.go:9` forwards to the typed interface and checks cancellation without adding actor proof or changing the SQL contract.

I read the retained clean RED, controlled GREEN, full native output and final race-group output. RED fails the real current adapter/wrapper and enabled positive before I/O. Controlled GREEN reports4.152s/1.741s; native reports45.422s with all15 subtests passing; final race group reports10.028s/3.901s. Native log lines73-74 record unchanged `[0,0,0,0]` effects and joined owned PostgreSQL shutdown. No suite was rerun; no service, source, index or git state was changed by this review.

## Still outside this verdict

Cannot verify from this diff: the unchanged production shared gate's rejection of base/none profiles and stale audit checksum/key on both real API connections. The controller must tie that claim to its earlier accepted evidence and unchanged hashes. This typed method has no key-version parameter and cannot replace that gate.

Ordered operation classification/fencing, workers, responder/provider/compensation paths, full constructor and aggregate deadlines, the14 unfinished migrations, baseline package failures, live Stytch/providers, deployment/profile upgrade and Go1.25.6 versus CI1.25.13 remain open. This review does not approve P7/P8 completion or a release.
