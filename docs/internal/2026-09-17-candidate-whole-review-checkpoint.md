# Complete candidate review and release-subset checkpoint

The preceding goal turn made progress: independently approved harness/staging
repair and candidate verification. This continuation froze the complete assembled
candidate for read-only review and ran additional local release/core checks.
No original task was promoted. No branch commit, push or deployment occurred.

## Fixed review snapshot

Base and worktree HEAD:8733b16f8d939d38a8157dd2519e57fc6f630542.
Local review-only commit object:49bf318c707245c682399449e4f86ab74432c2f4.
Tree:1fc24e8a6d9e68f65800264962eaf8ec7d3f0f45.
It contains734 selected changed/new files,172419 insertions/9104 deletions.

A temporary alternate git index assembled this snapshot. The real index stayed
empty and HEAD/branch did not move. The standard Superpowers review-package
generator produced the full12.5MB diff, including new files, under the candidate's
plan SDD directory. This local object is a review artifact, not a release commit.
An alternate-index comparison confirmed exact worktree parity before the new
evidence note. Ordinary git diff against the snapshot misleadingly lists files
still untracked in the real index as deleted; the alternate index includes them.

Reviewer /root/candidate_whole_review is performing broad integration review.
The brief requires explicit coverage limits, cross-feature tenant/authority,
schema52-55, runtime/UI/deployment/CI review, and separate external gate findings.
It does not equate selective review with exhaustive inspection of all734 files.

## Fresh release subset

Pinned local Go with GOPROXY=off/GOTOOLCHAIN=local and task GOCACHE:
-77842: go test -C services/platform -race -count=1
 ./externalclient ./database ./jobqueue ./agentsec-api ./healthserver, exit0.
-73659: go test -C cmd/agentsecctl -race -count=1 ./..., exit0.
-8014d5: six Node preflight/fail-closed release orchestration tests passed,
 zero skips. Local readonly module lists for health/platform resolved.

Pinned Nango and Collector images were verified present by exact digest.
Image proof26727 exited0:3 tests passed,0 skipped. Nango checked its actual image
entrypoint/configuration and local TLS valid/wrong-host/untrusted-CA behavior;
Collector rendered configuration redacted hostile trace/log/metric values.
A temporary PATH Docker wrapper refused pull/build (negative control exit64)
and injected --pull=never for run. No image download/provider request occurred.
These are cached-image/local fixtures, not real customer identity or cloud proof.
Post-run docker ps showed no proof containers, only unrelated pre-existing ones.

## Full compiled core package batch

All1339 Go input blobs in the recorded test inventory still matched before run.
Existing Linux/arm64 test binaries were reused. Cached owned PostgreSQL image:
postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba.
Runs used --rm --pull=never --network none, user postgres, LANG=C.UTF-8,
2 CPUs/2GiB/512 PID limits and read-only binaries. No host PostgreSQL started.

Initial10480 exited1 after six packages passed. Securityagent's manifest test
could not open its compiled absolute docs path. Source inspection confirmed
runtime.Caller plus relative traversal to security-agent-action-readiness.tsv.
This was a test-environment omission, not a product failure. The exact candidate
manifest was mounted read-only at that path. Only the remaining two packages
were run in24555, exit0. Both owned containers were removed.

Final per-package top-level passes:
artifactstore19, s3driver16, audit25, auditexportconfig4, bucketlayout8,
runtimeevent102, securityagent17, migrations70. Total261, zero skips.
These are compiled component/unit checks (including injected transactions),
not a replacement for the previously recorded real owned-database/operator and
mounted browser acceptance.

Logs in /private/tmp/zasp-schema55-candidate-tests.47H9Oq:
- core-batch.log SHA256
 1e722b69597781c2110ba4405dc27e3dee9ac2b5fa409f833b5c1f86a551fa09
- core-batch-fixed.log SHA256
 b0a7c2993d88e8d2a9004f7ffb12fb36e6467825583dcc2417d2b06c2eeb1376

## Still open

Superseding review: broad integration review returned with no actionable code
finding in inspected paths and explicit unread limits. Merge remains NO because
the advisory/release gates are open. See
[integration review](2026-09-17-candidate-integration-review.md).
Default owned-process SIGTERM test5183 passed1/1,0 skips. The two opt-in runtime
SIGTERM tests are now running in71877 with cached images and pull/build refusal;
do not treat those running tests as passed. No product source changed.

Production-release-gate still deliberately refuses missing fresh approved
exact-lock advisory evidence.
No unrestricted gate run, security-clearance claim, main publication/CI,
real deployment/provider/load acceptance or all728 completion is claimed.
Counts remain534 production-available/133 component-only/61 external.
Shutdown handle71877 is now terminal, exit1: runtime-pipeline passed35.17s,
composed Red Team failed211.40s BEFORE reaching its shutdown checkpoint. Its
real browser clicked Open Support agent on /discovery/assets; the generated
inventory selector triggered the global scoped-activity parser's invalid-link
page instead of Canonical record. The assertion failed at harness5582 and its
normal cleanup finished. No zasp-owned container remained in the post-run check.
This is a candidate navigation regression, not successful Red Team shutdown proof.

Root traced parseActivityLink(location,session) in ZaspProductionApp and its
rejection of any query path outside scoped activity routes. Legitimate product
inventory links must remain usable without weakening scoped-link validation.
/root/candidate_navigation_fix now owns a bounded TDD repair in recovery with
independent review and fresh candidate UI/build/browser acceptance required.
The earlier selective no-finding review does not overrule this runtime failure.
