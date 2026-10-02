# Targeted settlement fix review

Independent reviewer: /root/attack_lab_settlement_review. Read-only review;
no new test execution. Verdict: both Important findings from security-review-1.md
addressed, no new material issue in the fixes. This is not whole-Task2 acceptance.

Settlement SQL SHA256:
`dd9cc3f69d89aeed59689d43e26215a8313e3db39ef5e3507467d5d19b1a3ef8`.
Reconcile SQL remains at its original reviewed identity:
`8e7c83005bdd298105a7aebd40d9656cf96fcd29d2ed0e4a74d63294d6389452`.

Settlement replay now re-authorizes after blocking locks immediately before
receipt return. The registered-role test observes the wait, revokes authority,
and requires rejection. Authorized exact replay after lease expiry still passes.

Definite terminal no-sandbox failures can settle despite started_at being set
during Claim. Any retained sandbox identity or cleanup checkpoint excludes that
fast path; checkpoint-backed cleanup still needs confirmed completion. The
first-attempt Create403 case proves zero Job creation/proxy execution and Failed
settlement. Concurrent cancellation versus stale settlement also passes.

Reviewed retained evidence:

- settlement-edges-red-2.log SHA256
  `5c9c08365ecbe8527605219f1045a6b97fb29f0015d5c342898debd700b57087`.
- settlement-edges-green-1.log SHA256
  `498aaccc8881b56da157f56a9b289566b8ed9dd99c4b38e4c87bf99f3601b9a7`.

The reviewer reread four formatted Go production files and observed no semantic
difference. Missing intermediate pre-format bytes prevent a byte-level claim
that the edits were formatting-only. Task2 start/end capture is separate and
complete; whole-task review uses the frozen final source.
