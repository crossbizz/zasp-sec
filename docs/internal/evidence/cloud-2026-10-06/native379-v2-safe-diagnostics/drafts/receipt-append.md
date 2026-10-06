

## Reviewed source-only secondary collector diagnostics

The reviewed implementation retains bounded metadata when the secondary
collector fails: stage and error class, validated five-character SQLSTATE,
separate context/deadline state, source/query hashes, successfully scanned and
charged partial counts, proposed charge and read-only budget snapshots. It
retains no raw SQL, facts, PostgreSQL Message/Detail/Hint or parameters on
failure. Entries stay empty and comparison remains incomplete. Cleanup logging
reads the actual nil-safe snapshot after the owned subtest. Charges and limits
are unchanged; SQLSTATE `57014` alone does not identify a timeout.

Historical read-only diagnosis `345064…` links the old fallback to a prior
primary catalog Boolean false and then a secondary deferred stream failure.
Retained logs cannot recover either underlying cause. These diagnostics apply
to future secondary failures. The original d466 native attempt remains FAILED,
with no acceptance artifact and normal joined PostgreSQL cleanup. No new
PostgreSQL probe, native execution or deployed proof occurred.

A meaningful regression through the existing API fails on old 3ccc and passes
on new 6d02 using mocked rows with deferred SQLSTATE `42501`. Exact scaffold,
overlay sources/JSON and the reconstructed author invocation receipt remain.
That receipt is not automatic; unspecified environment variables were inherited.
The undefined-feature compile RED is separate. An accidental type failure and
a genuine stale-roster 12-pass/1-fail result are retained with truthful labels.

Author source tests passed all 13 groups in 53.249 seconds; Node passed six in
29.150 seconds; the independent component rerun passed 13 with zero failures or
skips. All 589 recorded outcomes, 6,348 steps and selected scripted executions
retain the same 379 rules, 10,052 facts, 565 sites, eight routines, SQL and caps.
This is component evidence, not 589 native PostgreSQL executions.

Exact identities:

- Implementation: `6d02b8f23bf4c53fbe6230cb536bd8f993cf78eb67abe1fd832b27badf8e324e`.
- Source manifest: `02ef1b7ce237fa49272bc7e8e778a6fd9e77bde9566b363f7821d770cb2bd989`.
- Packet: `5d18ca5f38c6f86c7cccda46fde1fb43008f6491b3c2a8319515592f7279a25a`.
- Source review: `41affaadd54eb518e95b47edea2bf5b35282d171e688961a52112d500ec4efea`.

The evidence manifest `a8c854674f59ac0fc315db6d42b57db4cac3f8b2eb03c08ae971ebf748852dc2`
binds 36 members. It preserves the original fourteen-member Node archive
manifest and explicitly identifies the omitted raw wire and source-inputs
members by their original hashes. Exact gzip expansion is verified. Root 2eef
and private 3ccc differ only in documentation; the separate normal ignore/docs
merge changed none of the four source bindings. No whole-current-repository
identity is asserted.

The inherited ae732 companion remains stale for this packet. Separately reviewed
new anchors, a full consumed-Go inventory, fresh frozen envelopes and root review
remain mandatory before any native attempt. Varied-login capacity, native parity,
product/deployed/security/release gates and all 728 categories remain unchanged.
