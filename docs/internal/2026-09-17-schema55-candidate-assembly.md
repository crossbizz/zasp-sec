# Isolated schema55 candidate assembly checkpoint

This is an uncommitted, incomplete candidate, not a release or a passing test suite.

Source: budget-recovery-20260916 at HEAD ecc047ee2e90c36ec702ade129a2b08eae0a7a1a.
Destination: cached-runtime-ship-20260917 on codex/cached-runtime-ship-20260917.
Destination HEAD and freshly observed remote main:
8733b16f8d939d38a8157dd2519e57fc6f630542.

The destination was clean before assembly. Its offline Linux/arm64 build of
agentsec-migrate, agentsec-api, agentsec-worker and red-team-adapter passed,
session91091 exit0. Existing cached dependencies were reused; no install,
download or PostgreSQL server was started.

The compilation inventory records 543 exact inputs across51 local packages,
including137 embedded SQL files and two unchanged module files. Controller
applied exactly the150 new/modified production inputs from that inventory to
the existing isolated destination. No tests, UI, deployment or other recovery
files were copied in this step. No index changes, commit or push occurred.

The first content check found one mismatch in security_agent_handler.go:
ambiguous repeated patch context put the run-response compatibility block in
getActivation. Candidate build21822 exited1 on its three missing fields.
A direct source/destination diff identified the transfer defect. Controller
reapplied that one complete file from the unchanged reviewed source, then
rechecked every543 input blob: zero mismatches. This was a transfer correction,
not a product implementation change.

Exact corrected candidate build8993 exited0:

    GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go build ./agentsec-migrate ./agentsec-api ./agentsec-worker ./red-team-adapter

Both worktrees passed git diff --check. Destination has150 dirty paths and an
empty index. The compilation-input TSV binds every selected source to its git
blob. New packaging changes must recheck those identities before reusing proof.

Next: add explicitly inventoried corresponding tests and assets, compatible UI
and lockfile/build inputs, and deployment/runtime inputs; review the complete
main-to-candidate delta; run the grouped gates against that exact candidate.
The 67-file expanded production UI source graph was resolved read-only, but not
copied or verified as a candidate build. A build of four Go executables does not
prove runtime closure, browser behavior, migration execution or production safety.

The final local operator integration review approved the four frozen feature
increments with no Critical/Important issues. That approval does not cover every
inherited hunk now included in this wider dependency candidate. Fresh advisory
evidence and live rollout/provider/load gates remain separately unavailable or
unproven. Ledger validation remains728 rows:534 production-available,
133 component-only,61 externally blocked,0 missing. No original task promoted.
