# Cache-first runtime preparation shipping increment

Implementation scope: six harness files, plus two evidence notes, isolated from
origin/main fda8ae99921be468b3d95f2369f54112a725e046.
No product API, migration, dependency version, deployment setting or capability
changes. The original 728-task goal remains incomplete.

The two preparation callers reuse exact digest-pinned cached arm64/amd64 images.
Only an exact missing-image error permits one bounded pull, followed by mandatory
inspection. Other errors refuse; owner closure prevents later commands. Container
ownership and cleanup code are unchanged.

Fresh candidate evidence:

- Exact-lock offline npm ci: 585 packages, exit0; no audit or network download.
- Three scoped Node suites: 32 tests pass, zero failures/skips.
- Dependency lock validation, TypeScript and six-file ESLint pass.
- Production source gate verifyReleaseSources passes, including source/container,
  license/SBOM and tracked-history secret checks. This is not deployment proof.
- UI build and compiled imports pass: seven client/eight server chunks.
- Actual loopback standalone smoke: root and seven JS/CSS assets HTTP200 and
  nonempty; exact owned server joined on SIGTERM.
- Real read-only Docker smoke: three exact cached images inspected; zero pulls
  or container creation. Cold-registry availability is not tested.
- Production release contract suites: 94 tests pass.
- Full web suite: 197 files, 1,244 tests pass, exit0 in28.90s.
- Fresh independent bounded review: no implementation defects, all seven code
  requirements satisfied and imports available on the base. Untested refusal
  variants and successful-cache closure races are test-hardening gaps, not
  observed regressions. No numeric coverage claim.

Failed attempt retained: an initial broader inherited combined-harness test
selection reports 68 pass, one fail and two opt-in skips. Its SIGTERM case
attempted prohibited host initdb and failed before readiness. This was a test
selection error, not a passing cleanup proof. Subsequent process inspection
found only pre-existing PostgreSQL PID69792 and its children, left untouched.
No newly owned database process remains. Do not rerun that case on the host.

This increment does not validate the full combined browser flow, cold pulls,
actual providers, production load, current advisory data or the full product
release gate. None of those gates is removed or reclassified. The ongoing
schema55 implementation stays in the recovery worktree and is excluded.

Availability rows are unchanged from main in this increment. Main's inherited
536/131/61 count is not a fresh production audit; the recovery ledger's stricter
534/133/61 assessment and pending evidence reconciliation are separate work.

Final whitespace check passes. No source changes followed these passing checks.
The commit/push identity is recorded in git and the recovery ledger after push;
this document alone is not proof that publication succeeded.
