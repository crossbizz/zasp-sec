# Cloud continuation evidence — October 2, 2026

This continues the original Agent Security Platform goal. It is a component
checkpoint, not production acceptance or completion of the 728 requirements.

## Starting source and handoff

Fetched origin/main at `e13ccb95451b03107681ccb59b3fc6fe175a228f`. The required
commit is the starting tip and passed the ancestry check. The two October 1
handoff documents, authoritative status/availability/owner ledgers, original
v1.5 plan, Temporal/OpenFGA design/execution plan and 728-ID crosswalk were
inspected before implementation. No repository or ancestor AGENTS.md or
writing-style.md was present. The workspace was clean at startup.

Fresh ledger validation: 728 rows, 523 production-available categories,
144 component-only, 61 blocked/external, zero missing. These classifications
are historical implementation evidence categories, not deployed acceptance.
No availability or owner row is changed by this batch.

## Superpowers and runtime

Local Superpowers skill files are installed at
`/home/agent/.agents/skills/superpowers`, pointing to
`/home/agent/.codex/superpowers/skills`. All 15 SKILL.md files are readable.
Upstream: https://github.com/obra/superpowers, commit
`8ca22dba9a94f28898bbce59f2537ff4d87c747d`, version 6.4.2.
The active executor skill catalog has not refreshed; this session directly
reads the installed files. The admin-disabled marketplace plugin remains
uninstalled. This is a local file installation, not plugin activation.

Applied executing-plans, systematic-debugging, test-driven-development,
requesting-code-review and verification-before-completion workflows.
Independent review used a fresh, read-only reviewer context. Existing session
authorization covers scoped branch commits and guarded integration; routine
permission menus do not supersede that authorization.

Node 22.23.1/npm 10.9.8 and Go 1.25.13 were prepared under
`/workspace/toolchains`. Node and Go archives matched official published
SHA-256 checksums over verified TLS; GOROOT selects that Go tree. Locked
`npm ci` completed (3,251 packages). The preinstalled Node22 requirement was
not met initially (Node24.19.0/npm11.9.0), and `/usr/bin/go` was not a working
Go compiler. No dependency locks were changed.

Docker28.4.0 passed the explicit local-socket check. Chromium is present.
Helm, psql and initdb are absent. Go1.26.5 for the isolated Neon proof was not
prepared. Local .env files, complete ignored historical archives and old
branch objects were not transferred; limited retained reports do not supply
those missing archives or prove their previous observations anew.

Cloud configuration reports current observations but unknown network-policy
and runtime-variable readiness, no secret bindings and no outbound identities.
Database, Redis, Stytch and Temporal variable names are present; values were
not printed and actual service authorization is not established. OpenFGA
endpoint/store/model/token variables checked at startup are absent. No live
Stytch login, connector sync, provider effects or deployed E2E was run.

Git fetch/read access works. GitHub API access (`gh api user`) is forbidden by
the cloud network policy. The Go authorization build is blocked downloading
OPA1.17.0 through a redirect to storage.googleapis.com (Forbidden). No alternate
route, proxy bypass, TLS bypass or interactive login was used. No local
credential hook path was configured; the laptop-specific gstack hook repair
is not supplied by this checkout. No hook was disabled or bypassed.

## Reviewed batch: companion snapshot completeness

The owned A reference snapshot included
`ordered-current-worker-source-replay-v1.test.mjs` but omitted its direct
`ordered-current-worker-source-descriptor-v1.mjs` dependency. The regression
copies the actual builder snapshot into an isolated temporary tree and runs
the real replay companion. RED failed with ERR_MODULE_NOT_FOUND for that
adapter. The builder now lists the adapter and regression among its explicit
source inputs, retaining the existing strict topology/read/hash binding.

Grouped GREEN: nine outer tests passed, zero failures/skips; the isolated
child ran all eight replay cases, including registration refusal and hostile
source/frame/profile mutation checks. The first post-fix attempt successfully
ran the child but exposed an incorrect expected count9 in the new regression;
that assertion was corrected to the actual eight existing cases. Additional
builder group: five passed, zero failures/skips, covering source maxima,
current-input inclusion, deterministic packet and source/manifest hash binding.

Independent read-only review found no Critical/Important/Minor issues and
reproduced nine passing outer cases plus eight child cases. Approval is scoped
to component branch commit/PR, not main activation or native acceptance.

Traceability: this is a P0/P1/P7 source-only prerequisite for current migration
and installed-worker acceptance, supporting the retained M1-45, M2-06,
M7A-46 and M8-22b requirements. It does not satisfy or promote any of those
original acceptance criteria. All 728 IDs and milestone coverage stay intact.
No SQL, generated reference, historical capture, runtime pin, permission,
production guard or UI behavior is changed. General closure of every other
companion import is not claimed.

## Fresh baseline and integration gates

- Launch runner: 12 passed, zero failures; rerun with pinned Node22 also
  passed all12 cases without skips.
- UI: 246 files; 2,533 passed, two failed. Sensor surface request assertion
  failed in the full concurrent run, then its isolated case passed (one
  passed/29 excluded). The full-run failure remains unresolved; the isolated
  pass is not a replacement for it. Nango release-render contract failed
  with `release rejected`; the required Helm executable is absent, and a
  focused invocation also failed.
- Migration group: 517 tests; 404 passed, 63 failed, 50 skipped. Failures
  include missing historical evidence, stale references/source identities,
  pinned macOS executable paths and native admission restricted to the
  approved Darwin/ARM64 executable. No fixtures or runtime authority were
  synthesized to turn these failures green. Full log is retained locally.
- Go: orchestration passed; authorization setup failed on denied OPA download.
- Typecheck and production UI build passed. Compiled import graph passed
  (seven client/eight server chunks).
- `npm run verify` stopped at dependency regressions: seven passed/two failed.
  The failing async/sync TypeScript transform and drizzle generation cases
  reported `owned process group survived child exit`. Remaining verify
  stages were not reached; no full-verify pass is claimed.
- Consolidated-reference `--check` reproduced the documented contract mismatch.
  This early check used the original installed Node24; subsequent source-only
  batch checks used pinned Node22. Generated outputs were not refreshed.
- The existing license/advisory, native379/registration, portability,
  installed-worker, capacity and deployed-provider gates remain open.

Main integration is gated by the required baseline/release checks. This
checkpoint may be committed on the continuation branch, but must not be
merged to main or used to enable guarded execution while these checks fail.
GitHub API policy prevents creating a PR through gh in this cloud session.
Git write authorization must be established by an actual non-forced push;
read access alone is not a write receipt.

## Review rulings

The reviewer declined to judge the pre-existing macOS-specific builder-test
Node path, native/production acceptance, broader728/release completion and
other companions' general dependency closure. Ruling: keep those separate
from this bounded descriptor repair and explicitly retain each gate. Cost if
wrong: this narrow component packet could be mistaken for wider acceptance;
the unchanged refusal guards and this report forbid that interpretation.

## Local evidence

Logs are under `/workspace/continuation-evidence`; that directory is local
runtime evidence, not an uploaded archive or guaranteed future transfer.
Hashes below bind the observed files without publishing credentials or raw
provider responses. No historical immutable evidence is rewritten.

| Log | SHA-256 |
| --- | --- |
| `runner-baseline.log` | `87bad58e2955691e95f07d8cc97cdeb3a3082e6307b244d0c8617c6cd0efae29` |
| `npm-ci.log` | `65e14dfa1e7e86fbd4ecd567e1af9c077c41c2bc5e67ee17aa4a8c1b4b25a21a` |
| `companion-red.log` | `4e96b482b949dd31c9f52290d4b20042ef79634d2516b8827b58b9365f4a2cec` |
| `companion-green.log` | `3d6c53f682492265ff13b83c0e02bce834f58690cb1d76676ef67359fc2d9c1e` |
| `companion-builder-group.log` | `331cac701ce5469592a13b73a0ffb23a4f0c2d88e192520d5a8d51f7be0e8077` |
| `ui-baseline.log` | `e07c136fcddfde6be69876860ef978634165a909a325450aeadd96779b13408c` |
| `migration-baseline.log` | `21e9f6ad475f24997a274d559fbdcd0f9772aa56e99db1e7bc483a32815eec7f` |
| `go-baseline.log` | `aaf1feca9e9383b24284c2e2a7bacd6b24f31882748af8fbbd0ac1f10fd83cee` |
| `verify.log` | `9127053a6ee1b4cb1e3ac1a1bffdfa55337df5b8cdf648d153b9db073da16a64` |
| `typecheck.log` | `f48bd1876f5408ffc0d939a2b0d826961d6115e6598a272fea04d98ac0431816` |
| `build.log` | `2bcffdeb2aec7495159868e53d7032ad142fa57183429c230875fbbce1050b55` |
| `compiled-imports.log` | `f819147b10ccdaab0ec2d7c8f00cd76e12cb14d5067329548bfac497fa95cae3` |
| `sensor-ui-focused.log` | `1387a799634ef74f767526cfdc001fde1278493fbd91945b34364327095a8083` |
| `nango-release-baseline.log` | `f0b96979de8166a781860750c0e88f187d487b7d971442c7919199f6c50b4f86` |
| `reference-baseline.log` | `986f06b0697579ddc5c795d4a8064eaf1aba75351001e7e7a1f546f7e5a7b4e7` |
| `runner-pinned.log` | `ed5b888f94eec326fde28e9e7891761a9d7356e60905edd329762528923f11c4` |

Original milestone rows: M0=27, M1=68, M1A=10, M2=72, M3=75, M4=82, M5=42, M6=36, M7=62, M7A=113, M8=141.


## Connected ordered-cleanup recovery checkpoint

This extends the approved Temporal/OpenFGA execution plan P3, particularly
original M7A-49 ordered execution and M7A-59 cancellation/cleanup. It is
component-only verification. Existing ledger categories, immutable generated
references, database authority profiles and runtime refusal guards remain
unchanged; no original requirement is promoted by this packet.

The ordered Security Agent workflow now retains its admitted scope, original
business deadline and terminal reason/outcome through a cleanup-only
continuation. Transient dependency failures and cleanup-pending observations
retry in bounded histories; permanent authority refusals still fail closed.
Resumed cleanup cannot plan, apply, advance or test another action. An SDK
version marker retains the existing finite compensation path for old histories.
The registered worker includes the cleanup workflow. Duplicate outbox starts
validate immutable root and predecessor continuation events, queue, run IDs
and exact input before acknowledging an already-started cleanup execution.
Mutable workflow metadata is not admission evidence.

Grouped TDD observed the cleanup-recovery and continued-start failures before
implementation. Tests cover original outcomes/deadline, cleanup-only resume,
standalone refusal, transient batch exhaustion, untrusted hints/cancellation,
and foreign scope, deadline, reason, queue, root and predecessor rejection.
Independent review approved the component scope. Its historical-compatibility
check exercises the SDK's mocked DefaultVersion branch; no recorded pre-change
history replay or live Temporal acceptance is claimed.

Two baseline fixture repairs accompany this packet. Linux dependency tests
now distinguish unreaped dead Z/X process-group members from live servers;
missing metadata, absent membership and changing snapshots remain conservative.
The reviewer found an initial fail-open snapshot race, which was repaired and
independently reviewed before publishing. Actual esbuild/drizzle regressions
and membership/error controls pass10/10 with no skips. A planner credential
fixture explicitly sets0444 because inherited cloud umask0077 otherwise
produces0400. Production exact-mode validation and the0400 rejection remain.

Fresh orchestration and authorization race packages pass. The full UI suite
passes2535 tests across246 files with the pinned runtime and prepared Helm;
the original two failing UI observations above are retained as history.
The corrected full worker package passes. The broader API baseline remains
failed: native database fixtures report migration2 failures, and the suite
reached its default10-minute timeout while building a budget process-loss
worker. That failed run is retained; it is not an API acceptance receipt.

Runtime preparation added sumdb-verified Helm3.19, locked OPA1.17 downloaded
through the approved goproxy.io mirror with matching repository checksums,
PostgreSQL17.11 and exact PostgreSQL18.3 core smoke tests, and a Chromium
headless smoke. Core PostgreSQL smoke does not verify all extension/migration
requirements or qualify the pinned Darwin/ARM64 native379 authority lane.
The current cloud policy reports enforced package-manager networking and
ready generic runtime variables, but no secret bindings or outbound identities.
The required actual ZASP_DATABASE_URL, ZASP_RUNTIME_SERVICES_ENABLED,
ZASP_ENVIRONMENT, ZASP_TEMPORAL_*, ZASP_OPENFGA_* and ZASP_STYTCH_* application
inputs checked here are absent. Generic names are not application configuration.
Digest-pinned local Temporal/OpenFGA container pulls failed at Docker Hub's
unauthenticated rate limit; no live cluster or provider mutation followed.

A fresh production release gate rejects the unresolved exact-release Nexus
proto-annotations license evidence before later stages. The approved fresh
advisory evidence gate also remains open. Main integration cannot proceed
through these guards. The reviewed component branch is the deliverable;
production activation and original728 completion are not claimed.

The next connected implementation batch is current-authority inventory API
coverage: detail/update operations and capability/relationship collections
need explicit current SQL contracts and secondary-resource authorization
before pagination. Legacy sessions returning an empty collection are not
verified session history. This requires an additive current profile and
actual installer/native authority verification; do not edit frozen predecessor
artifacts, loosen statement whitelists or infer readiness from component tests.
Ordered provider artifact settlement, native379/current registration, real
Stytch/provider acceptance and all original external gates remain tracked.


## Final runtime and verification observations for this packet

The missing pgcrypto extension in the first PostgreSQL18 core preparation
was confirmed. The same SHA-verified official PostgreSQL18.3 source was
rebuilt in a separate prefix with OpenSSL and zlib, and contrib/pgcrypto was
installed. An owned database passed CREATE EXTENSION pgcrypto, exact
server_version_num180003/extension1.4 and digest/HMAC/crypt controls, then
stopped cleanly. One previously failing real-PostgreSQL API authority control,
TestProductionSecurityAgentAutonomousResponsePostgresInstallsExactAuthority,
now passes. The earlier broad API run has489 top-level failure entries and a
timeout; it was not repeated or converted to a pass by this one control.

Fresh npm verify now passes dependency10/10 and progresses through health,
API health, the full worker race suite399.671s and event-ingest race checks.
It then fails the runtime-gateway unsafe-file fixture: umask0077 masked its
intended0640 mode to0600. The fixture now explicitly sets0640; production
permissions remain unchanged. Targeted RED and the complete corrected
runtime-gateway race suite passed in3.726s. Later npm verify stages were not
reached; this packet does not claim full verification. Independent review of
both umask fixture repairs found no blocking issue.

The reviewed batch is prepared on codex/cloud-continuation-20261002. Normal
branch publication preserves main and existing security/release guards.
GitHub API access remains denied in this cloud policy, so no PR creation or
merge receipt is claimed. Main remains at the recorded starting checkpoint.

Final local evidence hashes (same local-only retention limitation as above):

| Log | SHA-256 |
| --- | --- |
| `ordered-cleanup-red.log` | `77b17860bfe220a8ebb18ba4140e4eb4c86846e92155daf83c90862bc7617581` |
| `ordered-cleanup-green1.log` | `b398c3ba07bf6c0ea630135ffe710776ffb9ceafeb653dbde21b06437d989a64` |
| `ordered-start-red.log` | `e321358fd49776c21a3f881ec4a44db0ee8fc3f0a088d9c73cc616bbfc10b9ab` |
| `ordered-cleanup-integrated-green.log` | `02642ec60f8b64017e30bbddb1182f50cc5371dd91939ab9e557ca90dfb22aa3` |
| `ordered-race-authorization.log` | `603637e4ba70f56ed7b2188140d8242ee389ad3979ecc862698eba9e26f44b85` |
| `ordered-worker-api-group.log` | `f9ec141bfbeb94b48ef9feba009c95bb003fc2c32fa87029b642bc025dc322c1` |
| `ordered-worker-fixture-green.log` | `39fb287ea68e269b48382458bad9b088975eb96da350f7c76f535e89c127931d` |
| `ui-runtime-prepared.log` | `63b7fa2825175212e4e45ce9f86e7bf2b2fee37a0be28052a84f2ffcce84c0d1` |
| `verify-runtime-prepared.log` | `2f14df3d2e48677b2d72a045d5bd5140a1948ac2ed844629da360374223c590b` |
| `release-gate-current.log` | `185749672c531e8e2231b0c79143ca94dd3c272efacc20a66a9638e4734c0e67` |
| `planner-fixture-umask-red-green.txt` | `816b01e8ae0c896b3cf09ec1318c08cf935ec08786c513aec47091ad0775f784` |
| `gateway-fixture-umask-red-green.txt` | `406b2e5c73ce7745b679d16a383bb2ea4a7a418a2bbc862627b72cf5bf0bcdfc` |
| `api-pgcrypto-control.log` | `d0aeb0ff1eda018b5a60e0497a3adcd9a98b5922419454758bb2073032145942` |
| `runtime-preparation-summary.json` | `ec7cf6e7b236134b927509840e81dcede4e86d0025f1d9f1508de66fe0d2745a` |
| `runtime-readiness-observation.json` | `7582f996e8f8db19f6abdfb0563091df31bf141b47ccb13a380db77b3031e6a6` |
| `application-runtime-config-presence.json` | `f6a14befa449cf0ee9946e30ddd156465a5f31ed5b27f384a6a4e708fb85cae9` |
| `postgres18-pgcrypto-runtime-smoke.json` | `e68b3b531514755d304bd7719ed5d79d66b0a5f2e1d329079adf978de622963c` |


## Reviewed batch: current-authority inventory

Base: `c93c986b9261a62113db930b70cb2bacb5dbf92f`. Fresh origin/main remains
`e13ccb95451b03107681ccb59b3fc6fe175a228f`; the required ancestry check passes.
The official Superpowers file installation was reverified before continuing.
Cloud revision44 reports current observations, enforced package-manager-only
networking and ready generic runtime variables, but no secret bindings or
outbound identities. This does not establish actual ZASP_* application or
provider access.

Task mapping is retained in the existing728-row availability ledger:
M4-03 throughM4-15 cover current inventory lists/details, updates and the three
agent collections; M4-51/51c/51e cover connected detail/capability/session UI.
Only current_evidence was appended for these rows. Historical classifications,
IDs and owners remain unchanged:523production-available,144component-only,
61blocked/external, zero missing. This batch supplies local component and
application integration evidence; it does not requalify deployed availability.

The additive source14/canonical61 inventory profile preserves registered
61/79/80 predecessors and verifies their fingerprints before and after install.
It is installed idempotently through the registered migration operator, with
compiled catalog/readiness/owner/ACL checks. Current production wiring uses
its existing separate zasp_security_agent_api database for inventory, with no
fallback to the discovery database. The separate login cannot directly invoke
old public detail/update/capability/relationship/session shortcuts. Constructor,
resolver and each inventory effect transaction check compiled profile readiness;
the effect guard runs in that transaction before the existing signed fence.
No positive readiness answer is cached.

Detail supports all five stored kinds. Secondary-resource permission filtering
runs before keyset limit/lookahead. Sessions derive from stored runtime events
and summaries, require completed scoped cutover and bind exact/strong events to
the requested agent; earlier events for another agent do not change its start.
Parent permission is mandatory. Mutation scope, actor, kind, version, exact
replay, browser/PAT authority and revocation remain fenced. Cursor proofs bind
operation, credential and revision. Malformed statements remain refused.

Connected UI updates retain exact interrupted request/version/idempotency state
per agent. Definitive403/404 clears only that agent's pending request; network
and503 failures retain replay state. The shared query hook recognizes the actual
APIProductError shape and purges protected data on403, preventing a subsequent
network error from restoring the old data.

Grouped RED observations are retained, including parent response, current list
argument type, session cutover/version, UI request ownership and actual403 data
purge failures. Independent fresh read-only review found no Critical findings
and two Important findings: missing parents returned503 instead of403, and
session SQL omitted completed scoped cutover. Both were fixed with RED/GREEN
checks. Final real PostgreSQL18.3 application integration passes all ten groups
in63.36s; the owned server exits normally.
OpenFGA Check responses in this native fixture are controlled; PostgreSQL roles,
credentials, metadata, revisions, rows, mutations and deadlines are real.
Adjacent authorization/router/closed statement checks pass18.147s/0.131s.
Full affected API race checks pass6.606s;
new migration installer race checks pass3.316s and affected migrator race checks
pass95.082s. UI/query tests pass21tests, the related home group passes4tests,
and changed UI lint, typecheck, production build and compiled graph checks pass
(client7/server8 chunks). No Temporal/OpenFGA internals were tested.

Final review rulings:
- Retain legacy source14 discovery-role grants because changing registered
  predecessor bodies/ACLs would invalidate the preserved authority chain.
  Current inventory exclusively uses the separate checked login. Unmigrated
  legacy roles remain open work; the cost of treating this as global retirement
  would be an unverified authorization boundary, so that claim is refused.
- The reviewer declined completed native fixtures while they were being authored.
  The final real PostgreSQL run now covers the stated current inventory boundary;
  it does not supply pinned native379/worker activation evidence.
- External deployment/release acceptance and unrelated existing P7/vendor code
  were outside review. Those gates remain open; broader completion is refused.
No minor findings were deferred.

Original failed baselines and frozen evidence remain unchanged. Exact-release
Nexusv0.1.0 was independently matched to official tage558d6ed across all eight
module files; no license terms occur in that release. Current-main MIT terms
alone do not establish that pinned release's license. An official attestation
covering that release, or a reviewed successor, is still required by the guard.
Fresh advisories, actual Stytch/provider flows, native379/current workers and
production deployed E2E remain open. No obsolete implementation is retired
without equivalent behavior evidence. Main merge and GitHub API access remain
gated; normal verified branch publication is authorized.

Evidence below is newly produced local evidence, not a transferred historical
archive. Full logs remain outside git in /workspace/continuation-evidence;
these hashes identify observed bytes but do not guarantee transfer to another
runtime. Failed observations remain retained alongside passing runs.

| Log | SHA-256 |
| --- | --- |
| `inventory-ui-red.log` | `889f6c1b28616a116bbb2bcb410794a563ecd61dd2a7845e44013a3c75a845db` |
| `inventory-ui-green.log` | `bd684ed70eb6ab0af6c3ed952a58ebf0cba9df1ac0bb6dbf22cb6240b567e079` |
| `inventory-query-red.log` | `c5810ed6a58b6593ea7e7d55e4fbbeb4bc1bf1fe244c12cdd9103bb1a11e4c6e` |
| `inventory-query-green.log` | `fe9e303915365f93de41584de8ffd66a9d13ea3ad9c55d603723b3ae06a0eb3a` |
| `inventory-empty-parent-red.log` | `295cdf859df61112ac7c03b4b2aae70be9c21a6eca771de5e30dc656609d6acb` |
| `inventory-native-red.log` | `64ad084146afd874307a968b5ff7d6a6996c875f90fa75cbbe464d3e02fcbaad` |
| `inventory-native-complete.log` | `e123e9ef1a0dfa35ccf560fb2a6a6c9a2d414f8205f0dca688af99d07ca0b6df` |
| `inventory-native-final-guard.log` | `74d52f8cf209da554a7433a7e7c5dc152b16e893b0362ba05ba959d8b4ec40d9` |
| `inventory-transaction-acceptance.log` | `dfc386e6f4ce42858cc1dbc21fe95e0e7fee228fa23b3ba46a97eab9d40b56b6` |
| `inventory-api-race-final.log` | `33f32dfb1efd05826a1e98535fe440c387bdaed71dadaf46654f04200741345f` |
| `inventory-migration-race-final.log` | `fb6a51664914ed3e7c98758aeb156b4cc68ded16a23f4326a401dbf55a570848` |
| `inventory-migrator-race-final.log` | `fd12e9b34bf58a739e80bc93f67a7c1f29df3bbbba1a56bc6945886a9b12947f` |
| `inventory-ui-query-regression.log` | `cf71b8e3fec424b063c16d4ec875d80a3c6c9d0d80a80bfd600f86ed3e189592` |
| `inventory-ui-home-regression.log` | `d474936bde1db290d789b1e3c83368d1f61f14dcf02acfcb092d0ab154b0dde1` |
| `inventory-ui-lint.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `inventory-typecheck-final.log` | `f48bd1876f5408ffc0d939a2b0d826961d6115e6598a272fea04d98ac0431816` |
| `inventory-build.log` | `b9fd875ab446a85eb8bd82e1472ff0d6ddb707ad6ba89985f7748c62bc4b4f1c` |
| `inventory-compiled-imports.log` | `8bd395004fcdf411bb9cb003d142cd797802f025847a6c996ecf8e7cbd7b7926` |
| `nexus-exact-release-license-recheck.json` | `3e4c5546aa2be641f27f4ecb2c5bae938ddcbed4a20bedaf2d2ad51d88e516d1` |
| `inventory-profile-red.log` | `f9470756625dcb540a7854597151bd8de3a7e0c696331bdf6d08686503673971` |
| `inventory-profile-fix-group-green.log` | `15a2624f245c451cbac2bf80ad2a6119117c372733a327b86fdcbd494262d3ce` |


## Reviewed batch: real local OSS application integrations

Inventory batch8f88e030779e08707b48e4bf5cfc1d9078a41d99 was normally pushed;
remote branch SHA matched. No main merge or PR receipt is claimed.

Official module/sumdb-verified OpenFGA1.21.0 (commitab557c5592670c899de35297e7aa067015f06502)
and Temporal1.32.0 (commitd94e34a1ebba5410a2e7d07119a76896909591aa) were built
outside the checkout with isolated Go1.26.8; application checks still use pinned
Go1.25.13. Owned PostgreSQL18.3 supplies pgcrypto1.4 and btree_gin from the same
verified source. Actual Temporal GetSystemInfo reports1.32.0 on127.0.0.1:7233;
owned zasp-dev namespace registration succeeds. OpenFGA authenticated health is
SERVING on127.0.0.1:8088 and the checked-in eight-type model is published.
These are source-built local artifacts, not acceptance of the pinned Docker
image digests. Existing Docker pull failure remains part of the record.

The two existing application OpenFGA integration tests previously failed
because their real Docker-inspection credential fixture was unavailable.
A shared test-only helper now permits an explicit absolute private regular
file selector and literal-loopback HTTP endpoint; malformed explicit selection
fails without fallback. Missing selectors retain real Docker inspection, with
a bounded five-second inspection. Token values and SDK errors are not printed.
The production code, model and runtime configuration are unchanged.

Grouped RED/GREEN preserves the actual existing model assertion bodies and
fresh owned store/model pinning. Real OpenFGA checks pass93application
permissions and25organization/identity checker decisions, plus machine/model
denials and role/membership revocation. Three selector refusal/default tests
pass. The complete authorization race suite with both real-model opt-ins passes
once in6.797s. Fresh read-only independent review reports no Critical,
Important or Minor findings; no unchanged expensive suites were repeated.

Final review rulings:
- Digest equivalence/deployed acceptance remain outside this native fixture;
  treating a source build as a deployed receipt would erase the release guard.
- Runtime version enforcement belongs to the observed build/service receipt,
  not the test credential selector. The receipt pins the actual exercised
  source/binary versions; a later caller must supply fresh provenance or its
  run establishes only behavior at that endpoint.
- Other production prerequisites and vendor internals were outside review;
  their original completion gates remain in force.
- Live Docker success was unavailable. Its default behavior is preserved by
  inspection and selector controls, with no live-Docker success claim.

The existing TestSingleTestLiveCleanupContinuation also passes against real
Temporal in3.55s: cleanup continues after64pending observations, live and
terminal duplicate-starts verify continued history, and business execution is
not reentered. Product cleanup proof is controlled in this test; this is local
workflow/history integration evidence, not PostgreSQL/provider cleanup or
recorded pre-change history replay acceptance. No vendor internals were tested.

Fresh production:release:gate still rejects the exact-release Nexus license
before later gates. No allowlist, immutable reference, authority checksum or
activation guard was relaxed. Required actual Stytch/provider credentials,
approved remote network access, fresh advisories, native379/current worker
registration and deployed end-to-end acceptance remain prerequisites. All728
rows and523/144/61 historical categories remain intact. Original goal completion
and obsolete legacy-role retirement are not claimed.

| New local evidence | SHA-256 |
| --- | --- |
| `openfga-native-fixture-red-green.txt` | `7b27f8353b0b7d56ca704e540fd9b01641b1b98594090dbceadcbc1688c11df1` |
| `native-source-runtime-acceptance-receipt.json` | `4a1e057d7e1a7454c9e718def213aff9e03341001cab393822a18d874367e437` |
| `native-temporal-local-setup.json` | `0fae65c8e7ed07828e4b4b4f4ce2da178b59ee95eef1f5cdeb499345fbb6f94e` |
| `native-openfga-product-model.json` | `856ca058923d0a0aacf845794a313a2fd49958cff9f662f1d3c88b1baf71d0fd` |
| `ordered-cleanup-real-temporal.log` | `8dfeaaf460c0049a4cebc834f06540dcc52cf0e82d2ff6a19d643603a83adcd7` |
| `inventory-release-gate-final.log` | `185749672c531e8e2231b0c79143ca94dd3c272efacc20a66a9638e4734c0e67` |
