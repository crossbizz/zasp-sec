# Dependency advisory checkpoint

## Current integration evidence

The worktree's clean nested npm10 install17052 exited0. Root inspected final
logs for UI1625tests/208files, typecheck, lint and five-stage build, all exit0;
dependency checks pass9tests and refreshed npm audit reports zero findings.
The affected172-test group passed171 and failed only an undeclared transitive
OpenAPI test import. Crucially, its actual release-source SBOM/license test now
passes unchanged. The test import was corrected to resolve through the actual
generator/validator chain; its focused8tests pass. No unchanged UI/build rerun
is needed for that test-only correction.

The built standalone server served its page and referenced JavaScript asset
with200 on owned127.0.0.1:53377, stderr empty, and the owned process group joined
after SIGTERM. Root read both the bounded smoke script and its result. This
does not establish authentication, real browser rendering, native saving or
deployment. Nested integration is frozen and independently approved for SPEC
and QUALITY with no findings. Root read and hash-verified the complete review,
`f8b4852b25e8362e412ba37c0fd49b2d8942b4d61aee46d8df43dd1af2e211b5`,
and all32 retained integration evidence checksums. The review reconstructed
all seven current files from incoming snapshots and the patch, checked actual
consumer resolution and applied the unchanged license policy to the installed
SBOM. No broad suites were repeated. Native browser integration is now active.
Historical failing gates below remain retained evidence,
not the current release-source license result. No push or task promotion yet.

Independent combined dependency review now approves SPEC and QUALITY, with no
Critical or Important code finding. Root read the full review and matched its
SHA256fb60d903ae41d332819f251b12eaa0fc27c19cc3139eb0e9121520a64c942393.
Two Minor evidence corrections are recorded without rewriting frozen reports:
the correction lock has27 esbuild artifact/version changes plus34 libc-only
metadata changes (61entries total), and a documented checksum reader handles
the historical manifests' mixed path bases/single-space records. Root verified
all67 retained records (d9fdb9, exit0). Details and the reproducible command are
in local SDD `dependency-review-corrections.md`. The installed license gate is
still failing at that earlier checkpoint; the current nested integration above
resolves that local gate. Code-review approval is not release approval.

## Latest correction checkpoint, September 15

Full candidate result: pinned npm10 nested ci28254 exited0 (3254installed
packages,14.19seconds). Root inspected actual retained inventory/SBOM/native
output536d4d: zero invalid edges, one React/DOM/RSC copy each, both installed
Sharp native addons execute the same1x1PNG round-trip, and the64-entry
production SBOM passes the unchanged license block including its existing root
NOASSERTION exception. Unfiltered3255-entry SBOM remains retained, including
development license expressions. This is isolated-install evidence only.

Root authorized a scoped integration batch: consistent nested project/CI/web
container configuration, a tested4MiB bound for the larger package lock (other
limits unchanged), actual-consumer-relative esbuild regression resolution,
recoverable installation backup and genuine pinned project ci, followed by
focused and grouped verification. The candidate costs1,138,552KiB versus
639,016KiB for the previous installation. No app-level release clearance is
claimed before the integration, review and remaining runtime checks pass.

The recoverable clean pinned npm10 installation completed, but did not fix the
installed SBOM/license gate. The implementer retained the previous node_modules
at `/private/tmp/zasp-node-modules-backup.ZcUo7h/node_modules`; no deletion or
license waiver was authorized. This disproves the earlier leftover-only theory.

Root independently inspected pinned npm10's SBOM implementation and loaded the
actual and virtual Arborist trees read-only (command4f1c40, exit0). The installed
`@img/sharp-wasm32`, `@emnapi/runtime` and `tslib` nodes are all marked dev,
optional and extraneous. The WASM node has no incoming installed dependency;
its virtual parents are the optional FreeBSD and Webcontainers wrappers absent
on this host. Current package-lock.json marks the WASM node optional:true.
Contrary to an intermediate diagnosis, development classification is retained:
npm's SBOM selector explicitly includes extraneous nodes independently of its
development omission. The actual installed package still fails the unchanged
license policy. A lock-only inventory is not a substitute for resolving this
release gate. No package was removed to make the gate pass.

Root also inspected npm10's optional-failure removal code and evaluated its
`optionalSet` against each wrapper in the unchanged virtual tree (command10e69d,
exit0). Each set contains only its wrapper. The shared WASM child is retained
because the other wrapper is still an incoming dependency in that graph. This
explains a mechanism consistent with the clean-install orphan; it does not yet
prove a safe remediation or change the release policy. Independent diagnosis
is complete in `dependency-sbom-diagnosis-review.md` in the local SDD workspace.
No third project installation was attempted.

The paired sharp-only experiment now passes. Root read the complete
`dependency-nested-experiment-report.md` and both retained inspection JSON
outputs (ef3868, exit0): identical32 unique name/version/integrity tuples;
hoisted has three actual extraneous nodes and rejects WASM in its production
SBOM; nested has no extraneous nodes and its root-only production SBOM rejects
none. Both unfiltered SBOMs still report the actual native libvips development
license. Both native image operations return RGBA[17,34,51,255] and the same
91-byte PNG hash. Root also inspected the diagnostic assertions and distinct
nested wrapper subtrees. This is a minimal dev-only fixture, not the app release
gate or a license waiver.

Full-project nested candidate resolution is authorized only in owned
`/tmp/zasp-full-nested.IeG3PX`. Pinned npm10 resolution77705 exited1 with the
same Arborist loadPeerSet edgesOut error; no lock or installation was produced.
Root authorized the previously successful npm11 CLI under Node22 for isolated
lock generation only. The app's pinned package manager does not change.
Before any candidate install, artifact drift, platform entries and peer/module
identity must be checked. The app's manifest, lock and installation remain
frozen while the separate candidate is evaluated.

The correction owner reports nine bounded parser/esbuild/transform/schema
regressions passing (session10500, exit0). Root subsequently inspected retained
correction logs: full UI208files/1625tests passed, five-stage build exited0,
refreshed npm audit has zero findings, affected Node105passed/1failed with only
the unchanged installed-license rejection. Full lint found two new-test issues;
the focused correction passes all3 esbuild tests and both-file ESLint. The
independent review accepted that evidence without repeating unchanged suites.
The original728 task counts do not change. No live-runtime acceptance follows
from these checks.

The dated sections below retain earlier observations, including disproven
hypotheses, and do not override this latest checkpoint.

Read-only npm audit on September14,2026, against the existing worktree lockfile.
Node22.23.1/npm10.9.8. Owned session72467 completed: npm audit --json exited1;
the reporting wrapper exited0 after parsing that result. No installation,
dependency update, audit fix or lockfile mutation was performed in this check.

The registry response reports26 affected package entries:15 high,10 moderate,
1 low,0 critical. Propagated dependency findings are included; this is not a
count of26 unique advisories or26 demonstrated exploitable product paths.

## Direct dependencies requiring decisions

| Package | Locked version | Declared section | Audit severity |
| --- | --- | --- | --- |
| @cloudflare/vite-plugin | 1.37.1 | devDependencies | moderate |
| drizzle-kit | 0.31.10 | devDependencies | moderate |
| js-yaml | 4.1.1 | devDependencies | high |
| react-server-dom-webpack | 19.2.6 | devDependencies | high |
| vinext | 1.0.0-beta.2 | dependencies | high |
| vite | 8.0.13 | devDependencies | high |
| vitest | 4.1.10 | devDependencies | moderate |
| wrangler | 4.92.0 | devDependencies | moderate |

Sections and versions were read from current package.json/package-lock.json.
Development classification alone does not prove a package is excluded from
build, server-rendering, deployment or developer-exposed execution paths.

Other affected entries: @babel/core, @esbuild-kit/core-utils,
@esbuild-kit/esm-loader, @redocly/openapi-core, @vitest/mocker,
baseline-browser-mapping, brace-expansion, browserslist, esbuild, fast-uri,
fflate, image-size, miniflare, nanoid, postcss, sharp, undici and ws.

Representative advisory IDs returned by npm, to verify against primary
maintainer notices during remediation:

- react-server-dom-webpack: GHSA-wx67-qw84-cm4g, server-function denial of service.
- image-size via vinext: GHSA-w3rx-r6r6-pgpr and GHSA-5p2g-fcmc-qvqq,
  parser infinite loops.
- js-yaml: GHSA-h67p-54hq-rp68, GHSA-52cp-r559-cp3m,
  GHSA-5p4m-2wfm-xmqj and GHSA-2883-xcg3-v3hh, CPU exhaustion paths.
- vite: GHSA-v6wh-96g9-6wx3 and GHSA-fx2h-pf6j-xcff, Windows-specific paths.
- vitest/@vitest/mocker: GHSA-82fw-gwwq-j7x9, redirect-mock file read.

No remediation version is approved by this checkpoint. npm's proposed
drizzle-kit fix points to0.18.1 and marks a breaking change, despite the current
0.31.10 pin; do not apply that automatic suggestion blindly. Other suggested
upgrades also require compatibility and actual affected-flow verification.

Next security work must map advisory conditions to real imported/runtime/build
paths, verify maintained compatible fixes, make a reviewed dependency batch,
and rerun the affected build/test/security gates. Do not waive findings solely
because current tests pass. Until then this remains an open production gate.

## Source-path evidence, September 14

Read-only inspection of the installed packages and project entry points narrows
the next dependency batch. This is import/call-site evidence, not exploit proof
or a finding waiver. No package files were changed.

| Package family | Inspected execution path | Required verification after remediation |
| --- | --- | --- |
| vinext / Vite / Cloudflare plugin | `package.json:75-77` invokes vinext for dev, build and start. `vite.config.ts:43-55` imports the Cloudflare plugin and configures both vinext and the rsc/ssr environments. | Actual production build, start and authenticated browser flow; deployment build compatibility. |
| React server DOM | Installed `vinext/dist/entries/app-rsc-entry.js:111-119` conditionally generates decodeAction/decodeFormState/decodeReply imports when server actions exist. Its server-action executor calls the supplied decoders. | Inspect the actual generated server bundle and plugin resolution; check React/React DOM/RSC version compatibility together. |
| image-size | Installed `vinext/dist/server/metadata-route-build-data.js:5,32-34` imports imageSize and calls it on metadata image buffers read from disk. | Exercise metadata image build paths with the corrected parser; distinguish build input from any separately exposed request input. |
| js-yaml | `deploy/production/release-contract.mjs:360,417-418` parses rendered output; `audit-export-rollout.mjs:97` parses provider object configuration. Dependency and UI/API validation scripts also call load. | Run the release, dependency and UI/API contract checks using the corrected parser. |
| Vitest | `vitest.config.ts` imports vitest/config and runs app/web tests under jsdom; package scripts invoke both run and watch. | The grouped affected UI suite and full publication suite; review development-server exposure separately. |
| drizzle-kit | `package.json:136` invokes drizzle-kit generate. | Verify schema generation compatibility before accepting a replacement; do not apply the proposed downgrade automatically. |

A text search for `use server` in app, apps and worker source (excluding tests)
returned no matches. This does not prove the vulnerable decoding path is absent
from generated code or dependencies. Actual bundle inspection remains open.
Wrangler/Miniflare are part of the configured Cloudflare toolchain; the precise
advisory conditions and their reachable inputs still need inspection.

Batch sequencing: finish the active export contract implementation without
concurrent lockfile changes, then use this map for one compatible dependency
remediation batch and its affected gates. Reuse earlier runtime tests only when
the updated dependency paths do not invalidate their evidence.

## Primary advisory checks, September 14

The [React maintainer advisory](https://github.com/react/react/security/advisories/GHSA-wx67-qw84-cm4g)
confirms the installed react-server-dom-webpack19.2.6 is in its affected list;
19.2.8 is a fixed release on that line. The issue concerns resource exhaustion
through server-function requests. The project's RSC-capable server/build means
we cannot use the advisory's non-server/non-RSC exclusions without further
evidence. A patched version is a candidate, not an approved dependency set.

The [Vitest maintainer advisory](https://github.com/vitest-dev/vitest/security/advisories/GHSA-82fw-gwwq-j7x9)
identifies4.1.11 as fixed for vitest and @vitest/mocker. Its unauthenticated
file-read case requires a reachable development-server WebSocket using the
public mocker/interceptor plugins. Vitest browser RPC has a separate token
boundary. Project-source searches found no mockerPlugin, interceptorPlugin or
@vitest/mocker imports in app/apps/worker/scripts or the Vite/Vitest configs
(excluding tests); this is limited source evidence, not a dependency-wide or
network-exposure clearance. Installed4.1.10 still needs remediation.

The image-size advisory's linked upstream PR439 returned404 during primary
source verification. No maintained image-size fix was verified here. Keep that
decision open; do not claim an arbitrary newer version resolves both recorded
parser advisories. No exploit requests or malicious image/YAML fixtures were
executed against running services during this inspection.

## Candidate dependency constraints

Read-only registry metadata queries completed successfully in root command
output7152a5 with Node22.23.1/npm10.9.8. Installed package metadata was read in
command output1c00dc. Both commands exited0 without an ongoing session handle.
Commands queried version, engines, peerDependencies and
dependencies with `npm view <exact-version> ... --json`. No installation ran.

| Candidate | Verified constraint from registry | Consequence for the upgrade batch |
| --- | --- | --- |
| react-server-dom-webpack19.2.8 | Requires react and react-dom ^19.2.8. Installed React/React DOM are19.2.6. | Updating RSC alone would leave unsatisfied peers. Select and verify all three together. |
| vitest4.1.11 | Supports Node22 and Vite8; exact internal Vitest packages include @vitest/mocker4.1.11. | A same-line candidate exists; verify resolved internal packages and the affected UI tests. |
| js-yaml4.3.2 | Published with argparse ^2.0.1 as its dependency. | Candidate existence is confirmed; all four advisory fixes and parser compatibility still need verification. |
| vinext1.0.0-beta.9 | Requires @vitejs/plugin-rsc ^0.5.34; installed plugin is0.5.26. Its direct dependency map no longer contains image-size. | A vinext-only update is insufficient. Inspect the upstream parser replacement and complete resolved tree before claiming the image-size gate closed. |

Installed vinext beta2 pins image-size2.0.2 directly. The beta9 dependency-map
change is useful evidence for a maintained replacement path, but does not prove
image-size is absent transitively or that metadata images still work. This
checkpoint approves no version change and adds no production completion credit.

## js-yaml fix floor verified, September 15

Primary maintainer advisory metadata now resolves the previously open four-fix
question. The required 4.x floor for these four advisories together is 4.3.2:

| Advisory | Maintainer's patched 4.x version |
| --- | --- |
| [Repeated merge aliases](https://github.com/nodeca/js-yaml/security/advisories/GHSA-h67p-54hq-rp68) | 4.2.0 |
| [Merge-key chains](https://github.com/nodeca/js-yaml/security/advisories/GHSA-52cp-r559-cp3m) | 4.3.0 |
| [Ordered-map resolution](https://github.com/nodeca/js-yaml/security/advisories/GHSA-5p4m-2wfm-xmqj) | 4.3.1 |
| [Empty merge-source budget bypass](https://github.com/nodeca/js-yaml/security/advisories/GHSA-2883-xcg3-v3hh) | 4.3.2 |

Use the patched-version metadata even where the original report body still
describes an unpatched legacy line. The merge-chain fix introduces a default
10,000 merged-key budget; the later fix charges empty source mappings too.
The upgrade must check our rendered Helm/provider configuration parsing for
compatibility with those limits. Do not disable limits to make tests pass.

This establishes a candidate minimum, not installation or security clearance.
Current package.json still pins 4.1.1. Keep package/lock/node_modules unchanged
while the selected Security Agent browser run builds its evidence. The next
dependency batch must inspect all resolved copies, run affected release/parser
contracts, build the app and refresh the audit against its new lockfile.

## vinext beta9 is not an established parser replacement

September 15 primary tagged-source inspection contradicts a parser-removal
inference from the dependency map. The
[beta9 metadata reader](https://raw.githubusercontent.com/cloudflare/vinext/vinext@1.0.0-beta.9/packages/vinext/src/server/metadata-route-build-data.ts)
still imports image-size and invokes it on static metadata image buffers.
The [tagged package manifest](https://raw.githubusercontent.com/cloudflare/vinext/vinext@1.0.0-beta.9/packages/vinext/package.json)
lists image-size as a development dependency; the
[tagged workspace catalog](https://raw.githubusercontent.com/cloudflare/vinext/vinext@1.0.0-beta.9/pnpm-workspace.yaml)
pins it to 2.0.2. Its absence from published direct dependencies does not prove
absence from published bundled code. Inspect the actual package artifact before
claiming this advisory removed. Do not select beta9 merely to reduce audit counts.

Registry repository metadata was independently read with pinned npm (command
4808bd, exit0); no install or lockfile change. The security decision remains open:
verify a maintained corrected parser path or a reviewed bounded-input treatment
of the actual build input, with metadata-image acceptance. A newer version alone
is not proof, and the current working browser build stays unchanged.

## Published image-size 2.0.4 artifact inspection, September 15

Read-only registry discovery found image-size 2.0.4 and vinext beta10. The
image-size repository metadata now points to Codeberg. The attempted tagged
Codeberg source URL returned HTTP404 (session44563 terminal exit56); no source
verification credit comes from that request.

Instead, `npm pack image-size@2.0.4 --ignore-scripts` downloaded the published
artifact into the new owned directory `/tmp/zasp-parser-artifact.XSfM4M`.
Session82502 exited0. No project install or package/lock/node_modules edit ran.
The tarball SHA256 is
`7562a60f2316539588bd49f35213cf3e2b74229dc50ee8532b42c9adf157390a`;
its reported SHA512 integrity matches the earlier registry metadata:
`sha512-QRUkFFsRV/6fuESxb9Vkq+a0LkSrgKXuc2NEqfikiXxxN/G3tjWt5EVUlMaImRBZRZK/jRBEbYvpPYZL8t08Zw==`.

Root read the full published ESM ICNS, JXL, HEIF and box utility modules with
`tar -xOf`, without executing them. ICNS now rejects entry lengths below8;
JXL rejects partial-stream boxes below12; HEIF rejects ispe boxes below20 and
non-advancing offsets. The shared box scanner advances8 on undersized boxes.
The installed 2.0.2 ICNS code adds the supplied entry length without that guard.
These are concrete candidate fix-path differences, not executed regression proof.

Next decision: test malformed and valid metadata inputs against the exact
published parser, then choose a compatible resolved dependency set. Do not
assume beta10's omitted direct image-size dependency excludes a bundled parser.
No dependency finding is closed by this inspection; production build, browser,
resolved-tree audit and independent review remain required after any update.

## Bounded parser behavior checks

Root then ran both real ESM entry points in isolated Node22 child processes,
with `--max-old-space-size=32`, a750ms parent timeout, SIGKILL timeout handling,
and a16KiB output cap. The candidate was extracted only into the owned artifact
directory; the installed project package stayed unchanged. No service endpoint
received these inputs. Both parent diagnostics terminated normally.

| Input | Installed2.0.2 | Published2.0.4 |
| --- | --- | --- |
| ICNS16-byte file, icp5 entry length8 | width32, height32 | width32, height32 |
| Same ICNS, entry length0 | child SIGABRT | TypeError: Invalid ICNS |
| JXL signature + ftyp jxl + jxlp entry length0 | child SIGABRT, heap-limit diagnostic | TypeError: Invalid JXL |
| HEIF ftyp heic + meta/iprp/ipco/ispe, width16 height24 | width16, height24, type heic | width16, height24, type heic |
| Same HEIF, ispe length0 | child SIGABRT, heap-limit diagnostic | TypeError: Invalid HEIF, no sizes found |

Command outputs10d196 and e5f9c0 retain results. The malformed children were
owned and joined by spawnSync; none remains running. These checks establish
that the published candidate terminates on three reproduced parser failures.
They are diagnostic characterization, not the permanent product regression
suite, broad format compatibility, a Vite metadata build, or a deployed fix.
The next dependency batch must retain equivalent bounded regression coverage
at the actual imported parser boundary and verify the resolved dependency tree.

A fresh `npm audit --json` (session24357, terminal exit1) still reports26
affected package entries:15 high,10 moderate,1 low. No changes were installed.
It proposes Cloudflare plugin1.54.10 and Vite8.3.0 among other updates; these
remain unapproved suggestions pending primary fixes and compatibility checks.

## Vite selection and resolver recovery

Root selected Vite8.0.16 for the active batch. Both primary maintainer notices
name that fixed8.x release:
[Windows alternate-path denial bypass](https://github.com/vitejs/vite/security/advisories/GHSA-fx2h-pf6j-xcff)
and [launch-editor UNC credential disclosure](https://github.com/vitejs/launch-editor/security/advisories/GHSA-v6wh-96g9-6wx3).
Registry metadata accepts Node22.23.1. This is a selected update, not yet an
installed or browser-verified fix. No Windows exploit was executed.

Cloudflare plugin1.51.1,1.52.0 and1.54.10 registry metadata all select Miniflare5
alpha builds and paired Wrangler versions. Those candidates are not approved
merely from audit's suggested fix; their runtime compatibility still needs a
decision. Existing Cloudflare/Miniflare findings remain open.

The selected React/YAML/Vitest/parser install encountered npm10.9.8 Arborist
`edgesOut` errors in two terminal attempts, before lock or installed package
changes. Root inspected the stack and optional Vite-devtools/Vitest peer chain.
Recovery is an isolated lock-generation experiment using existing npm11.19.1
under Node22.23.1, then pinned npm10 installation and peer checks. No project
toolchain replacement, force resolution or legacy-peer-deps exception is allowed.

## Coordinated runtime selection and fresh lock

Later root decision: test the coordinated Cloudflare plugin1.54.10,
Wrangler4.132.0 and required workers-types5.20260915.1 in the same batch.
Their published peer/engine metadata permits the selected Vite8/Node22.
Miniflare5.20260915.0-alpha is intentional upstream dependency selection, with
sharp0.35.4, undici7.29.0, ws8.21.0 and workerd1.20260915.1. Earlier candidate
1.51.1 retained sharp0.35.2 below the recorded fix floor. This selection is not
runtime or release approval; typecheck, build and browser acceptance must
establish compatibility with the existing rsc/ssr configuration.

The nested Redocly1.34.19 package pins YAML4.3.1 exactly. Root explicitly approved
a scoped4.3.2 security override despite that upstream exact pin, with OpenAPI
and release/parser checks. npm initially kept the stale nested entry even after
a targeted update; those generated locks were rejected. Regeneration from the
intended manifest in the owned isolated directory (session46795 exit0) removed
that entry; all-peer validation returned0 with no problems. The old lock remains
preserved. Root read the fresh resolver delta and engine summary.

Three declared-range direct resolutions also moved: lucide-react1.46.0,
Testing Library React16.3.3 and user-event14.6.7. Root approved these with their
existing manifest ranges intact, requiring UI verification and matching reviewed
runtime version metadata. Exact direct pins stayed fixed. The final pinned
npm10 installation is underway (owner-reported exec91105); lifecycle scripts
remain disabled until the changed esbuild/workerd hooks are inspected.
No full-gate pass, audit clearance or production completion is inferred yet.

## First combined gate: passing build, three unresolved failures

Root read the frozen dependency-remediation-report.md and final command ledger,
plus raw full-UI, build, static and SBOM diagnostic outputs. Pinned installation
91105 exited0. Five-stage build37883 passed; typecheck/lint89320 each exited0.
Actual OpenAPI generation matched the existing generated client byte-for-byte,
and OpenAPI check/lint passed. These do not certify a running browser/server.

The affected Node group38627 had326 passes and two failures: stale js-yaml4.1.1
expectation in openapi/openapi.test.mjs and a release installed-SBOM failure.
Full UI58398 had1624 passes and one failure: audit source inventory now has220
declarations, while its old fixture assertion expects214. Root checked the six
added mixed-source declarations; lane coverage must remain independently checked.
The focused87-test export/dependency group45637 passed. No failed gate is waived.

Installed production SBOM reports47 packages and rejects leftover extraneous
@img/sharp-wasm32 for its combined LGPL license. Lock-only SBOM has44 and no
rejection. Three installed extraneous packages remain; a dry-run prune did not
establish their removal. Root authorized preserving the exact worktree
node_modules as an owned backup and a clean pinned install, followed by actual
installed-tree/license checks. Lock-only license output is not a substitute.

Fresh final-audit.json now reports four moderate package entries, zero high,
critical or low. All four belong to the esbuild0.18.20 -> core-utils -> loader
-> drizzle-kit chain, not four unique vulnerabilities. Root approved testing
a scoped core-utils esbuild0.25.12 override, outside its old declared range,
with a bounded cross-origin regression and actual sync/async transform plus
nonempty example-schema generation acceptance. No Drizzle downgrade or audit
exception is approved. The compatibility fix and two stale assertion corrections
are the next same-owner batch; independent review follows their frozen evidence.
