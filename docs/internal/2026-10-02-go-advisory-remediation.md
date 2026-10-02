# Bounded Go advisory remediation, October 2

The platform dependency batch removes GO-2026-6443 (grpc1.83.1) and GO-2026-5942 (x/net0.55.0) from actual scans against the same official Go database. This is specific-ID remediation, not overall advisory clearance. Production release remains blocked by the unchanged advisory guard, missing complete image evidence and unresolved findings. No severity or exception policy changed.

Official source authority: golang/vulndb commit `5cd8418cf9c867d344fda07a73ea844b0f34bca2`, tree `6a03454f45ac9c36b4cbd7e7feb539199cb5ee8d`, full2621-commit history,4577OSVfiles. The unchanged official `cmd/gendb` preserves Published and per-file Git-derived Modified times. It generated9160files; output rosterSHA256 `f5f4c48f0a2b43056b7923876cc929431f1ea3743ac5e5a41bed6ec3dacaf2e5`. Original database modified time remains `2026-10-01T20:24:15Z`, distinct from fetch/generation time. Exact original source, generated database, signed-checksum toolchain record, generator/scanner binaries and scan receipts are retained privately under `/workspace/scratch`; they are not caller-selected release trust.

The generator alone used separately verified Go1.26.2. Production compiler and govulncheck remain Go1.25.13; govulncheck is exactv1.7.0, normal module sum `h1:4MQBuhmXbz2uepNJrf3v+aaZLGDqw1JluwYboegA1qg=`, binarySHA256 `dbb441370210966cd75102a609865d33589917473bb705a04e3b9e9627af2bb2`. Scans explicitly used the official generated `file://` source, sanitized environment, readonly locks and disabled module-network access. Direct vuln.go.dev403 is denied network access, not absent configuration; this explicitly authorized official-source transport does not invent an unofficial mirror.

## Exact dependency closure

The initially proposed two-version change was stopped before mutation because grpc1.83.2 requires net0.58.0. The reviewed approved closure updates six existing platform go.mod entries:

| Module | Before | After |
| --- | --- | --- |
| google.golang.org/grpc | v1.83.1 | v1.83.2 |
| golang.org/x/net | v0.55.0 | v0.58.0 |
| golang.org/x/crypto | v0.51.0 | v0.55.0 |
| golang.org/x/sync | v0.21.0 | v0.22.0 |
| golang.org/x/sys | v0.45.0 | v0.47.0 |
| golang.org/x/text | v0.39.0 | v0.41.0 |

Exact required graph-only transitive changes are x/mod0.37.0→0.38.0, x/tools0.47.0→0.48.0 and x/term0.43.0→0.45.0. Isolated actual MVS confirmed exactly these nine version changes, with no other module changes. All are Go1.25-compatible. No generic upgrade/tidy was used. go.sum adds14normal verified checksum entries and retains existing entries. Go minimum1.25.4, production compiler1.25.13, licensed Nexus successor and local health replacement remain pinned.

Frozen platform go.modSHA256 `0605147a11b221177cfc9a6093a4ce165800702ca9ab23fcfe891476a72e62ad`; go.sumSHA256 `1228219a6c3691dd45177f3d85fabfd4c66ef273b1c7c79a944e42491a2b3df3`.

## Actual RED/GREEN and compatibility

The baseline actual package and symbol scans each reported20findingmessages/19uniqueIDs, including both targeted IDs. The isolated candidate against the identical official database reports3findingmessages/3uniqueIDs; both targeted IDs and14additional IDs disappear. Each receipt checks exact lock hashes before/after. Candidate package reportSHA256 `7b9c3c313f5701799cf38bd8fe0535175b4777ebe9ee78b5c6f2b9345c8f6030`; symbol reportSHA256 `74457090d22faa3db6d86c3b690ba1aa901c8c74a551c09184a148d261778f9c`. Scanner JSON exit0 is collection success and can contain findings; it is never a clean-policy assertion.

Baseline symbol scan had no reachable affected-function traces and one affected imported-package trace for grpc/internal/transport. Candidate symbol scan has no affected imported-package or function traces. The unchanged-source compatibility candidate passed actual Go race tests for identity, authorization, orchestration, agentsec-api, externalclient, database, jobqueue and healthserver. CGO0 API build passed; artifactSHA256 `cf03cf84ea71f607c8adbb4d33e4565ed29085724555abe2a67001c17687d169`. `go mod verify` passed. Live exact lockfiles were copied only after these checks and their original hashes were rechecked; live readonly MVS matches the candidate.

Remaining official IDs are GO-2026-5932 (unmaintained openpgp, no fixed version), GO-2026-6354 and GO-2026-6355 (SSH fixes require crypto0.56.0). Crypto0.56.0 requiresGo1.26.0 and is incompatible with the production compiler pin. No affected package/function trace was observed for those three in this platform scan, but this does not approve unknown severity or grant an exception. All19originalOSVs lacked top-level severity metadata. Full seven-module, final shipping-image, rendered third-party image and fresh release-policy acceptance remain separate work.

Private evidence: `advisory-prerequisite-proposal.md`, `platform-go-advisory-correlation.json`, `go-security-candidate-mvs-delta.json`, `go-security-candidate-advisory-differential.json`, actual baseline/candidate package/symbol JSON and receipts, candidate race/API build logs, immutable official source/output rosters and `official-go-vulndb-prerequisite-receipt.json`. No commit or publication was performed for this batch; independent review is required before claiming acceptance.

The preliminary platform-only report is preserved unchanged at `/workspace/scratch/go-consumer-closure/preliminary-platform-report.md` (SHA256 `8829faf6755fbda8561a44ef97106e1c3b6a34bf82d3b11d1258dc293a4f6d5f`). The following authorized consumer closure supersedes its temporary readonly-resolution limitation. Original old08bc locks and all failed attempts remain retained as independent evidence.


## Final consumer closure

Scope is ten lockfiles (platform plus four consumer go.mod/go.sum pairs) and this evidence document. Exact old commit `08bc8d5c402ab1d80f653041f94bfbcd392f2d4e` provided the causal baseline. With the supported normal proxy and ordinary Go checksums, all four unchanged consumer locks pass readonly MVS against the old platform locks and refuse against the upgraded platform locks. The first incorrectly sanitized attempt omitted proxy variables and produced DNS failures; that failure was retained and was not used to infer lock causality. The supported comparison has no input drift.

The refresh updates only existing requirement version lines from the approved nine-module roster. There are no new requirements, removals, unrelated upgrades or tidy. Event-ingest changes two existing version lines and adds four checksum entries; gateway-control four/eight; runtime-gateway five/ten; sensor-agent five/ten. Existing checksum entries are retained. Before the following compression patch, the ten-file batch has22existing requirement version changes and46checksum additions. Actual final MVS differences are restricted to the approved nine modules: event-ingest changes eight because its old graph already selected term0.45.0; the other three change nine. All seven shipping/CLI module roots now pass readonly resolution. Go minimums, compiler1.25.13, local replacement directives and the licensed Nexus pin are preserved.

All four consumers passed their actual full Go race suites and CGO0 binary builds in an isolated candidate with the final lock graph. The final candidate also repeated all eight platform race packages and the API build successfully. Each consumer `go mod verify` passed, with unchanged lock hashes. Only after these checks and live-original input hashes were rechecked were the four consumer pairs copied into the checkout. Live readonly graphs match the candidate; no source file or release guard changed.

A retained runtime fixture failure is independent of the dependency batch: `group_readable_database_file` writes0640 without a chmod, while inherited umask0077 creates0600. The exact old08bc fixture also fails under0077 and passes with child-only umask0022, which creates the intended unsafe0640 input. The unchanged guard then rejects it, and the complete updated runtime race suite passes. No assertion, source guard or test code was weakened. The test has an existing umask assumption; the failure and both baseline controls are preserved.

Before the compression patch, live package scans covered health, platform, event-ingest, gateway-control, runtime-gateway, sensor-agent and CLI against the same immutable official database, readonly locks, Go1.25.13 and CGO0. Platform and gateway-control retain the three crypto IDs above. Runtime-gateway additionally retains GO-2026-5841 in existing klauspost/compress1.18.5, with an affected imported s2 package (fixed1.18.7). An actual old08bc runtime scan also reports that same module/package finding, proving it predates this batch. The following separately authorized minimal runtime compression patch addresses that imported finding. The other four roots report no finding messages in these package scans; that is scanner output, not release-policy acceptance. No additional consumer symbol scan or severity mapping is claimed.

Final ten lockfile identities:

| Root | go.mod SHA256 | go.sum SHA256 |
| --- | --- | --- |
| platform | `0605147a11b221177cfc9a6093a4ce165800702ca9ab23fcfe891476a72e62ad` | `1228219a6c3691dd45177f3d85fabfd4c66ef273b1c7c79a944e42491a2b3df3` |
| event-ingest | `c269d7656dda7afaed597b8cb8463113b7219d7b591d20d01185678271b0a3f6` | `e7a85381cac36364c7c9a75e3b50926ece9fa405e84e5626ff70cc1769f7b529` |
| gateway-control | `70061342a23f5b06163fd82d1636acc1ebae76499fb7742a99fc4414045d9298` | `f91e798c0584524a6d86393f6c7ad8798877b7294be2901d4e71fba0a0295775` |
| runtime-gateway | `230f957f7fced944b050e90728a3dc93cd20346d042fae021dd095516a5e28c6` | `36ce6121510b7e113260644075081118db9890bba6820114069ec66856f174c9` |
| sensor-agent | `70ee7af2d66a87fee0d1158713a8cf11015f11017dca3f3630be7bb40fc64d51` | `1343f1d907678f4c9acedf607587181945312b2c927ad7c301ff4e247deb40a3` |


Retained closure evidence under `/workspace/scratch/go-consumer-closure`: original-lock roster, supported causal results, closed consumer graph/sum delta, exact module-download JSON, all seven final readonly MVS graphs, final lock roster, full race/build/module-verify receipts and logs, runtime umask controls, final seven-module package scan receipts/raw JSON, and the original runtime GO-2026-5841 scan. Build binaries are private prerequisite artifacts, not nine final shipping images. Unknown severity, unresolved findings, image inventory/scans and production release acceptance remain open. No commit or publication was performed.


## Minimal runtime compression patch

The preceding ten-lockfile candidate and document are preserved immutably at `/workspace/scratch/go-consumer-closure/frozen-reviewed-batch`, with eleven-file rosterSHA256 `2517fad26580d38c226f95cb2fca527ca2be769ac865d530038a997be83b20f2`. This subsequent authorized patch changes only the existing runtime-gateway indirect klauspost/compress requirement from1.18.5 to1.18.7 and adds its two normal checksums. No new global platform requirement is introduced. The runtime graph has exactly one additional version change and no other module changes; the complete ten-lockfile security batch now has23existing requirement version changes and48checksum additions, with no checksum removals.

Exact official module commit `8668e357e776d5152ed62f33c17f21b8690664fa` matches GO-2026-5841's official fix reference. compress1.18.7 requiresGo1.24 and is compatible with pinnedGo1.25.13. Module sum is `h1:aUyZsS4kH3QTKurYhAOwAHxllVPnOthb3vPfnF1Ehjw=`, GoMod sum `h1:cwPg85FWrGar70rWktvGQj8/hthj3wpl0PGDogxkrSQ=`. Ordinary module checksum validation and `go mod verify` passed; no production compiler/minimum changed.

The same official database and identical scanner configuration give actual package-level RED for GO-2026-5841 before this patch and GREEN after it, leaving precisely the three crypto IDs in runtime. The exact upstream `TestNewDictRepeatOverflow` passed with race detection, covering overflowing dictionary repeat values and the accepted equality boundary. The full runtime race suite and CGO0 runtime binary build passed. All seven final live readonly graphs pass. Other builds/races remain the validated preceding candidate because their lock bytes and selected graphs did not change.

Platform and gateway-control still select unused compress1.18.5 in their full MVS inventories; it was absent from their package scan inventories. This minimal runtime patch does not claim every MVS inventory is clean, approve unknown severity, erase unresolved crypto IDs, establish cross-platform portability or supply final image evidence. Broader module-inventory policy/pinning needs separate evidence and review. Original receipts and failed controls were not rewritten.

Compression proof is retained under `/workspace/scratch/go-compression-closure`: exact official module download, single-version graph/sum delta, matching-config actual RED/GREEN report identities, candidate package report, upstream dictionary regression/race/runtime build/module verify logs, final seven readonly results, final ten-lockfile roster and the separately frozen final eleven-file batch. No commit or publication was performed.


## Required dependency-policy closure

The final review scope is fourteen repository files: the ten Go lockfiles above, this document, `build/dependencies.lock.yaml`, `scripts/validate-dependencies.mjs` and its behavior test. The existing build-lock schema has no manifest SHA fields; none were added. Only three existing direct dependency records change: platform sys0.45→0.47, sensor sys0.45→0.47 and sensor grpc1.83.1→1.83.2. The validator retains its exact platform syscall metadata binding and updates only its approved version to0.47. All owners, SPDX license values, scopes, review fields, allow/prohibit lists, manifest/dependency rosters, exact key validation and replacement authority remain unchanged. The five changed Go manifest hashes are evidence above, not a new lock schema.

Actual x/sys normal verified module archive LICENSE bytes were examined for both0.45.0 and0.47.0. Each LICENSE is1453bytes and byte-identical BSD-3-Clause, SHA256 `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad`. ArchiveSHA256 values are `e51c1c88045b4edbe48ad810122131381ff541c89edbd97ef833ed6653b59e6a` (old) and `cdac013ddced0262926ec29ffcda645da39670e61c7e5b761e572b6b1809bb1b` (new). No module-cache license was substituted or changed.

Actual repository dependency validation initially returned `Dependency lock rejected`. Independently, the pre-existing synthetic positive fixture used sys0.44 despite the old validator's0.45 pin, causing five baseline behavior failures. That stale fixture defect is distinct from the new repository security-batch RED. The focused updated0.47 fixture and actual-repository acceptance tests were run RED before the policy change (eight failures); after the three approved records and exact validator pin were updated, the full behavior suite passed94/94. Tests preserve the existing0.43 refusal and cover old0.45, unapproved0.46/0.48, coherent lock-plus-manifest mutation, manifest-only drift, wrong allowed license, wrong owner/scope and existing generic policy/path/schema refusals. Actual repository inventory remains13manifests/42direct dependencies.

The complete bare `npm run dependencies:check` passed policy validation but refused one unchanged esbuild process-lifecycle regression: an exited esbuild native child remained a zombie owned by this container's PID1, so the owned process group still existed. Raw failure is retained; neither regression guard nor source was changed. The identical command under a private Linux child-subreaper runner passed all nine actual regression tests and returned actual exit0, reaping one owned adopted descendant. This is a local runner prerequisite, not a claim that unsupervised execution passes or an explanation of the hosted failure without logs. Root independently reran that same private command at21:06:41–21:06:42UTC; its live receipt/log replaced the initial scratch names, so the final proof freezes that actual later successful receipt rather than inventing the prior file hash. Previous PID1-owned zombies were untouched.

The policy proof retains baseline/focused RED logs,94-test GREEN, raw unsupervised npm failure, subreaper source and latest successful receipt/log, x/sys archive/license identities and the separately frozen fourteen-file roster. The preceding eleven-file snapshots and Go scanner/build/race receipts remain immutable. This policy closure approves reviewed dependency metadata; it does not supply advisory severity exceptions, all-MVS cleanliness, image evidence or release clearance.
