# Seven-root Go advisory component collection, 2026-10-03

The previously failing collection now completes all seven configured module roots using the unchanged Go 1.25.13 compiler and approved input manifest. This is package-level component evidence. Production release and full-MVS clearance remain false; no original 728 requirement row is promoted.

## Scope and retained guards

The separately versioned collector authenticates tracked source, normal module ZIP/GoMod checksums, compiler/scanner/Python/runtime inputs and every consumed advisory against the frozen official database. It scans an owned input snapshot with sanitized fixed commands, bounded output/process/time limits, a 2 GiB disk reserve, cleanup and joined descendants. Caller commands, authority flags and input drift are refused. Its environment-specific CLI requires the reviewed fixed inputs and tools; it is not a portable release gate or a deployed service.

Fresh failures identified three implementation mismatches: the pinned scanner's typed OSV serializer omits only `related`; the SBOM represents the standard library as `v1.25.13`; and a local module replacement has no version, independently of its original requirement version. The successor retains the complete original advisory bytes/document and reported OSV, allows only the verified schema-specific related omission, and keeps every other advisory field strictly equal. Module identities retain exact original/replacement versions and the fixed local-replacement multiplicity. No finding, UNKNOWN severity, module or failed attempt is waived.

## Verification

Portable collector tests: 26 passed. Existing release-gate tests: 3 passed. ESLint passed for both JavaScript files. Independent captured-platform plus portable tests: 27 passed after reproduced RED failures. The owned-runner tests cover success, exceptions, timeouts, output overflow and orphan cleanup.

Root's actual invocation ran from 2026-10-03T02:05:57.137854Z to 02:08:23.308721Z (146.171 seconds), exit 0, empty stderr, unchanged source pins and joined processes with zero new survivors. Every scan uses govulncheck 1.7.0, source/package scope and Go 1.25.13. The exact observation roots are:

| Module root | Findings | Unique consumed advisory bindings |
| --- | ---: | ---: |
| `services/health` | 0 | 167 |
| `services/platform` | 3 | 249 |
| `services/event-ingest` | 0 | 177 |
| `services/gateway-control` | 3 | 216 |
| `services/runtime-gateway` | 3 | 239 |
| `services/sensor-agent` | 0 | 206 |
| `cmd/agentsecctl` | 0 | 167 |

Platform, gateway-control and runtime-gateway each report GO-2026-5932, GO-2026-6354 and GO-2026-6355 against crypto 0.55.0, all UNKNOWN. The two SSH advisories identify 0.56.0 as fixed; OpenPGP 5932 has no fixed endpoint. Empty findings in the other package scans do not imply a clean complete module graph.

## Evidence identities

The immutable local invocation bundle is `/workspace/scratch/production-go-advisory-root-actual-v4-replacement-role`. Previous failed invocation and diagnostic bundles remain unchanged.

* Approved canonical input manifest: `d25585907c7a50c963f215b1414ff3caae875e95cf284653234d78af8463c190`.
* Fixed invocation envelope: `f214cb601d92825678a43930de725596a28bef73fc6ecadf80f6279d505a8e09`.
* Outer stdout: `1e0a72b416ac3d504a4a3bc8c9dc02e11977e7a5b0d160acd62b1fa4cea24b70` (18664470 bytes).
* Decoded component: `b6176f28848d0441016c6ed77506bd49c1fbe038c382bd80649d6393f6e734a7` (13,977,752 bytes).
* `scripts/collect-production-go-advisory-evidence-v1.mjs`: `e80588900a50903ab713d7a4fbcd3f10458280c3af1a0431229edac66afd4912`.
* `scripts/collect-production-go-advisory-evidence-v1.test.mjs`: `948b707d07e8accf658321b22ea050e39124f359edbc3b496687c8be6a56cfd1`.
* `scripts/production-advisory-owned-runner-v1.py`: `ff2151640e6d2f1d6715cc5cbf500d1478fd992a0dcbef2e67253f38984154e7`.

## Remaining acceptance

Independent actual-packet review accepted this component only: replay of all seven raw scanner streams matched their recorded inspections; all 1,421 original database bindings and 1,473 OSV messages verified. Sixteen binding occurrences omit only the verified `related` field while retaining the complete database record. Nine UNKNOWN finding occurrences remain unchanged. All process receipts joined, and owned snapshot/code/cache paths were absent after cleanup. The unconditional production release refusal remains. Complete npm policy, full-MVS advisory and severity policy, nine built shipping images, rendered third-party images, deployed identity/provider acceptance, native379 execution and verified legacy retirement remain open. A new compiler/dependency batch requires a new input manifest and new evidence; this frozen Go25 result must not be rewritten.
