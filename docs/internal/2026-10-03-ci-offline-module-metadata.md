# CI metadata preparation for the offline API module-layout test, 2026-10-03

Hosted checks identified one failed test, `API build dependency stage resolves its copied local health module`, with 286 tests, 285 passes, one failure and no skips. The annotations did not expose its assertion or child error. Its actual hosted cause remains unknown.

The workflow adds one five-minute CI preparation step before the unchanged canonical `npm run verify`: `GOENV=off GOWORK=off GOFLAGS= GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go list -C services/platform -mod=readonly -m all >/dev/null`. It populates module metadata for the existing platform graph and local health replacement. The dependency validator parses source manifests and does not perform this operation. Existing workflow steps, compiler pin, verification order, failure propagation and package scripts remain unchanged. The original regression still uses sanitized offline Go, `GOWORK=off`, `-mod=readonly`, the exact copied health path, source-lock equality and its 30-second child deadline.

Root reproduced a specific cache failure under pinned Node 22.23.1 and Go 1.26.8. With a new empty private module cache, the unchanged original regression failed in 0.140 seconds with module lookup disabled by `GOPROXY=off`. Normal official proxy/SumDB metadata preparation then completed in 7.045 seconds. The same original offline regression passed in 0.140 seconds, with one pass and no failures. Its private cache contained 469 files totaling 84,035 bytes, with no ZIPs or extracted modules; the cache roster was identical after the successful regression. All five owned processes joined. Source, platform/health locks, original test/runtime launcher, package inputs and tool bytes remained unchanged, including the absent health checksum file.

This controlled experiment demonstrates that metadata preparation resolves the reproduced empty-cache failure. It does not identify the hosted error or establish hosted GREEN. Source-contract TDD first rejected the original workflow for its missing preparation step. The author’s two focused contract suites passed 286/286; Root independently repeated them with 286/286 passes, zero skips, in 45.30 seconds. Independent source and bounded-recipe reviews approved their narrow scope. Independent review of the actual result verified all ten raw streams, five joins, source/tool bindings and complete metadata-cache membership, and approved this scoped diagnostic evidence.

Immutable evidence:

- Source candidate freeze: `/workspace/scratch/ci-platform-mvs-metadata-preparation-v1/freeze.json`, SHA256 `7b74623d2c41180732ba70a7dfaf80f983cf9d1782cb9994a53bf12ea55ec30a`.
- Root-only recipe freeze: `/workspace/scratch/ci-platform-mvs-causal-recipe-v1/freeze-v2.json`, SHA256 `fdbdb977454f927adc0fbef644c27b4683f4565d0abe21decacdb16bd19afa11`.
- Actual causal receipt: `/workspace/scratch/ci-platform-mvs-causal-actual-v1/receipt.json`, SHA256 `ddc77b04e5b02fb44fd2e82841912393c31b601d646def440fea811132bb0ba9`.
- Identical post-prime/post-regression cache rosters: SHA256 `eab56028eefa8e8010a656ec1a13a7365f176520bb63263e3355e8f8dda64c85`.
- Root focused contract log: `/workspace/scratch/root-ci-metadata-contracts-v1.log`, SHA256 `05b5a6a81dc58ec5f8093be81b6eb3588afe6e3e751cf5b9362430009b35a166`.

No test, offline/cache guard, deadline, source lock or acceptance requirement is weakened. This evidence grants no full-suite, release, native, installed-upgrade or deployed acceptance, and changes none of the original 728 requirement statuses.
