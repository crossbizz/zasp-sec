# Official vulnerability DB generator: lower23 checksum diagnostic, v1

Date: 2026-10-03 UTC. Diagnostic evidence only.

The 23 present lower-version module metadata files previously lacking a checksum in either retained sum set now have diagnostic provenance from normal Go1.26.8 execution and a fresh offline readback. Independent verification checked all 46 command phases, all 92 retained stdout/stderr buffers, exact 23 target checksums saved in isolated disposable modules, command order, normal proxy/SumDB then offline readonly settings, normal child joins, and pre/post source/compiler/helper/cache-byte bindings. This resolves exactly those23 metadata provenance gaps; it does not admit a producer or clear an advisory policy.

The original official source go.mod/go.sum remain unchanged. All 23 original source expected checksums remain nil; the earlier disposable130-added sum set also retains its nil entries for these 23 tuples. Supplemental checksums come from the new isolated-module records, not rewritten original source. The 239 absent lower graph metadata vertices remain separately recorded as unloaded absences. The 243 external MVS entries, 62 selected code archives and their expanded/package-input records are unchanged; no new Go or scan ran during this verification/derivation.

Each normal phase saved the expected target go.mod checksum but omitted the JSON GoModSum field. A separate process with GOPROXY/GOSUMDB off and -mod=readonly reread persisted go.sum and exposed the exact target GoModSum. The sum file remained byte identical during readonly confirmation. Pinned normalGo26.8 source explains this behavior: modload/build.go372–379 obtains GoModSum through RecordedSum; modfetch/fetch.go660–696 excludes entries marked dirty during the same invocation. Expected byte-derived hashes are kept separate from observed output values. The final exact output-plus-saved-checksum guard remains unchanged.

Earlier evidence remains intact: the original gap record and selected-closure V1/V2, the V1 actual query refusal (no checksums saved), and V2 actual first-module refusal (checksum saved, output omitted). V2's retained result demonstrates only the normal intermediate stage; it still refuses final confirmation. No claim is made that V1's different failure had the dirty-sum cause.

The current 23 SumDB cache notes contain exact target checksum lines and signed-note framing. This review does not independently cryptographically verify their signatures. Its diagnostic provenance is the pinned normal Go process using standard sum.golang.org verification, explicit persisted checksums, fresh offline confirmation and retained exact bytes. It does not promote sourceAcceptance, producerAcceptance, wholeDBAcceptance, fullMVSClearance, severityClearance or releaseAccepted: all remain false. GO-2026-5932 remains unfixed/UNKNOWN; no exception or severity waiver follows.

Evidence identities:

| Evidence | SHA256 |
|---|---|
| Actual paired execution receipt | bde8d88a03e93418a5fc5eb684d0b065d1d10bb6db9591ddf0d0b13b8132827d |
| Independent46-phase/92-buffer verification | 7edabbbc46a45b3191a791bba21d7e23cab1f5e1d1469eabfaae9f66fa0e1741 |
| Additive selected-closure V3 | 00441d63788d6cd465f5f878374c279136e8a5bb04761b94fba528bf1e4d8a3b |
| Selected-closure V3 receipt | 6f9df80a9426328f578f469058fc06575d41a6c6cad01e527ad57fcaab16845b |
| Prior exact 23 gap record | fffb552dbebd1b49a8fb928e38d2b364dfbe1ac76bf6863053b822d7fc4176d5 |
| V1 actual refusal | 58fc47e68d9fc99f730039cd8fe0b888484fe3d20b329a12fb030aba863251dc |
| V2 actual refusal | 82252056249161ec94db7b00934ef8a3482e17821de7186e99c842c5f65a4471 |

These artifacts reside under /workspace/scratch/official-vulndb-generator-selected-closure-v3 and /workspace/scratch/official-vulndb-generator-lower-mod-verification-recipe-v3; predecessor paths remain unchanged. The accepted captured Git 22-file history roster and current live Git 28-file observation remain distinct.

Separately, Root's cold-build measurement compiled the generator with pinned Go 1.26.8 in 47.69s, produced a 30,337,080-byte binary, and sampled a maximum 696,188,928 allocated bytes across cache/tmp/binary. Those are retained build-resource observations, not a continuous peak guarantee, protected producer admission or execution of the generator. Protected source/runtime/provisioning/output/generator admission remains outstanding; the generator was not run in that measurement.
