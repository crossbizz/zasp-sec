# Official advisory generator metadata and offline preflight — 2026-10-03

The prior offline metadata lookup failure is resolved for the fixed official generator source. Normal Go1.26.8 module resolution ran against exact disposable copies of the original `go.mod` and `go.sum`, with the standard Go proxy and checksum database enabled and no exclusions. Both metadata commands exited0, retained empty stderr, and joined their owned children. The disposable sum file gained130 lines and lost none; the original source locks did not change. This is a successful normal-tool diagnostic transcript, not separately retained signed-checksum response proof.

The original five offline, local-toolchain, read-only checks then passed: Go environment, complete module list, module graph, generator dependency-package inventory, and module verification. All five exited0 with empty stderr and joined children. Module verification returned exactly `all modules verified`. The complete11079 tracked source files and current28 Git metadata files remained unchanged, as did the compiler and consumed cleanup helper.

Observed outputs contain244 module rows,670 generator dependency packages (223 standard packages and62 external code modules), and1111 graph edges, with no reported module/package errors. These are observed counts, not an admitted selected-code/ZIP closure. The earlier partial diagnostic and failed preflight remain immutable. The current live28 Git files are distinct from the previously captured22-file history roster; no protected producer copy is inferred.

Retained evidence:

- Normal metadata: `/workspace/scratch/official-vulndb-generator-normal-metadata-recipe-v3/execution-receipt.json`, SHA256 `70c161e3e1e2a8187da7183c9f9b929b3e49247d206e020fa1604b6ac27b6a21`.
- Original offline checks: `/workspace/scratch/official-vulndb-generator-go26_8-measurement-v3/receipt.json`, SHA256 `a6fa647bc8a76d59046b8d32f028798a0cf14cbf2a3aac872ff95c3de9ba0bf2`.
- Consumed cleanup helper: SHA256 `a73a3161b5351027989e0bd97cde803166e6727078d4d3e9e8da19caca176e86`; recipe SHA256 `e4be26bd0f6b252c1618a1ad4b62f096cf3ffc515d707da8da66782b1004aaae`.

Independent review replayed all14 raw stream bindings and the source/Git pre/post roster. Tiny fault controls corrected direct-child cleanup before these actual invocations; process-inventory failure remains an explicit refusal with unresolved descendants. These host diagnostics do not establish protected execution authority.

No actual generator build, generator execution, database generation, protected provisioning, source/whole-database admission, severity policy, full-MVS clearance, release acceptance, or ledger promotion is claimed. Next steps are the exact selected input closure, bounded cold-build capacity measurement, protected executor/runtime/provisioner acceptance, and real official generation. The existing source, original version directives, immutable evidence, and original728 acceptance conditions remain unchanged.
