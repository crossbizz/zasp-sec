# Spec compliance: approved

P5 matches its approved component scope. No missing, extra or misunderstood requirement found in the frozen patch. The required checker, mapping, model and application examples are present; operation coverage includes the conditional exports (`checker.go:16`, `mapping.go:23`, `model.fga:19`, `operations_test.go:15`, `model_integration_test.go:19`, all under `services/platform/authorization/`). Short authorization filenames below use that same directory.

## What holds up

- Exact scope. Six human roles live on environments, every permission intersects organization membership, and direct grants keep that intersection (`services/platform/authorization/model.fga:19`, `model.fga:41`). The role matrix matches the approved production decision, including Security Admin identity administration and Developer/Owner's lack of workflow mutations.
- `Map` validates canonical product IDs and separates user, agent and service subjects. Organization/workspace checks retain their selected environment; `Hierarchy` emits one parent per level without claiming it proves SQL ownership (`services/platform/authorization/mapping.go:23`, `mapping.go:78`).
- Concurrent delegation has a concrete boundary: the key includes principal, task, target, scope and permission; the condition checks the task, and separate attachment tuples permit independent revocation (`services/platform/authorization/mapping.go:114`, `model.fga:79`, `mapping_test.go:73`). The real-service examples exercise both machine kinds and cross-task permission denial (`model_integration_test.go:186`, `model_integration_test.go:197`).
- The adapter borrows the existing official client, pins store/model on each Check, requests HIGHER_CONSISTENCY, bounds the call and redacts errors. No cache or old-policy allow fallback (`services/platform/authorization/openfga.go:20`, `openfga.go:29`, `openfga_test.go:25`).
- All 160 composed operations have explicit permissions. Seven empty relations retain their separate credential/bootstrap obligations, while the four PAT/fresh-auth route contracts remain recorded (`services/platform/authorization/operations.json:1`, `operations_test.go:122`, `mapping_test.go:97`).

## Issues

Critical: none found.

Important: none found in this batch.

Minor: none found.

## Cannot verify here

P6/P7 still own desired/applied revisions, projection generations, verified-group projection, immediate SQL revocation and the post-Check transaction lock. This diff cannot prove those guarantees. Nor does it prove production API/worker enforcement, capability calculation, authorized list counts/pagination, PAT intersection, browser CSRF/fresh auth, export restrictions or live Stytch/provider acceptance (`docs/internal/2026-09-24-openfga-p5-report.md:141`, `:154`). Keep those gates open.

One integration detail matters: machine checks also intersect `organization#member` (`services/platform/authorization/model.fga:12`, `:44`). P6 must derive that machine association from product-owned identity/activation facts. It is separate from the two delegation tuples and must never require an invented Stytch member. The local fixture supplies it explicitly (`model_integration_test.go:140`).

Single-parent SQL ancestry remains the projection writer's obligation; the model does not enforce cardinality (`services/platform/authorization/README.md:49`). I found no P5 interface that prevents the required downstream fences.

## Checks and evidence

Reviewed `p5/scoped.patch` against the absent baseline, not HEAD. Manifest SHA-256: `b40027b03f1183de2d3cb8fc488ec8e133e2c2a146a06f1f8b31ee02ef12b68e`; patch: `823720b51c796b7dacd2b3066b16026e9c03a7dcb3417687d8999263990cb72f`. All 14 source/report, 14 readonly-dependency and seven evidence hashes match. The full patch was read in contiguous chunks; a truncated registry line was recovered from that patch. No changed source file was separately reread.

I inspected two named risks outside the patch: ambiguous ID spelling/separators in the delegation key, checked against `services/platform/domain/ids.go:49` and `scope.go:13`; invalid pins or an unbounded timeout slipping through construction, checked against `services/platform/runtimeservices/config.go:48`. Both checks support the implementation.

Recorded evidence was readable: `p5/final-tests.txt` reports seven top-level tests, four Check-response cases, 93 real-service decisions and 160 extracted operations, with exit 0 and no warning/skip; `go vet` also exits 0. `p5/model-artifact-check.txt` records exact DSL/JSON agreement through the pinned CLI. RED evidence includes the delegation object-length failure corrected by the hashed key. These paths are under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/`. No suite was rerun, no vendor conformance test was added, and Temporal changes were excluded.

## Task quality: approved

The small adapter and tuple encoders have clear responsibilities, and the application tests exercise the risky policy boundaries on the actual model. Accept P5 as local component evidence only; require P6/P7 before activation.
