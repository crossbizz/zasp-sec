# Lessons

## 2026-08-10 — Over-engineering (pattern flagged on zapp, applies to zasp)
Manish flagged that the zapp application was overcomplicated and asked that ZaspOps not repeat it.

**Rules to apply:**
1. A component earns its place only if a current-MVP workflow or a named compliance control requires it. Otherwise cut it and write a reintroduction trigger — never keep infrastructure "for later."
2. Prefer buy/managed/omit over operate: don't self-host a platform (Nango, OPA bundle infra, Step Functions) to avoid writing a small amount of code you'd own anyway.
3. Keep security guarantees at the cheapest layer that actually enforces them (code-level lint boundary beats a separate network service; append-only + hash chain beats Merkle signing) until a threat model change forces more.
4. Plans must be vertical-slice sequenced: a demoable end-to-end slice early (read-only alpha), not layer-cake (all data → all ingestion → all UI).
5. Every task ≤ 10–15 minutes; if bigger, split before starting. Every UI flow must have its API tasks sequenced before the UI task.
6. Compliance-ready ≠ compliance-built: ship classification + fail-closed flags + audit/encryption now; open vendor/BAA workstreams only when a regulated customer is real.

## 2026-08-10/12 — Contested scope calls: propose the evidence gate, don't pendulum (ZaspOps v2 → v2.1 → v2.2)
Two corrections across two days. (1) Nango: I cut Enterprise to hand-rolled auth; Manish wanted the middle tier — self-hosted **OSS**. (2) Embeddings: I deferred them (v2.0), he pushed back, I restored them unconditionally (v2.1), then he said "only if adding significant value" (v2.2) — the right answer was never build/don't-build, it was **measure first**.

**Rules to apply:**
1. When a scope call is contested or uncertain, propose an **evidence gate** as the first option: cheap baseline + timeboxed spike + explicit adoption thresholds + a pre-specified conditional package. Don't swing between unconditional build and unconditional defer.
2. "Only if it adds significant value" is Manish's general bar for capability investments. Operationalize it with named metrics and thresholds, not vibes.
3. When a platform feels too heavy, check for a lighter tier of the same tool (OSS/free/cloud) before swinging to build-it-ourselves. The decision space is rarely binary.
4. Manish is comfortable operating lightweight self-hosted OSS services when they make integrations easier; his over-engineering objection is to footprint and premature platformization, not to running software.
5. Keep deferred options cheap to adopt later (e.g., pgvector installed, expand-only migrations) so the gate decision is low-stakes in both directions.

