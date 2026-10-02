# ZaspOps — plan review and revision (v2.2 as of 2026-08-12)

## Request
Review `docs/internal` PRD + Technical Implementation Plan. Criteria: MVP without over-engineering; reliable / enterprise-ready / compliance-ready (SOC 2, HIPAA); every task ≤ 10–15 min or rescoped; milestones dependency-correct; all APIs exist for all UI flows.

## Done
- [x] Read PRD and Technical Implementation Plan in full; assess against the six criteria
- [x] Archive v1 plan → `docs/internal/archive/ZaspOps Technical Implementation Plan (v1, archived 2026-08-10).md`
- [x] **v2.0:** descope table with reintroduction triggers (§2), simplified stack, vertical-slice milestones with Gate A read-only alpha, 10–15 min tasks with deps + verify commands (§21), UI ↔ API coverage map (§14), HIPAA as a gated track (§19); fixed v1 dependency bugs (§2.3)
- [x] **v2.1 (Manish):** Nango restored as self-hosted **OSS** scoped to connections/credentials (ZaspOps keeps syncs, provider webhooks, normalization; v1 caveats carried over — direct DB connection, non-rotatable encryption key exception, never evidence-of-record)
- [x] **v2.2 (Manish):** semantic retrieval is **evidence-gated** — MVP-1 ships graph + lexical; labeled eval baseline (M5.21–M5.22) → offline embedding spike, script-only (M5.23) → adoption ADR with thresholds (M5.24: recall@10 +10 pts or ≥30% cut in retrieval-miss failures); conditional R1 package (EmbeddingProvider, pgvector HNSW, hybrid RRF) builds only on adopt, re-check at N1 entry on defer
- [x] **Artifacts (2026-08-12):** architecture + per-flow diagrams → `docs/internal/ZaspOps MVP Diagrams.md`; coding-agent kickoff prompt → `docs/internal/Agent Kickoff Prompt.md`

## Decisions
- [x] ~~Nango~~ — **Manish:** self-hosted Nango OSS (applied in v2.1)
- [x] ~~Embeddings~~ — **Manish:** only if adding significant value → evidence gate + conditional R1 (applied in v2.2)
- [ ] TypeScript policy package instead of OPA/Rego (same determinism/hash contract; OPA when customers author policy)
- [ ] 3 AWS accounts (prod / staging / log-archive) instead of 4
- [ ] Partner launch framing: read-only production ≈ wk 6–8 (Gate A), write-enabled ≈ wk 10–12 (Gate B)

## Review
PRD untouched (flags in plan §2.4). Plan v2.2 keeps the governance core (RLS tenancy, provenance, deterministic policy, Proof Records, verification, fail-closed writes). Cuts still standing: Step Functions, custom EventBridge bus, OPA/Rego, separate model-gateway service, app-level Redis, edge mTLS CA in MVP-1, Merkle signing, 4th AWS account, PrivateLink, dual test rigs, premature partitioning. Open verification noted in §2.5: confirm the exact Nango OSS feature set against current self-hosting docs at bootstrap (fallback per provider = direct connector).
