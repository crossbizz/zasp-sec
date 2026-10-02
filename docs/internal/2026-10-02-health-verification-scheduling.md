# Default verification after bounded health package scheduling

The original default verification failed when the platform health server, API and worker packages competed during two existing one-second readiness contexts. Both unchanged tests passed in isolation. The reviewed fix adds `-p=1` only to the platform three-package invocation in `health:contract:test`; its two existing exact command contracts match. Other aliases, packages, race flags, test counts, contexts, deadlines and production guards are unchanged. No global Go serialization is used.

TDD observed both expected contract assertion failures before the script change. Focused Node6/6 and Vitest3/3 then passed; independent review and fresh coordinator checks approved the exact three-file candidate.

At HEAD4ce8418f03ad5581a8a1dc43e7729e4e84638235 with those exact candidate bytes, the coordinator ran the original complete `npm run verify` using Go1.25.13, Node22.23.1 and `GOFLAGS=-mod=readonly`. The joined run passed from2026-10-02T23:18:02.257371Z through23:40:41.070211Z. Health passed (API6.045s, worker343.128s), followed by OpenAPI, UI/API contracts, raw-fetch, tenancy, Neo4j, tenant-RLS, all2535 UI tests across246 files, typecheck, lint, import checks,30 staging checks,285 release checks, build, compiled imports and the original ledger validator.

All5978 tracked inputs, the three separately prepared collector sources, ten tools and narrow PostgreSQL libraries remained unchanged; four adopted descendants were reaped. The log SHA256 is `2b1216fd5279e1b81e626b6d601d1caf110147fbccdebbcce5c36a0dca4ebc25`. The source roster, invocation, log and receipt are retained read-only in `/workspace/scratch/npm-full-verify-canonical-default-health-candidate-4ce8418f-frozen`.

This is a complete local canonical pass, not deployed/provider, final-image/advisory, native379 or legacy-retirement acceptance. Hosted required checks remain mandatory and their earlier failure cause is unknown. The original ledger validates728 rows:523 production-available evidence categories,144 component-only,61 blocked/external and0 missing; no row was promoted and no original acceptance condition changed.
