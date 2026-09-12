# Precision checkpoint: full repository verification

After completion V3 executor integration, the root `npm run verify` command
ran to exit0 in `/tmp/zasp-daemon-replay.GUTSRq/worktree`. No implementation
source changed during the run. This refreshed the broader baseline beyond
the preceding focused precision package checks.

Observed evidence:

- Health contracts and Go health/API/worker packages passed. The full
  agentsec-worker package race run passed14.722s.
- OpenAPI tests, lint, generated-client consistency and UI/API coverage passed
  (planned6, API-available6, available141, public147).
- Raw-fetch enforcement, tenancy package races, graph adapter/proof tests and
  tenant-context/RLS tests passed.
- Vitest passed1238 tests across197 files. TypeScript and ESLint passed.
- Production source import checks passed44 files; staging gates passed7 tests;
  production release contract/gate tests passed70 tests.
- The standalone UI built. Compiled import checks passed7 client and8 server
  chunks. The final ledger check reported728 rows:536 production-available,
  131 component-only,61 external,0 missing.

This command does not run every owned external integration or verify deployed
infrastructure. Test names describing release behavior do not establish a live
rollout. No production readiness, new task credit or main publication is implied.

Read-only inspection confirmed the next integration dependencies:

1. `runtimeindex.Store.Apply` still decodes legacy archives. The precise path
   needs explicit V2 archive selection and deterministic index evidence without
   promoting observed lineage to semantic authority.
2. The index executor currently calls that legacy store interface. It needs an
   explicit V2 capability and compatible archive reader before V2 can be routed.
3. `PostgresProductionPipelineRepository.FinishStage` has a V2 sandbox-finalizer
   branch and otherwise selects the historical finalizer. Completion V3 needs
   its own database validation and readiness-bound finalization before activation.
4. Durable ingestion, outbox/claim routing, archive V2 execution and the new
   migration's checksum, semantic readiness, rollback and permissions must be
   composed before production startup enables the precise versions.

The full original scope remains open until those integrations and the other
ledger requirements have authoritative end-to-end evidence.
