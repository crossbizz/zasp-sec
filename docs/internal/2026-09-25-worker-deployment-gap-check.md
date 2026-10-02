# Worker deployment gate, September 25

September 28 source recheck: the missing-packaging findings below are historical.
`deploy/production/authorization-temporal-profile.mjs` and
`authorization-temporal-resources.mjs` now validate the named canonical61
Temporal/authorization worker profile, distinct authority references, key
mounts, projector and consumer network rules. The corresponding
`authorization-temporal-render.test.mjs` contains positive and refusal cases;
this recheck did not rerun them or verify a deployment. The authoritative
`docs/internal/implementation_status_v1.5.md` records current gates. Runtime
activation remains closed, and real service/identity/provider configuration
and deployed acceptance remain unverified. Do not use this older gap list to
reimplement existing packaging or enable the runtime prematurely.

This is local source/render evidence for P1/P7/P10. Nothing was deployed, no
secret was read or changed, and no production classification was promoted.

The current renderer does not package the Temporal/OpenFGA worker candidate.
`deploy/production/release-contract.mjs` defaults to schema49 and delegates
schema acceptance to `session-search-rollout.mjs`. That validator supports
48 through60 only. Direct Node22 assertions confirmed rejection of61/78/79/80
across every existing session-search phase, and `renderRelease` rejected each
of those four versions with the valid release fixture.

The existing runtime-services test passed: one test, zero failures/skips,
1078.719ms, exit0. Command:

```
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/production/runtime-services.test.mjs
```

Its scope is schema49, `agentsec-api` and `agentsec-discovery-scheduler`, the
runtime-services enable flag, FGA model ID, production environment and a
read-only client-secret mount. It does not prove the current worker profile,
its keys, projection reconciler, adapter or complete Temporal activity path.

The runtime-services template supplies Temporal TLS and FGA token files.
Search of `deploy` found no worker-profile name or either
`ZASP_AUTHORIZATION_WORKER_KEY_FILE` and
`ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE`. The worker config consumes those
two variables; its authorization composition requires distinct configured
key files when enabled. The staging overlay intentionally leaves FGA store
and model IDs empty, so it is not a deployable real-environment configuration.

Required next work, after the candidate's runtime contract is verified:

1. Add explicit profile-aware rendering and migration/registration ordering.
   Do not merely extend the schema-number allowlist or change the default.
2. Package the actual Temporal worker/activity queues and authorization
   reconciler with separate role credentials and purpose-specific keys.
   The adapter's dedicated authority must be covered too.
3. Group renderer tests around complete valid configuration, missing/swapped
   keys, incorrect profile, and unchanged unrelated workloads. Preserve the
   existing TLS, network, role and startup-refusal checks.
4. Supply real store/model/namespace/secret references through the approved
   deployment mechanism, then verify actual API-to-worker-to-provider receipts
   and tenant isolation. Local rendering cannot close that gate.

No renderer implementation was changed during the concurrent worker batch.
Partial worker readiness remains closed by design until all required families
and composition pass; packaging must not bypass that gate.
