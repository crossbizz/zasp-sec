# Correlation routing upgrade boundary

This is the next original-scope implementation boundary after PR45, not an
implemented migration or completion claim. Counts remain 535 production-available,
132 component-only and 61 blocked/external. M3-46, M3-47 and M7-07 remain open.

Independent source review supports a version-aware claim API. The existing claim
body is still in migration15; migration27 adds recovery protection through table
triggers. There is no implementation-version predicate before either the
exhaustion update or eligible-job selection. Filtering returned leases is too
late: an old worker could already consume retries or fail a v2 batch.

The forward change should retain the four-argument legacy entrypoint and make
its correlation path v1-only. A separate upgraded correlation entrypoint admits
exactly v1 and v2. Both use one private implementation with the same stage-wide
advisory lock, live-lease exclusion per organization and fairness table. Apply
the version predicate before both exhaustion and eligible selection. Preserve
scope/generation joins, predecessor digest, delivery visibility, lease ownership,
attempt increments and recovery triggers. Do not rewrite stored versions or
receipts. Keep exact owners, search paths, registered-principal checks and ACLs;
neither PUBLIC nor unrelated stage principals may invoke the upgraded API.

Repository capability must be immutable and explicit. Keep the old constructor's
behavior and select the upgraded entrypoint only for configured v2 readers.
Validate returned versions against that capability. Readiness and direct claim
entrypoints must reject drift, not rely solely on cached worker readiness. Do not
downgrade after a permission error, malformed response or missing function on
schema49. Any schema48 fallback requires independent exact healthy48 validation.

Migration48 rejects later schemas. The upgrade must extend the pinned predecessor
readiness chain, preserving historical checksums and fingerprints while binding
the complete new claim/routing definitions and ACLs. Migration runner, catalog,
CLI and rendered-release expectations need corresponding checks. Old API binaries
also explicitly reject schemas above48. Compatible worker overlap alone does not
prove API availability: account for API binary compatibility before activating
the migration. PR45 by itself does not establish this compatibility.

Required actual PostgreSQL and composed regressions:

- Ingest on48 creates v1; forward migration and fresh ingest create v2 without
  fixture stage-version updates. Old acceptance replay preserves its stages.
- Legacy claims leave v2 pending, retryable, expired-leased and attempt100 work,
  plus related batch/job/delivery rows, untouched while completing v1.
- Upgraded workers drain both versions, preserving v1 receipt bytes and binding
  v2 receipts to their frozen snapshots.
- Concurrent old/new claimers preserve tenant fairness, one live correlation
  lease per organization, attempt counts and exact lease ownership.
- Unauthorized principals, missing predecessors, expired deliveries, stale
  generation/token, recovery holds and unknown versions stay fail-closed.
- Function-body, ACL, checksum, metadata and later-schema drift reject readiness
  and direct claiming before mutations.
- Rollback refuses to restore unrestricted legacy claiming while retained v2
  work exists. Do not relabel or delete evidence to permit rollback.

The source review used the official upstream Superpowers review workflow because
the installed skill is unavailable. It is a design review only; no migration49
code or tests have been added yet. Sandbox, container, cgroup and process lineage,
ambiguity, real producer reachability and mixed-evidence browser acceptance all
remain required under the original plan.
