SPEC: issues found. QUALITY: needs fixes.

P3B-I implements the approved install/readiness slice, with one remaining catalog-binding defect. This is a task-scoped review of the dirty overlay at HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`, not approval of the parent P3B executor or runtime activation.

## What held up

I verified all ten before/after source hashes, reconstructed the supplied diff byte-for-byte in memory, and checked the report hash. The reviewed diff SHA-256 is `f3b124152f6824b4443d667b697bd9ed96ee70dee58d9273e3d471d0519a3503`. All 148 historical SQL files through 66 match the captured baseline; so do the ten captured Node runner files. No historical pin was edited.

The owner check is narrow. `services/platform/migrations/sql/0067_production_temporal_domain.base.sql:8` requires each helper owner to equal the authorized-scopes table owner and have a migration-authority registration. Lines 11-13 require exactly two EXECUTE grantees, the expected grantor and no grant option. Only those two helper identities are symbolic in the new fingerprint (lines 26-28).

`services/platform/migrations/production_temporal_domain.go:112` checks installed predecessor readiness before rewriting source; line 176 compares the three complete original catalogs against compiled pins. The new SQL retains the four replaced predecessor definitions and their ACLs at `services/platform/migrations/sql/0067_production_temporal_domain.up.sql:17`, binds that evidence and the post-transition catalogs at lines 58-61, and gives runtime roles only the public readiness entry at lines 91-92. The copied decision function remains private.

The retained test log records both packages passing: agentsec-migrate in 52.901s and apiserver in 123.487s. I read the complete log, including clean60, retained65, registered66, registered66_optional and registered61_optional cases, decision approval/cancel, and the principal-before-DDL check. The process-join messages report normal exits; there are no failure or warning lines.

The tests exercise real CLI execution and runtime database roles. `services/platform/agentsec-migrate/temporal_domain_test.go:55` injects failure at final registration and checks rollback; line 121 starts owner/ACL/helper/registration/facade drift probes. `services/platform/apiserver/security_agent_temporal_ownership_postgres_test.go:133` snapshots retained command/owner rows across cutover. Its shared product assertions check manual admission, replay, deactivation, selector exclusion, lease refusal and cancellation. `services/platform/apiserver/security_agent_temporal_domain_postgres_test.go:25` checks retained ordered approval/cancel and receipt-bound outbox commands.

## One fix before approval

Important, P2, confidence 9/10: `services/platform/migrations/sql/0067_production_temporal_domain.up.sql:52` does not bind table persistence. Its table identity is:

```sql
concat_ws('|','table',c.relname,c.relkind,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,''))
```

`c.relpersistence` is absent, and none of the other fingerprint branches or readiness checks covers it. Changing either new table with `ALTER TABLE zasp_temporal67.registration SET UNLOGGED` or `ALTER TABLE zasp_temporal67.predecessor_functions SET UNLOGGED` preserves the hashed definitions, ACLs, policies, triggers and row values, so the new boundary still accepts the changed durability contract. This is a static finding; I did not execute these mutations.

That matters for retained authority evidence. PostgreSQL truncates unlogged tables after a crash or unclean shutdown and does not replicate their contents to standby servers. [PostgreSQL documentation](https://www.postgresql.org/docs/16/sql-createtable.html). Losing either table's contents then makes readiness fail, while `services/platform/migrations/production_temporal_domain.go:55` treats the existing schema as replay-only and cannot reconstruct the lost registration/evidence. The immutable DML trigger does not prohibit this DDL change.

Bind `relpersistence` for the new67 relations, or explicitly require permanent tables in readiness. Add transactional drift probes for both new tables that require readiness and CLI replay to refuse the altered state. Refresh the new67 pin and affected evidence after that fix. Historical62 and65 already include this field; no historical migration edit is needed.

No Critical findings. No separate Minor findings.

## Checks beyond the diff

I used the Superpowers task-reviewer method. I read the scoped diff once and used retained passing results, without rerunning suites or changing implementation files.

Named risk: forwarding readiness could discard a predecessor guard or create a cycle. I checked the original62/65/66 readiness and fingerprint definitions. The new67 checks retain their registration/catalog and optional-retirement checks, with the approved base authority replacing old61 and the saved65 predecessor replacing its old dependency branch. The call graph reaches fingerprints, not the forwarded readiness entries.

Named risk: copying the private decision function could broaden caller authority. I checked the original61 transition entry and post-wait checks, plus the62 mutation entry. The copied source preserves session-principal, membership, scope, version and expiry validation, while its execute ACL stays private. The new source transformation and resulting catalog are pinned.

Named risk: retained extension removal could orphan67. I checked the66 runner, which has no removal method; the scoped62/65 changes reject removal when67 exists. The66 retirement guard still blocks independent63/64 restoration/removal.

Named risk: reused integration assertions could pass without exercising product behavior. The diff omits their unchanged middle section, so I inspected that section of the shared ownership test. It invokes the real repository and worker roles, checks rollback and receipts, and refuses old claims. The clean60 case deliberately expects historical61 planning readiness to remain false.

Named risk: role-name formatting could reject a legitimate configured owner. I checked `services/platform/agentsec-migrate/main.go:54`; the shipped principal grammar restricts names to lowercase letters, digits and underscores. No additional finding from that check.

## Still closed

The retained output is local component evidence, not deployed acceptance. I did not independently reproduce historical RED runs or execute a crash test for the persistence defect.

Parent P3B still owes executor/compensation authority, stable effect identity, atomic budget/effect checks, reconciliation, provider/artifact/signing checks and the actual linked-test journal/adapter/Node protocol. P3C workflow and Activity composition, P7 active OpenFGA revision enforcement, deployed provider/cleanup checks and publication gates remain required. Fix the67 persistence binding before this packet is approved; keep runtime activation closed.

## Fix1 checked

SPEC: compliant for P3B-I. QUALITY: approved for this staged slice. Original P2: ADDRESSED.

`services/platform/migrations/sql/0067_production_temporal_domain.up.sql:52` now includes `c.relpersistence` in the new67 table identity. Both registration and predecessor evidence use that branch. `services/platform/migrations/production_temporal_domain.go:21` refreshes only the new67 pin to `3559e54be45e44575699fb6fad8f23edffe3e98a5b8228f2b2b96ae42057ae92`; the portable base pin and historical migrations are unchanged.

The regression at `services/platform/agentsec-migrate/temporal_domain_test.go:44` covers both tables. It checks readiness inside the drift transaction, commits before invoking CLI replay (line 72), and restores LOGGED persistence with a successful runner replay during cleanup. So the CLI cannot pass this test merely by timing out behind the test's own DDL lock.

I read the retained RED and GREEN logs. Before the fix, both subtests report accepted unlogged readiness and successful CLI replay. After the fix, both pass; the affected command, principal, decision, retained-guard and four upgrade cases pass too. Final package times: 67.888s and 132.905s. No suite rerun here.

I verified the four fix before/after hashes, reconstructed the exact fix diff in memory, and verified both test-log hashes plus the original diff, manifest and review hashes before this append. Fix diff SHA-256: `9ad4224735066653386ffe2a56a6d83da8626778796f3e49e3845c34e2532582`. Source outside the three fix paths matches the pre-fix snapshot, including all 148 historical SQL files through66. The report change is an appendix; the initial finding above remains intact.

No new breakage found in the fix diff. This fix-only verdict supersedes the initial P3B-I needs-fixes verdict, not its recorded evidence or parent gates. Keep executor/journal/workflow, OpenFGA, deployed acceptance and runtime activation gates open.
