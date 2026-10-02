# Schema55 candidate test and UI assembly checkpoint

This records local candidate evidence, not publication or live readiness.
The previous goal turn made progress: independent local integration acceptance
and an isolated production-source candidate. This turn continues its assembly.

Shipping worktree: cached-runtime-ship-20260917, unchanged HEAD
8733b16f8d939d38a8157dd2519e57fc6f630542. Recovery source HEAD remains
ecc047ee2e90c36ec702ade129a2b08eae0a7a1a with inherited uncommitted changes.

## Exact inputs

Offline Linux/arm64 go list -deps -test for14 affected packages resolved1339
repository source/test/embed inputs. Compared to the production-only candidate,
299 inputs differed. Those exact test and shared test-helper files were applied
without changing the recovery source. All1339 destination blobs then matched
the source, zero mismatches. The first inventory output capture was too small
and discarded; the retained inventory was complete with no missing paths.
See 2026-09-17-schema55-test-inputs.tsv for every input and pre-copy identity.

All14 test packages compiled with go test -c, session99092 exit0:
agentsec-migrate, agentsec-api, agentsec-worker, red-team-adapter, apiserver,
migrations, securityagent, artifactstore, artifactstore/s3driver, audit,
auditexportconfig, bucketlayout, redteamadapter, runtimeevent.
No test executed on the host. Toolchain was local, GOPROXY=off, CGO_ENABLED=0,
GOOS=linux, GOARCH=arm64, GOCACHE=/private/tmp/zasp-budget-go-cache.
Binaries are in /private/tmp/zasp-schema55-candidate-tests.47H9Oq.
The actual agentsec-migrate executable was rebuilt from this candidate too.

## Grouped execution

Cached image only:
postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba.
All runs used --rm --pull=never --network none and read-only compiled binaries.
Database runs used user postgres and LANG=C.UTF-8, retaining fixture C/UTF8 DB
collation. No image pull, provider call or host PostgreSQL/initdb occurred.

API run81612 exit0 selected:
^(TestSecurityAgentGlobalControl.*Postgres|TestSecurityAgentExistingTestLifecyclePostgres|TestSecurityAgentExistingTestVersionedDefinitionPostgres)$
Sixteen top-level tests passed, no skips. This includes all eight stop/history/
rollback race cases, six operator authority/catalog/atomicity/rollback cases,
and two public lifecycle/definition regressions. All16 owned PostgreSQL servers
recorded normal joins. The observed rollback-first wait was on kill_switches,
then operator refusal after committed down, not external cancellation.
Log: /private/tmp/zasp-schema55-candidate-tests.47H9Oq/operator-api.log
SHA256:841a3f71de07c595c1ba0447341ec6d7db0f67f377f8a04147111bb08cd2aa46.

CLI run58085 exit0 selected ^TestGlobalExecutionControl: five top-level tests,
no skips. It used ZASP_TEST_MIGRATE_BINARY=/task/agentsec-migrate. Actual registered
NOSUPERUSER/NOBYPASSRLS operator read/stop/replay/conflict/stale/re-enable,
bad authority, expired context and release drift were checked against independent
durable reads. The database test took9.68s.
Log: /private/tmp/zasp-schema55-candidate-tests.47H9Oq/operator-cli.log
SHA256:b8aa12ed928b1dc0ee1b9d4e9feace38a147be5419ff5fc83a7a89ba08552310.

Transport run56263 exit0 selected ^TestGlobalExecutionControl in migrations.test:
two top-level tests and18 transport subcases passed, no skips. Commit-failure
coverage here uses a transaction mock; it is not proof of a live commit failure.

The three operator containers were confirmed absent after terminal success.

## UI source and exact wire assets

The existing production source checker, expanded to page/catch-all/layout/
sign-in/callback entries, resolved67 source inputs. Twenty-nine changed source
files were transferred to the candidate. This is a source inventory, not a
complete UI build dependency graph or successful browser/build check.

The eight audit wire JSON fixtures have no terminal newline. The generic patch
transfer correctly refused its first such file before writing it. Controller
used the existing deterministic TestAuditExportReadBrowserWireGolden generator
instead, in a fourth owned offline container as uid501/gid20. Only the selected
candidate testdata directory was writable; binary input stayed read-only.
ZASP_UPDATE_AUDIT_EXPORT_WIRE=1, selected only that pure codec/handler golden test.
Generation and exact canonical comparisons passed, including the1050863-byte
near-bound envelope. The container was removed. No recovery asset was changed.

Every75 UI/fixture input now matches its recorded source git blob exactly.
See 2026-09-17-schema55-ui-inputs.tsv. These eight JSON assets are local test
vectors, not real tenant data or production proof.

## Remaining candidate work

The candidate is uncommitted and its index is empty. git diff --check passes.
UI tests, matching npm lockfile/build configuration, runtime harness assets and
deployment files still need explicit assembly and review. The recovery lockfile
contains dependency upgrades, so the old shipping node_modules tree cannot be
assumed to validate it. Use offline cached dependency setup only.

The complete main-to-candidate review, grouped UI/browser/runtime/release gates,
approved fresh advisory evidence, publication/CI and live rollout proof remain
open. This check does not prove the299 transferred tests all pass, only that
their selected packages compile and the stated grouped selections passed.
Original728-task classifications remain unchanged.
