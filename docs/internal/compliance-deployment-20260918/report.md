# Compliance56 is connected locally

Task3 implementation batch, 2026-09-18. This is local component evidence, not
production acceptance. Root owns independent review and the status ledger.

I connected the opt-in configuration, two isolated workers, API reader settings,
exact migration command, network/RBAC checks, operations resources and schema56
coexistence. The default remains schema49. Schema55 predecessors still work;
schema57 is refused.

## What changed

The public JS input has exactly15 fields. It rejects accessor/symbol/extra fields,
malformed or newline-suffixed authority, duplicate roles/DSNs/principals,
predecessor collisions and invalid CIDRs, then copies before the first await.
Direct Helm input has its own closed validation. Enabled settings require56
and one of the two precision phases.

Both workers use their own service account, CSI-only DSN and projected STS
token. The rendered checks pin mode, database authority, original worker image,
resources, probes, replicas, grace, topology spread, HPA2..6, PDB, Service,
ServiceMonitor and availability rules. Extra containers, envFrom, host namespaces
and cross-workload secret mounts are refused. The API gets the five reader
fields, with no worker identity. Both workers have kube-dns-only DNS, explicit
DB5432 and STS/S3443 egress, and monitoring-only8081 ingress. Additive policies
and group/cross-namespace RBAC are checked, too.

The fixed migration command loads the migration DSN, runs up-to56, optionally
registers/configures audit exports, and registers compliance workers last.
The existing CLI takes `ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL` and
`ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL`; a focused RED caught my initial incorrect
`EXPORT_` infix before the PostgreSQL acceptance run.

The audit operational state/readiness dispatcher now accepts exact56 using the
compiled compliance checksum and fingerprint. Historical migration readers,
upgrade/down behavior, SQL bytes and pins were not changed. Task1 and Task2
source/evidence stayed frozen.

## Tests, with the bumps left visible

| Evidence | Result |
| --- | --- |
| `render-red.log` | Initial schema56 release request rejected; schema55 predecessor fixture passed. |
| `audit-red.log` | Three audit operational commands refused healthy56 at shared state dispatch. |
| `principal-red.log` | Published registration env names differed from my initial rendered names. |
| `image-red.log` | A different digest-pinned image initially escaped the new validator. The validator now pins the existing worker image. |
| `focused-green.log` | 42 passed: rendering/normalization,16 phase/optional-product combinations,20 resource mutations,16 direct-Helm negatives and legacy/future controls. |
| `audit-green.log` | Focused53..56 configuration/API/worker registration state and pre/post-readiness cases passed. Existing52 tests are included in the affected Go batch. |
| `runtime-config.log` | Real package-local API and both worker configuration loaders passed under race detection. Disabled API and role/partial-config negatives passed. |
| `staging-red.log` | Retained original `56 !== 55` staging failure before the gate update. |
| `connected-node.log` | 215 selected,213 passed. Two predecessor alert tests failed because `ZASP_PROMTOOL_BIN` was missing. All other checks passed, including the updated staging gate and the manifest-fed Go loader proof. |
| `predecessor-alerts-green.log` | Only those two alert tests reran with the already cached Prometheus3.14.0 tool:2 passed. No source correction was needed. |
| `affected-go-race.log` | Selected migrations, migrate and API tests passed. The worker selector had a wrong name and selected zero tests; that warning is retained. |
| `worker-config-race.log` | Corrected worker-only `TestComplianceRuntimeConfiguration` selection passed under race detection. |

No unchanged213-test rerun. The connected result is the213 passing checks plus
the two focused alert replacements, not a claimed single all-green process.

### The actual command chain

`owned-postgres-green.log` records a10.80-second owned, network-none PostgreSQL
run. The actual CLI executable ran the complete chain under a registered login
verified as LOGIN INHERIT, NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
NOBYPASSRLS. A fixture-only bootstrap created the existing schema/roles first;
that login was demoted before the tested chain, including the up-to56 replay.

The run checked separate audit/compliance bindings, selected audit policy and
compiled56 readiness. It replayed the chain, then tested invalid56 checksum and
unavailable56 readiness before and after optional registration. All four
operational commands and the complete chain refused invalid state without
changing bindings, policies, selection or grants.

The first run (`owned-postgres.log`) stopped on a fixture assertion: up-to56
reports `release principal registration or readiness failed`, while the four
operational commands report `release migration failed`. I accepted both existing
fixed public messages in the chain harness and rebuilt only the test binary.
No production behavior changed for this correction.

### Manifest-to-Go proof

`rendered-fixture.json` preserves enabled and disabled original rendered objects,
including env/valueFrom, shell arguments, CSI mounts and token volumes. The Node
test writes the same form to an owned temporary JSON file and joins the pinned,
offline Go test command. It never constructs cloud clients or calls providers.

The API harness substitutes only CSI secret values named by the rendered shell
loads. All ordinary env entries, including compliance/audit/connector settings,
come from the manifest. Workers substitute a synthetic DSN and resolve
`metadata.name` to a fixture pod ID. No compliance setting is copied from a
hand-built replacement environment. Each test calls the actual full runtime
loader and checks its result; it doesn't just inspect JS strings.

## Frozen review inputs

`source-hashes.json` lists exact before/after source hashes. Starting bytes for
all19 modified files are under `before/`;13 task-owned source files are new.
`scoped.patch` contains only this batch, measured against those starting bytes,
including inherited uncommitted files. `artifact-hashes.json` pins the logs,
report, commands, full rendered evidence and scoped patch.

The raw commands are in `commands.md`. All owned processes were joined. Both
owned PostgreSQL containers used `--rm`; the final label-filtered listing is
empty. Only task-local generated binaries were removed after hashing, and they
can be rebuilt with the recorded commands. Temporary Helm/JSON directories were
removed by their harnesses. No staging, commit, push, dependency download,
Terraform init/apply, host database, image pull/build, provider call, online scan
or production-release script ran.

The two pre-existing predecessor alert tests need the recorded cached tool
path, and the Node-to-Go proof currently pins this workstation's Go executable.
Portability outside this local acceptance environment remains a review concern.
Authorized account infrastructure plan, external login/secret provisioning,
IAM/S3/KMS/versioning/lifecycle canaries, hosted rollout/CI, exact advisory
evidence and required pre-push gates are still external acceptance gates.
