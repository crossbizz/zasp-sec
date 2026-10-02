# Registered CLI58 verification

Component verification complete, frozen for connected independent review. This does not prove a live deployment or advertise export workflow readiness.

The actual CLI exposed two Go defects missed by command-routing doubles. Runner.Version rejected schema counts above57, so up-to-58 applied the migration and then failed its final version check. After that correction, operational Attack Lab reconciler registration still used the exact57 historical state reader and refused58. Both are fixed without changing SQL or the accepted release pin.

## Scope

Five changed files, preserved before bytes in cli58-before:

- migrations.go recognizes exact58 and includes both57 and58 metadata in the row-by-row name/checksum verification. It still rejects59 and malformed predecessor rows.
- production_security_agent_attack_lab.go accepts only exact57 or58 for operational registration. Current compiled readiness is checked before and after the original57 registration operation. Its SQL, principal validation and compiled57 pins are unchanged. Historical upgrade/down readers remain exact57.
- compliance_deployment_postgres_test.go preserves the full existing56 and57 checks and extends the real binary fixture through58.
- migrations_test.go adds exact56/57/58 cases and moves its stale unsupported-version case from56 to59.
- production_compliance_registration_test.go now models the already-existing current-release dispatch count, exact reader count, current readiness and original family readiness. It adds healthy57/58 and independent family-readiness refusal. Production compliance registration was not edited.

Root-owned main.go is unchanged at6e0938bd5483bae29c0e096ccac9d33835e3810ecbccc6c16c932077c212acbf. No renderer, Helm, deployment configuration, SQL or migration fingerprint edit.

Accepted SQL fingerprint remains0d5ce2f2b6a6252ee8bc5e675b2776a5c23c03fb50754f7c46345f8fbae906f3. release.go hash remains813a6bf7f11ddd1e0d9246a2581690a60d0fe4a5c518dc8390ab4a3184c994fc; manual fragment remainscb4106ae08975d8b4ba38bfefc975a05d28aca8839ce5433745b8a75a4982bc4.

## Reached tests

cli58-red.log: actual56/57 assertions pass; up-to-58 exits with the public release migration failure. Test22.02s, container1. This is the first behavioral RED. The failure message alone did not prove58 was absent. Source tracing found the post-upgrade Runner.Version ceiling.

cli58-diagnostic.log: rollback-only execution of the actual58 SQL succeeds and computes the exact accepted0d5ce2f2 pin. The real CLI repeats its failure,22.00s, container1. Temporary diagnostic code was removed after isolating the Go issue.

cli58-registration-red.log: after only the Version fix, real upgrade/retry58 plus audit API/workers/configuration and compliance registration succeed. Actual Attack Lab reconciler registration then fails,29.58s, container1. The second Go fix follows this reached RED.

cli58-green.log: TestSecurityAgentExportsDeploymentBinaryOwnedPostgres passes40.00s, container0. It runs the actual mounted offline CLI, not a runner double. Existing56/57 assertions execute first. The58 checks cover:

- upgrade57->58 and repeated forward58;
- audit API/worker/configuration, compliance executor/cleanup and Attack Lab reconciler coexistence, plus existing-test worker scope reads;
- exact compiled58,57 and56 readiness after non-superuser operational registration;
- refusal of default up, older target commands, unsupported59, wrong downgrade and wrong-source58 rollback;
- checksum and readiness drift refusing every operational command and downgrade without binding/policy/grant changes;
- empty58 rollback restoring exact57 fingerprint/readiness, unchanged policy/bindings/grants and absence of the export readiness function; then real re-upgrade58;
- disabled export control retained as history: down-from-58 refuses and leaves exact58/history intact.

DDL bootstrapping and schema rollback use the fixture's controlled superuser, as the existing57 fixture did. Operational registration/replay uses the registered migration principal after explicit demotion to LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS. The owned fixture creates, stops and Waits its PostgreSQL child. Its existing helper does not log individual PostgreSQL stop/Wait status, so these logs establish the container/test result, not a separate reported child-exit code.

cli58-native.log: first affected native race batch found two stale fixture protocols, not new production failures: the Version future-case used56, and compliance scripted rows lacked the current-release count/readiness checks. The seven command/readiness groups passed. This failed batch is retained.

cli58-native-green.log: corrected affected native race batch passes all10 top-level groups: migrations6.323s and agentsec-migrate2.054s, command exit0. No PostgreSQL test name is selected by this anchored native selector.

## Commands

From services/platform, offline Linux/arm64 builds exited0 before each container run:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go build -o /private/tmp/zasp-cli58-migrate ./agentsec-migrate
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./agentsec-migrate -c -o /private/tmp/zasp-cli58.test
```

From the shipping worktree, final registered GREEN:

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-cli58-green --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw -e ZASP_COMPLIANCE_DEPLOYMENT_BINARY=/compliance-migrate --mount type=bind,src=/private/tmp/zasp-cli58.test,dst=/cli.test,readonly --mount type=bind,src=/private/tmp/zasp-cli58-migrate,dst=/compliance-migrate,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/agentsec-migrate --entrypoint /cli.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExportsDeploymentBinaryOwnedPostgres$' -test.v -test.timeout 360s 2>&1 | tee docs/internal/security-agent-export-20260919/database/cli58-green.log
```

The preceding exact container invocations used identical flags/selector with these name/log pairs: zasp-cli58-red / cli58-red.log, zasp-cli58-diagnostic / cli58-diagnostic.log, zasp-cli58-registration-red / cli58-registration-red.log.

From services/platform, final native race batch:

```sh
set -o pipefail
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./migrations ./agentsec-migrate -run '^Test(RunnerVersionDistinguishesEmptyBaselineCoreWorkflowsReceiptsAndDrift|ProductionAuditExportsRunnerVersion|ComplianceRegistrationTransaction|SecurityAgentExports(ExplicitReleaseCommands|ForwardReadiness)|AttackLabExplicitReleaseCommands|ExistingTests(ExplicitReleaseCommands|ReleaseBoundaries)|RegisterForwardReleaseChecksExactSchemaAfterPrincipals|RegisterForwardReleaseStopsOnFailedAuthorityOrReadiness)$' -count=1 -v 2>&1 | tee ../../docs/internal/security-agent-export-20260919/database/cli58-native-green.log
```

The first native invocation used the same selector and cli58-native.log.

## Frozen hashes

```text
1fac1e1324d307430b3d7afff9290a13bcd6e9591731d45366980e0c0cad55a6  before/attack_lab.go
75ac8533550c7563f092c858ad2e8d65018a12a3ac77ee27c67146e35c8ca7dc  before/compliance_registration_test.go
0860fe2a49efdecb9e32550626e4e90804cf8e0708f00a97d1f5002dfdc5ff88  before/deployment_test.go
66270fa83cb09eee22ae4dc26cfc48563446133847b1423fcd3ea7b665bdef83  before/migrations.go
c42c6364a706b8abd916f190612065134ae6da241767a157e543431d789570ba  before/migrations_test.go

9f1c9c182abfccd7f6bc0b9e37b5cf8faa1e1d566120b0a234be83d506b7f690  services/platform/agentsec-migrate/compliance_deployment_postgres_test.go
b31df076de530833cdaa62e24e6673da4041d74b2b020fe96590ced1fb912e2b  services/platform/migrations/migrations.go
3cd7b214a80029a97fe2c98c4bb8eb238d06d2eafdc90e24650816315225af15  services/platform/migrations/production_security_agent_attack_lab.go
dd2790d82ac5f31ba7c989098c4b1255bed5969e14b5bc062e14009897ecb0a9  services/platform/migrations/migrations_test.go
8141a046465a2583d3a4a1d8e1bb29fc3e1fb123a744555be9f3bfb8a6468b4c  services/platform/migrations/production_compliance_registration_test.go
b73b1408c37d84d45eaae9a1f423ddd271420d4f9addc20b3c668bc08c83603f  cli58.patch

e94f0c34fa526d3a7c1332475a68cea8130159407f05931964c2240eae37bd1b  cli58-red.log
6956276453270988c4a1dc8fd09c6b5bc35964aa939e9050def48b4eeee09e58  cli58-diagnostic.log
30abcc40dab3492b03ee85661f10fa4f8f98ea29d15d4eed808f2a3c5bcb46b9  cli58-registration-red.log
a868758ba585b58352404ad90abb257256ba127ed4c0d3612d788d302bf627e7  cli58-green.log
d371e0ea39a6ffb414005be5d9bad9c7db950821f4168ed1f53206c6f3b8f3d0  cli58-native.log
7dd095d62a02a44ff7699478de462e1ad2a8a19c2d43e4e116a0cd6a3521555e  cli58-native-green.log
```

Scoped reverse patch check and git diff --check on all five changed files exit0. No patch was applied/reversed. No host PostgreSQL, external provider/network call, image pull, commit, stage or push. No owned test/container remains.

Deployment renderer/Helm, rollout worker health and external provider acceptance remain root-owned connected work. This result does not establish deployed-worker-ready workflow capability.
