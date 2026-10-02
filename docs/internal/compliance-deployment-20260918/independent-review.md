# Task3 independent review: fixes required

Reviewer: /root/compliance_deployment_review, GPT-6 Astra high. Reviewed the
frozen task-only scoped.patch at SHA256
`ae1c743c246c585bd03a4ef899cb8a2b42fea84cce9a87b9858f784a58d7d8a9`.
Root verified32 source identities,24 artifact identities and reverse patch
applicability. This review is local component acceptance only.

## Important P1: mandatory test cannot run on hosted Ubuntu

`deploy/production/compliance-export-runtime.test.mjs:23` invokes
`/opt/homebrew/bin/go`, replaces PATH with workstation paths and fixes GOCACHE
at `/private/tmp/zasp-budget-go-cache`. `package.json:33,135` includes it in
release verification and verify. `.github/workflows/runnable-ui.yml` uses
Ubuntu24.04 and actions/setup-go. The absolute executable path causes ENOENT.
Use portable executable/cache resolution, retain offline settings and validate
the required toolchain version. Root independently confirmed the workflow and
script wiring.

## Important P2: compliance-only API startup shell is unchecked

`deploy/production/compliance-export-rollout.mjs:110` checks API env entries
and token mounts but not command/args. A local rendered compliance-enabled,
audit-disabled fixture still passes full validateRenderedRelease after adding
`export ZASP_COMPLIANCE_EXPORT_ROLE_ARN="<writerRoleArn>"` before API args[0].
The real loader at `services/platform/agentsec-api/compliance_config.go:20`
rejects that variable. Audit-enabled releases reject the mutation through the
audit validator's exact shell check, so the all-products loader fixture masks
this gap. Add shared canonical API startup validation and mutation coverage
with audit enabled and omitted. Root confirmed the unchecked API block and
the loader's explicit refusal.

## Verdict

Spec: with fixes. Quality: with fixes. No Critical or Minor findings.
SQL/checksum pins, default49, predecessor55, both56 precision phases, optional
predecessors, worker identity/CSI/network isolation, registration order and
operational audit readiness matched the design. Actual CLI-chain evidence
uses verified registered non-superuser migration authority.

Reviewer inspected requirements, scoped patch, full report/commands, changed
code/tests, Task1/2 interfaces and relevant logs. No files changed and no suites
rerun; one local Helm render supported the in-memory command mutation diagnostic.
Retain split evidence:42 focused passes,213 connected passes plus two focused
alert replacements, affected Go/race evidence with the empty worker selection
corrected separately, and actual isolated PostgreSQL CLI-chain acceptance.
Cloud/provider/hosted/publication gates remain open.
