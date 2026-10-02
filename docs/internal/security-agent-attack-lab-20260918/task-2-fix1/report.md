# Task2 fix1: IRSA admission

DONE_WITH_CONCERNS. The rendered Attack Lab reconciler now skips automatic IRSA injection for its `worker` container. Its service-account role remains available for CSI, and its explicit role configuration and projected identity token are unchanged. The production loader still rejects ambient AWS authority.

The whole-task review found that the role-annotated service account would cause standard IRSA admission to inject `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`. Those names are intentionally forbidden by the dedicated loader. The pod previously had only its schema annotation, so the untouched render-loader test missed this boundary.

## The observed failure

I added a local admission-environment model to the existing rendered Go test, using the rendered service-account role, pod annotations and container name. It models the documented comma-separated `eks.amazonaws.com/skip-containers` behavior from the [review-provided AWS webhook reference](https://github.com/aws/amazon-eks-pod-identity-webhook#eks-walkthrough). This is not execution of the webhook or live EKS proof. It models only the environment boundary; the existing exact resource validator covers the explicit projected token and mount.

`admission-red-detail.log` exited1. The actual unchanged Go loader failed with:

```
actual rendered loader rejected after modeled IRSA admission: worker runtime configuration rejected
```

The migration loader passed in the same invocation. `rollout-red.log` independently failed because removing the missing annotation was not rejected. The first `admission-red.log` also failed, but its subprocess wrapper hid the Go output; I retained it and added test-only failure diagnostics before rerunning with the prescribed compiler/cache paths. No production change preceded the observed RED.

## Five paths, two production changes

The template now puts `eks.amazonaws.com/skip-containers: worker` on pod metadata. Both exact pod-metadata comparisons in the rollout validator require it. No predecessor template, role, projected volume, production Go config, SQL, pin, migration command or runtime was changed.

Tests reject a missing annotation, the wrong container name and an annotation misplaced on Deployment metadata. They also reject removal of the service-account role. The real Go loader accepts the modeled admitted render and continues to reject either injected ambient identity variable; removing the skip annotation or naming another container reproduces rejection. The fifth file only makes failed Go subprocess stdout/stderr visible in the Node test log.

## Verification

All commands and complete raw outputs are retained in this directory. Logs have exact working directory/argv and exit status.

| Log | Result |
| --- | --- |
| `admission-red-detail.log` | Expected RED, exit1,17.360s; actual worker-loader failure, migration loader passed. |
| `rollout-red.log` | Expected RED, exit1; missing pod admission control was accepted by the old validator. |
| `affected-green.log` | Exit0,158/158 checks,12.847s. New rollout, actual rendered worker/migration Go loaders with race detector, shared release contract and audit/existing-test/compliance rollout regressions. Zero skips. |
| `integrity.log` | Exit0. All57 prior source paths match the original snapshot plus exactly this five-path overlay; each fix before-blob equals its original Task2 after-blob. Reverse patch check passed. Per-file SHA256 values are included. |

The GREEN command was:

```
node task-2-fix1/run.mjs affected-green env ZASP_GO_BIN=/opt/homebrew/bin/go GOCACHE=/private/tmp/zasp-budget-go-cache /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test deploy/production/attack-lab-reconciler-runtime.test.mjs deploy/production/attack-lab-reconciler-rollout.test.mjs deploy/production/release-contract.test.mjs deploy/production/test-reconciler-rollout.test.mjs deploy/production/compliance-export-rollout.test.mjs deploy/production/audit-export-rollout.test.mjs
```

The raw log contains the full runner path. Its Go launcher checks1.25.6, disables toolchain/module fetches, inspects the exact anchored native test names with `-list`, then runs only those two non-PostgreSQL tests with `-race`. No database, controller, migration-chain or broad runtime suite was repeated; their source and accepted evidence are unchanged. All processes were joined.

## Frozen overlay

`before/`, `blobs.json` and `scoped.patch` preserve exact bytes independently of the original Task2 artifacts. Nothing was staged, committed or pushed.

- Fix patch SHA256: `72b5a16c5703eb3062281bb0e7aabbc67543ec435285da02ffb6550199163329`.
- Fix blob manifest SHA256: `8e1728e87ef2d10954c94370c267fe57ebf87463d75c90752d76cd2147224f55`.
- Original Task2 patch remains `8c54010a1126138036b8c68abf07a9761300d471cc4ba9125fde1741972efb51`; original manifest remains `68780934e800f16eedc50b345683a304f315de821294294d21c1dcdc6755f878`.

The original Task2 report receives only an appended fix note. Existing evidence and before bytes remain intact. Release57 checksum/fingerprint are unchanged.

Review reception, systematic debugging and TDD led to the admission-aware RED before changing deployment. Verification stayed at the affected deployment boundary. Independent fix acceptance remains with root. Live EKS/CSI/IRSA acceptance, unexecuted Terraform mocks and Task3 are still external gates; no provider calls, downloads, secrets or host PostgreSQL were used.
