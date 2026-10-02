# Commands and observed results

CWD for every command:
`/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.

Evidence directory: `.superpowers/sdd/2026-09-18-compliance-production-plan/compliance-ci-evidence`.
Logs are combined raw stdout/stderr from `2>&1 | tee <log>` with `set -o pipefail`, except the explicitly marked transcribed initial lint diagnostic. Exit statuses below came from completed tool commands, including joined asynchronous sessions.

Node executable: `/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node`.
The `node` commands below used:

```sh
export PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
```

Focused TDD command, first run and first GREEN:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test scripts/browser-prerequisites.test.mjs
```

`focused-red.log`: exit 1, 22 failures. `focused-green.log`: exit 0, 22 passes.

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-name-pattern='explicit C1' scripts/browser-prerequisites.test.mjs
```

`control-red.log`: exit 1, one expected failure. The corrected C1 case passed in the next grouped run.

Exact affected-group command, unchanged between diagnostic and corrected rerun:

```sh
node --test scripts/browser-prerequisites.test.mjs scripts/browser-e2e-helpers.test.mjs scripts/production-combined-e2e.test.mjs scripts/audit-export-browser-proof.test.mjs scripts/audit-export-volume-proof.test.mjs scripts/runtime-precision-browser-proof.test.mjs scripts/runtime-pipeline-dependencies.test.mjs scripts/owned-command.test.mjs scripts/owned-browser-postgres.test.mjs scripts/bounded-signal-cleanup.test.mjs scripts/compliance-browser-bytes.test.mjs
```

`grouped-node-before-contract-update.log`: exit 1, 145 pass / 2 fail / 2 skipped (149 total). Both failures were obsolete inline source checks.
`grouped-node.log`: exit 0, 146 pass / 0 fail / 2 skipped (148 total). The removed pg_config source-only test is replaced by behavior coverage.

Final focused suite after four additional pg_config characterization cases:

```sh
node --test scripts/browser-prerequisites.test.mjs
```

`focused-final.log`: exit 0, 27 passes, zero skips.

```sh
node node_modules/eslint/bin/eslint.js scripts/browser-prerequisites.mjs scripts/browser-prerequisites.test.mjs scripts/production-combined-e2e.mjs scripts/production-combined-e2e.test.mjs
```

`lint-final.log`: exit 0, no output. `lint-initial-diagnostic.log` retains the earlier no-control-regex error (exit 1), corrected with Cc validation and its RED test. `lint.log` is an intermediate three-file clean check.

Source/build capture and workflow syntax/scope checks:

```sh
node .superpowers/sdd/2026-09-18-compliance-production-plan/compliance-ci-capture.mjs before-browser
node .superpowers/sdd/2026-09-18-compliance-production-plan/compliance-ci-capture.mjs after
```

Both exited 0. `source-before-browser.log` and `source-after.log`. The capture program parses YAML with installed js-yaml and runs `/bin/bash -n` against each new shell block without executing its Docker pull. It verifies all prior steps unchanged, exact image agreement, step ordering/timeouts, unchanged assertion/launch/cleanup bodies, 18 previous UI/package blobs and equality of 4513 source/build identities. It writes the patch and manifest from captured BEFORE files.

One actual browser run:

```sh
export PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache
ZASP_COMBINED_E2E_COMPLIANCE=true node scripts/production-combined-e2e.mjs
```

`browser.log`: exit 0. Worker interrupt/resume, browser acceptance and full owned cleanup are in the log. No npm combined command, UI rebuild or local image pull.

Read-only Docker checks:

```sh
/usr/local/bin/docker container ls --all --no-trunc --format '{{.ID}} {{.Names}} {{.Status}}'
/usr/local/bin/docker image inspect postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba --format '{{json .RepoDigests}}'
diff -u .superpowers/sdd/2026-09-18-compliance-production-plan/compliance-ci-evidence/containers-before.log .superpowers/sdd/2026-09-18-compliance-production-plan/compliance-ci-evidence/containers-after.log
```

All exited 0; the inventory diff was empty. Image inspection returned the exact requested RepoDigest. `local-prerequisites.log` retains the digest and version check below.

```sh
node --input-type=module -e 'import {execFileSync} from "node:child_process"; import {selectBrowserExecutable} from "./scripts/browser-prerequisites.mjs"; const browser=selectBrowserExecutable(); console.log(process.platform, process.version, browser); console.log(execFileSync(browser,["--version"],{encoding:"utf8",timeout:5000,killSignal:"SIGKILL"}));'
```

Exit 0: darwin, v22.23.1, existing macOS application path, Google Chrome 153.0.8010.48.

```sh
git diff --check -- scripts/production-combined-e2e.mjs scripts/production-combined-e2e.test.mjs .github/workflows/runnable-ui.yml
ps -ax -o pid=,ppid=,comm= | rg 'agentsec-(api|worker)|vinext|production-combined'
```

Whitespace check exited 0. Process-name search had no matches (rg exit 1), after the actual browser session itself had joined with exit 0. This is supplementary cleanup evidence, not a replacement for the harness's owned-process and container joins.

An exploratory `node -p "require.resolve('yaml')"` used the shell's default Node v26.8.2 and failed because that optional package was absent. No verification relied on it. The installed js-yaml package was then resolved under Node v22.23.1 and used successfully; nothing was installed.
