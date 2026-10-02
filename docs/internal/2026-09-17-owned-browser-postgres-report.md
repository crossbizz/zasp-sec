# Owned browser PostgreSQL prerequisite, 2026-09-17

DONE. The combined runner now uses the cached, owned Docker database by default. This is local database lifecycle evidence, not mounted-browser acceptance or production proof. Schema selection is unchanged; this work does not provide schema55 acceptance.

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/budget-recovery-20260916`.
Inherited dirty work was preserved. No commit, push, image pull, host PostgreSQL startup, broad Docker cleanup, migration edit, or test-action enablement occurred.

## What changed

- New `scripts/owned-browser-postgres.mjs`: synchronous owner construction, pinned `--pull=never` create, loopback-only publication, postgres user, read-only root, ephemeral tmpfs storage. PGDATA is `/tmp/pgdata`; tmpfs also covers the image's declared data volume and default Unix socket directory. Optional `track_functions=pl` remains available.
- Thirteen behavioral tests in `scripts/owned-browser-postgres.test.mjs` cover command arguments, validation, readiness/start failure, early exit, lost create response, identity rejection, concurrent stop, cancellation, deadline joins, and cleanup failure. Only the external owned-command boundary is replaced.
- `scripts/production-combined-e2e.mjs` registers the owner before awaiting startup; stop calls its joined cleanup. The retirement diagnostic inspects the owned container, not a Docker CLI child's PID.
- Two consumer regressions in `scripts/production-combined-e2e.test.mjs` execute the actual functions. Removed obsolete `initdb`/`pg_ctl` expectations from an inherited source-contract test; no new source-presence assertion was added.

The review patch is `docs/internal/2026-09-17-owned-browser-postgres-scoped.patch`. It contains only this task's consumer edits against their inherited dirty baseline, plus the complete new helper and helper tests. Its zero-context hunks are intentional. `git apply --check --reverse --unidiff-zero` passed against the finished worktree.

## RED, then the failures worth keeping

All commands ran from the worktree above. Node was `/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node`.

Initial focused RED:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test scripts/owned-browser-postgres.test.mjs
```

Exit 1: 13 tests, 0 pass, 13 fail. The missing lifecycle implementation produced `owned PostgreSQL lifecycle must exist`, actual `undefined`, expected `function`. The invalid-port assertion also failed because the implementation did not exist yet.

Consumer RED, after correcting incomplete VM fixtures:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-name-pattern='combined PostgreSQL startup|retirement diagnostic rejects' scripts/production-combined-e2e.test.mjs
```

Exit 1: 2 tests, 0 pass, 2 fail. Startup left `postgres` undefined instead of the owner. The diagnostic reached the SQL boundary before checking container liveness: `SQL reached before owned container liveness check`.

The first grouped attempt found two failures: the deadline path called stop twice, and the real combined-runner SIGTERM test found a container startup failure. After reusing the deadline's stop promise, a second grouped attempt had only the real startup failure. Counts were respectively 64 pass / 2 fail / 2 skipped and 65 pass / 1 fail / 2 skipped, each out of 68 tests. Those commands included a nonexistent `scripts/bounded-signal-cleanup.test.mjs` argument, which Node did not select; the actual bounded-signal tests are in `production-combined-e2e.test.mjs`. The final command below corrects that file list.

The failed live container's log explained startup: the server socket was moved to `/tmp`, but the image entrypoint's setup `psql` still expected `/var/run/postgresql/.s.PGSQL.5432`. It exited with `No such file or directory`. Failed container `5cad49192df62790b4e482d35c37bb227106b07d9113cfdc609e0ea0a352efd3` was removed by helper cleanup.

I changed the command-argument test first, then ran:

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-name-pattern='starts only pinned' scripts/owned-browser-postgres.test.mjs
```

Exit 1: 1 test failed on the missing `/var/run/postgresql` tmpfs and the incorrect `unix_socket_directories=/tmp` argument. The implementation now leaves the image's socket path unchanged and makes that directory ephemeral and writable.

## Grouped GREEN

```sh
PATH=/usr/local/bin:$PATH /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test scripts/owned-browser-postgres.test.mjs scripts/owned-command.test.mjs scripts/production-combined-e2e.test.mjs
```

Exit 0:

```text
1..61
# tests 68
# suites 0
# pass 66
# fail 0
# cancelled 0
# skipped 2
# todo 0
# duration_ms 3846.21875
```

This includes real combined-runner SIGTERM cleanup, bounded signal cleanup idempotence, failed-resource artifact retention, and owned-command TERM-resistant descendant joins. Two separate opt-in tests stayed skipped: `combined runtime proof removes owned containers and processes on real SIGTERM` requires `ZASP_RUNTIME_PIPELINE_SIGNAL_TEST=true`; `composed Red Team runtime removes its owned container on real SIGTERM` requires `ZASP_RED_TEAM_RUNTIME_SIGNAL_TEST=true`. Neither opt-in was enabled for this prerequisite.

## Cached-image SQL smoke

The initial read-only image check returned image ID `sha256:0984215845c9203725ec1049ec2b1bdd2e8f5e0eeb4a82cfea4d9928a952ad40`, with declared volume `/var/lib/postgresql`. The only database image used was:

```text
postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba
```

Exact successful smoke command:

```sh
PATH=/usr/local/bin:$PATH /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { createOwnedBrowserPostgres } from './scripts/owned-browser-postgres.mjs';
const listener=net.createServer().listen(0,'127.0.0.1'); await once(listener,'listening');
const port=listener.address().port; await new Promise(resolve=>listener.close(resolve));
const owner=createOwnedBrowserPostgres({port,trackFunctions:true});
const docker=args=>execFileSync('/usr/local/bin/docker',args,{encoding:'utf8',timeout:5000}).trim();
try {
 await owner.start(); await owner.assertRunning();
 const inspected=JSON.parse(docker(['inspect',owner.containerID]))[0];
 assert.equal(inspected.Config.User,'postgres'); assert.equal(inspected.HostConfig.ReadonlyRootfs,true);
 assert.deepEqual(inspected.HostConfig.PortBindings,{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:String(port)}]});
 assert.equal(inspected.Mounts.some(m=>m.Type==='volume'||m.Type==='bind'),false);
 const bin=execFileSync('pg_config',['--bindir'],{encoding:'utf8',timeout:5000}).trim();
 const sql=execFileSync(path.join(bin,'psql'),[`postgres://zasp_e2e@127.0.0.1:${port}/postgres?sslmode=disable`,'-X','-At','-v','ON_ERROR_STOP=1','-c',"SELECT current_user || '|' || current_database() || '|' || current_setting('track_functions') || '|' || (SELECT 40+2)::text"],{encoding:'utf8',timeout:5000}).trim();
 assert.equal(sql,'zasp_e2e|postgres|pl|42');
 console.log(JSON.stringify({containerID:owner.containerID,port,sql,user:inspected.Config.User,readOnlyRoot:inspected.HostConfig.ReadonlyRootfs,mountTypes:inspected.Mounts.map(m=>m.Type)}));
} finally {
 await owner.stop();
 const remaining=docker(['container','ls','--all','--no-trunc','--filter',`id=${owner.containerID}`,'--format','{{.ID}}']); assert.equal(remaining,'');
 console.log(JSON.stringify({containerID:owner.containerID,cleanup:'exact ID absent'}));
}
JS
```

Exit 0, output:

```json
{"containerID":"861a49507de0eb7d7074c64f1850d04f58b1929a6e7f9871414aecf8e07b470d","port":50618,"sql":"zasp_e2e|postgres|pl|42","user":"postgres","readOnlyRoot":true,"mountTypes":[]}
{"containerID":"861a49507de0eb7d7074c64f1850d04f58b1929a6e7f9871414aecf8e07b470d","cleanup":"exact ID absent"}
```

## Self-review and terminal cleanup

The helper uses invocation-random names and an ownership label for recovery when create's response is lost. A recovered resource must match its exact name, label, image, and full ID before cleanup; normal cleanup uses only the returned full container ID. No global removal or guessed historical ID is used. CLI deadlines include the existing owned-command bounded stop/join. Cleanup attempts removal and an independent exact-ID absence query even after stop errors. Repeated/concurrent stop shares one promise, including its failure. The runner's existing failed-cleanup branch retains artifacts.

These final checks exited 0 with no output:

```sh
git apply --check --reverse --unidiff-zero docs/internal/2026-09-17-owned-browser-postgres-scoped.patch
git diff --check -- scripts/production-combined-e2e.mjs scripts/production-combined-e2e.test.mjs
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --check scripts/owned-browser-postgres.mjs
/usr/local/bin/docker container ls --all --no-trunc --filter label=zasp.browser-postgres.owner --format '{{.ID}} {{.Names}}'
```

The last command is read-only inventory, not cleanup. It found no containers with this helper's ownership label. The grouped runner test also confirmed its owned temporary root disappeared and an unrelated root survived. All tool command sessions completed. The disposable databases and their ephemeral data were removed; they are not recoverable.

The full mounted browser flow was not run. Main owns independent review and the acceptance ledger.
