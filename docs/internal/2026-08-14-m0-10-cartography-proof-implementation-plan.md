# M0-10 Cartography Scope Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that exact-pinned Cartography AWS and GitHub fixture graphs normalize into collision-free, customer-safe records for two Product Organizations without depending on the blocked real-AWS authorization proof.

**Architecture:** A standard-library Node adapter normalizes strict graph records into Product Organization-scoped identities. A small Python 3.13 fixture bridge runs inside the exact Cartography image, loads one AWS account/role and one GitHub organization/repository through Cartography's `0.139.1` schemas into an exact-pinned disposable Neo4j graph, and emits a bounded allowlisted inspection record. A hardened Node orchestrator runs two independent graph targets, merges the normalized results, emits one fixed line, and proves exact cleanup.

**Tech Stack:** Node.js `22.23.1`, npm `10.9.8`, Python `3.13.11` for local unit tests, Cartography `0.139.1`, Neo4j Community `5.26.29`, Docker, Node built-in test runner, Python `unittest`, Vitest.

## Global Constraints

- Source of truth remains `docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md`; this plan implements M0-10 only.
- M0-09 and PROV-01 remain Blocked and R-03 remains incomplete.
- The August 14 delivery waiver permits M0-10 to start without claiming AWS or GitHub authorization parity.
- Cartography image is exactly `ghcr.io/cartography-cncf/cartography:0.139.1@sha256:f1d7c1f46a8a2137b9a955327d3cd47e8340c7d537d0447467d2e952af8bb8f0`.
- Neo4j image is exactly `neo4j:5.26-community@sha256:d9dd3dc7d1c78fa959191ff02dbdcbefadceaf83eee23428fb92a58cac8ad3fe`.
- The proof never reads ambient AWS, GitHub, Neo4j, proxy, Docker credential, or `.env` input and never contacts AWS or GitHub. Every Docker subprocess receives an owned empty `DOCKER_CONFIG` and an explicit environment allowlist.
- Every created Docker object uses an exact `zasp-m0-10-<16 lowercase hex>` run name, `zasp.proof=m0-10`, and the exact run marker.
- All process output and graph responses are byte- and time-bounded; user-facing output is fixed and secret-free.
- Cleanup authority requires fresh exact ownership proof and an independent bounded cleanup context; cleanup failure wins.
- Customer-visible normalized kinds and relationship names contain none of `Cartography`, `Neo4j`, `AWS`, or `GitHub`.
- The UI quality gate must remain runnable after every commit and push.

---

### Task 1: Authorize and start M0-10

**Files:**
- Create: `app/quality/cartography-scope-proof-contract.test.ts`
- Modify: `app/quality/localstack-iam-compat-proof-contract.test.ts`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the committed delivery-waiver design and the reviewed PROV-01 Blocked evidence.
- Produces: authoritative source-task counts `718/1/8/1`, M0 counts `17/1/8/1`, and an `M0-10` In progress row while M0-09 and PROV-01 remain Blocked.

- [ ] **Step 1: Write the status-transition RED**

Add a Vitest contract that reads the waiver, tracker, README, and source plan and asserts:

```ts
expect(tracker).toContain("| Pending | 718 |");
expect(tracker).toContain("| In progress | 1 |");
expect(tracker).toContain("| Complete | 8 |");
expect(tracker).toContain("| Blocked | 1 |");
expect(tracker).toMatch(/\| M0 \| 27 \| 17 \| 1 \| 8 \| 1 \|/);
expect(tracker).toMatch(/\| M0-10 \| August 14, 2026 \|/);
expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
expect(tracker).toContain("R-03 remains incomplete");
expect(readme).toContain("M0-10 is In progress under the Cartography delivery waiver");
expect(waiver).toContain("fixture-only Cartography normalization proof");
expect(sourcePlan).toContain("**M0-10 - Cartography proof**");
```

Update the existing LocalStack IAM contract so it expects M0-10 In progress under the new waiver while still requiring PROV-01 Blocked and no parity claim.

- [ ] **Step 2: Run the focused status contract RED**

Run:

```bash
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH \
  npx vitest run app/quality/cartography-scope-proof-contract.test.ts app/quality/localstack-iam-compat-proof-contract.test.ts
```

Expected: the new status/count assertions fail against `719/0/8/1` and the missing M0-10 row; existing PROV-01 assertions remain green.

- [ ] **Step 3: Update the authoritative status and README**

Move one source task from Pending to In progress. Add:

```markdown
| M0-10 | August 14, 2026 | Implement the two-Organization Cartography AWS/GitHub fixture proof under the delivery waiver; normalization and OSS integration only, with no AWS/GitHub authorization-parity claim. |
```

Record the waiver decision and preserve the exact blocked dependency text for M0-09/PROV-01. Update the README status note to state that M0-10 is In progress under the fixture-only delivery waiver.

- [ ] **Step 4: Run focused and full repository gates GREEN**

Run:

```bash
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH \
  npx vitest run app/quality/cartography-scope-proof-contract.test.ts app/quality/localstack-iam-compat-proof-contract.test.ts
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm run verify
git diff --check
```

Expected: focused contracts and the full repository gate pass.

- [ ] **Step 5: Commit the task start**

```bash
git add app/quality/cartography-scope-proof-contract.test.ts \
  app/quality/localstack-iam-compat-proof-contract.test.ts \
  docs/internal/implementation_status_v1.5.md README.md
git commit -m "docs: start M0-10 Cartography proof"
```

---

### Task 2: Organization-scoped graph normalizer

**Files:**
- Create: `proofs/cartography-scope/normalizer.test.mjs`
- Create: `proofs/cartography-scope/normalizer.mjs`
- Create: `proofs/cartography-scope/fixtures/org-a.json`
- Create: `proofs/cartography-scope/fixtures/org-b.json`

**Interfaces:**
- Consumes:

```ts
type RawGraph = {
  schema_version: 1;
  nodes: Array<{ labels: string[]; properties: Record<string, unknown> }>;
  relationships: Array<{
    type: string;
    source: { label: string; id: string };
    target: { label: string; id: string };
  }>;
};
```

- Produces:

```ts
export function validateOrganizationId(value: unknown): string;
export function parseRawGraph(value: unknown): RawGraph;
export function normalizeGraph(organizationId: string, rawGraph: RawGraph): NormalizedGraph;
export function mergeNormalizedGraphs(graphs: NormalizedGraph[]): NormalizedGraph;

type NormalizedGraph = {
  organization_id: string | "multiple";
  nodes: Array<{
    id: string;
    organization_id: string;
    provider: "aws" | "github";
    kind: "cloud_account" | "identity_role" | "code_organization" | "code_repository";
    source_id: string;
  }>;
  relationships: Array<{
    id: string;
    organization_id: string;
    kind: "contains_identity" | "owns_repository";
    source_id: string;
    target_id: string;
  }>;
};
```

- [ ] **Step 1: Add exact fixture bundles**

Each file has `schema_version: 1`, an AWS account and role, and a GitHub organization and repository. Both fixtures deliberately reuse these raw identities:

```json
{
  "aws_account_id": "000000000000",
  "aws_role_arn": "arn:aws:iam::000000000000:role/shared-fixture-role",
  "github_organization_url": "https://api.github.test/orgs/shared-fixture",
  "github_repository_id": "424242"
}
```

Only the Product Organization scope distinguishes the normalized records. Fixture files contain no credentials, tokens, real domains, or customer values.

- [ ] **Step 2: Write normalizer RED tests**

Cover the exact happy cardinality (four nodes and two relationships per Organization), overlapping raw IDs producing distinct canonical IDs, deterministic ordering, and fixed canonical-ID grammar:

```js
assert.match(node.id, /^org_[a-z0-9]{16}:(aws|github):[a-z_]+:[a-f0-9]{64}$/);
assert.equal(new Set(merged.nodes.map((node) => node.id)).size, 8);
assert.equal(merged.relationships.length, 4);
```

Add table tests that reject missing/null/unknown/case-aliased/duplicate keys, unknown or extra labels, extra properties, invalid Organization IDs, duplicate canonical IDs, duplicate relationships, cross-Organization endpoints, dangling endpoints, reversed edges, malformed source IDs, non-string values, arrays beyond eight entries, cyclic input objects, and customer-visible kinds containing any OSS/provider name.

- [ ] **Step 3: Run normalizer RED**

Run:

```bash
cd proofs/cartography-scope
node --test normalizer.test.mjs
```

Expected: module-not-found or missing-export failures before `normalizer.mjs` exists.

- [ ] **Step 4: Implement strict normalization GREEN**

Use only Node standard-library APIs. Define an exact label mapping:

```js
const nodeKinds = new Map([
  ["AWSAccount", ["aws", "cloud_account"]],
  ["AWSRole", ["aws", "identity_role"]],
  ["GitHubOrganization", ["github", "code_organization"]],
  ["GitHubRepository", ["github", "code_repository"]],
]);
const relationshipKinds = new Map([
  ["AWSAccount|RESOURCE|AWSRole", "contains_identity"],
  ["GitHubRepository|OWNER|GitHubOrganization", "owns_repository"],
]);
```

Canonical IDs use `sha256(JSON.stringify([organizationId, provider, kind, sourceId]))`. Parse with explicit recursive key enumeration and reject accessors, prototypes other than `Object.prototype`/`null`, duplicate semantic identities, non-plain objects, and non-finite sizes. Never pass raw labels or properties into normalized display fields.

- [ ] **Step 5: Run normalizer GREEN and stability**

```bash
cd proofs/cartography-scope
node --test normalizer.test.mjs
for run in 1 2 3 4 5; do node --test normalizer.test.mjs; done
```

Expected: all runs pass with identical fixture digests and normalized output.

- [ ] **Step 6: Commit the normalizer**

```bash
git add proofs/cartography-scope/normalizer.mjs \
  proofs/cartography-scope/normalizer.test.mjs \
  proofs/cartography-scope/fixtures/org-a.json \
  proofs/cartography-scope/fixtures/org-b.json
git commit -m "feat: normalize Cartography graphs by Organization"
```

---

### Task 3: Exact Cartography fixture bridge

**Files:**
- Create: `proofs/cartography-scope/fixture_runner_test.py`
- Create: `proofs/cartography-scope/fixture_runner.py`

**Interfaces:**
- Consumes: one strict fixture JSON document, `NEO4J_URI`, and the exact Cartography `0.139.1` runtime.
- Produces:

```py
def parse_fixture(raw: bytes) -> Fixture: ...
def load_fixture(session: object, fixture: Fixture, api: CartographyAPI) -> None: ...
def inspect_graph(session: object, fixture: Fixture) -> dict[str, object]: ...
def run_main(argv: list[str], environ: Mapping[str, str], stdout: TextIO) -> int: ...
```

`CartographyAPI` exposes only `load`, `AWSAccountSchema`, `AWSRoleSchema`, `GitHubOrganizationSchema`, and `GitHubRepositorySchema`. Runtime imports are lazy so unit tests inject a fake API without installing Cartography on the host.

- [ ] **Step 1: Write Python bridge RED tests**

Use Python `unittest`, strict fake sessions, and fake schema/load functions. Assert the bridge invokes exactly:

```py
api.load(session, api.AWSAccountSchema(), [fixture.aws_account], lastupdated=1, inscope=True)
api.load(session, api.AWSRoleSchema(), [fixture.aws_role], lastupdated=1, AWS_ID=fixture.aws_account["id"])
api.load(session, api.GitHubOrganizationSchema(), [fixture.github_organization], lastupdated=1)
api.load(session, api.GitHubRepositorySchema(), [fixture.github_repository], lastupdated=1)
```

Assert the two bounded inspection queries return exactly four allowlisted nodes and two allowlisted relationships. Add failures for query cardinality mismatch, duplicate/unknown labels, unexpected properties, missing endpoints, multiple records, malformed JSON, UTF-8 errors, oversized input/output, symlink fixture paths, ambient environment keys, driver exceptions, timeout, and stdout write failure.

- [ ] **Step 2: Run Python RED**

```bash
cd proofs/cartography-scope
/opt/homebrew/bin/python3.13 -m unittest -v fixture_runner_test.py
```

Expected: import or missing-symbol failures because `fixture_runner.py` does not exist.

- [ ] **Step 3: Implement the standard-library boundary and lazy Cartography imports**

The runner accepts only:

```text
--fixture /proof/fixture.json --neo4j-uri bolt://<owned-name>:7687
```

Require an absolute, regular, non-symlink fixture file under `/proof`, maximum 16 KiB, and a Neo4j URI with scheme `bolt`, exact owned container hostname grammar, port `7687`, empty user info/query/fragment, and no IP literal. Reject every environment variable except the fixed container runtime baseline allowlist documented in the tests; never read proxy or credential variables.

Use `neo4j.GraphDatabase.driver(uri, auth=None)` with a 10-second connection timeout and a 45-second absolute operation deadline. Import the five exact Cartography APIs lazily. Emit only one compact JSON document, capped at 16 KiB, to stdout; errors use one fixed `Cartography fixture bridge failed.` line and exit `1`.

- [ ] **Step 4: Run bridge GREEN and static checks**

```bash
cd proofs/cartography-scope
/opt/homebrew/bin/python3.13 -m unittest -v fixture_runner_test.py
/opt/homebrew/bin/python3.13 -m compileall -q fixture_runner.py fixture_runner_test.py
```

Expected: all tests and compilation pass.

- [ ] **Step 5: Commit the fixture bridge**

```bash
git add proofs/cartography-scope/fixture_runner.py proofs/cartography-scope/fixture_runner_test.py
git commit -m "feat: load Cartography fixture graphs"
```

---

### Task 4: Disposable Cartography and Neo4j orchestrator

**Files:**
- Create: `proofs/cartography-scope/run.test.mjs`
- Create: `proofs/cartography-scope/run.mjs`

**Interfaces:**
- Consumes: `normalizeGraph`, `mergeNormalizedGraphs`, both fixture files, and `fixture_runner.py`.
- Produces:

```ts
export const CARTOGRAPHY_IMAGE: "ghcr.io/cartography-cncf/cartography:0.139.1@sha256:f1d7c1f46a8a2137b9a955327d3cd47e8340c7d537d0447467d2e952af8bb8f0";
export const NEO4J_IMAGE: "neo4j:5.26-community@sha256:d9dd3dc7d1c78fa959191ff02dbdcbefadceaf83eee23428fb92a58cac8ad3fe";
export class DockerRuntime { /* exact owned lifecycle methods */ }
export async function orchestrate(runtime?: DockerRuntime): Promise<{code: number; line: string}>;
export async function runMain(runtime?: DockerRuntime): Promise<number>;
```

- [ ] **Step 1: Write orchestrator RED tests**

Create fake-runtime tests for:

- exact image digests, names, labels, marker, network membership, `NEO4J_AUTH=none`, and random loopback publication;
- an owned empty `DOCKER_CONFIG`, explicit Docker subprocess environment, exact-image pull/inspect behavior, and rejection of ambient credential/proxy input;
- two distinct Neo4j names and two one-shot Cartography names;
- Cartography `--entrypoint python`, read-only `/proof` mount, no credential/proxy environment, and exact fixture/Neo4j arguments;
- absent image/network/container, prefix collision, wrong image/name/label/marker/network/port, truncated IDs, ambiguous create/remove, and replacement objects;
- 16 KiB readiness/bridge output caps, 500 ms readiness calls, absolute readiness/build/proof deadlines, SIGKILL, split-stream overflow, malformed bridge JSON, graph mismatch, panic, cancellation, and construction failure;
- cleanup continuation and precedence across both Cartography containers, both Neo4j containers, network, and temporary directory;
- temp admission plus cleanup-time canonical path/device/inode reproof;
- exact absence of every owned prefix and preservation of an injected shared non-proof container;
- one exact success line:

```text
Cartography scope proof passed: fixtures=2 nodes=8 relationships=4 isolated=true labels_safe=true cleanup=true.
```

Failures are exactly `Cartography scope proof failed: <category> rejected.` with categories `configuration`, `provider`, `ownership`, `normalization`, `cleanup`, or `operation`.

- [ ] **Step 2: Run orchestrator RED**

```bash
cd proofs/cartography-scope
node --test run.test.mjs
```

Expected: module-not-found or missing-export failures before `run.mjs` exists.

- [ ] **Step 3: Implement DockerRuntime**

Use asynchronous `spawn`, combined 16 KiB stdout/stderr caps, absolute deadlines, and SIGKILL. Create and cleanup-time re-prove an owned empty Docker-config directory; pass it as `DOCKER_CONFIG` with an otherwise explicit Docker subprocess environment. Docker mutations are single-attempt; read-only list/inspect calls have two attempts with at most 500 ms backoff. Resolve direct and ambiguous results only through exact name, full ID, image digest, both labels, network, and marker.

Start two Neo4j containers with `--rm`, `--env NEO4J_AUTH=none`, the proof labels, the exact network, and `--publish 127.0.0.1::7687`. Start each Cartography runner with `--rm`, the same exact network, proof labels, `--entrypoint python`, a read-only owned proof-directory mount, and no inherited environment. Capture bridge JSON internally; never write it to user output.

- [ ] **Step 4: Implement orchestration and fixed output**

Preflight exact-prefix absence, create owned temp directory/network, start and verify both graphs, wait for exact Neo4j readiness, run both fixture bridges, parse/normalize/merge, assert exact cardinality and safety booleans, then cleanup in reverse dependency order. Cleanup re-proves every target immediately before mutation and requires exact post-delete absence.

The outer supervisor is 300 seconds. Cleanup has a separate 60-second budget. Construction and panic handling sit inside the fixed-output boundary.

- [ ] **Step 5: Run orchestrator and complete proof suite GREEN**

```bash
cd proofs/cartography-scope
node --test normalizer.test.mjs run.test.mjs
/opt/homebrew/bin/python3.13 -m unittest -v fixture_runner_test.py
for run in 1 2 3 4 5; do node --test normalizer.test.mjs run.test.mjs; done
```

Expected: all hermetic tests pass without starting Docker.

- [ ] **Step 6: Commit the orchestrator**

```bash
git add proofs/cartography-scope/run.mjs proofs/cartography-scope/run.test.mjs
git commit -m "feat: orchestrate disposable Cartography proof"
```

---

### Task 5: Repository commands and operator documentation

**Files:**
- Modify: `app/quality/cartography-scope-proof-contract.test.ts`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`

**Interfaces:**
- Consumes: the complete hermetic proof.
- Produces exact root commands:

```json
"proof:cartography:test": "cd proofs/cartography-scope && node --test normalizer.test.mjs run.test.mjs && /opt/homebrew/bin/python3.13 -m unittest -v fixture_runner_test.py",
"proof:cartography:run": "node proofs/cartography-scope/run.mjs"
```

- [ ] **Step 1: Extend repository contract RED**

Require both scripts, exact image/version digests, Python `3.13.11`, no dotenv/credential/proxy input, the exact fixed result, the README root command block, two-Organization fixture language, and explicit non-parity statements.

- [ ] **Step 2: Run focused contract RED**

```bash
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH \
  npx vitest run app/quality/cartography-scope-proof-contract.test.ts
```

Expected: command and README assertions fail while the M0-10 status assertion remains green.

- [ ] **Step 3: Add scripts and README instructions**

Add `## Cartography Organization-scope proof` with:

```bash
npm run proof:cartography:test
npm run proof:cartography:run
```

Document Docker and Python 3.13 requirements, exact fixture-only scope, no credentials, no AWS/GitHub calls, customer-label normalization, cleanup, and the unchanged M0-09/PROV-01/R-03 boundary.

- [ ] **Step 4: Run focused and full repository gates GREEN**

```bash
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH \
  npx vitest run app/quality/cartography-scope-proof-contract.test.ts
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm run verify
git diff --check
```

- [ ] **Step 5: Commit repository wiring**

```bash
git add app/quality/cartography-scope-proof-contract.test.ts package.json README.md \
  docs/internal/implementation_status_v1.5.md
git commit -m "docs: expose Cartography scope proof"
```

---

### Task 6: Live proof, audits, review, completion, and push

**Files:**
- Create: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-10-report.md`
- Modify: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/progress.md`
- Modify after clean review: `docs/internal/implementation_status_v1.5.md`
- Modify after clean review: `app/quality/cartography-scope-proof-contract.test.ts`

**Interfaces:**
- Consumes: root proof commands and exact disposable runtime.
- Produces: safe live evidence, zero-resource cleanup evidence, independent review package, M0-10 Complete status, and a pushed exact-SHA runnable UI gate.

- [ ] **Step 1: Record shared Docker state without mutation**

Use read-only inspection and record only booleans/counts. Never emit unrelated container IDs, names, images, labels, ports, mounts, or configuration.

- [ ] **Step 2: Run the live proof**

```bash
npm run proof:cartography:run
```

Expected: the exact fixed success line and exit `0`. On failure, first prove exact owned-resource absence, then use `superpowers:systematic-debugging`; never weaken fixture isolation, label safety, ownership, or cleanup requirements.

- [ ] **Step 3: Run separate cleanup and collision audits**

Require exact proof-prefix counts of zero for Cartography containers, Neo4j containers, networks, and temporary directories. Re-run the normalized merger against the retained fixture outputs only inside the proof boundary and emit safe evidence `fixtures=2 nodes=8 relationships=4 collisions=0 resources=0`.

- [ ] **Step 4: Run final local gates**

```bash
cd proofs/cartography-scope
for run in 1 2 3 4 5; do node --test normalizer.test.mjs run.test.mjs; done
node --test normalizer.test.mjs run.test.mjs
/opt/homebrew/bin/python3.13 -m unittest -v fixture_runner_test.py
/opt/homebrew/bin/python3.13 -m compileall -q fixture_runner.py fixture_runner_test.py
cd ../..
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm run proof:cartography:test
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm run verify
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm audit --omit=dev
git diff --check
```

Expected: all commands exit zero and production audit reports zero vulnerabilities.

- [ ] **Step 5: Run pinned Gitleaks v8.30.1 scans**

Scan the proof paths, repository contract, docs/tracker diff, ignored brief/report/ledgers, staged diff, and full history with redaction. Record only counts/categories; never emit findings or source values.

- [ ] **Step 6: Write evidence and request independent review**

Record exact pins, RED/GREEN counts, live fixed output, cardinality/isolation/label-safety result, cleanup counts, gates, scans, limitations, base/head SHAs, and reviewer package. Leave M0-10 In progress until the reviewer reports zero remaining Critical, Important, and Minor findings.

- [ ] **Step 7: Resolve review findings through TDD**

For every accepted finding, preserve a genuine focused RED, apply the minimal fix in a separate commit, rerun all affected/full gates, update ignored evidence, and request scoped re-review. Do not controller-fix subagent findings.

- [x] **Step 8: Mark M0-10 Complete after zero-finding review**

Move M0-10 from In progress to Complete. Counts become Pending `718`, In progress `0`, Complete `9`, Blocked `1`; M0 becomes Pending `17`, In progress `0`, Complete `9`, Blocked `1`. Keep M0-09/PROV-01 Blocked and R-03 incomplete.

- [ ] **Step 9: Run final verification, commit, push, and watch CI**

```bash
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm run verify
git add docs/internal/implementation_status_v1.5.md app/quality/cartography-scope-proof-contract.test.ts
git commit -m "docs: complete M0-10 Cartography proof"
git push origin codex/zasp-implementation
```

Require the remote `Runnable UI` workflow to pass at the exact pushed SHA before reporting completion.
