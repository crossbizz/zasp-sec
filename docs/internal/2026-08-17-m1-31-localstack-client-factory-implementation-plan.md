# M1-31 LocalStack Client Factory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one strict product AWS client factory whose SQS, S3, KMS,
Secrets Manager, and OpenSearch clients use the reviewed LocalStack endpoint
only in explicit local or CI mode.

**Architecture:** Add a focused `services/platform/awsclient` package that
constructs five official AWS SDK v2 clients from one validated authority
decision. Production uses only caller-supplied region, credential, and HTTP
authority; local and CI read the two exact M1-30d endpoint keys through an
injected lookup, replace credentials with fixed synthetic values, and use a
factory-owned proxy-free bounded client.

**Tech Stack:** Go 1.25.6, AWS SDK for Go v2, Node.js 22.23.1, npm 10.9.8,
Vitest 4.1.10, Gitleaks 8.30.1, GitHub Actions Runnable UI.

**Spec:** `docs/internal/2026-08-17-m1-31-localstack-client-factory-design.md`

## Global constraints

- Work only on M1-31. M1-32 remains Pending.
- Preserve M1-30 and all M1-30a through M1-30d contracts, manifests, output,
  provider traces, ownership, and cleanup.
- The factory reads no process environment, profile, shared AWS
  configuration, IMDS, web identity, proxy, dotenv, or Kubernetes authority.
- Local and CI read exactly `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_S3`
  through an injected lookup and no other key.
- Local accepts only
  `http://localstack.zasp-local.svc.cluster.local:4566`; CI accepts only
  `http://127.0.0.1:<1-65535>`.
- Both override values must be present, canonical, and byte-identical.
- Local and CI use region `us-east-1`, fixed `test` credentials, a proxy-free
  bounded owned HTTP client, no redirects, and no SDK retry.
- Production rejects endpoint lookup authority and requires explicit region,
  credential provider, and HTTP client authority.
- Add no provider mutation, live LocalStack lifecycle, adapter behavior,
  product service wiring, or compatibility claim.
- Every behavior or status change requires a witnessed tests-only RED first.
- Completion requires whole-range zero-finding review, full pinned gates,
  pushed completion and closure commits, and exact-SHA Runnable UI success.

---

### Task 1: Start M1-31 with an exact repository contract

**Files:**
- Create: `app/quality/aws-client-factory-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current count/status fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-31 source row, committed design, M1-30 Complete state, and
  exact blocker set.
- Produces: exact M1-31 In-progress status at overall `656/1/68/3` and M1
  `68/23/1/44/0`.

- [ ] **Step 1: Write the failing source, design, and status contract**

Create `app/quality/aws-client-factory-contract.test.ts`. Parse the M1-31
source section and require:

```ts
expect(section).toContain("Depends on: `M1-30`");
expect(section).toContain("Deliverable: Add AWS endpoint override in product AWS client factory for local/CI only.");
expect(section).toContain("Verify: Test points SQS/S3/KMS/Secrets/OpenSearch clients at LocalStack.");
expect(section).toContain("Timebox: <=15 minutes.");
```

Bind the selected single-factory design, exact two endpoint keys, explicit
production/local/CI modes, five service clients, no ambient authority,
synthetic credentials, one-attempt requests, dependency versions, and M1-32
deferral. Require M1-31 as the sole active row, M1-30 exactly once in Complete,
M1-32 absent from active and complete rows, and blockers exactly M0-09, M0-18,
and M0-19.

- [ ] **Step 2: Witness status RED**

Run:

```sh
npx vitest run app/quality/aws-client-factory-contract.test.ts \
  app/quality/local-start-target-contract.test.ts
```

Expected: the new contract fails only because M1-31 is absent, counts remain
`657/0/68/3`, and README does not document active M1-31. The completed M1-30
contract stays green.

- [ ] **Step 3: Move only M1-31 to In progress**

Change overall `657/0/68/3` to `656/1/68/3` and M1 `68/24/0/44/0` to
`68/23/1/44/0`. Add exactly one current row:

```markdown
| M1-31 | August 17, 2026 | Adding one strict product AWS client factory whose SQS, S3, KMS, Secrets Manager, and OpenSearch clients accept the reviewed endpoint override only in explicit local or CI mode. |
```

Update only current status/count fixtures mechanically. Preserve historical
mutation fixtures and every Complete or Blocked row.

- [ ] **Step 4: Run focused and full quality GREEN**

Run the new contract, the M1-30 contract, and `npm test`. Require 728-task
arithmetic, active rows exactly `['M1-31']`, 68 complete rows, one complete
M1-30 row, no complete M1-31 or active/complete M1-32 row, and the exact
blocker set.

- [ ] **Step 5: Scan and commit the start transition**

Run staged whitespace and pinned redacted Gitleaks checks. Commit only the
status, README, and quality-contract slice as:

```text
docs: start M1-31 LocalStack client factory
```

---

### Task 2: Build the strict five-client factory tests-first

**Files:**
- Create: `services/platform/awsclient/factory.go`
- Create: `services/platform/awsclient/factory_test.go`
- Modify: `services/platform/go.mod`
- Modify: `services/platform/go.sum`

**Interfaces:**
- Consumes: `config.AWSRegion`, injected lookup, explicit production
  credential and HTTP authority, and the six exact AWS SDK modules.
- Produces: `Mode`, `Options`, `Clients`, `New(Options)`, five typed getters,
  `Close()`, and fixed `ErrConfiguration`.

- [ ] **Step 1: Write the compiler-failing public-boundary tests**

Create `services/platform/awsclient/factory_test.go` in package `awsclient`.
First require the exact modes and constructors:

```go
region, err := platformconfig.ParseAWSRegion("us-east-1")
if err != nil { t.Fatal(err) }
clients, err := New(Options{
    Mode: ModeCI,
    Region: region,
    Lookup: exactLookup(map[string]string{
        "AWS_ENDPOINT_URL": server.URL,
        "AWS_ENDPOINT_URL_S3": server.URL,
    }),
})
```

Require non-nil SQS, S3, KMS, Secrets Manager, and OpenSearch clients, then
call `Close()` twice. Add compile-time checks for all getter return types.

- [ ] **Step 2: Witness absent-package RED**

Run:

```sh
go test -C services/platform ./awsclient -count=1
```

Expected: FAIL because the `awsclient` package and public symbols do not yet
exist. No other platform package is changed.

- [ ] **Step 3: Add strict mode and endpoint tests**

Add table tests that require:

```go
local := map[string]string{
    "AWS_ENDPOINT_URL": "http://localstack.zasp-local.svc.cluster.local:4566",
    "AWS_ENDPOINT_URL_S3": "http://localstack.zasp-local.svc.cluster.local:4566",
}
```

Reject zero/unknown modes, wrong or zero region, nil/typed-nil lookup,
missing/empty/unequal keys, extra lookup reads, userinfo, path, query,
fragment, percent escapes, trailing slash, HTTPS, missing/default/invalid
port, localhost, IPv6, wildcard, private/public non-loopback CI addresses,
wrong local host/port, production lookup, local/CI credentials or HTTP client,
and production missing/typed-nil credentials or HTTP client. Verify every
error is `ErrConfiguration` and contains no rejected value.

- [ ] **Step 4: Add five real SDK routing tests**

Start one `httptest.Server` on `127.0.0.1`. Record request method, escaped
path, query, `Authorization`, `X-Amz-Date`, `X-Amz-Target`, and body under a
mutex. Return minimal protocol-correct empty responses for:

```go
clients.SQS().ListQueues(ctx, &sqs.ListQueuesInput{})
clients.S3().HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("zasp-local-test")})
clients.KMS().ListKeys(ctx, &kms.ListKeysInput{})
clients.SecretsManager().ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
clients.OpenSearch().ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
```

Require exactly five requests, the exact capture-server authority, S3 path
`/zasp-local-test`, signing region `us-east-1`, services `sqs`, `s3`, `kms`,
`secretsmanager`, and `es`, credential ID `test`, and no request to a default
AWS host. Make the first response for each operation a retryable error in a
separate test and require exactly one request.

- [ ] **Step 5: Implement strict parsing and local HTTP ownership**

In `factory.go`, define the exact constants and validate own inputs before
constructing clients. Local parsing uses `url.ParseRequestURI`, exact
round-trip comparison, `net.ParseIP`, and numeric port validation. It accepts
only the fixed cluster URL in local mode or IPv4 `127.0.0.1` in CI mode.

Create an owned `http.Transport` with `Proxy: nil`, finite three-second dial
and TLS bounds, disabled keep-alives and forced HTTP/2 attempts, a ten-second response
header timeout, and a one-megabyte header cap. Create an owned
`http.Client` with a twenty-second total timeout and
`CheckRedirect: http.ErrUseLastResponse`. Use exact synthetic credentials and
`aws.NopRetryer`.

- [ ] **Step 6: Construct all five clients from one clean AWS config**

Build one new `aws.Config` using only validated fields. Do not clone a caller
configuration or call `config.LoadDefaultConfig`. Pass the validated base
endpoint separately into every service constructor and set
`s3.Options.UsePathStyle = true`:

```go
sqs.NewFromConfig(base, func(value *sqs.Options) { value.BaseEndpoint = &endpoint })
s3.NewFromConfig(base, func(value *s3.Options) {
    value.BaseEndpoint = &s3Endpoint
    value.UsePathStyle = true
})
```

Use the equivalent `BaseEndpoint` option for KMS, Secrets Manager, and
OpenSearch. Production constructs the same five clients without any base
endpoint and never owns or closes its caller HTTP client.

- [ ] **Step 7: Run focused race and stability gates**

Run:

```sh
go test -C services/platform ./awsclient -count=1
go test -C services/platform ./awsclient -race -count=1
for run in 1 2 3 4 5 6; do go test -C services/platform ./awsclient -race -count=1; done
```

Require all tests pass with no live LocalStack, process environment, profile,
IMDS, proxy, Docker, or provider access.

- [ ] **Step 8: Commit the factory slice**

Run `go -C services/platform mod tidy -diff`, module verification, vet, whitespace,
and pinned staged Gitleaks. Commit the package, tests, and exact module files:

```text
feat: add LocalStack-aware AWS client factory
```

---

### Task 3: Bind dependency, root command, and operator documentation

**Files:**
- Modify: `build/dependencies.lock.yaml`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/aws-client-factory-contract.test.ts`
- Modify: `scripts/validate-dependencies.test.mjs`

**Interfaces:**
- Consumes: Task 2 `services/platform/awsclient` package and its exact direct
  dependencies.
- Produces: `npm run aws:client:test`, strict dependency inventory entries,
  and bounded M1-31 operator documentation.

- [ ] **Step 1: Write dependency and command RED**

Extend the quality contract to require exactly:

```ts
expect(scripts["aws:client:test"]).toBe(
  "go test -C services/platform -race -count=1 ./awsclient",
);
```

Require the README section to name production/local/CI, both exact endpoint
keys, all five clients, synthetic local credentials, no ambient authority, no
provider mutation/parity claim, M1-30 Complete, and M1-32 Pending. Extend the
dependency validator test to require the six exact Apache-2.0
`platform-data` entries and reject omission, version drift, extra direct SDK
modules, prohibited license, wrong owner, or non-runtime scope.

- [ ] **Step 2: Witness documentation/dependency RED**

Run:

```sh
npx vitest run app/quality/aws-client-factory-contract.test.ts
node --test scripts/validate-dependencies.test.mjs
```

Expected: FAIL only because the root script, README section, and six strict
dependency entries are absent.

- [ ] **Step 3: Add exact dependency inventory and root command**

Add these sorted direct dependencies for `services/platform/go.mod` to
`build/dependencies.lock.yaml`, each with license `Apache-2.0`, owner
`platform-data`, scope `runtime`, and review `approved`:

```text
github.com/aws/aws-sdk-go-v2 v1.43.6
github.com/aws/aws-sdk-go-v2/service/kms v1.55.6
github.com/aws/aws-sdk-go-v2/service/opensearch v1.75.6
github.com/aws/aws-sdk-go-v2/service/s3 v1.107.2
github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.44.6
github.com/aws/aws-sdk-go-v2/service/sqs v1.46.6
```

Add only:

```json
"aws:client:test": "go test -C services/platform -race -count=1 ./awsclient"
```

- [ ] **Step 4: Document the exact factory boundary**

Add `## LocalStack-aware AWS client factory` to README. State that the command
is hermetic, production accepts no endpoint override, local/CI require the two
exact M1-30d keys, fixed local credentials never represent real AWS authority,
and the tests route five real SDK read operations to a bounded loopback
capture server. State explicitly that no LocalStack lifecycle or provider
resource is created and that M1-32 remains Pending.

- [ ] **Step 5: Run focused, dependency, and repository GREEN**

Run the quality contract, dependency validator tests and CLI, root AWS client
test, full platform race suite, tidy-diff, module verification, vet, pinned
`npm run verify`, `npm audit --omit=dev`, syntax, ESLint, whitespace, and
pinned redacted Gitleaks.

- [ ] **Step 6: Commit the integration slice**

Commit only the dependency inventory, root command, README, and focused
contracts as:

```text
docs: expose LocalStack client factory contract
```

---

### Task 4: Review, complete, push, and close M1-31

**Files:**
- Modify: review-found source/test files only when a finding is reproduced
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current count/status fixtures under `app/quality/`
- Modify: this implementation plan after completion CI succeeds
- Create ignored evidence under
  `.superpowers/sdd/2026-08-17-m1-31-localstack-client-factory-implementation-plan/`

**Interfaces:**
- Consumes: Tasks 1 through 3 and the M1-31 whole range.
- Produces: zero-finding review, exact Complete transition, exact-SHA CI
  success, and checked plan closure.

- [ ] **Step 1: Obtain a zero-finding whole-range review**

Review the source row, design, plan, factory API, mode/endpoint parser,
credential and HTTP authority, actual signed SDK requests, one-attempt
behavior, dependencies, docs, and status arithmetic. Reproduce every Critical,
Important, and Minor finding tests-first in a separate commit, rerun every
affected gate, and re-review until zero findings remain.

- [ ] **Step 2: Run the final gate matrix**

Require six focused race passes; full platform race, tidy-diff, module
verification, and vet; exact dependency CLI; pinned full repository
verify/typecheck/lint/build; production audit zero; syntax, whitespace, and
pinned redacted Gitleaks over the range, each commit, tracked HEAD, history,
and ignored evidence. Confirm no Docker, LocalStack, provider, profile, IMDS,
or process-environment request occurred.

- [ ] **Step 3: Write completion-contract RED**

Change only the focused current-status expectations to overall `656/0/69/3`,
M1 `68/23/0/45/0`, zero active rows, 69 complete rows, exactly one M1-31
Complete row, M1-32 absent, and unchanged blockers. Run the focused contract
and require failure only at the stale In-progress state.

- [ ] **Step 4: Transition only M1-31 to Complete**

Move exactly one M1-31 row from In progress to Complete with current evidence.
Update README and current aggregate fixtures mechanically. Preserve M1-30
Complete, M1-32 Pending, and blockers M0-09, M0-18, and M0-19. Run focused and
full gates, scan, then commit:

```text
docs: complete M1-31 LocalStack client factory
```

- [ ] **Step 5: Push completion and verify exact-SHA CI**

Push from a clean tracked tree and index. Require equal local, origin, and
tracking SHAs. Watch Runnable UI to terminal success for the exact completion
SHA and record run and job URLs in ignored evidence.

- [ ] **Step 6: Close, push, and verify the plan**

Mark every checkbox complete only after completion CI succeeds. Commit only
this plan as:

```text
docs: close M1-31 LocalStack client factory plan
```

Push the closure commit, require exact-SHA Runnable UI success again, and
finish with equal refs, zero active tasks, exact `656/0/69/3` counts, M1
`68/23/0/45/0`, M1-32 Pending, unchanged blockers, a clean tracked tree, and
all ignored evidence scans clean.
