# Provisional LocalStack IAM Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and live-verify a separate disposable LocalStack IAM/STS compatibility proof without changing or satisfying the blocked real-AWS M0-09 gate.

**Architecture:** Add an independent Go proof module with a narrow typed IAM/STS boundary and a Node disposable-container orchestrator. The proof uses two synthetic LocalStack account namespaces, exact ownership and immutable identity checks, one allowed self-read, one explicit denial, and independent cleanup; the existing real-AWS harness remains unchanged except for documentation that its state is Blocked.

**Tech Stack:** Go 1.25 language level with Go 1.26.5 toolchain, AWS SDK for Go v2 core 1.43.5/IAM 1.59.0/STS 1.45.5/Smithy 1.27.7, Node 22.23.1, LocalStack 4.7.0 exact image digest, Vitest 4.1.10, Docker.

## Global Constraints

- PROV-01 is temporary waiver work and is not one of the 728 source-plan tasks.
- After zero-finding review, PROV-01 is Blocked on exact LocalStack 4.7.0
  SourceIdentity forwarding and trust-condition enforcement. M0-10 remains
  Pending; the 728 source-plan counts do not change.
- M0-09 remains Blocked and R-03 remains incomplete; no LocalStack result may be presented as real-AWS IAM or release-parity evidence.
- Do not add a custom endpoint or LocalStack mode to `proofs/aws-cross-account-iam`.
- Do not address, restart, reconfigure, or remove the shared development LocalStack container.
- Use a proof-owned exact-image disposable container, random loopback port, no persistence, and only IAM/STS with `ENFORCE_IAM=1`.
- Treat the source and target account IDs as LocalStack namespaces only, not AWS account-isolation evidence.
- Fail rather than falling back to same-account, root-admin, or enforcement-disabled behavior.
- Use static synthetic credentials, direct SDK client construction, nil proxy, no redirect, no IMDS/profile/config chain, loopback-only dialing, hard body/deadline bounds, one-attempt mutations, and bounded read retries.
- Output only fixed result categories; never emit credentials, account IDs, ARNs, resource names, policies, tags, endpoints, ports, image digests, provider bodies, or SDK errors.
- Follow genuine RED/GREEN TDD before each production or dependency change.
- Use pinned Node 22.23.1/npm 10.9.8 for repository gates.

---

### Task 1: Core namespaced IAM/STS lifecycle

**Files:**
- Create: `proofs/localstack-iam-compat/proof_test.go`
- Create: `proofs/localstack-iam-compat/proof.go`
- Create: `proofs/localstack-iam-compat/go.mod`
- Modify: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/progress.md`
- Create: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-PROV-01-brief.md`

**Interfaces:**
- Consumes: approved design `docs/internal/2026-08-13-localstack-iam-provisional-design.md`; no production dependency.
- Produces:

```go
type CallerIdentity struct { AccountID, ARN, UserID string }
type PrincipalSpec struct { Name, ARN, Path, Marker string; Tags map[string]string }
type PrincipalState struct { PrincipalSpec; UserID string }
type RoleSpec struct {
    Name, ARN, Path, Marker, Description, PolicyName string
    RoleID, TrustPolicy, PermissionPolicy string
    Tags map[string]string
}
type RoleState = RoleSpec
type AssumeRequest struct {
    RoleARN, ExternalID, SessionName, SourceIdentity string
    Tags map[string]string
}
type AssumedSession struct {
    AccessKeyID, SecretAccessKey, SessionToken string
    AssumedRoleARN, AssumedRoleID, SourceIdentity string
    Expiration time.Time
}
type IAMBoundary interface {
    SourceIdentity(context.Context) (CallerIdentity, error)
    TargetIdentity(context.Context) (CallerIdentity, error)
    ListPrincipals(context.Context, string) ([]PrincipalState, error)
    CreatePrincipal(context.Context, PrincipalSpec) (PrincipalState, error)
    InspectPrincipal(context.Context, string) (PrincipalState, error)
    CreateAccessKey(context.Context, string) (string, string, error)
    ListAccessKeys(context.Context, string) ([]string, error)
    DeleteAccessKey(context.Context, string, string) error
    DeletePrincipal(context.Context, string) error
    ListRoles(context.Context, string) ([]RoleState, error)
    CreateRole(context.Context, RoleSpec) (RoleState, error)
    InspectRole(context.Context, string) (RoleState, error)
    PutRolePolicy(context.Context, string, string, string) error
    GetRolePolicy(context.Context, string, string) (string, error)
    AssumeRole(context.Context, AssumeRequest, string, string) (AssumedSession, error)
    AssumedIdentity(context.Context, AssumedSession) (CallerIdentity, error)
    AllowedGetRole(context.Context, AssumedSession, string) (RoleState, error)
    DeniedListRoles(context.Context, AssumedSession) error
    DeleteRolePolicy(context.Context, string, string) error
    DeleteRole(context.Context, string) error
}
type ProofOptions struct {
    Marker, Endpoint, SourceAccountID, TargetAccountID string
    Boundary IAMBoundary
    CleanupTimeout, PollInterval time.Duration
    Now func() time.Time
}
type ProofResult struct {
    Namespaces, Assumed, AllowedRead, ExplicitDeny, Cleanup, Audit bool
}
func RunProof(context.Context, ProofOptions) (ProofResult, error)
```

- [ ] **Step 1: Write the missing-lifecycle RED**

Create `proof_test.go` with a deterministic fake boundary and a happy test that calls `RunProof` with distinct synthetic account namespaces and asserts all six result booleans. The fake event log must require this order:

```go
want := []string{
    "source-identity", "target-identity", "list-principals", "list-roles",
    "create-principal", "inspect-principal", "create-access-key",
    "create-role", "inspect-role", "put-role-policy", "get-role-policy",
    "assume-role", "assumed-identity", "allowed-get-role", "denied-list-roles",
    "cleanup-get-role-policy", "cleanup-inspect-role", "delete-role-policy",
    "cleanup-inspect-principal", "delete-access-key", "delete-principal",
    "cleanup-inspect-role", "delete-role", "audit-principals", "audit-roles",
}
```

- [ ] **Step 2: Run the focused test and preserve the genuine RED**

Run: `cd proofs/localstack-iam-compat && go test proof_test.go`

Expected: compilation fails only because `RunProof`, `ProofOptions`, result types, and lifecycle types are undefined. Record exact safe counts in the ignored brief and ledger.

- [ ] **Step 3: Add the module and minimal lifecycle GREEN**

Create `go.mod` exactly as:

```go
module github.com/zasp-ai/zasp-sec/proofs/localstack-iam-compat

go 1.25.0

toolchain go1.26.5
```

Implement `proof.go` with fixed `errors.New` categories for configuration, capability, provider, authorization, ownership, and cleanup. Generate all names from `^[a-f0-9]{16}$` marker input, use fixed namespace IDs `000000000041` and `000000000042`, require their inequality, build strict duplicate-free JSON trust/permission documents, stage cleanup candidates before each mutation, and defer independent cleanup.

Use this control-flow shape so target arming and cleanup precedence are explicit:

```go
func RunProof(ctx context.Context, options ProofOptions) (result ProofResult, resultErr error) {
    if err := validateOptions(ctx, options); err != nil { return result, errConfiguration }
    principalSpec, roleSpec := expectedSpecs(options)
    var principal *principalTarget
    var role *roleTarget
    defer func() {
        if recover() != nil { resultErr = errProvider }
        cleanupCtx, cancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
        defer cancel()
        if err := cleanupAndAudit(cleanupCtx, options, principal, role); err != nil {
            resultErr = errCleanup
        }
    }()
    if err := preflightEmpty(ctx, options, principalSpec, roleSpec); err != nil { return result, err }
    principal, resultErr = createAndProvePrincipal(ctx, options, principalSpec)
    if resultErr != nil { return result, resultErr }
    role, resultErr = createAndProveRole(ctx, options, roleSpec)
    if resultErr != nil { return result, resultErr }
    return proveAssumeAllowDeny(ctx, options, principal, role)
}
```

- [ ] **Step 4: Run the focused happy test GREEN**

Run: `cd proofs/localstack-iam-compat && go test -run '^TestRunProof$' -count=1`

Expected: PASS with the exact event order and all result booleans true.

- [ ] **Step 5: Add adversarial lifecycle RED cases**

Add table-driven tests for:

```go
cases := []string{
    "same namespace", "unexpected source identity", "unexpected target identity",
    "prefix principal collision", "prefix role collision", "replacement principal id",
    "replacement role id", "wrong trust", "wrong permission", "wrong marker tags",
    "missing external id", "wrong session name", "wrong source identity",
    "wrong session tag", "wrong assumed role id", "wrong assumed caller user id",
    "allowed read returns foreign role", "implicit denial", "enforcement disabled",
    "create ambiguity exact", "create ambiguity mismatch", "delayed visibility",
    "panic after apply", "canceled main context", "cleanup mismatch",
    "cleanup continuation", "cleanup failure precedence", "audit prefix remains",
}
```

Require every failure to return one fixed category and never delete an unproven replacement.

- [ ] **Step 6: Run the adversarial tests RED**

Run: `cd proofs/localstack-iam-compat && go test -run 'TestRunProof_(Rejects|Reconciles|Cleans)' -count=1`

Expected: named cases fail on missing strict validation/reconciliation/cleanup behavior while the happy test remains green.

- [ ] **Step 7: Implement strict lifecycle behavior GREEN**

Implement recursive exact-key/duplicate-key JSON validation; immutable user/role/session identity binding; typed explicit-denial evidence; monotonic bounded reconciliation; independent cleanup with ownership reproof and failure precedence; and prefix-wide zero audit.

Use typed ambiguity rather than string matching:

```go
type ambiguousMutationError struct{ cause error }
func (e ambiguousMutationError) Error() string { return "mutation outcome ambiguous" }
func (e ambiguousMutationError) Unwrap() error { return e.cause }

func reconcileRole(ctx context.Context, boundary IAMBoundary, expected RoleSpec, interval time.Duration) (*RoleState, reconciliationOutcome) {
    observed := false
    for ctx.Err() == nil {
        roles, err := boundary.ListRoles(ctx, expected.Name)
        if err == nil && len(roles) == 1 {
            observed = true
            state, inspectErr := boundary.InspectRole(ctx, expected.Name)
            if inspectErr == nil && exactRole(expected, state) { return &state, reconciliationOwned }
            if inspectErr == nil { return nil, reconciliationMismatch }
        } else if err == nil && len(roles) == 0 && !observed {
            return nil, reconciliationAbsent
        }
        waitForPoll(ctx, interval)
    }
    return nil, reconciliationUnresolved
}
```

- [ ] **Step 8: Run and stabilize the full core suite**

Run:

```bash
cd proofs/localstack-iam-compat
go test -race -count=1 ./...
go test -run 'TestRunProof' -count=5 ./...
go mod tidy -diff
go mod verify
go vet ./...
```

Expected: every command exits zero; `go mod tidy -diff` prints no diff.

- [ ] **Step 9: Commit the core lifecycle**

```bash
git add proofs/localstack-iam-compat/proof.go proofs/localstack-iam-compat/proof_test.go proofs/localstack-iam-compat/go.mod
git commit -m "test: define provisional LocalStack IAM lifecycle"
```

---

### Task 2: Official SDK and loopback transport boundary

**Files:**
- Create: `proofs/localstack-iam-compat/sdk_test.go`
- Create: `proofs/localstack-iam-compat/sdk.go`
- Modify: `proofs/localstack-iam-compat/go.mod`
- Create: `proofs/localstack-iam-compat/go.sum`

**Interfaces:**
- Consumes: `IAMBoundary`, lifecycle types, and fixed errors from Task 1.
- Produces:

```go
type SDKBoundary struct {
    sourceIAM, targetIAM *iam.Client
    sourceSTS            *sts.Client
    transport            *http.Transport
    endpoint             validatedEndpoint
}
func NewSDKBoundary(context.Context, string, string, string) (*SDKBoundary, error)
func ValidateLoopbackEndpoint(context.Context, string) (string, error)
```

`NewSDKBoundary` receives endpoint, source namespace ID, and target namespace ID; it implements `IAMBoundary` without loading ambient AWS configuration.

- [ ] **Step 1: Add SDK boundary RED tests before dependencies**

Create `sdk_test.go` with loopback servers asserting exact IAM Query API actions and fields for identity, principal/key lifecycle, role/policy lifecycle, AssumeRole conditions/tags, allowed read, denied list, and deletion. Add hostile endpoint/resolver/proxy/redirect/body/status/retry/parser cases.

- [ ] **Step 2: Run SDK tests RED**

Run: `cd proofs/localstack-iam-compat && go test -run '^TestSDK|^TestValidateLoopback' -count=1`

Expected: compilation fails only because `NewSDKBoundary`, `SDKBoundary`, and endpoint validation are undefined.

- [ ] **Step 3: Add exact current SDK pins after RED**

Add exactly:

```go
require (
    github.com/aws/aws-sdk-go-v2 v1.43.5
    github.com/aws/aws-sdk-go-v2/service/iam v1.59.0
    github.com/aws/aws-sdk-go-v2/service/sts v1.45.5
    github.com/aws/smithy-go v1.27.7
)
```

Run: `cd proofs/localstack-iam-compat && go mod tidy`

- [ ] **Step 4: Implement the direct SDK clients and transport**

Construct separate source/target IAM and STS clients with `BaseEndpoint` set only after strict loopback validation. Use namespace IDs as synthetic access keys and `test` as ignored local secret. Set `Proxy: nil`, reject redirects, re-resolve every dial, reject any non-loopback resolution or port drift, cap bodies, use 25-second calls, one-attempt mutations, and at most two attempts/500 ms backoff for read-only operations. Do not import the SDK config package or call `LoadDefaultConfig`.

Construct clients directly with this shape:

```go
func NewSDKBoundary(ctx context.Context, rawEndpoint, sourceAccount, targetAccount string) (*SDKBoundary, error) {
    endpoint, dialContext, err := validatedLoopbackTransport(ctx, rawEndpoint)
    if err != nil { return nil, errConfiguration }
    transport := &http.Transport{Proxy: nil, DialContext: dialContext, DisableKeepAlives: true, ForceAttemptHTTP2: false}
    httpClient := &http.Client{Timeout: 25 * time.Second, Transport: transport, CheckRedirect: rejectRedirect}
    sourceCredentials := aws.CredentialsProviderFunc(staticNamespaceCredentials(sourceAccount))
    targetCredentials := aws.CredentialsProviderFunc(staticNamespaceCredentials(targetAccount))
    return newBoundaryFromOptions(
        iam.Options{Region: fixedRegion, BaseEndpoint: aws.String(endpoint), HTTPClient: httpClient, Credentials: sourceCredentials, RetryMaxAttempts: 2},
        iam.Options{Region: fixedRegion, BaseEndpoint: aws.String(endpoint), HTTPClient: httpClient, Credentials: targetCredentials, RetryMaxAttempts: 2},
        sts.Options{Region: fixedRegion, BaseEndpoint: aws.String(endpoint), HTTPClient: httpClient, Credentials: sourceCredentials, RetryMaxAttempts: 1},
    ), nil
}
```

- [ ] **Step 5: Implement strict provider conversion**

Convert provider outputs only after exact required-field and identity checks. Decode IAM policy documents exactly once; reject malformed, double-encoded, duplicate, alias, unknown, missing, null, trailing, and oversized representations. Preserve received HTTP status through body-bound errors so non-2xx is definitive and unexpected 2xx is ambiguous.

Status classification must follow this exact ordering:

```go
func classifyMutationError(err error) error {
    var responseErr interface{ HTTPStatusCode() int }
    if errors.As(err, &responseErr) {
        status := responseErr.HTTPStatusCode()
        if status >= 200 && status < 300 { return ambiguousMutationError{cause: err} }
        return errProvider
    }
    var apiErr smithy.APIError
    if errors.As(err, &apiErr) { return errProvider }
    return ambiguousMutationError{cause: err}
}
```

- [ ] **Step 6: Run SDK suite GREEN and stability gates**

Run:

```bash
cd proofs/localstack-iam-compat
go test -race -run '^TestSDK|^TestValidateLoopback' -count=1
go test -run '^TestSDK|^TestValidateLoopback' -count=5
go mod tidy -diff
go mod verify
go vet ./...
```

Expected: all exit zero and tidy prints no diff.

- [ ] **Step 7: Commit the SDK boundary**

```bash
git add proofs/localstack-iam-compat/sdk.go proofs/localstack-iam-compat/sdk_test.go proofs/localstack-iam-compat/go.mod proofs/localstack-iam-compat/go.sum
git commit -m "feat: add LocalStack IAM SDK boundary"
```

---

### Task 3: Fixed-output CLI and disposable LocalStack orchestrator

**Files:**
- Create: `proofs/localstack-iam-compat/main_test.go`
- Create: `proofs/localstack-iam-compat/main.go`
- Create: `proofs/localstack-iam-compat/run.test.mjs`
- Create: `proofs/localstack-iam-compat/run.mjs`

**Interfaces:**
- Consumes: `NewSDKBoundary`, `RunProof`, and `ProofResult`.
- Produces:

```ts
export declare const LOCALSTACK_IMAGE: "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c";
export declare function buildDockerRunArguments(name: string): string[];
export declare function buildProofEnvironment(endpoint: string, path: string): {AWS_ENDPOINT_URL: string; PATH: string};
export declare function buildGoToolEnvironment(path: string, buildCache: string, moduleCache: string): Record<string, string>;
export declare function orchestrate(runtime: DockerRuntime, options?: {readinessAttempts?: number}): Promise<{code: number; line: string}>;
export declare class DockerRuntime {
  constructor(options?: {path?: string; marker?: string});
  ensureAbsent(): Promise<void>;
  start(): Promise<string>;
  verifyOwned(token?: string): Promise<void>;
  endpoint(token?: string): Promise<string>;
  isReady(endpoint: string): Promise<boolean>;
  runProof(endpoint: string): Promise<number>;
  remove(): Promise<void>;
  requireAbsent(): Promise<void>;
}
export declare function runMain(options?: {runtime?: DockerRuntime}): Promise<number>;
```

- [ ] **Step 1: Write CLI RED tests**

Add Go tests that require exactly one success line:

```text
LocalStack IAM compatibility proof passed: namespaces=true assumed=true allowed_read=true explicit_deny=true cleanup=true audit=true container_cleanup=true.
```

Failures must be exactly `LocalStack IAM compatibility proof failed: <category> rejected.` with exit 1 and no dynamic provider data.

- [ ] **Step 2: Run CLI RED**

Run: `cd proofs/localstack-iam-compat && go test -run '^TestMain' -count=1`

Expected: compile failure on the missing CLI boundary.

- [ ] **Step 3: Implement the CLI GREEN**

Implement environment intake for only `AWS_ENDPOINT_URL` and `PATH`, fixed synthetic namespaces, random marker generation, bounded 90-second main context plus 30-second cleanup context, panic containment, exact success booleans, and fixed error categories.

The CLI entry boundary must retain the fixed output contract:

```go
func runMain(ctx context.Context, out io.Writer, getenv func(string) string) int {
    endpoint := getenv("AWS_ENDPOINT_URL")
    boundary, err := NewSDKBoundary(ctx, endpoint, sourceNamespace, targetNamespace)
    if err != nil { return writeFailure(out, "configuration") }
    result, err := RunProof(ctx, ProofOptions{Endpoint: endpoint, Boundary: boundary, CleanupTimeout: 30 * time.Second})
    if err != nil || result != (ProofResult{true, true, true, true, true, true}) {
        return writeFailure(out, fixedCategory(err))
    }
    _, _ = io.WriteString(out, successLine+"\n")
    return 0
}
```

- [ ] **Step 4: Write orchestrator RED tests**

Create `run.test.mjs` with deterministic runtimes covering exact arguments and ownership plus failure paths. Require these Docker environment entries:

```js
[
  "SERVICES=iam,sts",
  "ENFORCE_IAM=1",
  "PERSISTENCE=0",
]
```

Cover absent image, prefix collision, wrong image/name/label/ID, ambiguous start, non-loopback port, oversized/endless readiness, service not ready, proof exit propagation, output overflow, build failure, cleanup failure precedence, candidate cleanup, construction failure, and exact container/temp absence.

- [ ] **Step 5: Run orchestrator RED**

Run: `cd proofs/localstack-iam-compat && node --test run.test.mjs`

Expected: tests fail on missing exports and orchestrator behavior.

- [ ] **Step 6: Implement orchestrator GREEN**

Implement the declared exports with unique `zasp-prov-01-<16 hex>` names, labels `zasp.proof=prov-01` and exact marker, random loopback publishing, 16 KiB/500 ms readiness bounds, exact IAM/STS health checks, offline temporary Go binary build with allowlisted cache variables, proof process environment containing only endpoint and PATH, a 300-second outer proof timeout covering the 90-second main window plus three 30-second reconciliation/cleanup windows and at least 60 seconds of cleanup/process overhead, fixed 4 KiB output cap, and exact candidate-aware removal/absence.

Docker arguments must be constructed exactly from owned inputs:

```js
export function buildDockerRunArguments(name) {
  const marker = validateProofName(name);
  return [
    "run", "--detach", "--rm", "--name", name,
    "--publish", "127.0.0.1::4566",
    "--env", "SERVICES=iam,sts",
    "--env", "ENFORCE_IAM=1",
    "--env", "PERSISTENCE=0",
    "--label", "zasp.proof=prov-01",
    "--label", `zasp.marker=${marker}`,
    LOCALSTACK_IMAGE,
  ];
}
```

- [ ] **Step 7: Run CLI/orchestrator/full proof tests GREEN**

Run:

```bash
cd proofs/localstack-iam-compat
go test -race -count=1 ./...
node --test run.test.mjs
```

Expected: all tests pass with no container/provider identifiers in output.

- [ ] **Step 8: Commit CLI and orchestrator**

```bash
git add proofs/localstack-iam-compat/main.go proofs/localstack-iam-compat/main_test.go proofs/localstack-iam-compat/run.mjs proofs/localstack-iam-compat/run.test.mjs
git commit -m "feat: run disposable LocalStack IAM proof"
```

---

### Task 4: Repository commands, documentation, and contract

**Files:**
- Create: `app/quality/localstack-iam-compat-proof-contract.test.ts`
- Modify: `app/quality/aws-cross-account-iam-proof-contract.test.ts`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`

**Interfaces:**
- Consumes: runnable proof from Task 3 and approved claim boundary.
- Produces exact root commands:

```json
"proof:localstack:iam:test": "cd proofs/localstack-iam-compat && go test -race -count=1 ./... && node --test run.test.mjs",
"proof:localstack:iam:run": "node proofs/localstack-iam-compat/run.mjs"
```

- [ ] **Step 1: Write repository contract RED**

Add a Vitest contract that asserts exact Go/toolchain/SDK/image pins, both root commands, `SERVICES=iam,sts`, `ENFORCE_IAM=1`, no dotenv input, the exact README command block, fixed success text, and explicit statements that PROV-01 cannot complete M0-09/R-03. After the live capability result and zero-finding review, the contract must require PROV-01 Blocked, leave M0-10 Pending, and preserve the 728 source-plan counts.

Update the existing real-AWS contract expectation from `M0-09 and R-03 remain In progress` to `M0-09 is Blocked and R-03 remains incomplete`.

- [ ] **Step 2: Run the focused contract RED**

Run:

```bash
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH \
  npx vitest run app/quality/localstack-iam-compat-proof-contract.test.ts app/quality/aws-cross-account-iam-proof-contract.test.ts
```

Expected: new command/docs assertions fail while existing unrelated tests remain green.

- [ ] **Step 3: Add commands and documentation GREEN**

Add the exact scripts. Add README section `## Provisional LocalStack IAM compatibility proof` with:

```bash
npm run proof:localstack:iam:test
npm run proof:localstack:iam:run
```

State that Docker and Go are required, no credentials are accepted, IAM enforcement is mandatory, account values are emulator namespaces, and the result is not real-AWS parity. Update the real-AWS section to say M0-09 is Blocked and R-03 remains incomplete. Before independent review, keep PROV-01 In progress in the tracker; after review, apply Step 10's live-result ruling.

- [ ] **Step 4: Run focused and full repository gates GREEN**

Run:

```bash
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH \
  npx vitest run app/quality/localstack-iam-compat-proof-contract.test.ts app/quality/aws-cross-account-iam-proof-contract.test.ts
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm run verify
```

Expected: focused contracts and all repository tests/type-check/lint/build pass.

- [ ] **Step 5: Commit repository wiring**

```bash
git add package.json README.md app/quality/localstack-iam-compat-proof-contract.test.ts app/quality/aws-cross-account-iam-proof-contract.test.ts docs/internal/implementation_status_v1.5.md
git commit -m "docs: expose provisional LocalStack IAM proof"
```

---

### Task 5: Live proof, cleanup audit, evidence, and review handoff

**Files:**
- Create: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-PROV-01-report.md`
- Modify: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/progress.md`
- Modify only after a new RED if evidence exposes a defect: files created in Tasks 1-4.

**Interfaces:**
- Consumes: root proof commands and disposable runtime.
- Produces: review package with exact base/head SHAs, safe RED/GREEN counts, live fixed result, cleanup evidence, gates, scans, and claim limitations.

- [ ] **Step 1: Record shared-container identity without mutating it**

Use read-only Docker inspection to record only a boolean that the known shared development container exists and later remains unchanged. Do not emit its ID, ports, image, labels, or configuration.

- [ ] **Step 2: Run the disposable live proof**

Run: `npm run proof:localstack:iam:run`

Expected: one fixed success line and exit zero. If it fails, first prove candidate/container absence, then apply `superpowers:systematic-debugging`; do not relax cross-namespace, enforcement, explicit-deny, or ownership requirements.

- [ ] **Step 3: Run a separate exact-prefix zero-resource audit**

Use the same SDK boundary against a fresh disposable target or the proof's post-cleanup audit command to require zero principals, access keys, policies, or roles with the proof prefix in both namespaces. Output only `proof_resources=0` and an exit code.

- [ ] **Step 4: Prove disposable cleanup and shared isolation**

Require exact proof-container absence, temporary-build absence, and a boolean that the shared development container identity/state is unchanged.

- [ ] **Step 5: Run final local gates**

```bash
cd proofs/localstack-iam-compat
go test -run . -count=5 ./...
go test -race -count=1 ./...
go mod tidy -diff
go mod verify
go vet ./...
cd ../..
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm run proof:localstack:iam:test
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm run verify
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm audit --omit=dev
git diff --check
```

Expected: all exit zero; the production audit reports zero vulnerabilities.

- [ ] **Step 6: Run pinned secret scans**

Use the already verified Gitleaks v8.30.1 binary/module to scan the new proof, repository contract, README/tracker diff, ignored brief/report/ledger, staged diff, and full git history with redaction. Record counts/categories only; never output detected content.

- [ ] **Step 7: Finalize evidence without completing PROV-01**

Write `task-PROV-01-report.md` with RED/GREEN, exact versions, live fixed result, cleanup/audit, full gates, secret scans, and limitations. Append the ledger. Before independent review, leave PROV-01 In progress, M0-09 Blocked, R-03 incomplete, and M0-10 Pending. After review, apply Step 10's live-result ruling.

- [ ] **Step 8: Create the atomic implementation commit and post-commit scan**

```bash
git add proofs/localstack-iam-compat package.json README.md app/quality/localstack-iam-compat-proof-contract.test.ts app/quality/aws-cross-account-iam-proof-contract.test.ts docs/internal/implementation_status_v1.5.md
git commit -m "feat: prove LocalStack IAM compatibility"
git show --check --stat --oneline HEAD
```

Run the pinned post-commit full-history Gitleaks scan and confirm `git status --short` is empty.

- [ ] **Step 9: Request independent review**

Provide the reviewer the exact design, implementation plan, source-plan/R-03 boundaries, ignored evidence, and base-to-head range. Require Critical/Important/Minor counts and `Ready: Yes/No`; no live calls or edits during review. Resolve every accepted finding through a separate RED/GREEN fix commit and repeat gates before changing status.

- [ ] **Step 10: Record the provider-blocked outcome after clean review**

After final review reports zero remaining findings, apply the live capability result. Because exact LocalStack 4.7.0 did not return SourceIdentity and accepted a deliberately wrong SourceIdentity despite the trust condition, mark PROV-01 Blocked and leave M0-10 Pending. Keep M0-09 Blocked and R-03 incomplete. Preserve source-plan counts at Pending 719, In progress 0, Complete 8, Blocked 1 because PROV-01 is excluded from the 728. Official LocalStack v4.14.0 source retains the same unsupported forwarding path; record that as source inspection only, not live evidence. Run pinned `npm run verify`, scans, and local commit checks. Do not push without separate authorization.
