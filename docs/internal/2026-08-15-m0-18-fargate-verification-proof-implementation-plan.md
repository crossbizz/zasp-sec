# M0-18 Fargate Verification Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and independently review the exact EKS Fargate canary harness,
run it only with an authenticated disposable Fargate fixture, prove exact
cleanup, and record a truthful Complete or Blocked outcome.

**Architecture:** A Go lifecycle core owns strict typed Kubernetes objects and
an injected cluster boundary. A Node supervisor builds the offline Go binary,
passes only the explicit M0-18 inputs, enforces hard process/output bounds, and
emits one fixed line. The production boundary shells out only to a validated
`kubectl` executable with an exact kubeconfig/context; tests use hermetic fakes
and loopback fixtures. LocalStack/k3s can test no more than generic compatibility
and cannot satisfy the live authority.

**Tech stack:** Go 1.25 semantics with toolchain go1.26.5; Kubernetes JSON
objects through the `kubectl` process boundary; Node.js 22.23.1/npm 10.9.8 for
supervision/contracts; Vitest; immutable Kubernetes BusyBox test image;
Gitleaks 8.30.1.

## Global constraints

- No EKS cluster or Fargate-profile create/update/delete operation.
- No ambient AWS, kubeconfig, proxy, dotenv, or default-context authority.
- Single-attempt mutations; two-attempt reads with <=500 ms backoff.
- Exact UID/spec/label reproof before every dependent action and deletion.
- Global prefix-plus-label absence audit before success.
- LocalStack, Docker Desktop, kind, or forged labels cannot emit success.
- M0-19 stays Pending and R-11 stays `Not run — M0-18/M0-19` throughout.
- Every behavior change follows a witnessed tests-only RED.

---

### Task 1: Start M0-18 and bind the real-provider boundary

**Files:**
- Create: `app/quality/fargate-verification-proof-contract.test.ts`
- Modify: affected aggregate-count contracts
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Use: `docs/decisions/mvp-risk-register.md`

**Interfaces:**
- Start counts: `706/1/19/1`; M0 `27/5/1/19/1`.
- Sole active task: M0-18.
- R-11 remains exactly `Not run — M0-18/M0-19`.

- [ ] **Step 1: Write status-contract RED**

Reject missing/duplicate M0-18, concurrent M0-19, aggregate drift, any claim
that LocalStack/k3s is Fargate, premature R-11 PASS, and changes to M0-09,
PROV-01, or R-03.

- [ ] **Step 2: Apply minimal start GREEN**

Add the README boundary and move only M0-18 from Pending to In progress. Record
that the current capability audit has zero real-AWS inputs and no reachable
Fargate cluster; do not call a provider.

- [ ] **Step 3: Run affected/full gates and commit**

Commit as `docs: start M0-18 Fargate proof` after pinned verify, audit,
whitespace, and staged redacted secret scan pass.

---

### Task 2: Implement the strict canary lifecycle core

**Files:**
- Create: `proofs/fargate-verification/go.mod`
- Create: `proofs/fargate-verification/proof_test.go`
- Create: `proofs/fargate-verification/proof.go`

**Interfaces:**

```go
type ClusterBoundary interface {
    Create(context.Context, Resource) (ObjectState, error)
    Get(context.Context, ResourceRef) (ObjectState, error)
    List(context.Context, ListQuery) ([]ObjectState, error)
    Delete(context.Context, OwnedObject) error
    Logs(context.Context, OwnedPod) ([]byte, []byte, error)
}

func RunProof(context.Context, ProofOptions) (ProofResult, error)
```

- [ ] **Step 1: Capture absent-API compile RED**

Write the happy-path fake-boundary test before module or production files.

- [ ] **Step 2: Implement minimal ordered lifecycle GREEN**

Create namespace, ServiceAccount, Secret, and Job; wait for exactly one owned
Pod and completed Job; prove profile/node/canary evidence; clean Pod through Job
deletion, then Secret, ServiceAccount, and namespace; audit global absence.

- [ ] **Step 3: Add adversarial lifecycle RED/GREEN**

Cover definitive versus ambiguous create/delete results, delayed visibility,
cancellation, panic, cleanup precedence, UID replacement, owner-reference
drift, extra Pods, failed Job, wrong profile/node/image/exit/body, stale global
prefix resources, duplicate JSON members, and cleanup-time mutations.

- [ ] **Step 4: Run five stability passes, race, tidy, verify, vet, commit**

Commit as `feat: implement Fargate canary lifecycle`.

---

### Task 3: Implement the kubeconfig and kubectl boundary

**Files:**
- Create: `proofs/fargate-verification/kubectl_test.go`
- Create: `proofs/fargate-verification/kubectl.go`

**Interfaces:**
- Validate one absolute regular non-symlink kubeconfig and exact context.
- Invoke only fixed `kubectl --kubeconfig <path> --context <context> ...` argv.
- Parse bounded duplicate-key-free JSON with exact known-key schemas.

- [ ] **Step 1: Write loopback/fake-process RED**

Cover the complete request argv, allowlisted environment, stdout/stderr cap,
hard deadline, process kill/reap, read retry, mutation single-attempt, missing
versus generic failure, and strict JSON conversion.

- [ ] **Step 2: Implement boundary GREEN**

No shell, inherited kube variables, exec-plugin output, raw error, or manifest
content may cross the fixed result boundary. Sensitive Secret bytes are written
through stdin only and are zeroed after the call.

- [ ] **Step 3: Integrate lifecycle through the real boundary contract**

Run the complete lifecycle against a deterministic fake `kubectl` executable
that models Kubernetes UIDs, owner references, Pod/Node evidence, and deletion.

- [ ] **Step 4: Verify and commit**

Commit as `feat: add bounded Fargate kubectl boundary`.

---

### Task 4: Add the fixed CLI, supervisor, scripts, and immutable audit

**Files:**
- Create: `proofs/fargate-verification/main_test.go`
- Create: `proofs/fargate-verification/main.go`
- Create: `proofs/fargate-verification/run.test.mjs`
- Create: `proofs/fargate-verification/run.mjs`
- Create: `proofs/fargate-verification/adapter-license.json`
- Create: `proofs/fargate-verification/license-audit.test.mjs`
- Create: `proofs/fargate-verification/license-audit.mjs`
- Modify: `package.json`
- Modify: `README.md`

- [ ] **Step 1: Write CLI/supervisor RED**

Require exact capability intake, 10-minute main plus independent 5-minute
cleanup, async SIGKILL/reap, 16 KiB combined cap, fixed lines, offline build,
and temp-binary cleanup with retained identity reproof.

- [ ] **Step 2: Implement fixed boundary GREEN**

The live command fails at configuration before build/network unless all eleven
inputs are present. It never prints identifiers, URLs, credentials, kubeconfig,
provider output, paths, or raw errors.

- [ ] **Step 3: Add root commands and immutable image/license audit**

Expose `proof:fargate:test`, `proof:fargate:run`, and
`proof:fargate:license`. Bind the exact BusyBox index/platform digests and
upstream source/license evidence already used by the reviewed Kubernetes proof.

- [ ] **Step 4: Verify and commit**

Commit as `docs: expose EKS Fargate proof` after all local gates pass.

---

### Task 5: Whole-range review and capability decision

**Files:**
- Modify proof source/tests only for tests-first fixes
- Create ignored Task 5 report and append both progress ledgers

- [ ] **Step 1: Run adversarial whole-range review**

Review capability intake, kubeconfig identity, manifest secrecy, Fargate
evidence, mutation classification, ownership, replacement safety, deadlines,
fixed output, global absence, and immutable dependency evidence.

- [ ] **Step 2: Fix every finding tests-first**

Require zero Critical, Important, or Minor findings before the capability gate.

- [ ] **Step 3: Run the safe capability audit**

Emit booleans/counts only. If any required input is absent, run the root command
once to prove it fails at configuration before cluster I/O; do not fabricate a
LocalStack result.

---

### Task 6: Run live or record the exact blocker

**Files:**
- Modify completion/blocking contracts, README, tracker, and this plan
- Create ignored authoritative M0-18 report and append ledgers

- [ ] **Step 1: Execute the live proof only when fully authorized**

Require a preflight global-zero audit, exact live success, product-only evidence
capture, post-run global-zero audit, and unchanged unrelated cluster resources.

- [ ] **Step 2: Otherwise write blocking RED/GREEN**

With the current environment, transition only M0-18 from In progress to
Blocked at `706/0/19/2`; M0 becomes `27/5/0/19/2`. State the exact missing
authenticated disposable EKS Fargate profile, matching kubeconfig/context,
product proxy endpoint, and test credential. Keep R-11 Not run and M0-19
Pending. Reject any LocalStack-as-Fargate or premature completion claim.

- [ ] **Step 3: Verify, scan, commit, push, and watch exact-SHA CI**

Run proof/module/root/full repository gates, audit/license/whitespace/secret
checks, commit the truthful result, push, prove SHA equality, and watch Runnable
UI to success before deciding whether dependency-waived local work may continue.

## Plan self-review

- Every success claim is bound to real EKS Fargate evidence.
- LocalStack/k3s compatibility is explicitly non-authoritative.
- Inputs, manifests, timeouts, output, ownership, cleanup, counts, blocked
  state, and R-11 boundary are exact.
- The plan mutates no shared cluster/profile and contains no placeholder success
  path.
