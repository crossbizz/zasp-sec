# M0-19 EKS Fargate egress proof implementation plan

Date: August 15, 2026

## Goal

Build, review, and safely gate the exact real EKS Fargate Security Groups for
Pods proof without weakening M0-18 or fabricating LocalStack evidence.
Every behavior change follows a witnessed tests-only RED.

## Invariants

- Real EKS Fargate, EC2 security-group state, and the branch ENI are the only
  success authority; LocalStack cannot authorize success.
- Kubernetes and AWS mutations are single-attempt mutations. Only typed
  ambiguity or malformed successful acknowledgement may reconcile exact state.
- The pre-existing disposable security groups are read-only inputs and are
  never modified or deleted.
- Fixed output contains booleans only; credentials, endpoints, IDs, provider
  bodies, paths, and raw errors are prohibited.
- M0-18 stays Blocked, R-11 stays Not run, and M0-20 stays Pending until the
  final evidence decision.

## Tasks

### Task 1: Record design and start status

- [x] Write the tests-only repository contract RED.
- [x] Add this design and executable plan.
- [x] Move only M0-19 from Pending to In progress at `705/1/19/2` overall and
  `27/4/1/19/2` in M0.

### Task 2: Implement the typed lifecycle core

- [ ] RED/GREEN exact Namespace, ServiceAccount, Secret,
  SecurityGroupPolicy, Job, Pod, Node, ENI, and security-group models.
- [ ] RED/GREEN definitive versus ambiguous creates/deletes, immutable
  ownership, delayed visibility, cancellation, panic, reverse cleanup,
  precedence, and global absence.

### Task 3: Implement Kubernetes and EC2 boundaries

- [ ] RED/GREEN private immutable commercial-EKS kubeconfig, fixed kubectl
  process boundary, bounded duplicate-free Kubernetes parsing, UID deletes,
  and exact SecurityGroupPolicy/Pod annotation state.
- [ ] RED/GREEN official AWS SDK v2 EC2 read boundary with explicit static
  credentials, no ambient chain/proxy/IMDS/custom endpoint, bounded reads, exact
  security-group rules, and exact ENI attachment.

### Task 4: Implement fixed CLI and supervisor

- [ ] RED/GREEN exact input gate, offline build, 10-minute main plus 5-minute
  cleanup, hard supervisor margin, bounded output, panic containment, retained
  workspace cleanup, and fixed one-line output.
- [ ] Add root test/run/license commands and immutable dependency audit.

### Task 5: Review and verify

- [ ] Run an adversarial whole-range review and fix every Critical, Important,
  and Minor finding tests-first.
- [ ] Run five stability passes, race, module, root, full pinned repository,
  audit, license, whitespace, and redacted secret gates.

### Task 6: Live decision

- [ ] If every explicit authority is present, run the exact live proof and
  require direct=false proxy=true, exact ENI/rules, Fargate evidence, reverse
  cleanup, global absence, and unchanged unrelated resources.
- [ ] Otherwise transition M0-19 to Blocked with the exact missing real EKS,
  EC2, security-group, proxy, DNS, undeclared-fixture, and credential authority.
- [ ] Keep R-11 Not run and M0-20 Pending unless the real proof passes. Commit,
  push, and watch exact-SHA Runnable UI before closing this plan.
