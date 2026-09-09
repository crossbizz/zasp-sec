# Attack Lab egress acceptance fixture

Run `node proofs/attack-lab-egress/run.mjs` from the repository root with
Node 22, Go and a Linux Docker engine. Run the interruption acceptance with
`ZASP_ATTACK_LAB_EGRESS_DOCKER=true node --test proofs/attack-lab-egress/interruption.test.mjs`.
Both are mandatory in runnable-UI CI. Nothing is deployed to AWS.

The fixture reads `deploy/staging/attack-lab-egress-contract.json`, the exact
protocol/port source used by Terraform's six runner security-group rules.
It installs those rules as a default-deny nftables OUTPUT chain in its own
Docker network namespace. The probe runs as UID 65532 with zero effective
capabilities. The privileged supervisor has NET_ADMIN only in that namespace,
plus SETUID/SETGID to launch the probe. It has no host network or Docker socket.

A controlled destination must return a run nonce from an independent control
before and after the restricted probe. Proxy forwarding and infrastructure
access must succeed. Direct TCP access to that same reachable destination and
an undeclared proxy port must time out, with nonzero kernel drop counters.
An HTTP error, DNS failure, TLS error or connection refusal does not count.
The control endpoints use HTTP to isolate the packet boundary; production
TLS, signed tokens and target authorization have separate acceptance tests.

All containers and the internal network have unique pre-registered names and
owner labels. Cleanup reconciles exact names, validates labels, then removes
only matching IDs. Lost create responses are tested. SIGTERM is exercised
after real allocation, and the test checks that no owned resources remain.
An unverifiable cleanup fails the run and reports the exact unresolved names.

## Proof boundary

This proves the original M5-21 local direct-egress denial fixture. It is not
live evidence of AWS SG attachment, Fargate scheduling, CNI behavior, ECR
pulls or S3 endpoint-policy enforcement. The fixture maps SG classes to owned
endpoint IPs; source assertions bind each class to its exact production SG or
prefix-list reference and reject extra runner rules. Five offline Terraform
plan tests cover rendered image-layer policy, ports and disjoint subnet
constraints. Run them with `terraform -chdir=deploy/staging test -var-file=release.tfvars -filter=tests/attack_lab_egress.tftest.hcl`.
The release tfvars contain offline placeholders. Never apply them.

Sandbox subnet changes replace an existing Fargate profile. Before a live
upgrade, pause new Attack Lab consumption, drain and verify owned Job/Pod
cleanup, then apply the reviewed real-account plan and verify image pulls,
Pod ENI/SG attachment, allowed proxy traffic and forbidden direct traffic
before resuming. Keep product subnets and their S3 endpoint unchanged.

## Dependency boundary

This is a separate proof module, not a production binary dependency. The
exact module versions and checksums are in go.mod/go.sum. The six external
modules reachable in the Linux fixture were inspected from downloaded module
source on September 9, 2026:

| Module | Version | License | License file SHA-256 |
| --- | --- | --- | --- |
| github.com/google/nftables | v0.3.0 | Apache-2.0 | cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 |
| github.com/mdlayher/netlink | v1.7.3-0.20250113171957-fbb4dce95f42 | MIT | fc7c6fc520ba7d8bded1f601c13ed3918709b13e8b45c37820fdeddaecc9992a |
| github.com/mdlayher/socket | v0.5.0 | MIT | 7ac20f598f63dfd35c7c6c3844073af0bebfa436cfe58b91af9ac17cd727ea42 |
| golang.org/x/net | v0.33.0 | BSD-3-Clause | 911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad |
| golang.org/x/sync | v0.6.0 | BSD-3-Clause | 2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067 |
| golang.org/x/sys | v0.28.0 | BSD-3-Clause | 911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad |

The fixture reuses the existing digest-pinned Alpine 3.22.2 runner runtime
image as a local container shell; it executes only the mounted static Go
binary and does not redistribute or relicense Alpine's packages. The
temporary binary and all owned containers are removed after the proof.
