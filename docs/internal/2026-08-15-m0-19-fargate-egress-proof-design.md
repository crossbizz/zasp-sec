# M0-19 EKS Fargate egress proof design

Date: August 15, 2026

## Decision

M0-19 is a real-provider-only proof. It applies one proof-owned
`vpcresources.k8s.aws/v1beta1` `SecurityGroupPolicy` to a fresh canary Job on
the disposable EKS Fargate profile from M0-18. LocalStack cannot authorize
success because it cannot supply AWS-managed Fargate scheduling, Security
Groups for Pods, branch-ENI attachment, or authoritative EC2 security-group
rules.

LocalStack cannot authorize success under any compatibility or fixture mode.

The proof mutates no security group. An operator supplies a disposable,
preconfigured Pod security group and explicit read-only AWS credentials. The
proof reads that group through the official EC2 SDK, applies only Kubernetes
proof resources, and removes those resources in reverse dependency order.

## Exact authority

The live boundary accepts only these task-specific values:

`AWS_M019_ISOLATED_TEST`, `AWS_M019_KUBECONFIG`,
`AWS_M019_KUBE_CONTEXT`, `AWS_M019_CLUSTER_NAME`, `AWS_M019_REGION`,
`AWS_M019_FARGATE_PROFILE`, `AWS_M019_PROFILE_NAMESPACE_PREFIX`,
`AWS_M019_PROFILE_LABEL_KEY`, `AWS_M019_PROFILE_LABEL_VALUE`,
`AWS_M019_PROXY_URL`, `AWS_M019_DIRECT_URL`, `AWS_M019_CANARY_TOKEN`,
`AWS_M019_POD_SECURITY_GROUP_ID`, `AWS_M019_CLUSTER_SECURITY_GROUP_ID`,
`AWS_M019_PROXY_SECURITY_GROUP_ID`, `AWS_M019_VPC_ID`,
`AWS_M019_DNS_CIDR`, `AWS_M019_ACCESS_KEY_ID`,
`AWS_M019_SECRET_ACCESS_KEY`, optional `AWS_M019_SESSION_TOKEN`, and the
supervisor-owned `ZASP_M019_KUBECTL_EXECUTABLE`.

The required values carry:

- exact isolation attestation;
- private immutable kubeconfig, context, cluster, region, and Fargate profile;
- fixed namespace/profile selector values;
- product egress-proxy HTTPS endpoint and test canary credential;
- fixed undeclared-egress HTTPS fixture endpoint;
- explicit static AWS access key, secret key, and optional session token;
- exact Pod, cluster, and proxy security-group IDs;
- exact VPC DNS resolver `/32` CIDR.

Profiles, shared AWS config, IMDS, custom endpoints, ambient proxies, dotenv,
and credential-process/web-identity chains are refused. The kubeconfig must
select a commercial EKS endpoint in the declared region. The EC2 identity is
read-only and must return one exact security group with no ingress, no IPv6 or
prefix-list rules, and exactly these egress rules:

1. TCP 443 to the cluster security group;
2. UDP 53 to the DNS resolver `/32`;
3. TCP 53 to the same resolver `/32`;
4. TCP 443 to the product proxy security group.

No default cluster security group is added to the Pod policy because its
allow-all egress would invalidate containment.

## Lifecycle and evidence

The lifecycle creates a generated namespace, ServiceAccount, Secret,
SecurityGroupPolicy, and one restricted Job. The policy selects the same exact
proof and Fargate-profile labels as the Job template and lists only the
pre-proved Pod security group. All creates and deletes use single-attempt mutations;
only typed ambiguous outcomes enter bounded exact-state
reconciliation. Reads have two bounded attempts.

The Pod runs as UID/GID/fsGroup 65534 with a read-only root filesystem,
disabled privilege escalation, no added capabilities, fixed resource limits,
and the immutable M0-18 BusyBox image. Its fixed program performs two bounded
checks:

- direct TCP 443/HTTPS to the undeclared fixture must fail;
- the same named canary request through the product egress proxy must return
  exactly `agentsec-attack-lab-canary-v1`.

Success evidence is exactly `direct=false proxy=true`, the exact response
body, Fargate scheduling/node metadata, the Pod security-group annotation,
and an EC2 network-interface read proving that exact Pod ENI carries only the
declared Pod security group. No identifier, URL, credential, provider body, or
raw error crosses fixed output.

## Safety and completion

The main phase is bounded to ten minutes and independent cleanup to five. A
supervisor adds a one-minute margin, caps combined output, SIGKILLs and reaps
uncooperative children, and re-proves retained temporary-file identity before
deletion. Cleanup continues in reverse order, uses immutable UIDs and exact
state, proves global prefix/label absence, and gives cleanup failure precedence.

The current environment has none of the required real-provider fixture.
Implementation proceeds hermetically, then the exact command must fail at
configuration before any AWS or cluster request. If authority remains absent,
M0-19 becomes Blocked and R-11 remains `Not run — M0-18/M0-19`. Only a real
live pass can complete M0-19 and decide R-11.
