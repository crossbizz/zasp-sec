# Connected preflight operator contract

This component observes intended AWS targets through official SDK APIs. It is
not a launch acceptance receipt. Its current report always keeps readiness false
because the original IRSA, OpenSearch, EKS/private network, Neon, Stytch and selected
EC2 sensor checks are not all connected. Queue metadata does not prove send,
receive or delete authority. S3/KMS metadata does not prove artifact write rights.

After the CLI build passes, invoke the read-only inspector with an absolute,
operator-owned config file having no group/other permissions:

```sh
agentsecctl preflight run --mode before-install --config-file /absolute/private/preflight.json
agentsecctl preflight run --mode installed --config-file /absolute/private/preflight.json
```

Both modes retain all eight original sections. A blocked evaluation writes the
bounded JSON report to stdout and exits nonzero. Missing credentials do not fall
back to another source. Configuration and credential errors do not print paths,
credential values or raw provider errors. Failure details contain a fixed SDK
operation, exact target digest, closed outcome and fixed remediation hint.
SDK operation names and IAM permission names are deliberately distinct.

The strict `agentsec-preflight-config-v1` config contains `deployment` (account,
partition, region, supported profile and release), product-ID `scope`,
`credentials`, `features` and `aws` resource bindings. The executable declarations
in `services/platform/preflight/contract.go` and validation in `config.go` define
the accepted fields. Unknown/duplicate fields, observed Boolean attestations,
arbitrary endpoints, cross-account or cross-region resources and unsafe files
are rejected. Targets are operator intentions, not verified tenant enrollment.

Select exactly one credential source: `operator_file` (private owned JSON),
`operator_environment` (explicit standard AWS variables), or
`workload_web_identity` (the fixed EKS projected token path and expected role).
No profile, IMDS or operator fallback is attempted. Workload exchange uses STS;
identity is checked before resource reads. It does not establish the remaining
IRSA trust or Kubernetes binding observations. No permissions are installed.
Secret values are transient and never reported. Mutable buffers are cleared;
immutable Go/SDK strings cannot be guaranteed erased from memory.

Use `agentsecctl preflight evaluate --offline` for the original Boolean policy
evaluator. Bare `preflight` retains this compatibility mode. Its report states
`source: offline-evaluation`, `ready: false`, and records the policy decision in
`evaluation_ready`. Offline success is not installation readiness.

Production acceptance still requires the documented target, least-privilege
workload bindings, real Stytch/provider integrations and deployed end-to-end
flows. No original task is promoted by this component.
