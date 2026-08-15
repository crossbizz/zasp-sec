# M0 technical proof gate

Date: August 15, 2026

## Gate result

**PROCEED WITH BLOCKED PATHS**

The M0 proof record contains **12 PASS / 2 BLOCKED / 0 FAIL / 0 unclassified**
decisions. M1 foundation work may begin after M0-23 completes and its exact-SHA
CI passes. This result is not an unconditional provider-parity approval: R-03
and R-11 remain unpassed, and their dependent architecture claims remain
blocked.

## Decisions

| Risk | Outcome | Proofs | Evidence | Architecture decision |
| --- | --- | --- | --- | --- |
| R-01 | PASS | M0-02/M0-03 | .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-02-report.md; proof head da1323050a9875bde17190e6d84afa7fa4651a13; .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-03-report.md; proof head 5ddf9b23b9b781499281610da2ac153663ff42b8 | Adopt the Stytch B2B fresh-local and forced-remote JWT validation split, preserving normal remote handling for ineligible tokens. |
| R-02 | PASS | M0-04/M0-05 | .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-04-report.md; proof head e8a8f5fc56ace9570a23476771c8c48377cd4db3; .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-05-report.md; proof head 37d638f22d8e9e5b8075cc9aab755b6589084b07 | Adopt pooled Neon application connections and direct disposable-branch migration connections with exact destination and restoration checks. |
| R-03 | BLOCKED | M0-06/M0-07/M0-09 | M0-09 reviewed harness; 0/9 isolated real-AWS inputs; LocalStack cannot substitute | Keep supported local SQS/storage behavior, but block real-AWS IAM parity and dependent M1A/M3 claims. Resume only when M0-09 passes in isolated commercial AWS accounts. |
| R-04 | PASS | M0-06/M0-08 | .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-06-report.md; proof head ba02323b83618e096c67cb2380f5a4cbaf9c9086; .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-08-report.md; proof head 959f033c9f6b5d26e0c57b0e01dbb539358c7a09 | Retain SQS as durable batch transport and OpenSearch as an Organization-scoped rebuildable query projection rather than source of truth. |
| R-05 | PASS | M0-10 | .superpowers/sdd/2026-08-14-m0-10-cartography-proof-implementation-plan/task-6-report.md; proof head 23b759b793e02aba91c24b846651ed64018a9a03 | Adopt product-owned Organization-scoped Cartography normalization under the reviewed fixture-only boundary without claiming AWS or GitHub authorization parity. |
| R-06 | PASS | M0-11 | .superpowers/sdd/2026-08-14-m0-11-prowler-proof-implementation-plan/task-6-report.md; proof head 8d7c0c3c466e76910ce07ba8fb745392e85af70a | Adopt the reviewed fixture-only Prowler-to-product evidence mapping without treating it as real-AWS authorization or broad-provider parity. |
| R-07 | PASS | M0-12 | .superpowers/sdd/2026-08-14-m0-12-tetragon-proof-implementation-plan/task-6-report.md; proof head 5f336a8bec7f37524d8ade33d348a2ea64a4cad3 | Adopt Tetragon as observation-first runtime signal evidence with explicit workload identity, capability, and loss state, not semantic truth. |
| R-08 | PASS | M0-14a/M0-14b/M0-14c/M0-14/M0-15 | .superpowers/sdd/2026-08-15-m0-15-nango-proxy-proof-implementation-plan/task-6-report.md; proof head 7f64ca823365af066c273a755e01acd7cf05c0ab | Adopt free self-hosted Nango for long-tail Auth plus Proxy only; excluded Nango runtime and enterprise features remain outside MVP dependencies. |
| R-09 | PASS | M0-16 | .superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-16-report.md; proof head 4abd751918913be813a662ea0f3847676369b012 | Adopt Promptfoo as the MVP red-team engine through the strict objective, verdict, and evidence-reference normalization boundary. |
| R-10 | PASS | M0-17 | .superpowers/sdd/2026-08-15-m0-17-opa-sdk-proof-implementation-plan/task-5-report.md; proof head bd72e785c543f381d2d8a9bdf9a4150275605e3d | Embed the OPA Go SDK on the deterministic synchronous runtime-gateway fast path without adding an external policy-service dependency. |
| R-11 | BLOCKED | M0-18/M0-19 | M0-18/M0-19 reviewed harnesses; 0/11 and 0/19 real-EKS inputs; LocalStack cannot substitute | Keep EKS Fargate as the intended reference, but block EKS Fargate strong-isolation and egress claims. Resume only when M0-18 and M0-19 pass in an isolated real-EKS fixture. |
| R-12 | PASS | M0-13/M0-22 | .superpowers/sdd/2026-08-14-m0-13-otlp-proof-implementation-plan/task-6-report.md; proof head c91047923bcbf9e567e640ade8c308c03a0100bc; .superpowers/sdd/2026-08-15-m0-22-otlp-export-proof-implementation-plan/task-4-report.md; proof head 425accdf9293e7652c6cedd5e49e772799a431fa | Adopt the local Collector as the telemetry interface with bounded export and application progress independent of optional exporter availability. |
| R-13 | PASS | M0-20 | .superpowers/sdd/2026-08-15-m0-20-posthog-privacy-proof-implementation-plan/task-5-report.md; proof head e99edb0daa7d2cedf03c96a3108520b9a6b2edb5 | Keep PostHog optional and export only the reviewed allowlisted analytics schema after zero-I/O prohibited-field rejection. |
| R-14 | PASS | M0-21/M0-21a | .superpowers/sdd/2026-08-15-m0-21-openrouter-privacy-proof-implementation-plan/task-5-report.md; .superpowers/sdd/2026-08-15-m0-21a-security-agent-planner-proof-implementation-plan/task-5-report.md; proof head 6f4ed10198495b8f0b6019cb6d82221d7cac91c1 | Keep OpenRouter optional, redact its explanation input, and limit asynchronous Security Agent plans to the reviewed typed catalog and exact in-scope identifiers. |

## Blocker consequences

- R-03 does not block local foundation commands or supported LocalStack SDK
  behavior. It blocks any claim that real-AWS IAM authorization parity is
  established and blocks dependent M1A/M3 acceptance until M0-09 passes.
- R-11 does not block foundation commands or observation-only runtime work. It
  blocks any EKS Fargate strong-isolation or Security Groups for Pods egress
  claim until both M0-18 and M0-19 pass in the documented isolated fixture.
- M0-09, M0-18, and M0-19 remain Blocked in the authoritative tracker. No local
  emulator, source review, prepared harness, or fixture-only result is counted
  as provider evidence for either risk.
