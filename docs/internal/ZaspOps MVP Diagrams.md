# ZaspOps MVP — Architecture and Flow Diagrams

Aligned with **Technical Implementation Plan v2.2 (2026-08-12)**. Section references (§) point at the plan. Regenerate these when the plan changes.

## 1. Overall MVP architecture (§4–§7)

```mermaid
flowchart LR
  subgraph CUST["Customer boundary"]
    OP["Operator / Approver — web console"]
    EMP["Requester — Slack"]
    SAAS["Slack · Okta · ServiceNow · Datadog · PagerDuty · Confluence"]
    K8S["Kubernetes clusters — Go edge agent, read-only"]
    GEN["Generic producers — DCGM · Slurm · fabric telemetry"]
  end

  subgraph CELL["ZaspOps AWS cell — one region, ECS Fargate"]
    CF["CloudFront + WAF"] --> ALB["ALB"]
    ALB --> WEB["web — Next.js console"]
    ALB --> API["api — Fastify: authz · commands · webhooks"]
    API --> PG[("Neon Postgres — forced RLS<br/>graph · tsvector · pgvector<br/>work · outbox · audit · proof")]
    API --> OBX["outbox poller"]
    OBX --> SQS["SQS + DLQs"]
    SCH["EventBridge Scheduler<br/>sweeps · expiries · reconcile"] --> SQS
    SQS --> WK["worker — ingest · resolve · quality · retention"]
    SQS --> AR["action-runner — isolated task role<br/>write adapters · verification · rollback"]
    WK --> PG
    AR --> PG
    API --> S3[("S3 SSE-KMS, versioned<br/>raw payloads · proof evidence · exports")]
    NGO["Nango OSS — OAuth · token refresh · API-key connections"] --> NDB[("Nango Postgres<br/>direct endpoint, isolated")]
    API -- "connect session" --> NGO
    WK -- "read token" --> NGO
    AR -- "write token" --> NGO
    ING["ingest API — HMAC + edge tokens"] --> OBX
  end

  subgraph PROV["Provider boundary"]
    ST["Stytch B2B — SSO · SCIM · sessions · RBAC"]
    ORT["OpenRouter — pinned model allowlist"]
    EMB["Embedding API — conditional, §11 gate"]
  end

  OP --> CF
  EMP -- "messages" --> SAAS
  SAAS -- "webhooks" --> API
  WK -- "polls" --> SAAS
  NGO -- "OAuth flows" --> SAAS
  K8S -- "outbound HTTPS" --> ING
  GEN -- "signed HTTPS" --> ING
  API -- "sessions / SCIM" --> ST
  API -. "packages/model" .-> ORT
  WK -. "packages/model" .-> ORT
  WK -. "packages/model" .-> EMB
  AR -- "scoped short-lived write" --> SAAS
```

## 2. Milestone and gate map (§21–§22)

```mermaid
flowchart LR
  EXT["EXT.1–11 external prereqs<br/>Stytch · Neon · AWS · OpenRouter · sandboxes"] -.-> M1 & M9
  M0["M0 foundation<br/>repo · CI · compose"] --> M1["M1 tenancy + auth + RLS<br/>incl. real-Neon pooler GATE M1.18"]
  M1 --> M2["M2 core schema<br/>outbox · queues · audit"]
  M2 --> M3["M3 ingest framework + registry<br/>Okta + K8s connectors · resolver"]
  M2 --> M6["M6 policy · work/approvals · Proof Records"]
  M3 --> M4["M4 traversal + Ask + investigation UI"]
  M3 --> M5["M5 remaining connectors + quality admin<br/>retrieval gate M5.21–M5.24"]
  M4 --> GA{{"GATE A — read-only alpha"}}
  M5 --> GA
  M6 --> M7["M7 actions · Okta access lifecycle · Slack UX"]
  M4 --> M7
  M5 --> M8["M8 certification · audit/export · kill switches"]
  M6 --> M8
  M0 --> M9["M9 IaC · observability · hardening"]
  M5 -. "ADR = adopt" .-> R1["R1 conditional package<br/>semantic retrieval (pgvector)"]
  R1 -.-> GB
  M7 --> GB{{"GATE B — write-enabled"}}
  M8 --> GB
  M9 --> GB
  GA --> GB
  GB --> N["MVP-2 — N1 self-service · N2 incident enrichment<br/>N3 edge action · N4 admin/export"]
```

## 3. Flow: infrastructure investigation / blast radius (§12, §14; tasks M4.x)

```mermaid
sequenceDiagram
  autonumber
  actor Op as Operator (web or Slack)
  participant API as api (authz)
  participant WK as worker pipeline
  participant PG as Neon (RLS graph + docs)
  participant MG as packages/model → OpenRouter
  Op->>API: POST /v1/investigations — "what breaks if we drain gpu-h100-usw2-04?"
  API->>API: session → actor · RBAC/ABAC · tenant context
  API->>PG: persist investigation + outbox event
  API-->>Op: 202 accepted — state: loading context
  WK->>MG: extract entities + intent (schema-validated JSON)
  alt entity ambiguous
    WK-->>Op: clarification payload — entity selector
    Op->>API: POST /v1/investigations/id/clarification
  end
  WK->>PG: bounded traversal (depth ≤ 6, ≤ 2000 nodes) + lexical chunks (tenant/classification/authority/freshness filters)
  WK->>WK: build EvidencePacket — facts, edges, authority, freshness, conflicts, gaps
  WK->>MG: compose answer — every claim must cite packet IDs
  WK->>WK: citation validator — strip or label unsupported claims
  alt required source stale/missing, or model outage
    WK->>PG: evidence-only answer · gaps named · write actions disabled
  end
  WK->>PG: persist answer + proof draft (evidence view)
  Op->>API: GET /v1/investigations/id — answer pane + proof pane
  opt act from answer
    Op->>API: POST /v1/investigations/id/actions — ticket / notify / change draft
    API->>PG: work item + policy decision (+ approvals if Tier ≥ 2)
  end
```

## 4. Flow: Ask / retrieval pipeline with the embedding decision gate (§11)

```mermaid
flowchart LR
  Q["NL question"] --> AZ["authz + entity resolution<br/>tenant · RBAC/ABAC · classification"]
  AZ --> G["graph facts<br/>bounded traversal under RLS"]
  AZ --> L["lexical tsvector chunks<br/>tenant/classification/authority/freshness filters"]
  AZ -.-> V["vector candidates — pgvector<br/>ONLY if M5.24 ADR adopts · identical filters"]
  G --> F["rank — RRF fuse if vector active<br/>authority · certification · freshness · directness"]
  L --> F
  V -.-> F
  F --> EP["EvidencePacket<br/>fact/edge/source IDs · quality · gaps · redactions"]
  EP --> M["model via packages/model<br/>typed claims, each citing packet IDs"]
  M --> CV{"citation validator"}
  CV -- "supported" --> ANS["answer + proof draft"]
  CV -- "unsupported claim" --> STRIP["strip, or label as inference"]
  CV -- "validation fails" --> EO["evidence-only answer or escalate<br/>writes stay disabled"]
  GATE["Retrieval gate M5.21–M5.24<br/>lexical baseline → offline spike → ADR<br/>adopt if recall@10 +10 pts or −30% retrieval-miss failures"] -.-> V
```

## 5. Flow: time-bound Okta access — request → approve → provision → verify → expire → revoke (§12, §14; tasks M6–M7)

```mermaid
sequenceDiagram
  autonumber
  actor Req as Requester (Slack or web)
  actor App as Approver
  participant API as api
  participant POL as packages/policy (hashed bundle)
  participant PG as Neon (work · approvals · proof)
  participant AR as action-runner
  participant NGO as Nango (write connection)
  participant OKTA as Okta
  Req->>API: POST /v1/access-requests — "read-only prod capacity dashboard, 2 weeks"
  API->>PG: resolve person · manager · entitlement-catalog match
  API->>POL: evaluate — eligibility, SoD, duration cap, risk tier
  alt policy denies (e.g. SoD conflict)
    API-->>Req: denied — policy reason + escalation path
  else allow — Tier 2
    API->>PG: ONE txn — work item + proof draft + approvals + outbox
    API-->>App: approval card (Slack) / inbox (web) with proof summary
    App->>API: POST /v1/approvals/id/decision — policy-hash recheck · expiry check
    API->>PG: authorized → outbox → SQS
    AR->>PG: acquire lease (tenant, action, idempotency key)
    AR->>NGO: fetch scoped WRITE token
    AR->>OKTA: add group membership (idempotent)
    AR->>OKTA: verify — read membership back (HTTP 200 is not success)
    alt verification fails
      AR->>PG: failed → rollback if safe, else named escalation
    else verified
      AR->>PG: finalize proof — canonical hash → Postgres + S3
      API-->>Req: granted — visible expiry time
    end
    Note over PG,AR: expiry sweeper fires at T+2 weeks
    AR->>OKTA: revoke membership + verify removal
    AR->>PG: append revocation outcome to Proof Record
  end
  opt no approver resolvable
    API->>PG: route to fallback queue — never auto-approve
  end
```

## 6. Governed action lifecycle — state machine (§12)

```mermaid
stateDiagram-v2
  [*] --> Proposed
  Proposed --> CollectingEvidence
  CollectingEvidence --> Evaluated: draft proof complete
  CollectingEvidence --> Escalated: missing / stale / conflicting context
  Evaluated --> Rejected: policy deny or Tier 4
  Evaluated --> AwaitingApproval: allow
  AwaitingApproval --> Authorized: required approvals current
  AwaitingApproval --> Rejected: deny or approval expiry
  Authorized --> Executing: lease + scoped write credential
  Executing --> Verifying: adapter returned
  Executing --> Escalated: timeout / ambiguous target
  Verifying --> Finalized: authoritative state matches expectation
  Verifying --> RollingBack: verification failed, safe inverse exists
  RollingBack --> Finalized: rollback verified
  RollingBack --> Escalated: rollback failed
  Escalated --> Finalized: human resolution recorded
  Rejected --> Finalized
  Finalized --> [*]
```

## 7. Flow: Slack identity binding and approvals (§8, §12; tasks M7.21–M7.25)

```mermaid
sequenceDiagram
  autonumber
  actor U as Slack user
  participant SL as Slack
  participant API as api — /webhooks/slack
  participant ST as Stytch
  U->>SL: first sensitive command (e.g. approve)
  SL->>API: signed event — signature + timestamp verified, inbox dedupe
  API->>API: lookup binding (tenant, team, user) → none found
  API-->>U: one-time, state-bound web link
  U->>ST: SSO login — SAML/OIDC + MFA
  ST->>API: verified session → store binding → actor_id
  Note over API: rebind needs confirmation + audit · workspace collisions rejected
  U->>SL: tap Approve on card
  SL->>API: signed interaction
  API->>API: checks — binding · live session/lifecycle · approver role · policy-hash match · not expired/duplicate
  alt any check fails
    API-->>U: rejected with the reason (unbound, stale policy, expired)
  else all pass
    API->>API: record decision → action lifecycle proceeds (diagram 6)
    API-->>U: confirmation + link to full Proof Record
  end
```

## 8. Flow: connector ingestion → canonical graph (§9–§10; tasks M2–M3, M5)

```mermaid
flowchart TB
  subgraph SRC["Sources"]
    WH["provider webhooks<br/>Slack · ServiceNow · PagerDuty · Stytch"]
    POLL["polled APIs<br/>Okta System Log · Datadog · Confluence"]
    EDGE["edge agent<br/>K8s list/watch · sequence numbers"]
    GENP["generic producers<br/>signed envelopes"]
  end
  WH --> INB
  GENP --> INB
  EDGE --> INB
  POLL --> WKP["sync worker<br/>token from Nango · checkpointed"]
  WKP --> INB["ingest inbox<br/>durable write then ack · dedupe on delivery_id"]
  INB --> NRM["normalizer<br/>manifest mappings · per-field authority · classification"]
  NRM --> SR[("source_records<br/>immutable · revisioned · hashed")]
  NRM --> OBS[("observations + relationships<br/>append-only · provenance · valid_range")]
  NRM --> CKPT["advance checkpoint<br/>only after normalized commit"]
  OBS --> RES["resolver<br/>1 deterministic IDs → 2 exact alias → 3 scored"]
  RES --> MRG{"score vs threshold"}
  MRG -- "high + no authoritative conflict" --> CAN["canonical entity<br/>reversible merge"]
  MRG -- "otherwise" --> REV["human review queue"]
  CAN --> PROJ["canonical projection<br/>authority → certification → freshness<br/>conflicts stay visible"]
  PROJ --> QLT["quality + health<br/>freshness · lag · affected workflows"]
  DEL["deletion events"] --> TMB["tombstone — close validity<br/>history retained"]
```

## 9. Flow: Proof Record lifecycle (§13; tasks M6.13–M6.19)

```mermaid
flowchart LR
  W["work item created<br/>investigation · access request · action"] --> D["proof DRAFT — mutable<br/>evidence · policy I/O · approvals accrete"]
  D --> FIN{"finalization trigger<br/>approval granted / action completed"}
  FIN --> C["canonicalize JSON<br/>sorted keys · normalized forms"] --> H["SHA-256 digest<br/>+ prior_proof_hash chain link"]
  H --> TX["serializable txn<br/>proof_records + append event + outbox<br/>UPDATE/DELETE denied by trigger"]
  TX --> S3W["S3 copy — SSE-KMS · versioned · tenant prefix"]
  S3W -- "S3 failure" --> BLK["write-action finalization BLOCKED<br/>drafts stay readable, labeled"]
  TX --> AM["later corrections →<br/>linked amendments, never rewrites"]
  TX --> VER["pnpm proof:verify<br/>recompute hashes · walk chain · check S3 version"]
```

## 10. MVP-2 flows (gated on Gate B + 30-day safety hold; epics N1–N2)

### Employee self-service (N1)

```mermaid
flowchart LR
  E["employee asks in Slack"] --> ID["SSO-bound identity<br/>+ existing-access context"]
  ID --> CLS["classify request +<br/>retrieve certified knowledge"]
  CLS --> CQ{"context sufficient?"}
  CQ -- "no" --> GAP["name the gap ·<br/>offer human escalation"]
  CQ -- "yes" --> ANS["personalized steps + evidence<br/>(bounded clarifying questions)"]
  ANS --> RES{"resolved?"}
  RES -- "yes" --> FB["feedback → knowledge quality"]
  RES -- "no" --> TKT["enriched ServiceNow ticket<br/>thread · attempted steps · diagnostics · evidence"]
```

### Incident enrichment and guided diagnosis (N2)

```mermaid
flowchart LR
  EVT["PagerDuty / ServiceNow / Datadog event"] --> WI["work item"]
  WI --> ENR["enrich — service · owner · on-call<br/>recent changes · alerts · dependencies"]
  ENR --> SUM["prioritized summary + suspected cause<br/>inferred causes labeled — never write-enabling alone"]
  SUM --> OPR{"operator"}
  OPR -- "accept diagnostic" --> ACT["governed action lifecycle (diagram 6)<br/>preview → approval → verify"]
  OPR -- "correct / add evidence" --> ENR
  OPR -- "escalate" --> HUM["human path + ticket update"]
```
