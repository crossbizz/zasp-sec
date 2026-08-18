# M1-37 Deployment Mode Configuration Design

Date: August 18, 2026

## Goal

Extend the completed M1-07 typed platform configuration with one explicit
deployment-mode boundary. The same product binaries must distinguish managed
multi-tenant SaaS from a deployment pinned to one product Organization without
silently accepting an incomplete, ignored, or topology-specific value.

## Selected boundary

`services/platform/config` remains the single startup configuration owner. It
adds exactly two source keys:

- `AGENTSEC_DEPLOYMENT_MODE`
- `AGENTSEC_SINGLE_TENANT_ORGANIZATION_ID`

The deployment mode is required and accepts only the exact lowercase tokens
`saas` and `single_tenant`. There is no ambient/default mode: omission, an
empty value, whitespace, case drift, or any other token fails startup. An
explicit mode avoids accidentally starting a dedicated installation with SaaS
tenant assumptions, or a SaaS process with a silently ignored tenant pin.

The Organization key is conditional:

| Mode | Organization key | Result |
| --- | --- | --- |
| `saas` | absent | valid |
| `saas` | present, including empty | reject |
| `single_tenant` | absent or empty | reject |
| `single_tenant` | canonical product ID | valid |
| `single_tenant` | any other value | reject |

The pinned Organization value uses the completed M1-03 `domain.ProductID`
parser. Vendor IDs, raw UUIDs, uppercase or noncanonical UUID text, zero IDs,
and arbitrary strings are rejected. The loader does not generate an ID and
does not infer one from Stytch, Neon, AWS, a hostname, or any process state.

## Typed model

`DeploymentMode` is an opaque comparable enum with read-only `String` output
and two exported valid values. A direct invalid enum value does not validate.

`Deployment` contains the mode plus an optional opaque product Organization
ID. Read-only accessors expose the mode and return the pinned Organization only
when the complete single-tenant invariant is valid. `Config` contains this
deployment value alongside its existing required and optional dependency
groups. All values remain comparable and immutable by construction.

`Load` snapshots every known key exactly once through the existing injected
lookup boundary. It validates required dependency configuration and deployment
configuration from that snapshot, then performs the existing final whole-value
validation. Errors remain fixed categories and never contain a rejected mode
or Organization value.

## Startup and future enforcement boundary

For this task, "starts" means the typed `Load` boundary returns a valid
configuration. Command wiring, environment reads, provider calls, secret
resolution, topology, values files, and listener startup remain outside
M1-37. Existing platform commands continue to have no new runtime I/O.

The pin is configuration authority for later consumers, not authorization by
itself. M2-49 will reject an authenticated Organization that differs from the
configured single-tenant Organization before repository access. M8-55 and
M8-56 will supply the two deployment values profiles. M1-37 neither weakens
SaaS Organization scoping nor introduces a separate single-tenant data model,
API, image, schema, or product fork.

## Validation and regression evidence

Tests must prove:

- valid SaaS loading without a pinned Organization;
- valid single-tenant loading with exactly one canonical product Organization;
- missing, empty, malformed, case-drifted, and unsupported modes fail closed;
- SaaS rejects every present Organization key, including empty and canonical;
- single-tenant rejects an absent, empty, or malformed Organization value;
- accessors, comparability, direct invalid state, and exact one-read source
  snapshot behavior;
- every completed M1-07 required/optional dependency case remains unchanged;
  and
- fixed errors contain no rejected source value.

The focused package runs six consecutive race-enabled passes. Completion also
requires the full platform module race/tidy-diff/module-verify/vet matrix,
pinned repository verification, production audit, whitespace checks, pinned
secret scans, and a zero-finding review.

## Status boundary

Starting M1-37 changes the overall source counts to 646 Pending / 1 In progress
/ 78 Complete / 3 Blocked and M1 to 13 Pending / 1 In progress / 54 Complete /
0 Blocked. Completion changes them to 646 / 0 / 79 / 3 overall and 13 / 0 / 55
/ 0 within M1. M1-36e remains Complete exactly once, M1-38 remains Pending,
and M0-09, M0-18, and M0-19 remain the exact source blockers.

## Alternatives rejected

- Defaulting an absent mode to SaaS hides deployment mistakes.
- Allowing a SaaS pin but ignoring it creates misleading security
  configuration.
- Accepting arbitrary Organization strings duplicates and weakens the canonical
  product-ID boundary.
- Reading process environment directly inside the package breaks the injected,
  deterministic M1-07 source contract.
- Enforcing authenticated Organization equality here would pull the later
  M2-49 authorization task into startup configuration.
