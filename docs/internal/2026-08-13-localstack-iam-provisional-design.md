# Provisional LocalStack IAM compatibility design

**Status:** Approved design; implementation planning pending user review
**Date:** August 13, 2026
**Related source task:** M0-09
**Temporary work item:** PROV-01

## Context

M0-09 requires a disposable cross-account read-only role proof in isolated real
AWS. The reviewed real-AWS harness is complete, but the required two-account
credential fixture is unavailable. LocalStack cannot replace that release-parity
authority: the technical plan and R-03 explicitly require the real-AWS allowed
and denied results.

The user approved a temporary dependency waiver so development can continue.
This design adds separate LocalStack IAM/STS compatibility evidence while
keeping M0-09 blocked and preserving its existing real-AWS harness unchanged.
After PROV-01 passes implementation, live verification, and independent review,
M0-10 may start under the documented waiver.

## Goals

- Exercise IAM and STS through exact-pinned official AWS SDK clients against a
  proof-owned disposable LocalStack target.
- Demonstrate a complete local cross-namespace role-assumption lifecycle with
  one allowed self-read and one explicitly denied list operation.
- Require exact ownership, immutable identity, cleanup, and zero-resource audit
  before treating the provisional proof as passing.
- Preserve the real-AWS M0-09 harness and its credential, endpoint, identity,
  authorization, and cleanup boundaries without modification.
- Keep all output fixed and free of credentials, account IDs, ARNs, role/user
  names, policies, tags, endpoints, ports, image digests, or provider payloads.

## Non-goals

- Completing M0-09 or R-03.
- Claiming AWS IAM, STS, SCP, permissions-boundary, durability, or release
  parity from LocalStack behavior.
- Falling back to a same-account or enforcement-disabled happy path if the
  requested LocalStack behavior is unsupported.
- Mutating the shared development LocalStack container or using persistent
  emulator state.
- Adding a LocalStack endpoint mode to the hardened real-AWS proof.

## Architecture

Create a separate `proofs/localstack-iam-compat` module. It owns a narrow IAM
and STS abstraction plus a Node disposable-container orchestrator. It does not
import or configure the real-AWS runner.

The orchestrator starts an exact-digest LocalStack image on a random loopback
port with only IAM and STS enabled, IAM policy enforcement enabled, persistence
disabled, and unique proof labels. It validates the exact container ID, image,
name, labels, loopback binding, services, and health state before executing the
proof. Cleanup revalidates that identity before removal and proves absence.

The Go proof constructs official IAM and STS clients directly with synthetic,
non-secret LocalStack credentials. It disables ambient config, profiles, IMDS,
proxies, redirects, custom CA material, and non-loopback endpoints. Mutations
are single-attempt. Read-only calls have narrowly bounded transient retries.
Every request, response body, reconciliation loop, and total proof phase has a
hard deadline and size bound.

Two documented LocalStack account namespaces represent the source and target
for this compatibility exercise. They are emulator namespaces, not evidence of
AWS account isolation. If LocalStack cannot enforce the cross-namespace
assumption and allow/deny contract, PROV-01 fails with a fixed provider category
and the implementation must not weaken the scenario.

## Lifecycle

1. Validate the disposable target and prove both namespace prefixes are empty.
2. Generate unique source principal, target role, external ID, session name,
   source identity, session tag, proof marker, and policy identities in memory.
3. Create the source principal and its temporary local access key.
4. Create the target role with an exact trust policy requiring the source
   principal plus the generated external ID, session name, source identity, and
   session tag.
5. Attach an exact policy that allows only `iam:GetRole` for the target role and
   explicitly denies `iam:ListRoles`.
6. Re-fetch and validate all namespaced resources, tags, immutable identifiers,
   trust, and permission policy before assumption.
7. Assume the role with the exact generated conditions and validate the returned
   assumed-role identity against the immutable role identity and session.
8. Call `GetRole` for the assumed role and require the exact owned role result.
9. Call `ListRoles` and require the expected explicit-deny category. An implicit
   denial, disabled enforcement, or other authorization category fails.
10. Under an independent cleanup context, re-prove each resource before deleting
    policies, access keys, source principal, and target role in dependency order.
11. Audit both namespace prefixes to zero, remove the disposable container, and
    prove container and temporary-build absence.

## Ownership and failure semantics

Names are never sufficient ownership. Provider-returned immutable identifiers,
exact namespace, proof marker tags, trust policy, permission policy, and session
identity must agree before use or deletion. Definite provider rejection never
authorizes reconciliation. Transport uncertainty, panic after a sent mutation,
or invalid successful responses enter bounded exact reconciliation. An observed
candidate cannot later be downgraded to absence in the same window.

Cleanup uses a separate context, attempts all independently owned resources,
and wins error precedence. A mismatch blocks deletion. Panic, cancellation,
timeout, output overflow, readiness failure, and container-start ambiguity all
remain within the fixed-output boundary and still attempt exact cleanup.

## Verification

Implementation follows genuine RED/GREEN TDD before production or dependency
changes. Deterministic tests cover:

- namespace and immutable-identity confusion;
- exact trust, permission, tag, and session-condition parsing;
- explicit versus implicit denial and enforcement-disabled behavior;
- mutation rejection, ambiguity, delayed visibility, cancellation, and panic;
- prefix collisions and replacement resources;
- bounded bodies, deadlines, retries, proxy/endpoint refusal, and fixed output;
- cleanup authorization, continuation, precedence, and absence;
- exact image/container ownership, start ambiguity, readiness bounds, and
  temporary-build cleanup.

Completion of PROV-01 additionally requires the documented disposable live run,
a separate zero-prefix audit, container and temporary-file absence, Go race and
module gates, pinned Node tests/type-check/lint/build, production dependency
audit, pinned full-history secret scan, clean tracked tree, and independent
review with no remaining findings.

## Status and claim boundary

PROV-01 is tracked separately and does not change the count of the 728 source
tasks. M0-09 remains Blocked on the missing isolated real-AWS two-account
fixture. R-03 remains not run for real-AWS authorization. M0-10 remains Pending
until PROV-01 passes final review; it may then move to In progress under the
approved temporary dependency waiver. The waiver does not transitively satisfy
later real-AWS release gates.
