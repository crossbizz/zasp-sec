# M0-10 Cartography Delivery Waiver Design

**Date:** August 14, 2026  
**Decision owner:** Product owner, delegated to the implementation agent  
**Status:** Approved for execution by the instruction to decide, fix, and proceed

## Decision

M0-09 and PROV-01 remain Blocked, and R-03 remains incomplete. Their failure
is a real-AWS authorization-parity risk, not a dependency of the fixture-only
Cartography normalization proof. The existing waiver is replaced with a
delivery-first waiver that permits M0-10 to start while preserving those
blocked security gates.

M0-10 may prove only the Cartography adapter, graph extraction, Organization
scoping, collision resistance, label normalization, and disposable cleanup.
It may not claim cross-account IAM, AWS authorization, GitHub authorization,
or production-provider parity.

## Alternatives considered

1. **Proceed with an isolated fixture proof (selected).** Run exact-pinned
   Cartography and Neo4j against deterministic AWS and GitHub fixtures, then
   normalize the inspected graph through a product-owned adapter. This keeps
   delivery moving and preserves the blocked parity evidence.
2. **Patch or fork LocalStack.** This could emulate SourceIdentity locally, but
   it would prove our patch rather than LocalStack or AWS behavior and would
   weaken the release gate.
3. **Wait for real AWS credentials or a future emulator release.** This keeps
   the original dependency chain pure but stops unrelated OSS proof work and
   the application roadmap.

## Proof architecture

### Immutable runtime

- Cartography `0.139.1` at multi-platform digest
  `sha256:f1d7c1f46a8a2137b9a955327d3cd47e8340c7d537d0447467d2e952af8bb8f0`.
- Neo4j Community `5.26` at multi-platform digest
  `sha256:d9dd3dc7d1c78fa959191ff02dbdcbefadceaf83eee23428fb92a58cac8ad3fe`.
- Disposable Docker network, two Neo4j containers, temporary fixture files,
  and random loopback-only published ports.
- No ambient AWS, GitHub, Neo4j, proxy, or credential configuration.

### Fixtures

Two fixture bundles represent Product Organizations A and B. Each bundle
contains a minimal AWS account/role relationship and a minimal GitHub
organization/repository relationship. The bundles deliberately reuse raw
provider identifiers where the provider grammar permits it, so product
normalization must scope identity by Organization rather than trusting a
globally unique upstream label.

Each bundle is loaded through Cartography `0.139.1` model and graph-loading
interfaces into its own disposable Neo4j container. The proof inspects each
result through bounded Neo4j queries and exports only the exact allowlisted
node and relationship fields required by the product adapter.

### Product normalization

The adapter receives a validated Product Organization ID plus typed
Cartography graph records. It produces canonical product records with:

- a canonical ID derived from Organization, provider, source kind, and source
  ID;
- an exact source ID retained as evidence;
- allowlisted product kinds such as `cloud_account`, `identity_role`,
  `code_organization`, and `code_repository`;
- canonical relationships whose endpoints belong to the same Organization;
- no Cartography, Neo4j, AWS-label, or GitHub-label vocabulary in
  customer-visible labels or relationship names.

The merger rejects missing Organization scope, unknown labels/properties,
duplicate canonical IDs, cross-Organization edges, dangling endpoints,
unexpected graph cardinality, and ambiguous or malformed fixture output.

## Data flow

1. Preflight proves no owned proof containers, networks, volumes, or temporary
   directories already exist.
2. The orchestrator creates an exact-name disposable network and starts two
   exact-pinned Neo4j targets on independent random loopback ports.
3. Fixture A runs through one exact-pinned Cartography container and its graph
   is inspected and normalized for Organization A.
4. Fixture B runs through a second exact-pinned Cartography container against
   the other graph and is normalized for Organization B.
5. The product merger combines both normalized outputs and proves exact
   cardinality, relationship integrity, overlapping-source-ID separation, and
   absence of customer-visible OSS labels.
6. Cleanup removes only re-proven owned resources and proves exact absence.

## Failure and safety behavior

- Mutations are single-attempt unless the provider operation is demonstrably
  read-only.
- Ambiguous container or graph mutations reconcile exact name, image, labels,
  marker, network, and graph ownership before cleanup authority is retained.
- Every response and process has byte and absolute-time bounds.
- Cleanup uses an independent bounded context, continues across owned targets,
  and overrides a main failure when cleanup cannot be proven.
- Output is one fixed success or failure line and never includes source IDs,
  provider labels, ports, container IDs, graph contents, or credentials.
- The proof never contacts AWS or GitHub.

## Verification

Completion requires:

- genuine RED/GREEN coverage for normalization, collision, cross-scope edge,
  unknown-label/property, duplicate, malformed graph, timeout, panic,
  ambiguous mutation, cleanup precedence, and fixed-output cases;
- a live disposable run using both exact image digests;
- Organization A and B each returning only their own required nodes and
  relationships after normalization;
- deliberately overlapping raw source IDs producing distinct canonical IDs;
- zero customer-visible Cartography/Neo4j/AWS/GitHub labels;
- exact graph/container/network/volume/temp absence after cleanup;
- repository tests, type-check, lint, build, dependency audit, secret scan, and
  an independent zero-finding review.

## Status and release boundary

Starting M0-10 changes the 728-task counts to Pending 718, In progress 1,
Complete 8, Blocked 1. M0-09 stays Blocked and R-03 stays incomplete.

M0-10 completion does not change the M0-09/PROV-01 evidence. Real-AWS
authorization parity remains a required later release gate and must be closed
before any milestone that explicitly depends on that parity can complete.
