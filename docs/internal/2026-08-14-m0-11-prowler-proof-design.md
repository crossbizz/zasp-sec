# M0-11 Prowler Evidence Proof Design

**Date:** August 14, 2026

**Decision owner:** Product owner, delegated to the implementation agent

**Status:** Approved for execution by the instruction to decide, fix, and proceed

## Decision

M0-11 will execute one real, built-in Prowler AWS check against one disposable
synthetic IAM role in an exact-pinned LocalStack target. A product-owned adapter
will strictly parse the resulting JSON-OCSF finding and normalize it to the
same Organization-scoped resource identity proved by M0-10.

The proof is fixture-only. It proves the Prowler check, OCSF output boundary,
canonical resource linkage, normalized evidence, and exact cleanup. It does
not prove real-AWS authorization, broad Prowler coverage, LocalStack parity,
or the blocked M0-09/PROV-01 SourceIdentity behavior. M0-09 and PROV-01 remain
Blocked, and R-03 remains incomplete.

## Immutable runtime

- Prowler `5.39.0`, released August 13, 2026, at multi-platform image:
  `prowlercloud/prowler:5.39.0@sha256:58c8a0eb0c947517bd89b6214cde0cc1d5f59df4eebbb99a87475ab741914959`.
- Linux arm64 descriptor:
  `sha256:cb6b5d566130c0fe119fbb1891c167adb2490bf2849252dfbd557d71fb227b8b`.
- Linux amd64 descriptor:
  `sha256:64ff238bfaa6da041960dfeb55883dc966d650b527c12864895731e94af807b6`.
- The image runs as its non-root `prowler` user. Ownership verification binds
  the exact resolved image ID, image metadata, container name, run marker,
  network, environment, mounts, entrypoint, command, and security settings.
- LocalStack uses an existing repository-pinned disposable image version or a
  newly exact-pinned version justified in the task brief. It is never the
  shared development target.

## Fixture and check

The fixture creates exactly one IAM role in the synthetic account
`000000000000`:

```text
arn:aws:iam::000000000000:role/shared-fixture-role
```

Its trust policy permits `lambda.amazonaws.com` to call `sts:AssumeRole` but
omits `aws:SourceArn` and `aws:SourceAccount`. Prowler runs only the built-in
check `iam_role_cross_service_confused_deputy_prevention`, filters to `FAIL`,
and writes only JSON-OCSF. Expected Prowler exit code `3` is retained as proof
that a failed check occurred; the outer proof succeeds only after strict
artifact validation and cleanup.

All AWS traffic is confined to a private disposable Docker network and the
disposable LocalStack target. The scanner receives only fixed synthetic
credentials and endpoint values. It does not load `.env`, AWS profiles,
credential files, IMDS, host proxies, or host Docker authentication.

## Product adapter boundary

The parser accepts exactly one bounded, regular, non-symlink JSON-OCSF artifact
with valid UTF-8, no duplicate keys, no trailing JSON, bounded nesting and
string sizes, and the exact allowlisted schema. It requires:

- OCSF `metadata.version` `1.5.0` and Prowler product version `5.39.0`;
- the exact check ID and one `FAIL` / `High` result;
- Detection Finding class/type identifiers `2004` / `200401`;
- AWS account `000000000000`, region `us-east-1`, and one IAM role resource;
- exact ARN, name, type, service grouping, partition, and region;
- one service-principal allow statement for `lambda.amazonaws.com` and
  `sts:AssumeRole` with no source-scoping condition.

Upstream prose, remediation text, UUIDs, scan timestamps, arbitrary tags, and
Prowler-native labels are not trusted or forwarded.

## Normalized product record

Trusted Organization scope is supplied by the proof job, never by upstream
tenant fields. The canonical resource ID is derived from:

```text
[organization_id, "aws", "identity_role", source_arn]
```

using the same SHA-256 grammar as M0-10. For Organization A the exact ID is:

```text
org_aaaaaaaaaaaaaaaa:aws:identity_role:81eeba69c5c0887f4083a0e195a431b852d750fd3ee41ad276c1142285d1b77b
```

The product-owned normalized result contains:

- one resource with Organization, provider `aws`, kind `identity_role`, and
  exact source ARN;
- one finding with category `privileged_identity`, rule code
  `cloud_identity_role_confused_deputy`, severity `high`, status `open`, and
  the canonical resource ID;
- one exact-confidence `cloud_posture_check` evidence record linked to the
  same Organization and resource, containing only the account, region,
  service principal, and `source_scope_present=false` fact.

Evidence identity is deterministic from Organization, canonical resource ID,
rule code, outcome, and the proof's fixed observation instant. Customer-facing
fields contain no Prowler, OCSF, Docker, LocalStack, or provider-native label.

## Lifecycle and cleanup

1. Prove no proof-owned container, network, output, or temporary-directory
   prefix exists.
2. Create an exact-name disposable internal Docker network and LocalStack
   target, then prove ownership and readiness.
3. Create the exact IAM role and re-fetch its immutable identity, trust policy,
   tags, and account namespace.
4. Start the exact Prowler container with network confinement, read-only root,
   dropped capabilities, no-new-privileges, PID/resource limits, bounded
   output, and one exact output mount.
5. Require exact scanner exit `3`; validate and normalize exactly one artifact.
6. Re-prove each owned resource, delete in dependency order, and prove exact
   full-ID/name/prefix/marker/output/temp absence.

Mutations are single-attempt. Ambiguous outcomes use bounded exact
reconciliation. Cleanup uses an independent timeout, continues across owned
targets, and wins error precedence. Process output is capped and converted to
one fixed success or failure line with no identifiers or provider payloads.

## Verification and release boundary

Completion requires genuine RED/GREEN coverage for schema, canonical identity,
Organization separation, evidence linkage, runtime ownership, network
confinement, ambiguity, timeout, overflow, panic, cleanup precedence, and fixed
output. It also requires an exact live disposable run, zero-resource audit,
repository verification, dependency/license audit, redacted secret scan, and
an independent review with zero Critical, Important, or Minor findings.

M0-11 start changes the 728-task counts to Pending `717`, In progress `1`,
Complete `9`, Blocked `1`; M0 becomes `16/1/9/1`. Completion changes them to
`717/0/10/1` and M0 to `16/0/10/1`. M0-09/PROV-01 remain Blocked and R-03
remains incomplete. Successful reviewed live evidence also closes risk gate
R-06 only; historical risk-gate reconciliation remains separate work.
