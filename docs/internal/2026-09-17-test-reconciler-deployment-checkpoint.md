# Reconciler deployment candidate

Component-only, disabled by default, unshipped. Original728 status counts do not
change. This is a chart candidate, not proof of a deployed service or IAM access.

## Implemented and tested

`deploy/staging/product/templates/test-reconciler.yaml` renders an explicit
control-plane/schema55 worker with a digest-pinned image, dedicated IRSA service
account, PostgreSQL CSI secret and projected STS token. No planner/target secret
is mounted. Its environment matches the dedicated Go runtime: batch1, lease60s,
poll1s, shutdown20s, explicit account/region/evidence bucket/KMS/role bindings.
It has two replicas, rolling updates, spread constraints, PDB, bounded HPA,
nonroot/read-only filesystem, and startup/readiness/liveness probes.

The network candidate admits only configured PostgreSQL5432 and STS/S3/KMS443
endpoint snapshots, plus kube-dns TCP/UDP53. Snapshots must be bounded canonical
IPv4 ranges and cannot be empty, overlapping, local, metadata or multicast.
Ingress is closed. Defaults in values.yaml leave the worker disabled.

Real Helm acceptance RED83b8ea preceded the template. Initial GREENe586cf
passed3 cases, including32 malformed range cases. Independent review found an
Important interaction: the shared DNS policy also selected the new pod and
granted DNS-port access to all kube-system pods. A composed test using the real
shared chart reproduced two grants (REDe912d0). The shared policy now excludes
only zasp-test-reconciler; its dedicated kube-dns rule remains. Focused Helm
GREEN698dc0 passed4 cases,2.150s.

Full release regression f58979 then exposed10 failures in the audit-export
validator's exact old DNS-selector contract. Inspection traced the failure to
that selector comparison. Its exact contract now includes the reconciler-only
exclusion, with tamper tests rejecting a removed exclusion or an exclusion of
the audit worker. This preserves the existing audit workers' DNS access.

Final `npm run production:release:test`, Node22.23.1, exit0 b3d6e1:
208 tests passed,0 failed/skipped,25.037s. The new Helm tests are included in this
grouped release test command. This is release regression, not release clearance.
Independent follow-up reviewed the composed selector and audit-validator fix:
no remaining Critical/Important findings in that delta. It did not run tests or
clear schema55 activation, IAM or live deployment gates.

## Open gates

- Terraform IAM generation is now implemented and mock-tested in the
  [IAM continuation](2026-09-17-test-reconciler-iam-checkpoint.md). Applying it,
  binding its output into rollout and verifying effective live permissions remain open.
- Full schema55 chart/release normalization and migration activation. The shared
  policy test renders a supported historical chart plus the isolated candidate;
  it does not claim a complete schema55 deployment render.
- Private operational monitoring/alerts, provider endpoint snapshot ownership
  and refresh, authenticated cloud readiness, cluster rollout and live canary.
- Registered multi-tenant runtime/process restart/reclaim acceptance and load.
- Fresh advisory evidence and all other existing shipping gates before push.

IAM follow-up must account for version-specific S3 reads and SSE-KMS checksum
requirements. Consult the official [HeadObject permissions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html)
and bucket-key encryption context when writing/testing that policy; neither
documentation nor mocked policy evaluation proves effective live permissions.

No cloud mutation, commit, push, or production-status promotion in this batch.
