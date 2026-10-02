# Linux production compilation input inventory

Read-only inventory for candidate preparation, not a staging allowlist or release proof.

Base main: `8733b16f8d939d38a8157dd2519e57fc6f630542`.
Recovery HEAD: `ecc047ee2e90c36ec702ade129a2b08eae0a7a1a`, with inherited uncommitted work.

An offline `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go list -deps` for
`./agentsec-migrate ./agentsec-api ./agentsec-worker ./red-team-adapter` resolved
51 local packages. Their selected Go sources and embedded files, plus go.mod and
go.sum, total 543 paths. Git blob comparison against main finds 150 new/modified
paths and 393 unchanged paths. Both module files are unchanged. This inventory
includes transitive compilation inputs, not tests, UI, deployment or all runtime
assets. Compilation dependency does not prove that each changed hunk is required.

Initial suspicious cross-feature deltas inspected directly: connector_aws adds
an audit-read identity; discovery_cloud adds the test-reconciler session;
discovery_repository preserves the budget-required error; precise ingest adds
budget release readiness; bucketlayout adds scoped export key construction.
These connect to the 52 audit-export / 53 budget / 55 execution chain. They are
not automatically approved by the operator-only review.

Use the TSV alongside this note to choose and review a dependency-complete
candidate. Blob IDs identify exact observed content, not a security signature.
Recompute before copying or testing a shipping candidate. No file was staged.
The initial inventory made no source copies. The subsequent isolated transfer
and its exact build result are in the schema55 candidate assembly checkpoint.
No commit or push occurred.

The earlier empty graph used an incorrect module-path filter; it was discarded.
The retained graph uses the observed module path
`github.com/zasp-ai/zasp-sec/services/platform` and Linux build selection.
