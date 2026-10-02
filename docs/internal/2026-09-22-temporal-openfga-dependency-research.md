# Temporal/OpenFGA dependency research

Date: 2026-09-22. P1 preparation only. No installed runtime, security approval, integration compatibility, or production availability is claimed.

Official GitHub release APIs and tagged source were queried directly. Candidate versions must still pass dependency advisory/license checks, image digest resolution, manifest rendering, and application connection smoke tests before pinning is complete.

| Component | Candidate | Source and observation |
| --- | --- | --- |
| Temporal server | 1.32.0 | https://github.com/temporalio/temporal/releases/tag/v1.32.0 |
| Temporal Helm chart | 1.7.0 | https://github.com/temporalio/helm-charts/releases/tag/temporal-1.7.0 ; tagged Chart.yaml has appVersion 1.32.0 |
| Temporal Go SDK | 1.48.0 | https://github.com/temporalio/sdk-go/blob/v1.48.0/go.mod ; requires Go 1.25.4 and API 1.63.4 |
| Temporal API | 1.63.4 | Required by the selected SDK's tagged module; resolve the actual module graph before installation |
| Temporal CLI | 1.9.1 | https://github.com/temporalio/cli/releases/tag/v1.9.1 |
| OpenFGA server | 1.21.0 | https://github.com/openfga/openfga/releases/tag/v1.21.0 |
| OpenFGA Helm chart | 0.3.15 | https://github.com/openfga/helm-charts/releases/tag/openfga-0.3.15 ; tagged Chart.yaml has appVersion v1.21.0 |
| OpenFGA Go SDK | 0.8.2 | https://github.com/openfga/go-sdk/blob/v0.8.2/go.mod ; Go 1.25.0 with toolchain go1.25.4 |
| OpenFGA CLI | 0.8.0 | https://github.com/openfga/cli/releases/tag/v0.8.0 |

The newest Temporal SDK release, 1.49.0, requires Go 1.26.0. The approved plan specifies the existing Go 1.25 platform. Use the compatible 1.48.0 candidate while verifying its supported server contracts; a platform-wide toolchain upgrade is unnecessary for the required workflows and schedules. The local toolchain reports go1.25.6 darwin/arm64. The platform module currently declares go 1.25.0, so SDK adoption requires an explicit minimum patch-version adjustment to at least 1.25.4.

Docker daemon inspection succeeded (29.4.0); Helm and Go executables are available. This proves tooling availability only. No service was started by this preparation.

Registry manifests resolved using `docker buildx imagetools inspect` on 2026-09-22:

- `temporalio/server:1.32.0@sha256:c3e752127759616bb1615e0f9ba0e21635aeb5fdeb922de4f371c350955f46ae`, OCI index with linux/amd64 and linux/arm64 images.
- `openfga/openfga:v1.21.0@sha256:2113c664a486b5da8d7a2cdab479e0d4e30639c80fd2c000540f645c1dbc1e55`, image index with linux/amd64 and linux/arm64 images.

Digest resolution proves artifact identity, not advisory clearance or runtime acceptance. Migration tooling, PostgreSQL and CLI images still need their own pins where used.

OpenFGA chart 0.3.15 includes optional PostgreSQL 12.12.10 and MySQL 9.6.0 charts plus the common 2.13.3 library. Configure dedicated external PostgreSQL databases/roles as the design requires; inspect rendering and inherited templates before using the chart. No datastore credentials have been read or written.

Remaining P1 work: pin verified image digests and dependency graph; inspect exact tagged service/TLS/auth configuration; create local and staging manifests with separate persistence/visibility/FGA databases; wire consuming API/worker configuration; run application configuration checks and one real connection smoke for each dependency. Store/model provisioning and production identity/provider gates remain separate acceptance work.
