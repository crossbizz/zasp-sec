# Release advisory evidence

Release Engineering supplies the exact candidate that will be promoted. AppSec approves public advisory sources and signing authorities. The scanner matches the candidate on an isolated runner. A release decision covers one Git commit, production lock, deployment render, platform set and build inventory.

## Prepare the public mirror

Provision four distinct Ed25519 public keys in the protected release environment. The build, advisory intake, scanner and exception authorities each retain their own signing key. Set the PEM-encoded public keys in `ZASP_RELEASE_BUILD_PUBLIC_KEY`, `ZASP_RELEASE_INTAKE_PUBLIC_KEY`, `ZASP_RELEASE_SCANNER_PUBLIC_KEY` and `ZASP_RELEASE_APPSEC_PUBLIC_KEY`. Each detached signature is standard base64 over the Ed25519 signature of the exact JSON file bytes, stored beside the file with a `.sig` suffix. Newlines are part of the signed JSON. Generate production signatures through the organization's approved signer.

Enable `ZASP_PUBLIC_ADVISORY_SYNC_ENABLED=true` on the default branch to schedule the public refresh every eight hours. The job reads the official npm advisory Git ref, Go database index and Anchore v6 listing. It retains the unmodified publisher responses as an unsigned, content-addressed refresh receipt. A failed publisher request fails the refresh. The same job can run on an organization-owned schedule with `node scripts/release-security/refresh.mjs /public/observations`. Only the public refresh artifact is suitable for public CI storage.

On a public-only intake system, authenticate the official source and current revision of each feed, verify the manufacturer’s release checksum or other approved origin proof, and retain the original source metadata. Pin SHA-256 hashes and versions for the Go, govulncheck, Syft and Grype executables. In `intake.json` (`zasp.release.intake.v1`), record `observedAt`, `refreshSha256`, `sources` and `tools`. Copy the approved public receipt unchanged to `refresh.json` in the evidence bundle. All three source refresh times and versions must match this receipt. For Grype set the version to the listed archive filename without `.tar.zst`, and include its official transfer URL, exact byte length and publisher checksum. For Go use its index’s `modified` timestamp. Every source includes `id`, `origin`, `version`, `sha256` and `refreshedAt`. Every tool includes `id`, `version` and `sha256`. Use UTC timestamps and lowercase hexadecimal digests. The intake approval and each successful upstream refresh must be at most 24 hours old at scan and promotion time.

| Source | Authenticated revision and local identity |
| --- | --- |
| `npm` | Use the exact public GitHub Advisory Database commit. Set `sha256` to the full corpus roster SHA-256 and `npmManifestSha256` to the npm record roster digest used by the existing exact-lock collector. It checks the full committed blob roster during the scan. [Corpus matcher](../../scripts/npm-public-corpus.mjs) |
| `go` | Use the official Go vulnerability database snapshot. Set `sha256` to the digest of the local expanded database tree, including the OSV records and indexes. [Go database documentation](https://go.dev/doc/security/vuln/database) |
| `grype` | Use Anchore's Grype v6 database listing and verify the archive checksum. Set `sha256` to the digest of the imported Grype cache tree with the exact pinned Grype build. [Grype database distribution](https://oss.anchore.com/docs/architecture/grype-db/) |

The exact origins and tree digest algorithm are in [the intake implementation](../../scripts/release-security/intake.mjs). To acquire the public archives, include a `transfer` object on each source with the official HTTPS `url`, approved transport `sha256` and exact `bytes`. The downloader rejects redirects, credentials, unknown origins, overlarge responses and digest changes. Run these commands on the intake system. It receives no release inventories.

```sh
node scripts/release-security/intake.mjs mirror /approved/intake.json /mirror/archives
node scripts/release-security/intake.mjs checkout-npm /approved/intake.json /mirror/checkout
```

Import the verified Go archive and Grype database with the pinned toolchain into read-only staging directories. Transfer the approved local copies and receipt to the isolated scanning environment. If a refresh fails, keep its previous successful timestamp. Once it expires the release stays pending.

## Build and scan one candidate

Build from a clean candidate commit. Save the exact rendered deployment as `rendered.yaml`. Keep a production-only, platform-specific npm install, each Go executable's bytes and offline module cache, and each OCI image layout. Protect staging inputs against writes during the scan. Disable external networking on the scan runner. The scan does not need signing keys or registry credentials.

The build signer attests `candidate.json` with format `zasp.release.candidate.v1` and the following fields.

| Field | Build evidence |
| --- | --- |
| `commit`, `lockSha256`, `renderedSha256` | Exact checkout, raw production lockfile bytes and raw rendered YAML bytes. |
| `deploymentTarget` | The AWS installer requires `profile: "aws"` and the exact `release`, `namespace` and Kubernetes `context`. Sign each Environment’s render and each rollout phase, including bootstrap with identity verification enabled. |
| `deploymentPlatforms`, `productImages` | Linux platforms in `os/arch` form and a mapping from the nine production Dockerfile names, without the suffix, to full `repository@sha256:digest` references. Include the on-demand Attack Lab runner. |
| `images` | One record per rendered or product image and platform with `ref` (repository), `platform` and `digest` (platform manifest). Add `deploymentDigest` when the render references an OCI index. Retain the index and child manifests in the layout. |
| `binaries` | Every shipped Go executable's `name`, module `root`, `platform` and `sha256`. The verifier checks the hosted Go outputs named in the Dockerfiles, native zaspctl for Linux/macOS/Windows and the two endpoint programs. Include additional distributed Go binaries in the signed roster. |
| `npmInstalls` | One record per platform with `platform`, `libc` (`glibc` or `musl`) and `inventorySha256` computed over the installed package roster. [Inventory format](../../scripts/release-security/scan-npm.mjs) |

The private scanner configuration contains absolute paths: `repoRoot`, `rendered`, `goModCache`; `sources` keyed by npm/go/grype; `tools` keyed by go/govulncheck/syft/grype; `npmInstalls` entries with root/platform/libc; and `binaries` and `images` mapping subject IDs to executable and OCI layout paths. Binary IDs are `go:NAME@OS/ARCH`; image IDs are `image:REPOSITORY@sha256:DIGEST#OS/ARCH`. The destination must be a new directory.

```sh
node scripts/release-security/scan.mjs /approved/candidate.json /approved/intake.json /private/scanner-config.json /private/new-scan
```

Keep the raw npm, Go and image evidence from the scanner. Review `report.json` and sign it as `scan.json` through the independent scanner authority. Stage all three signed documents with their signatures, `rendered.yaml` and the referenced evidence files in one read-only directory. Retain provenance and image signatures according to the deployment release process.

## Promote and adjudicate

The protected `production-promotion` job accepts only the default release branch. Provision its isolated runner label `zasp-release` with the repository’s release prerequisites, offline npm and Go caches, and evidence at `/var/lib/zasp/release-evidence/<git-sha>`. Configure deployment branch restrictions and required reviewers on the environment, and require this job’s success in the release controller before deployment. The job has read-only repository permissions. A failed or skipped UI acceptance check cannot authorize promotion.

The gate reports every active high, critical or unknown severity to AppSec. When an exception is justified, AppSec signs `exceptions.json` with format `zasp.release.exceptions.v1`, the exact `candidateSha256` and an `exceptions` array. Each entry names `subject`, `advisory`, `ecosystem`, `package`, `version`, `severity`, `owner`, `reason`, `approvedAt` and `expiresAt`. An exception expires at the stated instant. Withdrawn reports remain in evidence. Missing subject scans, stale snapshots and unsigned evidence require a new complete scan.

For a staging rehearsal, point `ZASP_RELEASE_EVIDENCE_DIR` at the absolute private evidence directory and run `npm run production:release:gate` from the clean checkout. A successful run prints a release receipt with its commit and immutable evidence digests. Configuration of production signers, mirrors, published candidate images and release-controller enforcement belongs to the deploying organization.


## AWS installer admission

`./zasp --profile aws install images` uploads commit-tagged build candidates to ECR for scanning. This build step does not run a workload. Restrict direct cluster writes and registry tag replacement to the designated release administrators.

`install release`, `up`, `start` and `upgrade` verify the signed evidence again before applying a release. The installer stages chart bytes from the attested Git commit and private copies of the supplied values, compares the local render with the signed bytes, then compares a Helm server dry run with all approved objects including hooks. A Helm post-renderer checks the ordinary resources a second time during the live upgrade. The bootstrap step verifies the registration-phase render and exact API image before starting the container that receives operator credentials. A changed value or hook requires a newly signed render. Secret values in a rendered bundle must remain private.

Produce `rendered.yaml` with `helm --kube-context CONTEXT -n NAMESPACE template RELEASE deploy/staging/product -f values-terraform.json -f values-images.yaml -f operator-values.yaml` using the same Helm version, effective values and `--set` options the installer will receive. A preview through `./zasp --dry-run` prints the planned commands. The local and single-pod Kubernetes evaluation profiles do not use this production gate.

## Continuous deployment to private k3s

To verify a batch of CD fixes before merging, include `[verify-production-cd]` in the last commit message you push to the pull request branch. GitHub runs the production acceptance suite on hosted runners for that commit with read-only repository access. [Pre-merge acceptance workflow](../../.github/workflows/production-acceptance-pr.yml)

Each merge to `crossbizz/zasp-sec` main starts the production workflow. Its hosted enrollment step sets `ZASP_PRODUCTION_CD_ENABLED=true` for that step and reports the candidate commit in the Actions summary. The protected deployment job upgrades the `agentsec` Helm release in the `zasp` namespace. It waits for the main push checks and full acceptance suite at the candidate commit, then runs the existing protected production promotion. The upgrade job rechecks the signed evidence, the branch head and the identity of the target cluster. It serializes upgrades and waits for the workloads and migration jobs. Helm can roll back a failed release. Database recovery follows the migration runbook. [Production CD workflow](../../.github/workflows/production-cd.yml)

### Enroll the installation

1. Protect `main`, the `production-promotion` and `production` GitHub environments, and changes to workflows, deploy scripts and charts. Limit each environment to `main` and configure the reviewers your release process requires. Restrict the private runner group `zasp-production` to this repository and the workflow `.github/workflows/production-cd.yml@refs/heads/main`. Use dedicated, ephemeral Linux runners with the label `zasp-production-deploy`, Helm 3, kubectl, Git, tar, Node 22 and a prewarmed locked npm cache. The private promotion runner retains its existing independent `zasp-release` assignment. Run pull request jobs on separate runners.
2. An installer verifies the cluster's UID and applies the product namespace Role, the binding for the `zasp-cd` ServiceAccount the read-only cluster identity permission and the runner-specific admission policy (Kubernetes 1.30 or later). Give the deploy runner a private kubeconfig at `/var/run/zasp-production-cd/kubeconfig` for that account, using short-lived credentials. Its namespace Role includes reads of Helm revision Secrets to inspect both releases. The admission policy confines Secret writes to `agentsec` revision records and denies changes to objects owned by the evaluation release. Keep runner access restricted accordingly. Its only cluster-scoped grant reads the `zasp` and `kube-system` Namespace objects. [CD identity and RBAC](../../deploy/vps/production/cd-rbac.yaml)
3. Set protected `production` environment secrets `ZASP_VPS_KUBE_CONTEXT`, `ZASP_VPS_CLUSTER_UID` and `ZASP_VPS_INSTALLATION_ID` from the verified installation inventory. The application namespace must have the matching `zasp.io/installation` label. Configure these Actions variables in both protected environments: `ZASP_RELEASE_BUILD_PUBLIC_KEY`, `ZASP_RELEASE_INTAKE_PUBLIC_KEY`, `ZASP_RELEASE_SCANNER_PUBLIC_KEY` and `ZASP_RELEASE_APPSEC_PUBLIC_KEY`. Each is the PEM-encoded public key for its existing, independent Ed25519 authority. Signing private keys stay with those authorities. The workflow uses its automatic read-only GitHub token for source and check reads. Deliver the signed evidence to each runner at `/var/lib/zasp/release-evidence/<commit>`.
4. Build the nine product images from the exact commit, publish them to the cluster's registry and retain their immutable digests. The independent private build, intake, scan and AppSec authorities provide the signed evidence described above. Image publishing, signers, current advisory data and protected runner provisioning are deployment prerequisites.
5. Perform the first installation using `./zasp --profile vps install application` from the signed checkout and the approved operator configuration. The underlying command `node scripts/release-security/deploy.mjs install-vps-production` requires an unused Helm release name in the preprovisioned application namespace. It enforces the same signed image, render and cluster identity checks as the upgrade. The ongoing CD job requires an installed product release and reports a skipped upgrade if it is absent. The workflow supplies the enrollment flag itself. A push to the upstream `main` or a manual dispatch on that branch starts the pipeline.

### Build the private evidence bundle

The signed `candidate.json.deploymentTarget` uses `profile: vps-production`, `release: agentsec`, `namespace: zasp` and the verified `context`, `clusterUID` and `installationID`. Keep actual installation identifiers and network addresses in private evidence. Put the site's merged infrastructure and operator settings in `production-values.yaml` beside `candidate.json`. Use references for runtime credentials.

Generate the final image values from the build inventory as shown below. Supply the private render from this exact chart, values order, Helm version and source commit to the signer. The deployment wrapper independently reconstructs these values from the verified candidate.

```sh
jq '{global: {releaseCommit: .commit, productImages: (.productImages | {
  web, agentsecApi: .api, agentsecWorker: .worker,
  attackLabRunner: .["attack-lab-runner"], redTeamWorker: .["redteam-worker"],
  eventIngest: .["event-ingest"], gatewayControl: .["gateway-control"],
  runtimeGateway: .["runtime-gateway"], sensorAgent: .["sensor-agent"]
})}}' private-build-inventory.json > candidate-images.json

helm --kube-context "$ZASP_VPS_KUBE_CONTEXT" -n zasp template agentsec deploy/staging/product \
  -f "$ZASP_RELEASE_EVIDENCE_DIR/production-values.yaml" -f deploy/vps/production/values.yaml \
  -f candidate-images.json > "$ZASP_RELEASE_EVIDENCE_DIR/rendered.yaml"
```

The installer verifies the cluster UID against the live `kube-system` object and verifies the owner label on `zasp` immediately before applying. CD also verifies the calling ServiceAccount, checks that a recorded previous release commit is an ancestor of the new commit, and examines the previous manifest and hooks for resources that Helm could delete. The installer also checks the stored manifests and hooks of the co-located evaluation release named `zasp` for object collisions, overlapping pod selectors and intersecting ingress hosts, paths or rewrites. The scoped release excludes the independent connector and search workloads. Readiness or admission failures stop the deployment and appear in the protected job log. [Signed Helm entry point](../../scripts/release-security/deploy.mjs)
