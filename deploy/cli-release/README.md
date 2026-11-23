# Distribute a signed zaspctl release

The console's **Scan this device** panel offers binaries when the deployment includes an explicitly staged, signed release. The repository ships an empty download configuration. Its source build works until the release owner activates a verified bundle.

## Stage all four console downloads

Run **Sign and stage native zaspctl downloads** from the default branch with a version such as `v1.2.3`. The workflow builds the exact commit on native Linux amd64, macOS arm64, macOS amd64 and Windows amd64 runners. It signs and notarizes both Mac builds and verifies the Windows signature and timestamp before sealing the four-file manifest. [Signing workflow](../../.github/workflows/zaspctl-release-sign.yml)

Configure the `zasp-cli-signing` GitHub environment and its protected runners. On macOS, set `ZASP_APPLE_SIGN_IDENTITY`, `ZASP_APPLE_TEAM_ID` and `ZASP_NOTARY_PROFILE` to the approved identity, team ID and preprovisioned Keychain profile. On Windows, set `ZASP_WINDOWS_SIGN_THUMBPRINT` and `ZASP_WINDOWS_TIMESTAMP_HTTPS_URL` and provision the matching certificate in the signing account’s store. On the Linux release runner, set `ZASP_CLI_RELEASE_PRIVATE_KEY_FILE` and `ZASP_CLI_RELEASE_PUBLIC_KEY_FILE` to the release key paths. Keep private key material on its designated runner.

Download `staged-zaspctl-console-<commit>` from that run. The artifact contains the immutable files under `public/downloads/zaspctl` and their console pin at `app/features/tools/cli-release-pin.json`. Include both in the same console deployment. The protected pilot verifier checks the staged artifact and its independently trusted key. [Pilot evidence](../../docs/operations/pilot-verification-evidence.md)

## Prepare native candidates

Choose the reviewed commit and version. Run the manual **Prepare native zaspctl release candidates** workflow on the corresponding protected ref. It tests the CLI on each native runner, builds the checked-out commit, and stores candidates for ten days as GitHub Actions artifacts. Its token has read-only repository permissions. Download artifacts from the trusted run and extract the approved files into a private directory without renaming them. [Workflow](../../.github/workflows/zaspctl-candidates.yml)

| Candidate filename | Native build |
| --- | --- |
| `zaspctl-linux-amd64` | Linux x64 |
| `zaspctl-darwin-amd64` | macOS Intel with cgo and Keychain support |
| `zaspctl-darwin-arm64` | macOS Apple silicon with cgo and Keychain support |
| `zaspctl-windows-amd64.exe` | Windows x64 |

A release can contain a subset of these platforms. For a manual native build, use Go 1.26 on a clean checkout and place the output **outside** that checkout.

```sh
go test -C cmd/zaspctl -mod=readonly ./...
go build -C cmd/zaspctl -mod=readonly -trimpath -buildvcs=true -o "$ABSOLUTE_CANDIDATE_PATH" .
```

Complete applicable platform signing on those native runners **before** computing the release signature. For macOS distribution, use the approved Developer ID and notarization workflow. For managed Windows distribution, sign the executable with the approved Authenticode certificate and validate it on the recipient policy. The detached release signature binds the distributed bytes to the commit recorded by the release owner. The trusted build run establishes where the candidate came from. Native Gatekeeper and Intune trust each require their own successful probe. Publish only the platforms whose release owner approved those checks.

## Sign and verify

Use Node 22 and Go 1.26 on a protected Unix signing host. Supply the independently reviewed full Git commit and version, for example `v1.0.0`. Supply an owner-only Ed25519 PKCS8 private key dedicated to CLI distribution. Keep its public key in the enterprise's trusted release channel. The signing command reads the Go metadata from each final platform binary, checks the package, architecture, commit and clean worktree flag, and signs a manifest of file names, byte counts and SHA-256 values. It creates a new directory.

```sh
node deploy/cli-release/release.mjs seal "$VERSION" "$COMMIT" "$PRIVATE_RELEASE_KEY" "$CANDIDATES" "$NEW_BUNDLE"
node deploy/cli-release/release.mjs verify "$VERSION" "$COMMIT" "$TRUSTED_PUBLIC_KEY" "$NEW_BUNDLE"
```

Do not ship the private key or establish trust by downloading a replacement verification key alongside a bundle. Give the consumer the trusted public key through the release administrator's independent channel. The byte-level checks and signature are repeatable using the open-source tools shown in the console.

## Stage, publish or reverse

Run the staging command before building the console in the deployment checkout. Verification occurs before copying and again on the staged bytes. Files go under a versioned, same-origin path. The command updates the console pin after the immutable files verify. Reusing a version for different bytes fails.

```sh
node deploy/cli-release/release.mjs stage "$VERSION" "$COMMIT" "$TRUSTED_PUBLIC_KEY" "$NEW_BUNDLE" "$WEB_CHECKOUT"
```

Deploy the built console and matching static assets through the existing release process. In **Scan this device**, check that every offered platform is present, its URL starts with `/downloads/zaspctl/<version>/`, the displayed manifest hash matches the signed manifest and an independently downloaded binary matches its checksum. The release script performs local operations only.

To roll back, rerun `stage` with a retained, previously approved version, its exact commit, trusted key and verified bundle, then rebuild and deploy the console. To return to source-build guidance, run `node deploy/cli-release/release.mjs disable "$WEB_CHECKOUT"` before the next build/deployment. Disabling the UI pin removes new download links. Previously distributed binaries and immutable URLs require separate recall or removal by the release owner.

CI users can run the isolated disposable-key test without publishing a release.

```sh
node --test deploy/cli-release/release.test.mjs
```
