# Staging pilot verification evidence

Reviewed November 22, 2026. The local fixture checks the verifier, cryptographic bindings, measurement thresholds and complete staged console pin using synthetic bytes. Live results for the release under review are **pending** for all seven scenarios. A passed staging workflow produces the authoritative dated assessment for its commit and environment.

| Scenario and scope | Evidence an operator must collect | Latest staging result |
|---|---|---|
| Native zaspctl downloads | Two notarized Darwin binaries, Authenticode and timestamp for Windows, signed four-platform manifest, exact console pin and verified download | Pending signing and staged-console access |
| Stytch B2B login to findings-only add-on review | Hosted login approval, findings-only share and authenticated reviewer opening that digest | Pending Stytch tenant |
| AWS discovery, remediation and rollback | Bedrock and IAM inventory, approved change on synthetic resource, provider confirmation of applied and restored state | Pending disposable AWS staging account |
| Hosted model gateway | Authenticated governed route and successful upstream model response | Pending staging model credential |
| Remote MCP gateway | Streamable HTTP route and a real remote response to a harmless registered read operation | Pending approved staging MCP endpoint |
| Private artifact retention | KMS-backed encryption and exact S3 version, expiry after 24 hours and authorized exact-version absence | Pending live versioned staging bucket and full retention period |
| Jamf and Claude Code on macOS | Two distinct enrolled Macs. Each needs OS build, Claude build, enrollment, control evidence, measured latency and complete lifecycle | Pending managed hardware and Jamf tenant |

## Run each scenario

Use one approved staging environment and a single immutable release commit. Record opaque receipt IDs in a protected evidence store. Retain the source readbacks there under their existing access controls. Use synthetic resources and test credentials scoped to that environment. An unavailable dependency leaves that scenario pending.

1. **Native release.** On the candidate commit, run the protected native signing workflow for the intended version. Save the two Apple notarization submissions and Accepted readbacks, the Authenticode verification with timestamp, the staged manifest and the signing run ID. Deploy the staged artifact to a pilot console. In **Scan this device**, download the matching asset on a supported machine and compare its hash to the signed manifest. Record the console download readback. Keep the output tree containing both `public/downloads/zaspctl/<version>` and `app/features/tools/cli-release-pin.json`. The verifier checks all four actual files before accepting the receipt. [CLI release](../../deploy/cli-release/README.md) · [Signing workflow](../../.github/workflows/zaspctl-release-sign.yml)
2. **Stytch.** On an employee test account, run `zaspctl auth login --environment ENVIRONMENT_ID`. Complete the normal Stytch browser login and check the terminal code during approval. Scan a harmless local skill and share findings only. Sign in as its authorized reviewer, open **Tools & MCP → Add-ons**, and compare the displayed manifest digest with the CLI receipt. Keep opaque references to the login, upload and opened review. [CLI commands and normal workflow](../getting-started/local-skill-scan.md)
3. **AWS remediation.** Connect a disposable staging account, synchronize Bedrock and IAM inventory, and locate an intentionally prepared finding on a reversible synthetic resource. Record its provider state. Use Security Agent's normal approval and execution flow for the planned change. Read the changed state from AWS, invoke the approved rollback, and read the restored state from AWS. Preserve the approval and both distinct provider readback IDs.
4. **Model gateway.** Register an approved staging upstream and credential, then send a benign request through the authenticated hosted gateway. Correlate the gateway trace with the upstream provider request and successful response. Keep identifiers only.
5. **Remote MCP.** Register the approved remote Streamable HTTP MCP connection. Through the same governed gateway, invoke its harmless read-only fixture tool. Correlate the route and actual remote result. Keep the receipt distinct from the model gateway trace. [Pilot scope and gateway evidence](feature-v2-pilot.md)
6. **Archive.** Configure a disposable versioned bucket with the approved KMS key. Select encrypted 24-hour retention for a synthetic scan. Preserve authorized readback for the exact key, version and encryption at creation. Run the documented status and verification commands for that same grant. After the real retention interval and cleanup, confirm the same object version is absent using a principal whose version-read access is independently established. Preserve both timestamps and the exact version identifier. An authorization failure or an ordinary delete marker alone cannot establish version removal. [Private artifact operations](private-addon-worker.md)
7. **Jamf.** Install the signed, notarized package on two independently enrolled Macs. On each device record an opaque device ID, macOS build and actual Claude Code build. Verify effective hook precedence. Exercise the supported V2 rules, run the synthetic ticket pair with independent target readback, and record upgrade, higher-revision rollback, retirement and uninstall. Capture at least 20 native hook end-to-end latency samples on each Mac. The verifier computes nearest-rank p95 per device and requires at most 75 ms on each. [Endpoint deployment](../../deploy/endpoint/README.md) · [Ticket verification](../../services/platform/cmd/verify-ticket/README.md)

## Build signed receipt files

Use the source authority for each profile. The workflow holds only public verification material. The seven collector profiles are `native_signing`, `stytch_login`, `aws_remediation`, `model_gateway`, `remote_mcp`, `archive` and `jamf`. Store one JSON file and one raw detached Ed25519 signature per profile. The two Jamf basenames must be `jamf-1` and `jamf-2`.

Every JSON document contains `schema` set to `zasp.live-pilot.v1`, `lane` set to `staging`, the profile, the exact environment identifier, the full commit SHA, `observed_at` in UTC and an `evidence` object. Each required evidence field holds a distinct reference to a corresponding source record. The verifier exports its per-profile field lists. Print them locally with the following command.

```sh
node --input-type=module -e 'import {profiles} from "./scripts/verify-live-pilot.mjs"; console.log(JSON.stringify(profiles,null,2))'
```

The native record also carries `version` and `manifest_sha256`. The archive record carries `version_id`, `deleted_version_id`, `created_at` and `deleted_at`. Jamf records include `device_ref`, `os_build`, `harness_build` and `hook_latency_ms`. Omit additional fields. Produce the JSON as UTF-8 `JSON.stringify(record)` followed by one newline. On the collector host, sign the bytes after inspecting the source observations. In this example set `RECEIPT`, `COLLECTOR_KEY` and `SIGNATURE` to the local source JSON, its protected private key, and the new signature destination.

```sh
umask 077
signed_input=$(mktemp)
trap 'rm -f "$signed_input"' EXIT
node --input-type=module -e 'import fs from "node:fs"; const raw=fs.readFileSync(process.argv[1]); if (raw.toString()!==JSON.stringify(JSON.parse(raw))+"\n") throw Error("canonical JSON required"); process.stdout.write(Buffer.from("zasp.live-pilot.v1\0")); process.stdout.write(raw)' "$RECEIPT" > "$signed_input"
openssl pkeyutl -sign -rawin -inkey "$COLLECTOR_KEY" -in "$signed_input" -out "$SIGNATURE"
```

The deployment administrator pins the SHA-256 of the reviewed trust JSON in the protected GitHub Environment. Its fields are `lane`, `environment`, `keys` mapping each of the seven profile names to its approved Ed25519 public key in SPKI PEM format, and `release_key_sha256` covering the exact public release PEM file. Keep the trust anchor outside the collected receipts. The workflow accepts receipts observed within seven days and rejects future observations, missing references, failed thresholds, mismatched commits, changed binary bytes or a mismatched staged pin.

## Run the assessment

PR CI runs the fixture suite locally. A separate protected, manually dispatched workflow evaluates actual receipts. Configure GitHub Environment `zasp-live-pilot` with approved reviewers and protected release refs. Mount the trusted files read-only on the release runner. Configure `ZASP_PILOT_ENVIRONMENT`, `ZASP_PILOT_RECEIPTS_ROOT`, `ZASP_PILOT_TRUST_FILE`, `ZASP_PILOT_TRUST_SHA256` and `ZASP_CLI_RELEASE_PUBLIC_KEY_FILE` as Environment variables. The receipt directory is `$ZASP_PILOT_RECEIPTS_ROOT/<commit>`. Dispatch **Verify staging pilot evidence** on that commit and supply its successful signing workflow run ID. The job checks the signing run identity and commit, verifies the downloaded staged bundle and saves the assessment under `staging-pilot-evidence-<commit>`. It never invokes a provider operation. [Manual workflow](../../.github/workflows/verify-live-pilot.yml)

To reproduce verification offline, use Node 22.23.1 with the retained approved files. The last parameter must name a new report file.

```sh
node --test scripts/verify-live-pilot.test.mjs
node scripts/verify-live-pilot.mjs staging "$COMMIT" "$ENVIRONMENT_ID" "$TRUST_FILE" "$TRUST_SHA256" "$RECEIPT_DIR" "$STAGED_ROOT" "$RELEASE_PUBLIC_KEY" "$NEW_REPORT"
```

The report includes the environment, candidate SHA, trust digest and assessment time. Each row includes the signed observation time, receipt digest and access-controlled evidence references. The native row includes its release version and manifest digest. Each Jamf row includes measured samples, p95 and builds. An attestation records what its authorized source observed. A reviewer can follow the saved IDs for independent provider audits. Fixture outputs always carry the `fixture` lane and cannot fulfill the protected staging workflow's trust requirements.
