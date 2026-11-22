# Managed ticket-action pilot

The endpoint broker evaluates a signed policy for Claude Code's named `mcp__pilot__update_ticket` tool on a local Unix socket. The managed process owns the device key, policy cache and encrypted receipt queue. The hook uses Claude Code's `PreToolUse` permission-decision response. On a permitted call it emits `{}`, preserving the harness's own permission prompts. Triggering the hook produces an adapter decision. Target effect and skill usage are both recorded as unknown.

## Run the local proof

From the repository root run `go -C services/endpoint-agent test -race -count=1 ./...`. On Linux the executable test builds the program, starts the daemon, invokes the CLI hook with synthetic Claude Code events in two simultaneous sessions, reads back an independent local HTTP ticket recorder, verifies the signed receipt batch, and archives it. Unit tests on both platforms cover tampering, scope, revision rollback, expiry, conflict, archive and spool capacity. The disposable macOS CI gate runs the actual binary as root and as a separate employee UID, creates and reuses one throwaway System Keychain item, validates two signed hook decisions, and verifies deletion of the test item. This fixture exercises OS integration using a synthetic local policy.

## Package and configure a test Mac

1. On a macOS signing host, set `ZASP_APP_SIGNING_ID`, `ZASP_INSTALLER_SIGNING_ID`, `ZASP_NOTARY_PROFILE` and `ZASP_PACKAGE_VERSION`. Run `deploy/endpoint/package-macos.sh /absolute/new/path/zasp-endpoint.pkg`. This builds a universal binary with native Keychain support, signs the executable and installer, notarizes, staples and assesses the package. Distribute it through the pilot Jamf group.
2. As the Mac administrator, run the signed `/usr/local/libexec/zasp-endpoint init-device-key --account DEVICE` on that Mac. It creates a **distinct per-device** Ed25519 seed in the System Keychain generic-password item with service `ai.zasp.endpoint.receipt.v1`. The command emits only the public key for registration. Repeating it reuses the device’s existing key. The account ID and ACL must allow the signed daemon identity to read this item without UI. The seed is software-backed. Provision the trusted policy issuer's public key independently. Hold its private key off the laptop. Provisioning seeds or tokens in the shared installer would let unrelated devices impersonate each other.
3. Create managed directories under `/Library/Application Support/Zasp`. Use `run` root-owned with mode 0755 and `state` root-owned with mode 0700. Install an admin-owned `endpoint.json` (0644 or more restrictive). Protect its parent directory and all components of the configured paths from employee writes. A pilot configuration has this shape. Replace identifiers, UID and public key with actual values.

```json
{
  "binding": {"organization_id":"ORG", "workspace_id":"WORKSPACE", "environment_id":"ENVIRONMENT", "device_id":"DEVICE", "credential_generation":1},
  "allowed_uid": 501,
  "policy_public_key": "BASE64_OF_32_BYTE_ISSUER_PUBLIC_KEY",
  "policy_file": "/Library/Application Support/Zasp/policy.json",
  "state_dir": "/Library/Application Support/Zasp/state",
  "socket": "/Library/Application Support/Zasp/run/endpoint.sock",
  "keychain_account": "DEVICE"
}
```

4. Install an issuer-signed policy as `policy.json`. Its outer JSON contains `payload` and `signature` (both standard padded base64). The issuer signs the **exact decoded payload bytes** using Ed25519. On the authorized issuer host, `go -C services/endpoint-agent run ./cmd/endpoint-policy --key /private/issuer.pk8 --policy /private/policy-draft.json` validates and signs a policy with an owner-only PKCS#8 PEM private key. Use its JSON result for upload or managed distribution. The JSON payload has `audience` set to `zasp.endpoint-policy.v1`, the same `binding`, a positive integer `revision`, RFC3339 `issued_at` and `expires_at` (at most 24 hours apart), `mode` (`monitor` to start), `tool` set to `mcp__pilot__update_ticket`, and `allowed_destination` set to the approved ticket destination label. Missing or unclassifiable destinations trigger the restriction. A newer unexpired revision activates atomically. Invalid or superseded updates leave the prior valid cache active. Reverting publishes the prior rules under a higher revision.
5. Load the installed `ai.zasp.endpoint` LaunchDaemon after configuration. Merge [the command hook fragment](claude-code/managed-settings.fragment.json) into your managed Claude Code settings, preserving existing admin policies. The socket admits the configured local UID via kernel peer credentials. The production hook checks the broker runs as root. A user on that account can invoke the socket directly, so these receipts attest an adapter evaluation. An independent target receipt or a stronger origin binding is needed for claims about execution.
6. Run `/usr/local/libexec/zasp-endpoint status` as the intended user and inspect the policy revision and queue. Test a real allowed and denied staged write and a lost broker on the pinned harness version. The supplied fragment continues normal harness operation on outage. Use `--on-unavailable deny` for a named critical action only after verifying failure behavior and hook precedence. The hook cannot stop a call that never runs it. The Linux executable test covers the hook protocol and local broker. macOS/Jamf install, managed-harness compatibility, session resume, mode enforcement and uninstall require a real fleet gate.

## Retention and recovery

State uses AES-GCM with a random nonce and a purpose-derived key. The store retains 256 pending signed receipts. On overflow status shows the dropped count. A known blocked action remains blocked when evidence storage fills. As the service owner, use `zasp-endpoint export` for read-only access, or `zasp-endpoint archive --out /protected/new-file.json` to persist a private export before freeing its slots. Archive uses exclusive file creation, file and directory fsync, and a compare-and-ack of each receipt signature. Historical action IDs stay replay-protected for 24 hours with an upper bound of 4,096 archived IDs per device during that window.

The signing seed also protects the local state. Export records and stop the service before rotating this pilot identity. Provision an increased credential generation and a new private state directory for the new seed, retain the previous encrypted state with its own recovery policy, and confirm a new policy acknowledgment. Removing the MDM hook, stopping the service and revoking its server registration are separately observable operations.

## Register and synchronize the pilot

In an authorized Environment, create a dedicated API token with only `sync_endpoint`. Register one device through `POST /api/v1/device-enrollments` with the token **ID**, device Ed25519 public key, distinct policy issuer public key and cohort. Use its returned device ID and credential generation for the local binding. Admin changes use the existing browser fresh-auth, CSRF and idempotency controls. The token secret stays in that device's System Keychain item with service `ai.zasp.endpoint.transport.v1`. Its ACL should grant just the signed daemon read access. Pre-registration binds one device to one PAT. Copying the shared package or presenting the PAT alone cannot exchange the enrollment.

The optional `control_plane` member of the configuration enables periodic HTTPS exchange, signed policy fetch, heartbeat, and delivery of up to 16 buffered receipts and 16 inventory reports per cycle. Idle devices check every minute. New local evidence wakes the transport, with at least ten seconds between cycle starts. For macOS use `{"origin":"https://zasp.example.com","keychain_account":"DEVICE","inventory_enabled":true}`. For local Linux integration testing replace `keychain_account` with a service-owned 0600 `token_file` that contains only the independently scoped PAT. The origin must be HTTPS without a path, query or embedded credentials. The client uses the system CA roots, disables redirects and proxy forwarding, and verifies the policy signature against the independently provisioned public key. A remote unavailable state is visible in local status. The hook stays offline-capable while its current policy is valid.

Publish a signed per-device bundle through `PUT /api/v1/devices/{id}/policy-bundle`. The heartbeat reports the last local policy status. The fleet counts separate preassigned devices, enrollment, recent online health, and acknowledgment of the exact assigned revision. Revocation stops new server access. An already-disconnected device can still honor its cached signed policy until its expiry.

Use a user-context managed job with scoped project selection to deliver inventory. The CLI walks the locations readable by that employee. The privileged daemon only consumes the report and never opens employee paths. For a selected project, run the following commands from its root:

```bash
zaspctl addons inventory --local --scope project --project "$PWD" --json |
  /usr/local/libexec/zasp-endpoint inventory --project "$PWD"
```

Configure the job to surface the CLI's partial exit status as well as the broker result. For managed/personal inventory omit the project flag on both tools and select the corresponding scope. The broker sends opaque, device-keyed partition and installation IDs, observed manifest digests and completeness. It excludes file paths, personal names and raw source. A complete report updates only its matching partition. An unreadable, absent or incomplete root retains the previous complete installation report until a subsequent complete report establishes removal. The endpoint API keeps observations separate from independently verified side effects. Stored `target_effect` and `skill_usage` remain unknown.

For rotation provision a fresh device key and independently issued transport credential, then use the browser-authorized `/devices/{id}/credential-rotations` mutation with the prior version. After exchanging the new generation, publish a higher policy revision bound to that generation. Once the old identity has been retired or rotated its future uploads fail, including buffered historical observations. Archive any required local evidence before rotation. Retiring a device through the control plane preserves its audit history. MDM package removal requires a separate step.

For Windows managed inventory, see [the LocalSystem and Intune deployment instructions](intune-device/README.md). Windows reports installation metadata and cannot acknowledge a ticket-hook policy.

## Sign a ticket cohort rollout

Review the target Environment, cohort, phase, rollout revision and each device generation before signing. All participating Macs in this pilot must already trust the same Ed25519 policy-issuer public key. Keep the corresponding private PKCS#8 PEM in an owner-only file on the operator machine. A plan contains 1–32 distinct devices in one tenant scope. Each entry carries the current device resource version, a complete device-bound policy JSON from the single-device workflow, and the same staging ticket destination. Use `monitor` policies in the `monitor` and `rollback` phases and `enforce` policies in the `canary` and `promote` phases. Rollback issues newer per-device revisions in monitor mode.

```sh
cd services/endpoint-agent
go run ./cmd/endpoint-policy --cohort-plan ./reviewed-cohort.json --key ./issuer.pem > ./signed-cohort.json
```

The input object has `schema_version` set to `ticket-cohort-plan.v1`, plus `cohort`, `phase`, `expected_rollout_revision` and `items`. Each item has `expected_device_version` and `policy`. The signer emits a `ticket-cohort-bundle.v1` object with the same metadata and ordered `items`, replacing each policy with its signed `bundle`. Each signature binds the exact policy and device generation. The server independently authorizes the operator, checks cohort membership and revisions, and collects device acknowledgments. The signing command works offline.

Run `zasp-endpoint prove-ticket --help` to produce a scoped staging scenario, two real hook decisions and independent ticket readback in one command. The [staging proof guide](../../services/platform/cmd/verify-ticket/README.md) covers isolated runs, enrolled pilots and import into a queued product run.
