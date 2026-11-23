# Managed pre-tool policies for employee Macs

An endpoint administrator saves an Environment-scoped template, signs a policy for each enrolled device, and installs the hook for each managed harness. The daemon evaluates signed rules locally even while offline. The control plane displays the assigned revision, last device acknowledgment and signed device decisions.

## Save and sign

1. Enroll the device with the existing device enrollment workflow, a cohort name, its transport identity, its device verification key and the operator's policy verification key. The issuer keeps the corresponding Ed25519 private key offline. Give the daemon its assigned local employee UID.
2. In Sensors, open the cohort pre-tool policy editor. Begin in monitor mode. Save these settings with the revision currently displayed. Via the API, browser-session readers use `GET /api/v1/device-cohorts/{cohort}/pretool-policy`. A fresh authorized workflow administrator uses `PUT` on that same route with CSRF, origin, idempotency and `expected_revision`. Concurrent edits return HTTP 409. Revision zero means that the cohort has no saved template.
3. On the operator's machine, build a device policy from the saved template's exact `rules`, `mode` and `failure_mode`. Set `audience` to `zasp.endpoint-policy.v2`. Copy the device's exact `binding` (organization, workspace, environment, device and credential generation). Set a strictly increasing device `revision`, UTC `issued_at` and `expires_at` within 24 hours. Advance the device revision for each new assignment, including a rollback.
4. Sign the reviewed JSON. The issuer accepts an owner-only private Ed25519 PKCS#8 PEM. It verifies the policy against its scope, rules and validity before emitting the base64 payload and detached signature.

```sh
go -C services/endpoint-agent run ./cmd/endpoint-policy \
  --policy /absolute/path/to/device-policy.json \
  --key /absolute/path/to/issuer.pem > signed-device.json
```

5. Under **Sensors → Devices**, open the enrolled device, choose **Publish signed policy**, and select the signed envelope file. Verify the selected revision, then publish it. The control plane records the assigned revision. The same action is available through the browser-authenticated `PUT /api/v1/devices/{id}/policy-bundle`, including CSRF, origin, an idempotency key and `If-Match` set to the current device resource version. The server verifies the enrolled issuer signature, generation, time, device revision and equality with the latest template in that device's cohort. A saved template alone has no effect on existing assignments.
6. The active device retrieves its bundle with its registered transport token and signed device request. Check the reported revision and heartbeat time on the device detail page. A recorded monitor match has `would_block: true` and `verdict: continue`. A matching enforced action has `verdict: deny`. The action ID links to signed device evidence. Use separate authoritative service readback to establish any target effect.


### Rotate the device credential

In the selected device's detail view, choose **Rotate device credential**. Supply the replacement endpoint credential ID and the replacement device's public verification key, then confirm. Check the credential generation in the returned device record. Provision the matching credential and private key through your managed device channel. A new signed policy must use the new generation.

## Install the hook

Set `adapter` in the managed daemon configuration to `macos_claude_pretool_v2` or `macos_codex_pretool_v2`. Both shipping shims can use this supervised daemon. Its heartbeat reports the configured adapter. A receipt identifies the calling shim. UID checks authenticate the local peer. A user who can invoke a shim can submit a synthetic event, so the receipt cannot establish the originating desktop process or an independent target outcome.

- For Claude Code, merge [the managed PreToolUse fragment](claude-code/managed-pretool.fragment.json) into the machine's managed settings. It covers Bash, the named file operations, WebFetch and MCP calls. Existing staging ticket pilots can keep their [ticket-only fragment](claude-code/managed-settings.fragment.json).
- For Codex, merge [the system hook fragment](codex/hooks.fragment.json) into `/etc/codex/hooks.json` on a managed Mac. Use a Codex version and managed policy permitting command hooks. It covers supported Bash, MCP and `apply_patch` calls. Patch headers supply the affected file paths. Other file reads, arbitrary shell internals and tool calls that the host does not expose have no file-level coverage through this adapter. [Codex hook documentation](https://developers.openai.com/codex/hooks/)
- Deploy the root-owned daemon, device key, UID assignment and hook fragments with MDM. Verify with `zasp-endpoint status` as the enrolled user. A root-owned package distribution, signing, notarization and management-system assignment are separate rollout steps. Use a staging Mac with the actual approved harness versions to qualify them.
- The sample hook fragments use `--on-unavailable deny` if the shim cannot reach the daemon or there is no authenticated policy. An authenticated, expired V2 policy uses its own signed failure mode. In monitor mode the daemon continues and reports observation gaps. In enforce mode a closed policy denies a scoped action on expiry or unverifiable input; an open policy continues. Use a newer signed revision to restore monitor mode or renew before expiry.

## Rule inputs and handling

| Rule type | Allowed fields and local meaning |
| --- | --- |
| `mcp_tool_policy` | `match` is `allowlist` or `denylist`. `values` contain exact MCP tool names or a server namespace such as `mcp__docs__*`. Approved tools can also require `allowed_destinations` with exact names or wildcard subdomains. |
| `shell_command_policy` | `values` select `shell_pipe`, `secret_transfer`, `reverse_shell`, `privileged_mode` or `encoded_execution`. These indicators inspect bounded command text at the Bash hook. They provide pattern coverage and cannot establish what an arbitrary program does at runtime. |
| `file_path_policy` | `values` select `ssh`, `aws`, `gcloud`, `dotenv`, `pem` or `identity_key`. Inspection uses field paths, the assigned home and the hook's working directory. Symlinks, explicit parent traversal and network or automounted volumes are classified as `unverifiable_path`. The Darwin broker queries the kernel’s cached mount table without refreshing remote filesystem statistics. This operates before the tool runs and cannot mediate later filesystem changes. |
| `destination_domain_policy` | `WebFetch` and MCP URL/host fields support exact hostnames or wildcard subdomains. A wildcard excludes the apex domain. URL paths and query strings stay on the laptop. DNS resolution, redirect tracking and network egress filtering require independent network controls. |

The daemon signs stable reason and rule IDs, the device binding, scoped opaque action and session IDs, timestamp, adapter, tool class, policy revision, verdict and monitor status. It never includes raw paths, domains, prompts, commands, SIDs or file contents in V2 receipts. The existing bounded encrypted queue retains receipts during a network outage. The shim returns a human-readable system message and a JSON string in the host's supported `permissionDecisionReason` field. The string contains `action_id`, `rule_id`, `policy_revision`, `reason_code` and `next_step_hint`. Unrecognized input, a full queue and an expired policy have separate outcomes.

## Verify the local control

Run `go -C services/endpoint-agent test -race -count=1 ./...` for signed policy validation, the V1 ticket regression, monitor and enforce results, rule matching, receipt privacy, expiry and CLI-to-daemon behavior. To measure local classification and durable broker decisions on the pilot hardware, run `go -C services/endpoint-agent test -count=1 -v -run '^TestPretoolLatencyOnBoundedSyntheticInput$' .`. The broker measurement includes signing and encrypted queue persistence. Both measurements exclude starting a hook process.

The [isolated Codex smoke](../../scripts/smoke-codex-managed-hook.py) runs an installed Linux Codex against a loopback synthetic model, loads the managed hook fragment and verifies a denied and a permitted patch through target readback. The macOS CI job uses the shipping binary, a dedicated System Keychain item and an assigned nonprivileged UID. A rollout on managed hardware still requires the MDM assignment, the actual vendor harness versions and a signed device heartbeat.
