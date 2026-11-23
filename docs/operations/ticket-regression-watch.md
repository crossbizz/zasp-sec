# Run the managed ticket regression on change

The endpoint watcher repeats the synthetic ticket experiment when the enrolled device receives a new Enforce policy revision, the installed endpoint/recorder executable changes digest, or the selected MCP tool’s input or output schema changes. It uses a fresh run from an existing, operator-approved Red Team schedule. The only writes are synthetic updates to the recorder on a private local listener. The capability supports the macOS staging pilot and a Linux test Environment.

## Set up the pilot

1. Pick one enrolled device and its dedicated ticket cohort. Publish the signed Enforce revision for `mcp__pilot__update_ticket`, with `internal` as the allowed destination. Keep the agent’s enrolled device credential separate from its product read credential.
2. In Red Team, save an enabled staging definition for the pilot target with the `test_write` credential and the single expected effect `synthetic_ticket_update`. Enable its continuous schedule. Record its definition ID and version, target ID, and schedule version. The existing schedule retains its usual timing and authorization. The watcher reads its latest queued run. It sends no generic job requests.
3. Grant a dedicated Environment-scoped product token `view` access to this test and its scheduled runs. On macOS, provision it through the existing managed Keychain workflow as a generic password with service `ai.zasp.ticket-watch.read.v1` and the endpoint configuration’s `keychain_account`. In a Linux test enrollment, place it in the endpoint state directory as `ticket-watch.read-token`, owned by the daemon account with mode `0600`. The watcher sends it only to the enrolled HTTPS product origin. The three existing product reads return the authenticated organization/workspace/Environment in `X-Zasp-Verified-Scope`.
4. Use the existing deployment that supplies the fixture’s approved `tools/list` capture to refresh the selected server and view’s digest snapshot at least daily. The watcher consumes the schema for `update_ticket`. It reads no employee project files. Install the following snapshot as `ticket-watch-schema.json` inside the endpoint’s private state directory with mode `0600`, owned by the daemon account.

```sh
zaspctl mcp snapshot --environment "$ENV_ID" --server "$SERVER_ID" --view ticket-pilot \
  --out ticket-watch-schema.json --json < approved-tools-list.jsonl
```

5. Provision the consent below as `ticket-watch.json` in the same directory with mode `0600`. Replace the sample values with the actual enrollment, schedule, server and target IDs. The server ID is the registered MCP server used for the authorized schema capture. The target ID is the saved staging definition’s target. Set expiry within the next 30 days. Confirm these refer to the same synthetic pilot fixture before enabling the watcher.

```json
{
  "schema_version": "ticket-watch.v1",
  "enabled": true,
  "environment_class": "staging",
  "binding": {
    "organization_id": "pid_a5000001-0000-4000-8000-000000000001",
    "workspace_id": "pid_a5000001-0000-4000-8000-000000000002",
    "environment_id": "pid_a5000001-0000-4000-8000-000000000003",
    "device_id": "pid_a5000001-0000-4000-8000-000000000004",
    "credential_generation": 1
  },
  "definition_id": "pid_a5000001-0000-4000-8000-000000000005",
  "definition_version": 1,
  "schedule_version": 1,
  "target_id": "pid_a5000001-0000-4000-8000-000000000006",
  "schema_server_id": "pid_a5000001-0000-4000-8000-000000000007",
  "schema_view": "ticket-pilot",
  "cohort": "ticket-pilot",
  "expires_at": "REPLACE_WITH_FUTURE_UTC_TIMESTAMP"
}
```

6. Deploy the optional `deploy/endpoint/ai.zasp.ticket-watch.plist` through the pilot’s MDM policy. Install it under `/Library/LaunchDaemons` as `root:wheel`, mode `0644`, and load it into the system launchd domain. It checks every five minutes. Use the command below for an immediate check. Removing or disabling consent stops future attempts. The Linux test adapter requires `environment_class` set to `test`.

```sh
/usr/local/libexec/zasp-endpoint watch-ticket \
  --managed-config "/Library/Application Support/Zasp/endpoint.json"
```

## Read results

The first observation establishes a baseline. The first observation of a changed tuple records when the change was seen. Execution requires the latest run of the pinned, enabled schedule to have been queued at or after that observation and within the last 15 minutes. The device checks the source tuple, signed assignment, active policy and consent again before executing. It allows at most one attempt per hour and one attempt per exact revision tuple. A new definition or schedule version requires explicit renewed consent. If another revision arrives before a run is authorized, the watcher verifies the currently observable revision.

| Output status | Meaning |
|---|---|
| `baseline`, `already_observed` | This tuple is registered. A subsequent check returns the recorded outcome and available private proof directory. |
| `pending_approved_schedule`, `pending_unused_run` | A fresh eligible scheduled run is needed. A recent run belongs to at most one local attempt. |
| `cooldown`, `in_progress` | A recent or concurrent attempt holds this enrollment’s runner. |
| `pending_local_evidence`, `pending_device_evidence`, `pending_product_authority` | A required signed policy, schema capture, local identity or scoped product read is unavailable. |
| `passed`, `unexpected_effect`, `inconclusive`, `unsupported` | The local paired attempt completed with this result. Inspect the private proof directory named in the output. |
| `inconclusive_interrupted`, `journal_limit` | Inspect the device journal. Crash reservations prevent duplicate writes. Each consent journal holds up to 1,024 observed or attempted tuples and then pauses. |
| `disabled`, `unsupported_staging_adapter` | Consent is absent, disabled or expired, or the operating system lacks the required staging adapter. |

The private journal stores revision digests, run IDs and outcomes. The evidence directory contains the ordinary scenario, adapter, device and independent recorder exports. An authorized test operator imports these files on that exact product run through **View ticket proof**. Upload remains an explicit consent step. Product promotion still requires matching signed action receipts and independent recorder readback.

The Linux end-to-end test compiles the endpoint binary, uses an enrolled fixture with real device credentials and an isolated TLS product boundary, starts the actual broker and hook processes, and verifies the durable recorder write and repeated-run deduplication.

```sh
go test -C services/endpoint-agent -p 1 -race -run '^TestTicketWatch' -count=1
```
