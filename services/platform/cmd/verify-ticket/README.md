# Verify a staging ticket control

`verify-ticket` evaluates a pair of synthetic staging actions using a predeclared scenario, an adapter’s decisions and the target recorder’s independent readback. The same adapter, cohort, policy revision, operation, target and run must cover both attempts. The allowed update must write a ticket before the protected attempt. A passing verdict requires an applied block and a healthy target readback that covers the full observation window.

From the repository root, build the command and try the included **fixture** exports. This example reads local files and makes no network requests.

```sh
go build -C services/platform -o /tmp/zasp-verify-ticket ./cmd/verify-ticket
sample=services/platform/cmd/verify-ticket/testdata
/tmp/zasp-verify-ticket "$sample/scenario.json" "$sample/adapter.json" "$sample/recorder.json"
```

## Produce the three exports in one run

On Linux, run the real local hook with an ephemeral Enforce policy and an isolated synthetic ticket recorder. Choose a new output directory under a private parent.

```sh
go build -C services/endpoint-agent -o /tmp/zasp-ticket-endpoint .
work=$(mktemp -d)
/tmp/zasp-ticket-endpoint prove-ticket --out "$work/proof"
/tmp/zasp-verify-ticket "$work/proof/scenario.json" "$work/proof/adapter.json" "$work/proof/recorder.json"
```

Two hook processes hold distinct sessions. The command pins the scenario and opens both inputs, then releases the allowed update first. Its write must reach the recorder before the second attempt. The recorder accepts either pinned action. It independently commits each actual write to a private journal, seals it after the declared window, and reads the durable receipts. The proof directory includes the three importable files, the matched device-signed source receipts and the recorder journal. An isolated run uses an ephemeral test identity and is labeled `isolated_linux_ticket_fixture`.

For an **enrolled staging pilot**, queue a Red Team definition whose target represents this supervised local ticket recorder. A target ID binds the evidence to that saved definition. On the assigned test device, run the installed executable as the endpoint service owner. The current signed revision must be in Enforce mode with `internal` as its allowed destination. Use the queued run ID, the saved target ID, the device's enrolled cohort, and the Environment class from the definition.

```sh
/usr/local/libexec/zasp-endpoint prove-ticket \
  --managed-config "/Library/Application Support/Zasp/endpoint.json" \
  --out "/private/staging-proof/run-001" \
  --run-id "$STAGING_RUN_ID" --target-id "$STAGING_TARGET_ID" \
  --cohort "$PILOT_COHORT" --environment-class staging
```

For a Linux test Environment use its protected configuration and `--environment-class test`. The command derives the tenant, signing identity, policy revision and action references from the configured device. It runs the fixed ticket hook as the assigned employee. Each target write goes only to the private synthetic recorder on loopback. No provider URL, shell command, production credential or deployment selector is accepted. The recorder's coverage is limited to this staging fixture. The CLI does not submit, approve or promote a run.

The default window is five seconds. Set `--window` between two seconds and two minutes when measuring a slower staging device. A missing signed receipt, a policy change during the exercise or a missing positive write can yield an inconclusive result. Open the generated evidence, check device health and repeat with a new queued run and directory. Keep `device-receipts.json` and the recorder journal scoped to the staging operator. The web import consumes only `scenario.json`, `adapter.json` and `recorder.json`.

Other authenticated staging adapters and recorders can provide the same three export shapes. Their recorder must cover the full window and account for delayed writes. Record a disconnected recorder with `healthy: false` and an unobserved capability with `capability: "unknown"`. The evaluator checks its own clock and the submitted evidence. The operator establishes source identity and deployment provenance.

| Result | Exit | Meaning |
| --- | --- | --- |
| `passed` | 0 | Both applied decisions, the control write and complete target readback agree. |
| `unexpected_effect` | 1 | The recorder reports a confirmed write for the protected action. |
| Invalid input | 2 | A file, schema, bounded synthetic scenario or output stream is invalid. |
| `inconclusive` | 3 | Evidence is incomplete, mismatched or inconsistent. |
| `unsupported` | 3 | The bound adapter reports that it cannot control this action. |

A fixture verdict describes that fixture. Staging evidence has its own run, revision and source records. For automatic, approved reruns when the signed endpoint policy, fixture binary or selected tool schema changes, configure the [managed ticket watcher](../../../../docs/operations/ticket-regression-watch.md).

### Attach evidence to a product run

In a staging Environment, start a test whose saved definition pins the target, test-write credential, and expected effect `synthetic_ticket_update`. Capture the adapter decisions and recorder watermark after the run is queued. Open that run’s detail in Red Team, choose **View ticket proof**, select the three JSON exports and choose **Import ticket proof**. A test-run operator can import once. Authorized viewers can reopen the digest, revision and result. Replaying the same input returns the same record. A distinct experiment needs its own run.

The product verifies the authenticated submission, tenant, saved definition, target, observation window and structured evidence. The recorded source is `operator_import`. Source authentication and independent recorder completeness remain with the operator. The existing run verdict and production coverage are tracked separately.


For a cohort canary, use the enrolled device’s reported adapter and decimal policy revision. The scenario’s cohort label and control/protected IDs must match the current canary’s signed action observations. Fleet promotion checks both digests, the device and credential generation, the observation window and the independent recorder result. Consult the [cohort rollout guide](../../../../docs/operations/purpose-and-policy-rollout.md).

## Independently authenticated staging sources

A paired import can earn `verified_prevention` on the existing staging ticket-verification route. Supply one Ed25519 signature from the adapter authority and one from the ticket recorder authority. The recorder must own its target log and independently measure both the permitted write and the entire protected interval. Give the two authorities separate keys and administration. Giving one uploader both signing keys defeats source independence.

The deployment administrator mounts a read-only JSON file and sets `ZASP_TICKET_ATTESTATION_TRUST_FILE` on the API and compliance-reporting processes. The directory and file must be writable only by the deployment administrator. The envelope has a `keys` array. Each entry contains the following fields.

| Field | Value |
|---|---|
| key_id, authority_id | Unique rotation key ID and the independently administered source identity |
| role | `adapter` or `recorder` |
| scope | Exact organization_id, workspace_id and environment_id |
| target_id, source_id | Approved staging target and the adapter_id or recorder_id for this role |
| public_key | Standard padded base64 of the 32 raw Ed25519 public-key bytes |
| valid_from, valid_until | UTC timestamps covering the experiment and server submission |

Use a PKCS#8 PEM key on each source host with permissions 0600. Each source checks the approved scenario and its own export against the local record. On the adapter host, sign only its locally authenticated decisions. On the independent recorder host, sign only its own target log and coverage window.

```sh
verify-ticket sign-source adapter adapter-key-1 /private/adapter.pem scenario.json adapter.json > adapter-attestation.json
```

```sh
verify-ticket sign-source recorder recorder-key-1 /private/recorder.pem scenario.json recorder.json > recorder-attestation.json
```

The uploader receives the metadata exports and detached signatures. Add the two signature objects as `attestations.adapter` and `attestations.recorder` beside the existing scenario, adapter and recorder. Submit this bundle as the authorized operator's first PUT to the existing test run. Each signature covers a versioned signing domain, role, key ID, issue time, full scenario and that role's typed local evidence. The source signs after the observation window. The server requires submission within 24 hours of the window closing. A run preserves its first import. A new or corrected experiment needs another eligible staging run.

GET returns `evidence_qualification` beside the original comparison result. Both authenticated sources and a passing independent target comparison are required for `verified_prevention`. An unsigned completed pair, or a valid signed pair that confirms an unintended write, can qualify as `tested_control`. Missing trust, conflicting signatures or incomplete recorder coverage yield `unknown`. The service rereads the public trust file for signed imports and live reports. Keep earlier verification keys in the trust file when rotating. Remove a compromised key to invalidate current evaluations. Previously frozen exports retain their as-of result. The CLI example and installed test exercise a synthetic staging fixture.
