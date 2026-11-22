# Verify a staging ticket control

`verify-ticket` evaluates a pair of synthetic staging actions using a predeclared scenario, an adapter’s decisions and the target recorder’s independent readback. The same adapter, cohort, policy revision, operation, target and run must cover both attempts. The allowed update must write a ticket before the protected attempt. A passing verdict requires an applied block and a healthy target readback that covers the full observation window.

From the repository root, build the command and try the included **fixture** exports. This example reads local files and makes no network requests.

```sh
go build -C services/platform -o /tmp/zasp-verify-ticket ./cmd/verify-ticket
sample=services/platform/cmd/verify-ticket/testdata
/tmp/zasp-verify-ticket "$sample/scenario.json" "$sample/adapter.json" "$sample/recorder.json"
```

For a staging exercise, copy the shape of `scenario.json`, pin a unique run, two distinct action IDs, an independent recorder ID and a window up to one hour. Obtain `adapter.json` and `recorder.json` separately from their authenticated sources. The recorder should report the timestamp through which it guarantees complete observation, including delayed writes. Its coverage must start at or before the opening of the scenario window. The verifier uses its own current time to check the watermark. Represent a disconnected recorder with `healthy: false`, and an unobserved adapter with `capability: "unknown"`. Retain the input evidence with the result under the same Environment’s access controls. The command checks the supplied evidence. An operator must establish source authenticity and deployment provenance before using it in a live coverage report.

| Result | Exit | Meaning |
| --- | --- | --- |
| `passed` | 0 | Both applied decisions, the control write and complete target readback agree. |
| `unexpected_effect` | 1 | The recorder reports a confirmed write for the protected action. |
| Invalid input | 2 | A file, schema, bounded synthetic scenario or output stream is invalid. |
| `inconclusive` | 3 | Evidence is incomplete, mismatched or inconsistent. |
| `unsupported` | 3 | The bound adapter reports that it cannot control this action. |

A fixture verdict describes that fixture. Staging evidence has its own run, revision and source records. This local evaluator does not install a provider hook, schedule a regression, or publish a production verification badge.

### Attach evidence to a product run

In a staging Environment, start a test whose saved definition pins the target, test-write credential, and expected effect `synthetic_ticket_update`. Capture the adapter decisions and recorder watermark after the run is queued. Open that run’s detail in Red Team, choose **View ticket proof**, select the three JSON exports and choose **Import ticket proof**. A test-run operator can import once. Authorized viewers can reopen the digest, revision and result. Replaying the same input returns the same record. A distinct experiment needs its own run.

The product verifies the authenticated submission, tenant, saved definition, target, observation window and structured evidence. The recorded source is `operator_import`. Source authentication and independent recorder completeness remain with the operator. The existing run verdict and production coverage are tracked separately.


For a cohort canary, use the enrolled device’s reported adapter and decimal policy revision. The scenario’s cohort label and control/protected IDs must match the current canary’s signed action observations. Fleet promotion checks both digests, the device and credential generation, the observation window and the independent recorder result. Consult the [cohort rollout guide](../../../../docs/operations/purpose-and-policy-rollout.md).
