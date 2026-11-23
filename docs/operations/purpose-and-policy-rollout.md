# Review an agent’s tool use and roll out a policy

Open **Guardrails → Suggestions → Open runtime policies → Review agent purpose** and choose an agent in the intended Environment. An operator with workflow-management access can save the set of inventory tools that the agent should use. An empty declaration requires an explicit **Declare no intended tools** and save. Each change starts a new revision and preserves earlier declarations.

1. Choose a UTC observation window of up to 30 days and select **Check runtime observations**. Zasp reads up to 5,000 indexed tool events, checks the durable event’s exact agent and session attribution, and resolves a canonical tool ID against active inventory. Free-text tools, unattributed events and access inferred from permissions remain outside the eligible count. The panel reports the number examined, eligible events and truncation. Narrow the interval to inspect older events.
2. Open a suggested tool to inspect its evidence IDs and the window in which it was observed. **Dismiss suggestion** preserves the review decision. **Save as inactive draft** records a draft request and uses the existing, authorized policy workflow to create a rule scoped to this agent and tool. If the response was lost, use **Reload saved reviews** followed by **Resume inactive draft** where needed. The linked draft retains its policy ID and creation audit ID through later policy edits and rollouts.
3. Open the policy, choose the agent and UTC interval, and run **Replay revision**. The result reports the specific revision, input count, matches, potential blocks and any truncation. Zero indexed events and missing adapter telemetry leave coverage unknown. An indexed replay can support review without establishing a downstream effect.
4. Choose **Roll to monitor**, review runtime decisions and inspect the relevant adapter before selecting **Enforce policy**. Each transition checks the current revision and writes an audit receipt. **Return to monitor** creates a new revision restoring the previous mode of an unedited enforcement promotion. A conflicting revision requires a current read. An intervening policy edit prevents this rollback. **Disable policy** remains available through its existing workflow.
5. To roll out the signed endpoint ticket rule, use **Sensors → Devices → Staging ticket cohort**. Enter the named cohort and the allowed synthetic ticket destination. The enrolled devices must use the intended policy issuer. Eligible devices report the macOS ticket adapter. A test Environment also accepts the Linux test adapter. The panel includes excluded and unconfirmed members in its assigned count. One publication supports up to 32 assigned devices.

### Replay a pinned policy from the CLI

Set `ZASP_API_URL` to your HTTPS deployment and `ZASP_API_TOKEN` to a scoped credential with `manage_workflows`. Select the policy and its current revision, one agent, and an indexed UTC interval of up to 30 days.

```sh
zaspctl guardrails simulate policy-ticket@3 --agent "$AGENT_ID" --since 2026-10-01T00:00:00Z --until 2026-10-02T00:00:00Z
```

Read `examined_count`, `eligible_count` and the policy trigger's `would_block_rate` together. With zero eligible events the rate map is empty. The service examines up to 5,000 events across ten pages. If it returns `truncated: true`, repeat the request with the same `--since`, setting `--until` to `next_window_to` and `--before-event-id` to `next_before_event_id`. The event ID distinguishes events at the same millisecond. Ordinary adjacent windows include their start and exclude their end. The result describes indexed history for that trigger, agent and revision.

### Run a staged ticket rollout

1. Inspect **monitor**, review the device IDs and expected revisions, and download the signing plan. Use `endpoint-policy -cohort-plan ticket-cohort-plan.json -key issuer.pem > ticket-cohort-bundle.json` on the issuer’s machine. Upload the signed file and publish. Every policy pins its device, tenant, credential generation, destination and revision. A rejected member leaves the batch unapplied. Retrying the identical file retrieves the original receipt.
2. Run an allowed and an outside-destination synthetic update on every eligible device. A recent matching heartbeat, both signed action observations, and an empty receipt queue are required to advance. Inspect **canary** to see the single selected device, the first eligible device ID in sort order. Sign and publish its enforcement plan.
3. Queue a Red Team run for the staging target before the canary’s two actions. Capture the allowed control, the protected attempt, and independent target readback. Import the three files in the run’s **View ticket proof** panel. The proof must include the actual canary cohort label, its reported adapter, its decimal device policy revision and the two signed action digests within the run’s observation window. Promotion checks the independent recorder result as well as the device evidence. A confirmed protected write blocks promotion for that revision.
4. Inspect **promote**, sign the plan for the remaining monitored devices and publish it. Inspect again for acknowledgement. **Rollback** issues the last monitored rule at a higher device revision to each currently enforced member. Offline devices can receive the replacement when they reconnect. An issued rollback remains unconfirmed on a device until its heartbeat acknowledges the new revision. A device changed outside the cohort transaction requires reconciliation before further promotion.
5. The cohort receipt records the submitted phase and exact device IDs. The generic policy editor manages Environment policies independently. Cohort promotion signs only the named staging ticket rule.

### Review asynchronous workload analysis

Open **Policies → Review agent purpose** and select the agent. Choose **Inspect workload action analysis**. With workflow-management access, declare the expected operation labels, application-reported data classifications, destination classes and restricted adjacent operation pairs. An empty dimension remains undeclared. Saving creates a new analysis revision. It grants no access and activates no block.

The worker analyzes admissions for credentials already bound to this agent and session. The current revision shows the last 30 days of analyzed admissions, pending work and unknown destinations, with up to 50 recent findings. A missing destination stays unknown. A restricted operation pair uses adjacent observed admissions in the same session, declaration and policy revision within 15 minutes. Check each finding’s decision ID and linked session. Downstream effects and activity outside the reporting workload require separate evidence.


## Local acceptance fixture

An installed disposable PostgreSQL baseline is required. The following command uses the same migration test environment as the installed API regression suite. It creates scoped test objects and exercises the authenticated handlers and database functions.

```sh
go test -C services/platform ./apiserver \
  -run '^TestAgentSuggestionsOnInstalledBaselinePostgres$' -count=1 -v
```

Set `ZASP_BASELINE_RELEASE_TEST_DSN` to that disposable database before running. The fixture injects indexed runtime observations for an allowed tool and an out-of-purpose tool, including duplicates and weaker attribution. It checks the resulting evidence, saved decision, creation audit, promotion, stale revision handling and returned monitor revision. The OpenSearch driver’s separate tests verify the scoped query and bounded response handling. For a deployed adapter, attach independent target evidence with the [staging ticket verifier](../../services/platform/cmd/verify-ticket/README.md).


The cohort acceptance fixture runs with `go test -C services/platform ./apiserver -run '^TestTicketCohortOnInstalledBaselinePostgres$' -count=1 -v`. It uses the signed device enrollment, heartbeat, observation, policy-fetch, cohort and test-run import entry points on the disposable installation.
