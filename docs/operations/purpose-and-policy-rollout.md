# Review an agent’s tool use and roll out a policy

Open **Guardrails → Suggestions → Open runtime policies → Review agent purpose** and choose an agent in the intended Environment. An operator with workflow-management access can save the set of inventory tools that the agent should use. An empty declaration requires an explicit **Declare no intended tools** and save. Each change starts a new revision and preserves earlier declarations.

1. Choose a UTC observation window of up to 30 days and select **Check runtime observations**. Zasp reads up to 100 indexed tool events, checks the durable event’s exact agent and session attribution, and resolves a canonical tool ID against active inventory. Free-text tools, unattributed events and access inferred from permissions remain outside the eligible count. The panel reports the number examined, eligible events and truncation. Narrow the interval to inspect older events.
2. Open a suggested tool to inspect its evidence IDs and the window in which it was observed. **Dismiss suggestion** preserves the review decision. **Save as inactive draft** records a draft request and uses the existing, authorized policy workflow to create a rule scoped to this agent and tool. If the response was lost, use **Reload saved reviews** followed by **Resume inactive draft** where needed. The linked draft retains its policy ID and creation audit ID through later policy edits and rollouts.
3. Open the policy, choose the agent and UTC interval, and run **Replay revision**. The result reports the specific revision, input count, matches, potential blocks and any truncation. Zero indexed events and missing adapter telemetry leave coverage unknown. An indexed replay can support review without establishing a downstream effect.
4. Choose **Roll to monitor**, review runtime decisions and inspect the relevant adapter before selecting **Enforce policy**. Each transition checks the current revision and writes an audit receipt. **Return to monitor** creates a new revision restoring the previous mode of an unedited enforcement promotion. A conflicting revision requires a current read. An intervening policy edit prevents this rollback. **Disable policy** remains available through its existing workflow.
5. For managed endpoints, **Sensors → Devices** shows device cohorts and acknowledgements of signed per-device revisions. The endpoint ticket rule has its own signing and distribution protocol. Restoring older device rules requires publishing them at a higher signed revision and checking the device’s acknowledgement. The common policy editor changes Environment policy. The agent/tool conditions limit which actions it can match.

## Local acceptance fixture

An installed disposable PostgreSQL baseline is required. The following command uses the same migration test environment as the installed API regression suite. It creates scoped test objects and exercises the authenticated handlers and database functions.

```sh
go test -C services/platform ./apiserver \
  -run '^TestAgentSuggestionsOnInstalledBaselinePostgres$' -count=1 -v
```

Set `ZASP_BASELINE_RELEASE_TEST_DSN` to that disposable database before running. The fixture injects indexed runtime observations for an allowed tool and an out-of-purpose tool, including duplicates and weaker attribution. It checks the resulting evidence, saved decision, creation audit, promotion, stale revision handling and returned monitor revision. The OpenSearch driver’s separate tests verify the scoped query and bounded response handling. For a deployed adapter, attach independent target evidence with the [staging ticket verifier](../../services/platform/cmd/verify-ticket/README.md).
