# Two fixture behaviors failed before their changes

These were native focused tests in `services/platform`, with `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`. Neither failure is a production SQL defect.

```text
/opt/homebrew/bin/go test ./agentsec-worker -run '^TestSecurityAgentExportPublicRestartPlannerSelection$' -count=1

--- FAIL: TestSecurityAgentExportPublicRestartPlannerSelection (0.00s)
security_agent_export_public_process_test.go:118: provider must select only original manual tuple
FAIL github.com/zasp-ai/zasp-sec/services/platform/agentsec-worker 1.100s
exit1
```

The actual candidate in that output had both the manual digest tuple and a `run_audit` tuple. The test required exactly the original manual tuple. The new controlled-response selector filters that actual trusted candidate; after the change the same command returned `ok .../agentsec-worker 1.058s`, exit0. The full process test then reached H and verified the downloaded single manual record against retained link selection, including association digest.

For the reviewer-requested HTTP write guard, the first implementation deliberately had `beforeConsume() error { return nil }` while the test already required rejection after either kind of output:

```text
/opt/homebrew/bin/go test ./apiserver -run '^TestSecurityAgentExportPublicConsumeWriteBoundary$' -count=1

--- FAIL: TestSecurityAgentExportPublicConsumeWriteBoundary (0.00s)
    --- FAIL: TestSecurityAgentExportPublicConsumeWriteBoundary/header (0.00s)
        security_agent_export_public_process_test.go:61: consume checkpoint accepted pre-commit header output: <nil>
    --- FAIL: TestSecurityAgentExportPublicConsumeWriteBoundary/body (0.00s)
        security_agent_export_public_process_test.go:61: consume checkpoint accepted pre-commit body output: <nil>
FAIL github.com/zasp-ai/zasp-sec/services/platform/apiserver 1.130s
exit1
```

After the guard checked its synchronous counters, the combined focused command passed:

```text
/opt/homebrew/bin/go test ./apiserver ./agentsec-worker -run '^TestSecurityAgentExportPublic(ConsumeWriteBoundary|RestartPlannerSelection)$' -count=1
ok github.com/zasp-ai/zasp-sec/services/platform/apiserver 1.102s
ok github.com/zasp-ai/zasp-sec/services/platform/agentsec-worker 1.657s
exit0
```

Both focused tests also passed in `native-race.log`. The final process pass records all three counters as zero at the actual committed-consume checkpoint in `final-summary.json`; the child exits86 only after the guard accepts that state.
