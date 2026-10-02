# Cleanup response taxonomy: focused RED then GREEN

The new test exercises the production exact-version cleanup driver through the AWS SDK and persistent controlled transport. It distinguishes denied access, a generic HTTP 404, and typed `NoSuchVersion`.

The initial generic-404 fixture deliberately returned the wrong code, `NoSuchVersion`. The assertion rejected that false absence result. The terminal result was:

```text
--- FAIL: TestSecurityAgentExportCleanupResponseTaxonomy/generic404 (0.03s)
generic404 classified as confirmed absence: <nil>
FAIL github.com/zasp-ai/zasp-sec/services/platform/agentsec-worker 1.193s
```

The focused test can be rerun from `services/platform` with:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off /opt/homebrew/bin/go test -race ./agentsec-worker -run '^TestSecurityAgentExportCleanupResponseTaxonomy$' -count=1 -v -timeout=120s
```

Changing only the new test fixture's generic response code to `NotFound` produced GREEN in 1.238s. The final retained native run repeats the test with the grouped driver/store regressions. See `native-race.log` and `native-race.json`. The initial RED was observed in terminal output; no separate raw log was retained. This is a negative control for the new harness, not a discovered or fixed product defect.

Two setup errors were separate from the behavioral RED: canonicalizing macOS's symlinked temporary path for the existing store guard, and supplying the required `action_key:"*"` in the public second-organization environment-control request. The latter's complete failed process log and cleanup result are retained in `2026-09-20T01-39-06.555Z/`. Neither required a production change.
