# task-4-final-fix-focused-green-diagnostic.log.md

The focused command exited 0. This early tool capture was output-limited; it is diagnostic only. The complete grouped race log reruns every focused case and is the accepted full GREEN evidence.

## finalgreen

Working directory: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform`

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver ./artifactstore ./agentsec-api -run '^(TestComplianceReadFailureClassification|TestGetClassifiesReturnedObjectIntegrity|TestComplianceAPIProductionComposition)$' -count=1 -v
```

Exit: 0

```text
Warning: truncated output (original token count: 1812)
Total output lines: 106

=== RUN   TestComplianceReadFailureClassification
=== RUN   TestComplianceReadFailureClassification/head-outage
=== RUN   TestComplianceReadFailureClassification/head-outage/driver
=== RUN   TestComplianceReadFailureClassification/head-outage/store
=== RUN   TestComplianceReadFailureClassification/head-outage/http
=== RUN   TestComplianceReadFailureClassification/get-outage
=== RUN   TestComplianceReadFailureClassification/get-outage/driver
=== RUN   TestComplianceReadFailureClassification/get-outage/store
=== RUN   TestComplianceReadFailureClassification/get-outage/http
=== RUN   TestComplianceReadFailureClassification/body-outage
=== RUN   TestComplianceReadFailureClassification/body-outage/driver
=== RUN   TestComplianceReadFailureClassification/body-outage/store
=== RUN   TestComplianceReadFailureClassification/body-outage/http
=== RUN   TestComplianceReadFailureClassification/cancel
=== RUN   TestComplianceReadFailureClassification/cancel/driver
=== RUN   TestComplianceReadFailureClassification/cancel/store
=== RUN   TestComplianceReadFailureClassification/cancel/http
=== RUN   TestComplianceReadFailureClassification/deadline
=== RUN   TestComplianceReadFailureClassification/deadline/driver
=== RUN   TestComplianceReadFailureClassification/deadline/store
=== RUN   TestComplianceReadFailureClassification/deadline/http
=== RUN   TestComplianceReadFailureClassification/version
=== RUN   TestComplianceReadFailureClassification/version/driver
=== RUN   TestComplianceReadFailureClassification/version/store
=== RUN   TestComplianceReadFailureClassification/version/http
=== RUN   TestComplianceReadFailureClassification/metadata
=== RUN   TestComplianceReadFailureClassification/metadata/driver
=== RUN   TestComplianceReadFailureClassification/metadata/store
=== RUN   TestComplianceReadFailureClassification/metadata/http
=== RUN   TestComplianceReadFailureClassification/checksum
=== RUN   TestComplianceReadFailureClassification/checksum/driver
=== RUN   TestComplianceReadFailureClassification/checksum/store
=== RUN   TestComplianceReadFailureClassification/checksum/http
=== RUN   TestComplianceReadFailureClassification/body-mismatch
=== RUN   TestComplianceReadFailureClassification/body-mismatch/driver
=== RUN   TestComplianceReadFailureClassification/body-mismatch/store
=== RUN   TestComplianceReadFailureClassification/body-mismatch/http
=== RUN   TestComplianceReadFailureClassification/envelope
=== RUN   TestComplianceReadFailureClassification/envelope/driver
=== RUN   TestComplianceReadFailureClassification/envelope/store
=== RUN   TestComplianceReadFailureClassification/envelope/http
=== RUN   TestComplianceReadFailureClassification/valid
=== RUN   TestComplianceReadFailureClassification/valid/driver
=== RUN   TestComplianceReadFailureClassification/valid/store
=== RUN   TestComplianceReadFailureClassification/valid/http
--- PASS: TestComplianceReadFailureClassification (0.46s)
    --- PASS: TestComplianceReadFailureClassification/head-outage (0.0…312 tokens truncated…eClassification/deadline (0.05s)
        --- PASS: TestComplianceReadFailureClassification/deadline/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/deadline/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/deadline/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/version (0.04s)
        --- PASS: TestComplianceReadFailureClassification/version/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/version/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/version/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/metadata (0.04s)
        --- PASS: TestComplianceReadFailureClassification/metadata/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/metadata/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/metadata/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/checksum (0.04s)
        --- PASS: TestComplianceReadFailureClassification/checksum/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/checksum/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/checksum/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/body-mismatch (0.04s)
        --- PASS: TestComplianceReadFailureClassification/body-mismatch/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/body-mismatch/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/body-mismatch/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/envelope (0.04s)
        --- PASS: TestComplianceReadFailureClassification/envelope/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/envelope/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/envelope/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/valid (0.04s)
        --- PASS: TestComplianceReadFailureClassification/valid/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/valid/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/valid/http (0.02s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/apiserver	1.752s
=== RUN   TestGetClassifiesReturnedObjectIntegrity
--- PASS: TestGetClassifiesReturnedObjectIntegrity (0.00s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/artifactstore	0.587s
=== RUN   TestComplianceAPIProductionComposition
=== RUN   TestComplianceAPIProductionComposition/installed
=== RUN   TestComplianceAPIProductionComposition/disabled
=== RUN   TestComplianceAPIProductionComposition/unregistered
--- PASS: TestComplianceAPIProductionComposition (0.06s)
    --- PASS: TestComplianceAPIProductionComposition/installed (0.03s)
    --- PASS: TestComplianceAPIProductionComposition/disabled (0.01s)
    --- PASS: TestComplianceAPIProductionComposition/unregistered (0.02s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/agentsec-api	1.759s

```
