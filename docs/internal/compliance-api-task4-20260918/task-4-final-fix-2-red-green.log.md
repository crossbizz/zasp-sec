# task-4-final-fix-2-red-green.log.md

## fix2red

Working directory: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform`

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver -run '^TestComplianceReadFailureClassification$/^sdk-' -count=1 -v
```

Exit: 1

```text
=== RUN   TestComplianceReadFailureClassification
=== RUN   TestComplianceReadFailureClassification/sdk-checksum
=== RUN   TestComplianceReadFailureClassification/sdk-checksum/driver
    compliance_read_classification_test.go:221: driver read category: s3 artifact get failed
=== RUN   TestComplianceReadFailureClassification/sdk-checksum/store
    compliance_read_classification_test.go:221: store read category: artifact get failed
=== RUN   TestComplianceReadFailureClassification/sdk-checksum/http
    compliance_read_classification_test.go:253: read effects [read] want read,integrity_failure
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage/driver
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage/store
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage/http
=== RUN   TestComplianceReadFailureClassification/sdk-spoof
=== RUN   TestComplianceReadFailureClassification/sdk-spoof/driver
=== RUN   TestComplianceReadFailureClassification/sdk-spoof/store
=== RUN   TestComplianceReadFailureClassification/sdk-spoof/http
=== RUN   TestComplianceReadFailureClassification/sdk-cancel
=== RUN   TestComplianceReadFailureClassification/sdk-cancel/driver
=== RUN   TestComplianceReadFailureClassification/sdk-cancel/store
=== RUN   TestComplianceReadFailureClassification/sdk-cancel/http
=== RUN   TestComplianceReadFailureClassification/sdk-valid
=== RUN   TestComplianceReadFailureClassification/sdk-valid/driver
=== RUN   TestComplianceReadFailureClassification/sdk-valid/store
=== RUN   TestComplianceReadFailureClassification/sdk-valid/http
--- FAIL: TestComplianceReadFailureClassification (0.21s)
    --- FAIL: TestComplianceReadFailureClassification/sdk-checksum (0.05s)
        --- FAIL: TestComplianceReadFailureClassification/sdk-checksum/driver (0.00s)
        --- FAIL: TestComplianceReadFailureClassification/sdk-checksum/store (0.00s)
        --- FAIL: TestComplianceReadFailureClassification/sdk-checksum/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/sdk-body-outage (0.04s)
        --- PASS: TestComplianceReadFailureClassification/sdk-body-outage/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-body-outage/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-body-outage/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/sdk-spoof (0.04s)
        --- PASS: TestComplianceReadFailureClassification/sdk-spoof/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-spoof/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-spoof/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/sdk-cancel (0.04s)
        --- PASS: TestComplianceReadFailureClassification/sdk-cancel/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-cancel/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-cancel/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/sdk-valid (0.04s)
        --- PASS: TestComplianceReadFailureClassification/sdk-valid/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-valid/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-valid/http (0.02s)
FAIL
FAIL	github.com/zasp-ai/zasp-sec/services/platform/apiserver	1.334s
FAIL

```

## fix2green

Working directory: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform`

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver -run '^TestComplianceReadFailureClassification$/^sdk-' -count=1 -v
```

Exit: 0

```text
=== RUN   TestComplianceReadFailureClassification
=== RUN   TestComplianceReadFailureClassification/sdk-checksum
=== RUN   TestComplianceReadFailureClassification/sdk-checksum/driver
=== RUN   TestComplianceReadFailureClassification/sdk-checksum/store
=== RUN   TestComplianceReadFailureClassification/sdk-checksum/http
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage/driver
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage/store
=== RUN   TestComplianceReadFailureClassification/sdk-body-outage/http
=== RUN   TestComplianceReadFailureClassification/sdk-spoof
=== RUN   TestComplianceReadFailureClassification/sdk-spoof/driver
=== RUN   TestComplianceReadFailureClassification/sdk-spoof/store
=== RUN   TestComplianceReadFailureClassification/sdk-spoof/http
=== RUN   TestComplianceReadFailureClassification/sdk-cancel
=== RUN   TestComplianceReadFailureClassification/sdk-cancel/driver
=== RUN   TestComplianceReadFailureClassification/sdk-cancel/store
=== RUN   TestComplianceReadFailureClassification/sdk-cancel/http
=== RUN   TestComplianceReadFailureClassification/sdk-valid
=== RUN   TestComplianceReadFailureClassification/sdk-valid/driver
=== RUN   TestComplianceReadFailureClassification/sdk-valid/store
=== RUN   TestComplianceReadFailureClassification/sdk-valid/http
--- PASS: TestComplianceReadFailureClassification (0.24s)
    --- PASS: TestComplianceReadFailureClassification/sdk-checksum (0.05s)
        --- PASS: TestComplianceReadFailureClassification/sdk-checksum/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-checksum/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-checksum/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/sdk-body-outage (0.04s)
        --- PASS: TestComplianceReadFailureClassification/sdk-body-outage/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-body-outage/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-body-outage/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/sdk-spoof (0.05s)
        --- PASS: TestComplianceReadFailureClassification/sdk-spoof/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-spoof/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-spoof/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/sdk-cancel (0.04s)
        --- PASS: TestComplianceReadFailureClassification/sdk-cancel/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-cancel/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-cancel/http (0.02s)
    --- PASS: TestComplianceReadFailureClassification/sdk-valid (0.05s)
        --- PASS: TestComplianceReadFailureClassification/sdk-valid/driver (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-valid/store (0.00s)
        --- PASS: TestComplianceReadFailureClassification/sdk-valid/http (0.02s)
PASS
ok  	github.com/zasp-ai/zasp-sec/services/platform/apiserver	1.174s

```
