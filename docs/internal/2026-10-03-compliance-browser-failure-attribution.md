# Attribute hosted compliance-browser failures without changing acceptance

For PR50 at74526bb8, GitHub reports that the hosted UI verification and browser prerequisite provisioning passed, followed by a failure in the current compliance-browser acceptance step. The only available annotation was exit1. Both authenticated log-download routes were denied by the environment's egress proxy, and the run had no uploaded artifacts. The failed command and assertion were not demonstrated.

The workflow now labels failures of its two existing commands separately: the four-file Node prerequisite suite and the combined runtime acceptance harness. Each failure branch saves and exits with the original status. Commands, argument lists, ordering, environment and15-minute timeout remain unchanged; failure of the first command prevents the second from running. Annotations contain only a fixed phase label and numeric status.

Five regression cases execute the actual parsed workflow run block with an owned fake Node executable. They verify first-command failures17/143, second-command failures23/1, success without annotation, original arguments/output and temporary-fixture cleanup. Baseline RED reproduced the four missing annotations; candidate GREEN passed the full269-check workflow contract. Independent review also executed all five shell cases. The coordinator separately passed the unchanged45-check browser prerequisite suite; those fixtures execute no actual Go, PostgreSQL, Docker or browser workload.

This is failure attribution only. It does not identify or repair the inaccessible browser assertion, accept hosted/browser/deployed behavior, or promote any original728 ledger row. Required hosted checks remain mandatory.
