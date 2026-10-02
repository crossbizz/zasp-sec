The overbroad first native-race selector timed out during the owned fixture `TestProductionSecurityAgentBudgetStopsClaimedPolicyApply/stopped_reclaim`. A read-only process inventory after the test ended found no native PostgreSQL process. I did not signal any unrelated process or change shared-memory settings.

Its remaining synthetic database directory was created at2026-09-19 18:00:05 local time, matching this run:

`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestProductionSecurityAgentBudgetStopsClaimedPolicyApplystopped1440309735`

After validating that exact path and inspecting its fixture contents, I moved it to the user's Trash at `/Users/manishmaheshwari/.Trash/zasp-public-restart-native-timeout-20260919-180005` (exit0). It remains recoverable there. The failure and stack remain in `native-race-prior.log`; no product or user data was removed. A preceding exact-path recursive removal request was rejected by the tool and made no change.
