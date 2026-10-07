# Hosted compliance startup diagnostics

Both hosted checks at `cbcfc6ab` passed `npm run verify` and failed compliance browser acceptance. Run37585168510 reached API readiness; run37585174368 failed current fixture preparation. Log downloads were forbidden and no artifacts were available. Underlying causes remain unknown; the prior approval-readiness diagnosis is not established for these two runs.

The runner now distinguishes fixture seed and fixture SQL preparation and emits one fixed readiness-reason annotation from the owned startup waiter's typed failure. Unknown errors/getters/emitter faults stay contained. Commands, SQL, acceptance gates, timeout/cleanup budgets and startup order are unchanged.

The actual same-case baseline failed its diagnostic assertion once. The first owner refused that valid baseline because it incorrectly expected filtered tests to be skipped; the refusal is retained. The corrected owner passed four new groups and 23 affected regressions, with zero failures/skips, unchanged29inputs and normal waits. The lossless baseline JSON preserves the original TAP bytes. This is controlled component evidence, not browser, SQL, Temporal/OpenFGA or deployed acceptance.
