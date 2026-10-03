# Sensor request CI synchronization, 2026-10-03

Required CI check 111106411050 at checkpoint `5c39d4ad81b3ba23c38451c76dbc6d74d3a63211` failed the authorized sensor-surface test at `app/components/ZaspApp.test.tsx:375`: the heading was visible while the recorded requests contained only session bootstrap. Rendering the heading does not establish that the sensor view's effect has issued its request.

The one-line fix awaits the existing `/api/v1/sensors` assertion with Testing Library `waitFor`. The request assertion, navigation, active link, capability fixtures, product implementation and default deadlines are unchanged. No arbitrary delay or test scheduling instrumentation is shipped.

Independent private characterization delayed only the sensor effect to reproduce the exact missing-request failure. The original assertion failed; the awaited assertion passed with the same characterization. The final candidate removes that instrumentation. Four related test files passed all 79 tests without skips, and targeted lint passed. Root inspected the exact one-line diff and copied the frozen candidate, SHA256 `97cb897014c0a3ad9a43644db82233bf28ebaedd7842dc3e328ae5539afcc3b0`.

Root full UI verification then passed all 2,544 tests in 246 files (188.32 seconds), with the separately prepared Go 1.26.8 compiler-contract candidate present in the worktree. UI build, compiled production imports and the changed test's lint passed. The initial full UI run had passed 2,543 tests and failed one Nango render test because Helm was omitted from that invocation's PATH; the unchanged Nango test passed with Helm, and the full successor used the proper PATH. Both logs remain preserved. This batch ships only the sensor test and this record; compiler changes are a separate batch.

Evidence: `/workspace/scratch/sensor-surface-ci-race-v1/private-candidate-receipt.json` (SHA256 `238a92b0a6dd71186b7c78290f000038f4cd5c7bf1bec58004835c78bbd05845`), controlled RED/GREEN logs and frozen candidate in the same directory; Root full suite `/workspace/scratch/go268-live-full-ui-sensor-wait-v2.log`.

The other required check at this checkpoint also failed Verify runnable UI with only a generic exit annotation. Its exact failure remains unknown because the redirected log host is denied by the network proxy. No required check, browser acceptance condition or original 728 acceptance row is waived or promoted.
