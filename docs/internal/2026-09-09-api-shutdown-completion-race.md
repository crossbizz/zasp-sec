# API shutdown completion race

PR 29 push CI 34419491374 failed the existing hostile lifecycle shutdown test.
Its separate PR CI 34419494031 passed. A local race-enabled 50-repeat run
reproduced the failure in 6.863 seconds, so this was not waived as a CI flake.

The runtime can select the internal health server's successful, nil completion
when cancellation and that completion are both ready. The later drain used
`internalErr == nil` as its unread flag and waited on the consumed channel again.
This could block shutdown indefinitely. The fix tracks product and internal
completion separately from their error values, as the lifecycle worker already
does. It does not change shutdown budgets or relax the existing error contract.

The existing test keeps its 100ms shutdown budget and one-second assertion.
Deferred cancellation and worker release now also clean up a failing test.

Verification after the fix:

- The hostile lifecycle regression passed 100 race-enabled repetitions in
  12.118 seconds.
- Complete API-service and health-server race suites passed in 2.686 and
  6.606 seconds respectively.
- Independent Superpowers review accepted the root cause and correction and
  passed another 50 race-enabled repetitions in 6.747 seconds.
- The correction does not change UI files. Those exact UI sources previously
  passed full verification and the complete Chrome/runtime proof for PR 29.

The correction is limited to the API runtime, its test cleanup, and this evidence
record. Uncommitted timeline work is not part of the correction. Shipping CI
must pass before PR 29 is merged; no new task credit follows from this fix.
