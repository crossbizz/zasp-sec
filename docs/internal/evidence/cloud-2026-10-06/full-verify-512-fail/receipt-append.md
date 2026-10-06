## Fresh verification at 512beb18 failed before UI; cause triage remains private

Fresh faithful full `npm run verify` at unchanged before/after
`512beb183a0f7994f8769fc6765e3e1b80af4523` ran from 01:59:21 to 02:04:23 UTC
and FAILED after 302 seconds. Dependencies passed; the health-contract phase
failed with three observed cases: API current typed-release readiness deadline
refusal, compliance close upload-not-reached, and Temporal settlement/effect
fixture panic on []byte versus json.RawMessage. API package took 9.332 seconds;
worker package took 286.233 seconds. UI, release and all later phases were
unreached. The earlier 246-file / 2,535-test UI pass belongs to the separate
3ccc verification, which failed after 733 seconds at its historical 546-finding
security gate; it does not establish current full verification success.

Root's separate faithful full-history Gitleaks8.30.1 scan at the same512 commit
passed with zero findings in 93.65 seconds under the reviewed fingerprint
configuration. That separate scanner result does not clear the failed npm run
or the production release gate's unavailable approved-advisory requirement.
No online audit, disclosure, provider mutation or deployed acceptance occurred.

The exact failure packet's original 17-member manifest is
`140bbe54abdd55868bd22874eca2d68af51a734f8da39f1b86f48713926f1fff`.
All original bytes and earlier failures are preserved. Its private raw log was
scoped-scanned with zero findings and compressed only after URL/ANSI sanitization.
A separate bounded crosswalk links existing M1-28/M1-28b health-command gate
rows and the M7-14 compliance-export component, without changing categories,
guessing additional IDs or promoting original acceptance. The original 728
rows and 523/144/61 evidence categories remain unchanged.

Separate private API instrumentation retained the original one-second caller
and five-second production bounds. Five focused plus three full-package race
runs passed without reproducing expiry. They show duplicate fixture expected-
pin materialization consumes deadline time, but do not prove the baseline
expiry stage or a production defect. No API fix was selected or adopted;
negative cancellation/deadline guards remain. Diagnostic manifest:
`8fb8c50adcb14afb2e545b20ddcfda4a44d7a790c468333cb42ca0587a58f3e7`.
Worker triage remains a separate private scope. At this documentation checkpoint,
root's separately owned exact512 native attempt is in progress; no outcome,
cleanup receipt or native/deployed acceptance is asserted here.
