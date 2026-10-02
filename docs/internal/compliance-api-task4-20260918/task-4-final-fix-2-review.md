# SDK checksum correction re-review

Reviewer: /root/compliance_api_review. Three-file incremental patch
f02aa947bb1853feebd531fa80ff3c7dbf0c37a6; manifest
5219759b1deb657eecd9a24abb271038b4a6d222.

SDK checksum integrity classification: ADDRESSED. driver.go:174 preserves actual
SDK checksum rejection as ErrIntegrity and errors.Is(ErrGet), with cancellation
precedence. Validation remains enabled and diagnostics opaque.

The regression replaces only HTTP transport, preserving the real SDK reader and
checking immutable request authority. It covers corruption, interruption,
spoofed error text, cancellation and valid bytes across driver, Store and mounted
HTTP. The saved RED reproduces the defect; GREEN and race output pass.

The registered SQL fixture checks exactly one safe committed audit and terminal
grant for corruption; unchanged bounded leases without audits for the other
failures; valid download bytes and replay denial. All16 classification cases
pass in the saved SQL output. The private type-identity dependency is documented
at driver.go:190 and guarded by the real-SDK regression, matching root's ruling.

Spec: approved. Quality: approved. All findings addressed; no new Critical or
Important breakage. Telemetry remains unchanged and previously approved.
No out-of-scope observations.

Reviewer read the complete incremental diff, manifest, report, prior finding,
ruling, RED/GREEN and full verification logs. No mutations, external calls or
test reruns. Evidence supports52 selected race tests, five SQL tests and fresh
test-binary builds. It is not live AWS, deployment or fresh browser proof.
