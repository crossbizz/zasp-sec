# Archive V2 execution

Archive V2 now requires the private authorized execution capability. Direct
Execute accepts only archive V1. Authorized execution validates worker/token,
stage, supported version and current lease before S3 access. After the existing
version/owner/KMS/metadata/checksum-bound read, V2 validates the strict precise
archive and rechecks the current lease/cancellation before reporting success.
The executor supports V2 configuration draining historical V1 jobs.

Superpowers evidence:

- New tests failed before implementation: authorized execution was absent and
  direct V2 execution incorrectly returned success.
- Focused archive/stage race tests passed in 2.484s.
- Expanded full worker races passed in 14.963s, including invalid credentials,
  expired leases, renewed windows, lease loss during GET, legacy-body refusal
  for V2 and unchanged historical V1 effects.
- Independent review found no issues and approved this local checkpoint once
  the full worker races passed.

The S3 API is a declared test dependency. This does not prove live S3 or IAM,
server V2 ingestion, durable database routing, startup selection or activation.
Those integrations remain open. No push and no original task credit.
