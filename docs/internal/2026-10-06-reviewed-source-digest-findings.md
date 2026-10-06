# Reviewed source-digest findings, October 6, 2026

PR51 lacked the previously independently adjudicated baseline fingerprint exceptions from commit cace013f. The exact append-only 435-fingerprint change and its historical review document were ported without importing that commit's other changes. Original exception bytes, failed scans, history, security rules and acceptance conditions remain intact.

A new comparison scan of 8f537fec used the critical-path checkout's reviewed ignore file because its working directory was that checkout. It found eight matches in the source-inputs manifest at commit 3c123ef4. This is an inherited-configuration comparison, not a faithful PR51 gate result. Root and independent review separately verified all eight matched literals against SHA256 of the referenced tracked Git blobs at the exact finding commit. They are source identities, not credentials.

Only the eight exact immutable commit/path/rule/line fingerprints were appended. The scanner rules, content matching, path coverage and future-commit detection remain unchanged. A newly introduced value at the same path or a new path remains subject to detection. The historical 546-finding failure remains evidence of its original configuration and is not rewritten or retrospectively promoted.

Private comparison report SHA256: `0a8f06138e80495cd01bc3c8568aad48e2c3b3992cd03fcfbb8b5e872a09310e`.
Private Root classification SHA256: `26263acb914922b90a8d2ba1f6ce3ae020c435b8bd40d1aec3e087d6e23cd07f`.

The fresh full-history scan from this branch's own checkout remains required before claiming this gate cleared. Native, deployed, advisory, CI and original 728-requirement acceptance remain separate and unpromoted.
