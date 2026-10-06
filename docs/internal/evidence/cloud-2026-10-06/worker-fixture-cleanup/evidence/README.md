# Private worker fixture correction at exact baseline

Only two worker test files change. Production source, modules, caps, deadlines, security guards and frozen anchors retain exact baseline bytes. All tracked source blobs were independently compared to the baseline Git tree; exactly the two test paths differ.

The Temporal mock incorrectly asserted every JSONDatabase argument was json.RawMessage, although the real own runner uses json.Marshal bytes for its stop query. A controlled reserved-dispatch failure with the original cast reproduces the historical type panic. The correction accepts both legal JSON byte representations and covers reserved recovery, started/unknown no-resend, and cancellation without engine or settlement calls. Mocked SQL remains distinct from native authorization proof.

A controlled capture failure proves the compliance harness previously ignored an already-returned worker while waiting for upload. The corrected test observes terminal completion, preserves the one-second upload and two-second join limits, avoids mistaking simultaneous upload/completion for pre-upload failure, and checks a real pre-upload source-failure lifecycle has no Prepare/Put/Finish and source_failed accounting.

Both deterministic red checks failed against the original fixture behavior. The corrected four-test group passes normally and with the race detector. This does not establish the cause of the earlier compliance close upload failure or the earlier dispatch-validation error that triggered recovery. Those original failures remain evidence; the isolated unchanged baseline pair also passed and does not erase the full verification failure. No load assumption, timeout increase or production workaround is made.

No real providers, PostgreSQL, native attempts, shared source edits or commits occurred. Root must obtain independent review before any bounded integration. Fresh full verification remains a separate requirement.
