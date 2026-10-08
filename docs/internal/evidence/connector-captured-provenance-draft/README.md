# Draft captured connector enqueue provenance

This draft adds three source/test files based on f84adb35230dfe359efeda58da232d2c69ba29b5. Actual compiler, PostgreSQL and OpenFGA tests executed: **0**. Independent review covers source only; this is not verified native execution or production readiness.

The supplementary capture-only installer derives its real checksum and the unchanged original PKCE-stage source pin. The wrapper requires the original signed native80 browser/fresh-auth authorization and selected integration, then calls the original enqueue in the same transaction. It stores the verified source-proof digest separately from the actual committed request/effect digests and refuses existing originless work. It issues no task, grant, lease, lifecycle authority, activation or readiness decision.

The prepared PostgreSQL top has eight groups: genuine capture and replay/conflict, wrong purpose, wrong scope, modified envelope, originless refusal, transaction rollback, own-catalog drift and outbox-role refusal. These use the existing original composed native authorization/PG/FGA fixture; they have not run. The private prepared omission-RED recipe is also unrun.

Important open limits:

- NULL inputs, concurrent first capture and SAVEPOINT/subtransaction behavior are unverified. Concurrent captures can refuse one caller through the xmin guard; later replay can succeed. Subtransaction xmin can differ from the top-level transaction ID. Unchanged concurrent replay availability is not established.
- Source-proof verification does not claim that arbitrary request-body fields were signed. Future issuance must bind the stored committed-effect digest and genuine provenance.
- Current production enqueue routing is unchanged. All eight connector native worker lifecycle methods, registered runtime pool/factory, workflow metadata authority and full-family integration remain unfinished.
- No legacy originless work receives new authority. No ledger availability, deployment, external-writer withdrawal or launch claim is made.

`source-review.json` is the byte-exact independent source receipt, SHA256 a25adbaa41ccaf6875a5deab7f07c0b3b447c55fee9fb3c61073d303af99b898. `source-manifest.json` is the byte-exact reviewed private source/control manifest, SHA256 705bf3d597fdb0356a0fb15077e271056287110280ef8339a305ffafec6df0c5. Its three repository-file hashes bind this draft; private control paths describe prepared, unexecuted artifacts rather than a portable admitted runner.
