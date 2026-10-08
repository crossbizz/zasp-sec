# Draft capture successor V2 — native cases executed: 0

This source-only successor preserves the V1 commit e1a7626d562a73419d040dcf4ebdb55edb46c86c and its original manifest/review unchanged. It changes only capture SQL and the associated PostgreSQL test; the source compiler/installer is byte-identical.

The SQL refuses required NULL arguments explicitly. A protected transient creation witness is inserted before invoking the unchanged original stage. Exact witness/effect xmin equality proves creation in the current subtransaction, including SAVEPOINT calls. The witness grants no authority, is removed before successful return, and rolls back atomically with effect/origin/audit writes. Existing originless work is still refused. No trigger, FK or definition is added to the predecessor catalogs.

The original eight prepared PostgreSQL groups remain, plus one grouped required-input/SAVEPOINT/concurrent-replay control. It checks NULL reason refusal, SAVEPOINT rollback and release, then two actual registered API transactions: it observes the original organization lock wait, commits the first capture and requires identical original replay plus exactly one inactive origin. These nine groups are **unrun**. This is source review, not native verification.

Correction to the historical V1 review's concurrency speculation: original native80 fence calls native79.revalidate, which locks the organization revision row FOR UPDATE before observing effect absence. Genuine same-organization captures serialize through that original lock. The proposed test checks this complete path; the old statement that two genuine captures can both observe absence is not established. The original raw review remains intact.

Fresh hosted checks on e1a7626 compiled all apiserver test sources through the successful selected signed-notification-delivery test step. They did not select the capture top. Both compliance browser checks subsequently failed api-ready/deadline with child stage unavailable. This establishes compilation of V1, not execution of these native capture cases or compilation of V2.

The current production enqueue route remains unchanged. All eight connector native lifecycle methods, genuine purpose/task projection, registered runtime pool/factory and workflow metadata permission remain unfinished. No Ready, activation, legacy authority, ledger promotion, provider/deployment or launch claim is made.

Byte-exact independent V2 review: `source-review-v2.json`, SHA256 82a75ee6eb607b43d8999fe4e6a2e454807db5ea8229dfa4be453aa9a23ae4fc. Byte-exact prepared source/control manifest: `source-manifest-v2.json`, SHA256 b0a0c7723334f35bc6d7c7c84f8dca9c91febc1f0fb8a779fa7dc856d816d9f9. Actual native execution still requires ROOT's admitted original PG/FGA fixture, selected source/embed/module/tool closure, resource floors and normal cleanup; private recipe paths are prepared artifacts, not runtime authority.
