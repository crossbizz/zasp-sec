# Compliance prerequisite phase expectations

At commit `9ea88051fa0855ac886255d4a7c1bcdce366ddac`, hosted run 37592530973 passed runnable UI, ledger and current-profile diagnostics, then reported “Compliance browser unit prerequisites failed (exit 1)”. Log downloads were denied; the check annotation identifies this boundary only.

The identical four prerequisite test files locally reproduced 224 passes and one failure: the fixture error expected the old `compliance-current-fixture` label instead of the actual `compliance-current-fixture-sql`. The correction updates that expectation and adds a distinct seed failure control. The first correction accidentally used `compliance-current-fixture-seed`; its two-failure run is retained. The final expectation uses the actual `compliance-current-seed` label.

Node 22.23.1 command: `node --test scripts/browser-prerequisites.test.mjs scripts/browser-e2e-helpers.test.mjs scripts/owned-browser-postgres.test.mjs scripts/compliance-browser-bytes.test.mjs`.

Final result: 226 passes, zero failures/cancellations/skips. Raw failed TAP is represented losslessly in JSON, with its original byte digest; the successful TAP is unmodified. No assertions, startup allowances or release guards were removed. This addresses the reproduced prerequisite failure and does not prove deployed compliance acceptance or explain earlier browser failures. No ledger rows are promoted.
