# Existing-test worker snapshot decoder checkpoint

M7A-21 stays component-only and disabled. The worker can now decode the guarded
database evidence envelope into complete-attempt artifact verification requests.
It checks the expected tenant, parent run, step, linked test run, ownership
version and unexpired deadline. Duplicate and aliased JSON fields are refused.
Scoped artifact references, output key, attempt bounds, test/target/category
identity and journal observations are checked before artifact retrieval.

Pending and terminal non-complete runs do not become evidence requests. Started
journals and persisted outcome_unknown errors both retain unknown status. A late
journal completion cannot erase a run's durable unknown classification. The
after-run error code is retained for the future reconciliation decision.

## Verification

- RED b5d052: tests could not compile because the decoder was not implemented.
- Initial focused decoder run bc83fb passed1.080s. These tests exercise claim
  identity substitutions, stale expiry, missing/null unknown flag, duplicate/
  aliased keys, changed artifact key and pending/unknown preservation.
- Independent review found that a failed/outcome_unknown run could lose its
  classification after all journal entries completed. RED af5fad reproduced
  exactly that shape. Final code preserves the persisted error as well as the
  journal flag. The review's null-observation test concern was also fixed:
  the negative now changes only observations, without adding another bad key.
- A decoded comparable baseline/current pair feeds the real artifactstore and
  existing comparison verifier, with four exact-version reads and a retained
  fail-to-pass proof. Storage remains a controlled in-memory provider fixture.
- Final grouped worker/actual Node race cb1075 passed5.892s:
  TestExistingTest, TestRedTeam, TestProductionRedTeamRunner, TestComposeRedTeam.
- Independent re-review found the Important issue resolved and no remaining
  Important findings in this decoder slice. No database tests were run by the
  reviewer. SQL and its compiled release fingerprint are unchanged.

This decoder accepts only bytes from the guarded database entrypoint once the
client is wired. Shape validation does not authenticate caller-supplied JSON.
Direct database-to-decoder acceptance, the registered client, lease-aware worker
composition and durable settlement are still open. A caller must check unknown
status before comparison and perform final ownership CAS at settlement. The
current tests are not live S3/provider/deployment proof.

No UI build, full release gate, commit or push is claimed. All728 original tasks
remain in scope; class counts stay534 production-available,133 component-only
and61 blocked/external. Accounting validation is not production acceptance.
