# Feature-batch shipping policy

Approved by the user in the side conversation on 2026-09-17: implement the
acceleration recommendations and ship frequently. This changes execution cadence,
not the original 728-task scope or the separately approved collector scope.

## Execution rules

- Finish a coherent, dependency-complete feature batch before expanding work
  into another unfinished component. Choose boundaries that can be reviewed and
  shipped independently; don't split coupled SQL/client protocols across pushes.
- During development, use Superpowers TDD with focused tests for changed behavior.
  Run the relevant integration suite and independent review once per completed
  batch. After corrections, rerun affected checks; reuse other evidence only
  when the tested source and dependencies are unchanged.
- Preserve explicit tenant isolation, permission, migration, cancellation and
  failure-path coverage. Batching doesn't remove required assertions.
- Update the authoritative status ledger once per batch, with concise evidence
  pointers mapped to every original task it covers. Keep detailed run history in
  one batch checkpoint instead of repeatedly copying it into every ledger.
- Before each push, verify the UI build, runnable smoke path, required regression
  and release gates against the exact commit candidate. Ship to main after those
  gates pass, without waiting for every milestone or another approval prompt.
- Audit the existing dirty work before staging. Preserve unrelated work, avoid
  blanket staging, and keep unverified or coupled changes out of a shipped batch.
- Track external gates separately with the required evidence and dependency.
  Continue independent coding work while those gates remain unavailable.
- Report shipped commit, verified scope and remaining gates. A local test pass,
  component implementation or push alone is not deployed production proof.

No source changes, commits, pushes or production promotions were performed by
the side conversation when recording this policy. The main implementation task
owns execution and shipping to avoid competing writers.
