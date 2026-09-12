# Precise search documents

BuildPreciseDocuments now joins committed V3 receipt bytes to their exact V2
archive. It decodes the precise receipt, reprojects the archive, compares every
item and effect digest, then constructs the existing search document shape.
Identity comes from the validated projection; observed lineage cannot promote
weak records. BuildDocuments retains its historical decoder and byte contract.

Superpowers evidence:

- After correcting fixture canonical serialization, the rejecting implementation
  failed the new strong/probable/unattributed document tests as expected.
- Search/projection/worker race suites passed1.609s/1.839s/14.886s. Expanded
  wrong-scope/batch/generation/digest and legacy-refusal tests passed1.569s.
- Tests compare exact replay bytes, sandbox/source bindings, display fields,
  metadata availability and absence of semantic identity on weak records.
- Independent review found no implementation issues. Its initial fixture
  limitation prompted qualified nanosecond lineage and1ns drift coverage.
- A fresh UI build exited0 and generated standalone output.

Worker dispatch, provider writes, queue routing, precise finalization and
production activation remain open. This local document builder is not deployed
search acceptance. No push or original task completion credit.
