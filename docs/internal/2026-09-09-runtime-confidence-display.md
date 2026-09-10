# M7-07c confidence and source display

Status: focused/full local verification and the final full Chrome run passed.
Shipping gates are pending. No M7-07c production credit yet.

Original scope: display source and Exact, Strong, Probable and Unattributed;
the Probable fixture must look different from Exact.

The production row and canonical evidence dialog now share one four-state
confidence component. It uses explicit labels, distinct badge tones and a short
description of each association. Probable explicitly says agent/session
association is not confirmed. The source field remains visible.

Four new test-first cases cover all labels, tones and descriptions. Existing row
and evidence tests first failed on their old lower-case display; the corrected
four-file selection passed 27 tests. Full Node 22 verification passed 196 test
files / 1,176 tests, generated API, typecheck, lint, build and source/compiled
boundaries. The source release gate passed.

## What the browser fixture proves

After the separately verified six-class worker proof, the owned disposable
database receives exactly two synthetic confidence-display rows: one Strong,
one Probable. The live product API and generated-client UI read those rows.
Probable retains null authoritative agent and session IDs. The browser compares
four labels, source text and computed foreground/background colors, then opens
the Probable evidence dialog to verify unknown identity.

The fixture removes only its two exact owned rows and compares all original
worker events and summaries byte-for-byte with their prior snapshot. It is not
a worker/provenance fixture and cannot establish Strong/Probable reachability.

The first Chrome run passed the four labels, source, computed colors, unknown
metadata and cleanup, then failed a responsive helper's heading assertion:
the helper searched h1/h2 for a Card's h3 title. Its target now names the visible
drawer h2, "Runtime timeline"; no product assertion or layout check was removed.
The corrected full Chrome run passed the confidence-display marker, subsequent
discovery/connector/Red Team/recovery flows and owned-process cleanup.

Independent review found no blocker in this narrow display implementation or
the explicitly synthetic fixture. After the full Chrome result, independent
review conditionally accepted M7-07c pending M7-07b's dependency gate and its own
shipping/main CI. M7-07's authentic mixed-evidence composition remains incomplete.

## Corrected earlier correlation credits

M3-46 and M3-47 inherited production credit from source/deployment reviews and
domain tests. Independent inspection found their production paths unreachable:
Tetragon ingestion does not retain lineage, OTLP retains only sandbox, the
matcher needs two matching lineage fields and its candidates are confined to
one single-source batch. Missing candidates yielding Unattributed do not prove
that concurrent ambiguity is handled.

Both tasks are now component-only under their unchanged T04 owner. Historical
completion records remain intact; production availability is corrected to
533 production-available, 134 component-only and 61 external gates. The new
regression failed on inherited credit, then all 27 ledger tests and the ledger
command passed after correcting task rows, M3/global counts and documentation.

Restoring these credits requires observed lineage and provenance-backed,
tenant-scoped candidate composition across batches, bounded event-time/host/boot
identity and receipt-bound replay. Confidence-display fixtures cannot close
that work.
