# Precision ingestion repository

`NewPostgresPreciseProductionIngestRepository` explicitly selects compiled51
readiness. V2 reservations are Tetragon-only. The historical constructor still
rejects V2 reservation and replay lookup before database access.

Ready uses strict closed decoding and the runtime-ingest principal. Reserve,
LookupAcceptance and Finalize check51 again; a cached successful health result
doesn't authorize a later mutation or acceptance replay after drift. The existing
SQL methods retain credential binding and migration51 supplies persisted-schema
tuple selection and table-side guards. HTTP still rejects the V2 transport.

Superpowers RED reproduced V2 rejection without a database call, then the new
route passed focused tests. Full runtimeevent race suite passed in5.479s,
including schema/principal boundaries and readiness changing between health and
lookup/finalization. These use declared database responses, not deployed intake.
Independent review found no issues and UI build passed. No activation, push or task credit.
