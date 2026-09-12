# Shared production intake composition

The production resource factory now delegates repository, readiness cache, HTTP
router and reconciler wiring to `composeProductionIngestDependencies`. Database
connection/ping, cloud clients, S3 adapter construction and idempotent cleanup
remain in the resource factory. Composition failures return to its existing
resource cleanup path.

A composed test invokes this same wiring with declared database, artifact and
cloud-readiness boundaries. It proves release51 startup selection, V2 recovery
through the actual reconciler to artifact inspection and retry release, then
recovery and HTTP refusal after readiness drift despite cached healthy cloud
state. Temporarily selecting the historical reconciler reproduced abandoning
the V2 lease; precise selection was restored.

Full event-ingest race suite passed in1.496s and UI build passed. Independent
review found no issues and repeated targeted races in1.255s. This tests common production wiring, not live PostgreSQL
connection acquisition, AWS clients or deployed startup. The separate actual
PostgreSQL HTTP/recovery tests cover registered database semantics. No publication
or original microtask credit.
