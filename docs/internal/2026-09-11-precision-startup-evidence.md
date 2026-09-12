# Explicit precision worker startup

Runtime configuration now permits archive2/index2/correlation4/project3/complete3.
Index2 requires the V2 session index target. Defaults and charts are unchanged.
Composition selects the immutable precision pipeline repository and checks
compiled51 readiness before work. Index2 also selects the precision search
authority and actual precise-capable session executor in its provider factory.

The startup composition test covers all five stages with healthy/unhealthy51
declared database responses, exact stage claim names and the index search claim.
Initial RED rejected the new configuration; the fixture also needed correction
to supply session dependencies only to the index worker. With that corrected,
all ten readiness/claim cases pass. Old unknown-version rejection tests now use
the next unsupported versions; authority/account/token checks remain intact.

Full worker race suite passed in19.233s and UI build passed. Independent review
found no issues in this startup slice. Migration51 still needs complete SQL verification/review, enrolled HTTP
V2 admission, composed provider/browser acceptance and deployment approval gates.
No manifests changed, no push, no production activation or original task credit.
