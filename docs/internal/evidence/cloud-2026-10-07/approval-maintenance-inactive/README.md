# Inactive approval maintenance verification

The linked report describes this component batch, its original task associations and remaining launch dependencies. Tests cover our application, integration and permission boundaries; they do not test Temporal or OpenFGA internals.

V4 reproduced the intended authority-denial regression, then passed 21 component test events. Its actual PostgreSQL preservation assertion failed: the test incorrectly checked only the discovery registry, omitting the original scheduler execution registry. The five other native cases passed. That failed raw output and result identity remain preserved.

V5 added four independent readiness observations, correct two-registry coverage and complete principal-row comparisons before/after installation. The cloud runtime restarted during that retry, leaving no final result or observed outer exit; it has no acceptance claim.

V6 retains every implementation/SQL byte and adds meaningful API configuration/payload controls. Its actual 1+6 native tests and 3+22 API boundary tests pass, with no failures/skips, normal outer exit 0 and both PostgreSQL server stop/wait exits 0. All 8,691 recorded inputs have equal pre/post maps. The flawed discovery-only predicate is false both before and after; all four real readiness predicates and the complete original principal rows are preserved. The actual source, results, joins and prior component-byte association were independently reviewed.

Public summaries are explicitly derived from unchanged private full results and input maps. Raw JSON test event streams are copied unchanged. Original V2 irregular-embed setup failure and the unexecuted overbroad V3 preparation checkpoint also remain privately retained. No ledger promotion, activation or production acceptance is inferred.
