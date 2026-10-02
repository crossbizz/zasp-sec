# Export public workflow readiness

In progress. This is not feature acceptance or production enablement. Preserve
the original728 tasks and the required composite/multi-step workflows.

The existing export settlement capability only proves the installed job protocol.
It cannot advertise usable public definition creation or activation. A separate
installed admission probe now checks
`public.zasp_sa_export_workflow_readiness(text,text)` with exact release58 checksum
and fingerprint. `PostgresJSONDatabase.SecurityAgentExportDefinitionsAvailable`
returns false for an absent function, error for installed drift/unavailability,
and rejects nil/cancelled contexts or closed database before querying.

The catalog now consumes optional
`SecurityAgentExportsWorkflowAvailable(context.Context) (bool,error)` on its
repository. A true result publishes the existing create_evidence_export metadata;
false withdraws it and error refuses the catalog response. No static production
classification changed. Composite templates remain unchanged: advertising one
requires support for every action and its actual multi-step execution contract.

## Evidence so far

- Catalog behavioral RED session18952: ready=true yielded zero export actions.
  Package1.132s, exit1. Initial test's target assertion was corrected from a guessed
  security_agent_run to the existing catalog contract evidence before GREEN.
- Catalog plus existing Attack Lab/template identity checks session2738: exit0,
  package1.094s.
- Dedicated admission probe RED session97942: all four cases reported the
  capability missing, package1.033s, exit1.
- Five affected native groups session25243 passed, package1.104s:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver -run '^TestSecurityAgent(ExportDefinitionsRequireAdmissionRelease|ExportCapabilityReleaseChecks|ExportCatalogRequiresConnectedReadiness|AttackLabCatalogRequiresConnectedReadiness|TemplateIdentifiersPreserveExistingBoundary)$' -count=1
```

These are controlled capability-boundary checks, not registered admission SQL
or deployed worker proof. Independent component acceptance is recorded below.

## Connected work still required

The dedicated SQL readiness function is not implemented yet. Missing means
unavailable, never fallback to settlement capability. SQL owner confirmed this
name/signature does not conflict with the activation path; its claim-isolation
review correction takes priority before activation edits.

Production repository/decorator and configuration now connect the installed
admission probe to fixed private health checks for agentsec-security-agent,
agentsec-security-agent-action, zasp-compliance-export-worker and
zasp-compliance-cleanup-worker, all on8081/readyz. Follow the existing Attack Lab
bounded deadline, no redirects/proxy, closed readiness response and no positive
cache semantics. Require configured retrieval resources and explicit deployment
opt-in; callers cannot supply destinations. Deployment policies must still grant only
the needed same-namespace API-to-worker health paths (current compliance ingress
allows monitoring only). Inspect actual service definitions before changing them.

Then connect public draft/update/read/activation/control authority and real UI,
using current per-action scope, idempotency, fresh-auth and budget checks. Keep
release fingerprints and downgrade restoration exact. The authenticated public
flow must create its own definition/run/plan rather than owner-seeding them.
Full multi-step execution and existing-test lost-reply recovery remain required.
Batch the affected tests/review; do not mark this document as task completion.

## Production composition checkpoint

The closed opt-in is ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW=enabled;
empty is disabled and other values refuse configuration. Enabled composition
requires compliance retrieval configuration and the separate Security Agent
database. The readiness callback is installed only when the export download
surface was mounted. Each catalog check repeats installed public-admission and
settlement authority before checking the four private services.

The bounded HTTP probe engine is shared with the existing Attack Lab gate;
its deadline, single-flight sharing, no-positive-cache, no proxy/redirect and
closed-response behavior are unchanged. Each caller supplies an internal fixed
service list, copied by the engine. This does not validate live deployment or
provider identities.

Production-composed behavioral RED session95364: invalid opt-in accepted,
ready catalog omitted export, installed admission drift returned200, and an
enabled workflow accepted missing storage. Package1.092s, exit1. SQL and service
placement are controlled; catalog is produced by the actual API composition.
After wiring, the same tests plus affected Attack Lab and export composition
passed in session73168, package1.329s, exit0.

Affected race batch session17212 passed: apiserver2.920s, agentsec-api2.493s,
exit0, from services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver ./agentsec-api -run '^Test(SecurityAgent(ExportDefinitionsRequireAdmissionRelease|ExportCapabilityReleaseChecks|ExportCatalogRequiresConnectedReadiness|AttackLabCatalogRequiresConnectedReadiness|TemplateIdentifiersPreserveExistingBoundary|ExportAPIProductionComposition)|ExportWorkflow(ConfigurationIsClosed|ProductionCatalogRequiresWorkersAndAdmission)|AttackLabWorkflow.*|AttackLabProductionDecorator.*)$' -count=1
```

Candidate SHA256 hashes under services/platform:

```text
389140cf914eaead1723680444a2bc7c179398a45fa48dcea2d3d2c175e77f51 apiserver/workflow_handler.go
7865811db73eb5c096b87b2e6bd0122777067228cfef8e8bfea253cc6ce38295 apiserver/security_agent_export_catalog_test.go
fe191037ef80ad4d46c294e59c09e0b58879ac479a8781bb12925eefc6e5aff5 apiserver/security_agent_export_workflow_capability.go
9510287924bb1f876912cac6305d6a4853541a5c6541b7ec237d56087b37b701 apiserver/security_agent_export_workflow_capability_test.go
ae95790d7168483d2d39df06d50f44aad9afa9e1d5b1e45eebac026287a1b2fa agentsec-api/runtime.go
83af0a3f9d81028596888df5f5766519c3db89e80a55ae1e861704167ca519dc agentsec-api/production_runtime.go
0abad1cab348e474fa844f89a46e8bbf9d35074d9cb74b55dd5cc563ab639d50 agentsec-api/attack_lab_workflow_readiness.go
5f36ccf0997e346f20976537736a25ef6be4da41cd80bce1874cb20041fe776c agentsec-api/export_workflow_readiness.go
9835612cb43c534987366450a370b24e77f271d79758e81c6ceff63c37fd13bf agentsec-api/export_workflow_readiness_test.go
```

Independent bounded review accepted these nine source files with no actionable
findings. Root rechecked all nine hashes against this manifest after the review.
The reviewer checked the separate admission and settlement gates, explicit
opt-in, mounted retrieval requirement, four fixed endpoints, withdrawal and
installed-drift behavior, unchanged templates and shared probe restrictions.
The reviewer inspected reported race evidence but did not rerun it.

The dedicated admission SQL function,
definition/activation/control integration, deployment opt-in/network policy and
authenticated full workflow are not implemented by this component checkpoint.
