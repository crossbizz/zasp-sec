# Pending task cards

Execution companion to [the launch plan](README.md). Original requirements below are preserved verbatim. Every card is open in this planning snapshot; unchecked steps do not erase already accepted component evidence. Review the linked ledger row before doing work.

DISPATCH-GATE, SHIP-GATE and lane/file-ownership rules are defined in README.md. These cards are coordination stages, not complete coding recipes. Resolve exact files, contracts and focused checks once per selected packet at DISPATCH-GATE. Nearest pending upstream IDs include dependencies reached through historical production-available rows; they gate original acceptance at the release stage, not local verification. Contract-verified implementation and testing may overlap. Production promotion still requires the original prerequisites and correct proof scope.

<a id="m0-02"></a>
## M0-02: Stytch test config

Class: **component-only**. Owner: **T11-identity-admin**. Lane: **L3**. Batch: **identity-audit**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 680, exact task ID M0-02. Status/evidence: row `M0-02` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-01.
- Nearest pending prerequisites: none.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/apiserver`, `services/platform/audit`, `app/features/administration/AdminOperationsView.tsx`.
- Consumes: Stytch session/current membership and existing admin/audit API contracts.
- Produces: Current-authority admin mutations, scoped audit jobs and actual downloaded bytes.

**Original deliverable:** Wire a non-production Stytch project into a one-file proof without committing credentials.

**Original verification:** A test login/session can be created and repository secret scan remains clean.

- [ ] **M0-02.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-02 and locate the existing Stytch test config implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-01). Prepare bounded inputs and expected observations for this task's criterion: A test login/session can be created and repository secret scan remains clean. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-02.deliver** (depends on: M0-02.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Wire a non-production Stytch project into a one-file proof without committing credentials.
  Output: Wire a non-production Stytch project into a one-file proof without committing credentials.

- [ ] **M0-02.verify** (depends on: M0-02.deliver). Run or reuse eligible candidate-bound evidence in the identity-audit feature batch. Required assertion: A test login/session can be created and repository secret scan remains clean. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: A test login/session can be created and repository secret scan remains clean.

- [ ] **M0-02.release** (depends on: M0-02.verify, M0-01, SHIP-GATE). Have the batch reviewer map M0-02 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-03"></a>
## M0-03: Stytch JWT proof

Class: **component-only**. Owner: **T11-identity-admin**. Lane: **L3**. Batch: **identity-audit**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 686, exact task ID M0-03. Status/evidence: row `M0-03` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-02.
- Nearest pending prerequisites: M0-02.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/apiserver`, `services/platform/audit`, `app/features/administration/AdminOperationsView.tsx`.
- Consumes: Stytch session/current membership and existing admin/audit API contracts.
- Produces: Current-authority admin mutations, scoped audit jobs and actual downloaded bytes.

**Original deliverable:** Validate a fresh B2B session JWT through the Stytch backend SDK local-validation path.

**Original verification:** Validation succeeds locally when eligible and an expired/old token follows documented remote refresh/auth behavior.

- [ ] **M0-03.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-03 and locate the existing Stytch JWT proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-02). Prepare bounded inputs and expected observations for this task's criterion: Validation succeeds locally when eligible and an expired/old token follows documented remote refresh/auth behavior. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-03.deliver** (depends on: M0-03.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Validate a fresh B2B session JWT through the Stytch backend SDK local-validation path.
  Output: Validate a fresh B2B session JWT through the Stytch backend SDK local-validation path.

- [ ] **M0-03.verify** (depends on: M0-03.deliver). Run or reuse eligible candidate-bound evidence in the identity-audit feature batch. Required assertion: Validation succeeds locally when eligible and an expired/old token follows documented remote refresh/auth behavior. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Validation succeeds locally when eligible and an expired/old token follows documented remote refresh/auth behavior.

- [ ] **M0-03.release** (depends on: M0-03.verify, M0-02, SHIP-GATE). Have the batch reviewer map M0-03 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-06"></a>
## M0-06: LocalStack SQS proof

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 704, exact task ID M0-06. Status/evidence: row `M0-06` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-05.
- Nearest pending prerequisites: M0-03.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Create queue, DLQ and send/receive a batched event message in LocalStack.

**Original verification:** Message round trip and redrive attributes are asserted.

- [ ] **M0-06.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-06 and locate the existing LocalStack SQS proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-05). Prepare bounded inputs and expected observations for this task's criterion: Message round trip and redrive attributes are asserted. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-06.deliver** (depends on: M0-06.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create queue, DLQ and send/receive a batched event message in LocalStack.
  Output: Create queue, DLQ and send/receive a batched event message in LocalStack.

- [ ] **M0-06.verify** (depends on: M0-06.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Message round trip and redrive attributes are asserted. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Message round trip and redrive attributes are asserted.

- [ ] **M0-06.release** (depends on: M0-06.verify, M0-05, M0-03, SHIP-GATE). Have the batch reviewer map M0-06 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-07"></a>
## M0-07: LocalStack storage proof

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 710, exact task ID M0-07. Status/evidence: row `M0-07` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-06.
- Nearest pending prerequisites: M0-06.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Exercise LocalStack S3, KMS and Secrets Manager through the AWS SDK abstraction.

**Original verification:** Encrypted object and secret round trip succeeds.

- [ ] **M0-07.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-07 and locate the existing LocalStack storage proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-06). Prepare bounded inputs and expected observations for this task's criterion: Encrypted object and secret round trip succeeds. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-07.deliver** (depends on: M0-07.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Exercise LocalStack S3, KMS and Secrets Manager through the AWS SDK abstraction.
  Output: Exercise LocalStack S3, KMS and Secrets Manager through the AWS SDK abstraction.

- [ ] **M0-07.verify** (depends on: M0-07.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Encrypted object and secret round trip succeeds. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Encrypted object and secret round trip succeeds.

- [ ] **M0-07.release** (depends on: M0-07.verify, M0-06, SHIP-GATE). Have the batch reviewer map M0-07 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-08"></a>
## M0-08: OpenSearch proof

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 716, exact task ID M0-08. Status/evidence: row `M0-08` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-07.
- Nearest pending prerequisites: M0-07.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Index and filter one session event in a disposable OpenSearch target.

**Original verification:** Query by session/environment returns the expected event.

- [ ] **M0-08.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-08 and locate the existing OpenSearch proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-07). Prepare bounded inputs and expected observations for this task's criterion: Query by session/environment returns the expected event. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-08.deliver** (depends on: M0-08.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Index and filter one session event in a disposable OpenSearch target.
  Output: Index and filter one session event in a disposable OpenSearch target.

- [ ] **M0-08.verify** (depends on: M0-08.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Query by session/environment returns the expected event. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Query by session/environment returns the expected event.

- [ ] **M0-08.release** (depends on: M0-08.verify, M0-07, SHIP-GATE). Have the batch reviewer map M0-08 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-09"></a>
## M0-09: real AWS IAM proof

Class: **blocked/external**. Owner: **EXT-live-aws**. Lane: **L6**. Batch: **aws-parity**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 722, exact task ID M0-09. Status/evidence: row `M0-09` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-08.
- Nearest pending prerequisites: M0-08.
- External gate: EXT-live-aws.
- Primary source surfaces: `deploy/staging`, `cmd/agentsecctl`, `services/platform/connectors`.
- Consumes: Authorized isolated AWS account, exact role trust and bounded resource scope.
- Produces: Actual STS/IRSA allowed/denied observations and resource cleanup record.

**Original deliverable:** Assume one disposable cross-account/read-only role in an isolated AWS test account.

**Original verification:** Allowed call succeeds and denied call fails as expected.

- [ ] **M0-09.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-09 and locate the existing real AWS IAM proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-08). Prepare bounded inputs and expected observations for this task's criterion: Allowed call succeeds and denied call fails as expected. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-09.deliver** (depends on: M0-09.prepare, DISPATCH-GATE, EXT-live-aws). After the external prerequisite (Authorized isolated AWS account, exact role trust and bounded resource scope) is available: Assume one disposable cross-account/read-only role in an isolated AWS test account.
  Output: Assume one disposable cross-account/read-only role in an isolated AWS test account.

- [ ] **M0-09.verify** (depends on: M0-09.deliver). Run or reuse eligible candidate-bound evidence in the aws-parity feature batch. Required assertion: Allowed call succeeds and denied call fails as expected. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Allowed call succeeds and denied call fails as expected.

- [ ] **M0-09.release** (depends on: M0-09.verify, M0-08, SHIP-GATE). Have the batch reviewer map M0-09 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-10"></a>
## M0-10: Cartography proof

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 728, exact task ID M0-10. Status/evidence: row `M0-10` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-09.
- Nearest pending prerequisites: M0-09.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Run two minimal Cartography AWS/GitHub fixtures for different Organizations and inspect their graph output.

**Original verification:** Required source IDs and relationships normalize into separate Organization scopes with no collision or customer-visible Cartography labels.

- [ ] **M0-10.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-10 and locate the existing Cartography proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-09). Prepare bounded inputs and expected observations for this task's criterion: Required source IDs and relationships normalize into separate Organization scopes with no collision or customer-visible Cartography labels. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-10.deliver** (depends on: M0-10.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Run two minimal Cartography AWS/GitHub fixtures for different Organizations and inspect their graph output.
  Output: Run two minimal Cartography AWS/GitHub fixtures for different Organizations and inspect their graph output.

- [ ] **M0-10.verify** (depends on: M0-10.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Required source IDs and relationships normalize into separate Organization scopes with no collision or customer-visible Cartography labels. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Required source IDs and relationships normalize into separate Organization scopes with no collision or customer-visible Cartography labels.

- [ ] **M0-10.release** (depends on: M0-10.verify, M0-09, SHIP-GATE). Have the batch reviewer map M0-10 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-11"></a>
## M0-11: Prowler proof

Class: **component-only**. Owner: **T03-launch-connectors**. Lane: **L2**. Batch: **connectors**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 734, exact task ID M0-11. Status/evidence: row `M0-11` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-10.
- Nearest pending prerequisites: M0-10.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/connectors`, `services/platform/integration`, `workers/security-python`, `deploy/production`.
- Consumes: Saved connection configuration, scoped credentials and allowlisted destinations.
- Produces: Real connection/auth/proxy/discovery receipts and denied-egress evidence.

**Original deliverable:** Run a minimal Prowler AWS fixture and parse one relevant finding.

**Original verification:** Finding maps to a canonical resource ID and normalized evidence.

- [ ] **M0-11.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-11 and locate the existing Prowler proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-10). Prepare bounded inputs and expected observations for this task's criterion: Finding maps to a canonical resource ID and normalized evidence. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-11.deliver** (depends on: M0-11.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Run a minimal Prowler AWS fixture and parse one relevant finding.
  Output: Run a minimal Prowler AWS fixture and parse one relevant finding.

- [ ] **M0-11.verify** (depends on: M0-11.deliver). Run or reuse eligible candidate-bound evidence in the connectors feature batch. Required assertion: Finding maps to a canonical resource ID and normalized evidence. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Finding maps to a canonical resource ID and normalized evidence.

- [ ] **M0-11.release** (depends on: M0-11.verify, M0-10, SHIP-GATE). Have the batch reviewer map M0-11 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-14a"></a>
## M0-14a: Nango free boot proof

Class: **component-only**. Owner: **T03-launch-connectors**. Lane: **L2**. Batch: **connectors**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 752, exact task ID M0-14a. Status/evidence: row `M0-14a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-13.
- Nearest pending prerequisites: M0-11.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/connectors`, `services/platform/integration`, `workers/security-python`, `deploy/production`.
- Consumes: Saved connection configuration, scoped credentials and allowlisted destinations.
- Produces: Real connection/auth/proxy/discovery receipts and denied-egress evidence.

**Original deliverable:** Start the free self-hosted Nango build with only required Auth/Proxy dependencies.

**Original verification:** Health endpoint is reachable from the product test network.

- [ ] **M0-14a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-14a and locate the existing Nango free boot proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-13). Prepare bounded inputs and expected observations for this task's criterion: Health endpoint is reachable from the product test network. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-14a.deliver** (depends on: M0-14a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Start the free self-hosted Nango build with only required Auth/Proxy dependencies.
  Output: Start the free self-hosted Nango build with only required Auth/Proxy dependencies.

- [ ] **M0-14a.verify** (depends on: M0-14a.deliver). Run or reuse eligible candidate-bound evidence in the connectors feature batch. Required assertion: Health endpoint is reachable from the product test network. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Health endpoint is reachable from the product test network.

- [ ] **M0-14a.release** (depends on: M0-14a.verify, M0-13, M0-11, SHIP-GATE). Have the batch reviewer map M0-14a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-14b"></a>
## M0-14b: Nango OAuth proof

Class: **component-only**. Owner: **T03-launch-connectors**. Lane: **L2**. Batch: **connectors**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 758, exact task ID M0-14b. Status/evidence: row `M0-14b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-14a.
- Nearest pending prerequisites: M0-14a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/connectors`, `services/platform/integration`, `workers/security-python`, `deploy/production`.
- Consumes: Saved connection configuration, scoped credentials and allowlisted destinations.
- Produces: Real connection/auth/proxy/discovery receipts and denied-egress evidence.

**Original deliverable:** Complete one OAuth connection against a fixture provider through the product wrapper.

**Original verification:** Product receives a durable connection reference.

- [ ] **M0-14b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-14b and locate the existing Nango OAuth proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-14a). Prepare bounded inputs and expected observations for this task's criterion: Product receives a durable connection reference. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-14b.deliver** (depends on: M0-14b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Complete one OAuth connection against a fixture provider through the product wrapper.
  Output: Complete one OAuth connection against a fixture provider through the product wrapper.

- [ ] **M0-14b.verify** (depends on: M0-14b.deliver). Run or reuse eligible candidate-bound evidence in the connectors feature batch. Required assertion: Product receives a durable connection reference. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Product receives a durable connection reference.

- [ ] **M0-14b.release** (depends on: M0-14b.verify, M0-14a, SHIP-GATE). Have the batch reviewer map M0-14b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-14c"></a>
## M0-14c: Nango API key proof

Class: **component-only**. Owner: **T03-launch-connectors**. Lane: **L2**. Batch: **connectors**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 764, exact task ID M0-14c. Status/evidence: row `M0-14c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-14b.
- Nearest pending prerequisites: M0-14b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/connectors`, `services/platform/integration`, `workers/security-python`, `deploy/production`.
- Consumes: Saved connection configuration, scoped credentials and allowlisted destinations.
- Produces: Real connection/auth/proxy/discovery receipts and denied-egress evidence.

**Original deliverable:** Complete one API-key connection against a fixture provider through the product wrapper.

**Original verification:** Product receives a connection reference without storing the raw provider key in product state.

- [ ] **M0-14c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-14c and locate the existing Nango API key proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-14b). Prepare bounded inputs and expected observations for this task's criterion: Product receives a connection reference without storing the raw provider key in product state. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-14c.deliver** (depends on: M0-14c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Complete one API-key connection against a fixture provider through the product wrapper.
  Output: Complete one API-key connection against a fixture provider through the product wrapper.

- [ ] **M0-14c.verify** (depends on: M0-14c.deliver). Run or reuse eligible candidate-bound evidence in the connectors feature batch. Required assertion: Product receives a connection reference without storing the raw provider key in product state. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Product receives a connection reference without storing the raw provider key in product state.

- [ ] **M0-14c.release** (depends on: M0-14c.verify, M0-14b, SHIP-GATE). Have the batch reviewer map M0-14c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-14"></a>
## M0-14: Nango free auth proof

Class: **component-only**. Owner: **T03-launch-connectors**. Lane: **L2**. Batch: **connectors**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 770, exact task ID M0-14. Status/evidence: row `M0-14` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-14c.
- Nearest pending prerequisites: M0-14c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/connectors`, `services/platform/integration`, `workers/security-python`, `deploy/production`.
- Consumes: Saved connection configuration, scoped credentials and allowlisted destinations.
- Produces: Real connection/auth/proxy/discovery receipts and denied-egress evidence.

**Original deliverable:** Record the validated Nango free feature boundary for MVP.

**Original verification:** Proof explicitly marks Functions, Webhooks and MCP as out of scope.

- [ ] **M0-14.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-14 and locate the existing Nango free auth proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-14c). Prepare bounded inputs and expected observations for this task's criterion: Proof explicitly marks Functions, Webhooks and MCP as out of scope. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-14.deliver** (depends on: M0-14.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Record the validated Nango free feature boundary for MVP.
  Output: Record the validated Nango free feature boundary for MVP.

- [ ] **M0-14.verify** (depends on: M0-14.deliver). Run or reuse eligible candidate-bound evidence in the connectors feature batch. Required assertion: Proof explicitly marks Functions, Webhooks and MCP as out of scope. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Proof explicitly marks Functions, Webhooks and MCP as out of scope.

- [ ] **M0-14.release** (depends on: M0-14.verify, M0-14c, SHIP-GATE). Have the batch reviewer map M0-14 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-15"></a>
## M0-15: Nango proxy proof

Class: **component-only**. Owner: **T03-launch-connectors**. Lane: **L2**. Batch: **connectors**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 776, exact task ID M0-15. Status/evidence: row `M0-15` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-14.
- Nearest pending prerequisites: M0-14.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/connectors`, `services/platform/integration`, `workers/security-python`, `deploy/production`.
- Consumes: Saved connection configuration, scoped credentials and allowlisted destinations.
- Produces: Real connection/auth/proxy/discovery receipts and denied-egress evidence.

**Original deliverable:** Proxy one authenticated GET through free self-hosted Nango.

**Original verification:** Provider response succeeds and product code never persists the raw provider token.

- [ ] **M0-15.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-15 and locate the existing Nango proxy proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-14). Prepare bounded inputs and expected observations for this task's criterion: Provider response succeeds and product code never persists the raw provider token. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-15.deliver** (depends on: M0-15.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Proxy one authenticated GET through free self-hosted Nango.
  Output: Proxy one authenticated GET through free self-hosted Nango.

- [ ] **M0-15.verify** (depends on: M0-15.deliver). Run or reuse eligible candidate-bound evidence in the connectors feature batch. Required assertion: Provider response succeeds and product code never persists the raw provider token. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Provider response succeeds and product code never persists the raw provider token.

- [ ] **M0-15.release** (depends on: M0-15.verify, M0-14, SHIP-GATE). Have the batch reviewer map M0-15 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-16"></a>
## M0-16: Promptfoo proof

Class: **component-only**. Owner: **T12-red-team**. Lane: **L2**. Batch: **red-team**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 782, exact task ID M0-16. Status/evidence: row `M0-16` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-15.
- Nearest pending prerequisites: M0-15.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `workers/redteam-node`, `services/platform/agentsec-worker`.
- Consumes: Existing TestDefinition and bounded fake target contract.
- Produces: Normalized objective/verdict/evidence from the pinned runner.

**Original deliverable:** Run one prompt-injection case against a local fake agent target.

**Original verification:** Result can be normalized to objective, verdict and evidence reference.

- [ ] **M0-16.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-16 and locate the existing Promptfoo proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-15). Prepare bounded inputs and expected observations for this task's criterion: Result can be normalized to objective, verdict and evidence reference. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-16.deliver** (depends on: M0-16.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Run one prompt-injection case against a local fake agent target.
  Output: Run one prompt-injection case against a local fake agent target.

- [ ] **M0-16.verify** (depends on: M0-16.deliver). Run or reuse eligible candidate-bound evidence in the red-team feature batch. Required assertion: Result can be normalized to objective, verdict and evidence reference. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Result can be normalized to objective, verdict and evidence reference.

- [ ] **M0-16.release** (depends on: M0-16.verify, M0-15, SHIP-GATE). Have the batch reviewer map M0-16 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-18"></a>
## M0-18: Fargate verification proof

Class: **blocked/external**. Owner: **EXT-live-fargate**. Lane: **L6**. Batch: **fargate**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 794, exact task ID M0-18. Status/evidence: row `M0-18` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-17.
- Nearest pending prerequisites: M0-16.
- External gate: EXT-live-fargate.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `workers/redteam-node`.
- Consumes: Authorized disposable EKS/Fargate profile, canary target, SG/proxy and cleanup owner.
- Produces: Actual scheduling/canary and denied-direct/allowed-proxy egress with cleanup.

**Original deliverable:** Run a canary workload on an existing disposable EKS Fargate test profile.

**Original verification:** Pod is Fargate-scheduled, canary criterion is observed and run resources are deleted.

- [ ] **M0-18.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-18 and locate the existing Fargate verification proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-17). Prepare bounded inputs and expected observations for this task's criterion: Pod is Fargate-scheduled, canary criterion is observed and run resources are deleted. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-18.deliver** (depends on: M0-18.prepare, DISPATCH-GATE, EXT-live-fargate). After the external prerequisite (Authorized disposable EKS/Fargate profile, canary target, SG/proxy and cleanup owner) is available: Run a canary workload on an existing disposable EKS Fargate test profile.
  Output: Run a canary workload on an existing disposable EKS Fargate test profile.

- [ ] **M0-18.verify** (depends on: M0-18.deliver). Run or reuse eligible candidate-bound evidence in the fargate feature batch. Required assertion: Pod is Fargate-scheduled, canary criterion is observed and run resources are deleted. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Pod is Fargate-scheduled, canary criterion is observed and run resources are deleted.

- [ ] **M0-18.release** (depends on: M0-18.verify, M0-17, M0-16, SHIP-GATE). Have the batch reviewer map M0-18 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-19"></a>
## M0-19: Fargate egress proof

Class: **blocked/external**. Owner: **EXT-live-fargate**. Lane: **L6**. Batch: **fargate**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 800, exact task ID M0-19. Status/evidence: row `M0-19` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-18.
- Nearest pending prerequisites: M0-18.
- External gate: EXT-live-fargate.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `workers/redteam-node`.
- Consumes: Authorized disposable EKS/Fargate profile, canary target, SG/proxy and cleanup owner.
- Produces: Actual scheduling/canary and denied-direct/allowed-proxy egress with cleanup.

**Original deliverable:** Apply a SecurityGroupPolicy that permits only required cluster/DNS plus product egress-proxy path.

**Original verification:** Direct undeclared egress fails and allowed proxy egress succeeds.

- [ ] **M0-19.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-19 and locate the existing Fargate egress proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-18). Prepare bounded inputs and expected observations for this task's criterion: Direct undeclared egress fails and allowed proxy egress succeeds. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-19.deliver** (depends on: M0-19.prepare, DISPATCH-GATE, EXT-live-fargate). After the external prerequisite (Authorized disposable EKS/Fargate profile, canary target, SG/proxy and cleanup owner) is available: Apply a SecurityGroupPolicy that permits only required cluster/DNS plus product egress-proxy path.
  Output: Apply a SecurityGroupPolicy that permits only required cluster/DNS plus product egress-proxy path.

- [ ] **M0-19.verify** (depends on: M0-19.deliver). Run or reuse eligible candidate-bound evidence in the fargate feature batch. Required assertion: Direct undeclared egress fails and allowed proxy egress succeeds. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Direct undeclared egress fails and allowed proxy egress succeeds.

- [ ] **M0-19.release** (depends on: M0-19.verify, M0-18, SHIP-GATE). Have the batch reviewer map M0-19 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-20"></a>
## M0-20: PostHog privacy proof

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 806, exact task ID M0-20. Status/evidence: row `M0-20` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-19.
- Nearest pending prerequisites: M0-19.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Send one allowlisted analytics event to a fake PostHog endpoint.

**Original verification:** Serializer rejects seeded prompt, secret, IP and raw evidence fields.

- [ ] **M0-20.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-20 and locate the existing PostHog privacy proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-19). Prepare bounded inputs and expected observations for this task's criterion: Serializer rejects seeded prompt, secret, IP and raw evidence fields. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-20.deliver** (depends on: M0-20.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Send one allowlisted analytics event to a fake PostHog endpoint.
  Output: Send one allowlisted analytics event to a fake PostHog endpoint.

- [ ] **M0-20.verify** (depends on: M0-20.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Serializer rejects seeded prompt, secret, IP and raw evidence fields. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Serializer rejects seeded prompt, secret, IP and raw evidence fields.

- [ ] **M0-20.release** (depends on: M0-20.verify, M0-19, SHIP-GATE). Have the batch reviewer map M0-20 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-21"></a>
## M0-21: OpenRouter privacy proof

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 812, exact task ID M0-21. Status/evidence: row `M0-21` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-20.
- Nearest pending prerequisites: M0-20.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Send one redacted finding explanation to a fake OpenRouter-compatible endpoint.

**Original verification:** Seeded secret/PII fields are absent and structured result validates.

- [ ] **M0-21.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-21 and locate the existing OpenRouter privacy proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-20). Prepare bounded inputs and expected observations for this task's criterion: Seeded secret/PII fields are absent and structured result validates. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-21.deliver** (depends on: M0-21.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Send one redacted finding explanation to a fake OpenRouter-compatible endpoint.
  Output: Send one redacted finding explanation to a fake OpenRouter-compatible endpoint.

- [ ] **M0-21.verify** (depends on: M0-21.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Seeded secret/PII fields are absent and structured result validates. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Seeded secret/PII fields are absent and structured result validates.

- [ ] **M0-21.release** (depends on: M0-21.verify, M0-20, SHIP-GATE). Have the batch reviewer map M0-21 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-21a"></a>
## M0-21a: Security Agent planner boundary proof

Class: **component-only**. Owner: **T07-security-agent-authority**. Lane: **L1**. Batch: **agent-budget**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 818, exact task ID M0-21a. Status/evidence: row `M0-21a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-21.
- Nearest pending prerequisites: M0-21.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent`, `services/platform/agentsec-worker`, `services/platform/apiserver`, `services/platform/migrations`.
- Consumes: Immutable prepared plan, actual pricing policy, current lease, Organization budget and action controls.
- Produces: Bounded typed plans and accounted execution; no action after a budget stop.

**Original deliverable:** Send a structured security-response planning request containing untrusted injection text and a fixed two-action catalog to a fake OpenRouter-compatible endpoint.

**Original verification:** Returned plan validates only when it uses catalog actions and in-scope IDs; arbitrary URL/shell/action output is rejected by product validation.

- [ ] **M0-21a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-21a and locate the existing Security Agent planner boundary proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-21). Prepare bounded inputs and expected observations for this task's criterion: Returned plan validates only when it uses catalog actions and in-scope IDs; arbitrary URL/shell/action output is rejected by product validation. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-21a.deliver** (depends on: M0-21a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Send a structured security-response planning request containing untrusted injection text and a fixed two-action catalog to a fake OpenRouter-compatible endpoint.
  Output: Send a structured security-response planning request containing untrusted injection text and a fixed two-action catalog to a fake OpenRouter-compatible endpoint.

- [ ] **M0-21a.verify** (depends on: M0-21a.deliver). Run or reuse eligible candidate-bound evidence in the agent-budget feature batch. Required assertion: Returned plan validates only when it uses catalog actions and in-scope IDs; arbitrary URL/shell/action output is rejected by product validation. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Returned plan validates only when it uses catalog actions and in-scope IDs; arbitrary URL/shell/action output is rejected by product validation.

- [ ] **M0-21a.release** (depends on: M0-21a.verify, M0-21, SHIP-GATE). Have the batch reviewer map M0-21a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m0-22"></a>
## M0-22: OTLP export proof

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 824, exact task ID M0-22. Status/evidence: row `M0-22` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M0-21a.
- Nearest pending prerequisites: M0-21a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Export bounded operational telemetry through Collector to a fake OTLP sink.

**Original verification:** Exporter failure does not block the proof application.

- [ ] **M0-22.prepare** (depends on: none; preparation only). Read the current ledger evidence for M0-22 and locate the existing OTLP export proof implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M0-21a). Prepare bounded inputs and expected observations for this task's criterion: Exporter failure does not block the proof application. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M0-22.deliver** (depends on: M0-22.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Export bounded operational telemetry through Collector to a fake OTLP sink.
  Output: Export bounded operational telemetry through Collector to a fake OTLP sink.

- [ ] **M0-22.verify** (depends on: M0-22.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Exporter failure does not block the proof application. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Exporter failure does not block the proof application.

- [ ] **M0-22.release** (depends on: M0-22.verify, M0-21a, SHIP-GATE). Have the batch reviewer map M0-22 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-01b"></a>
## M1-01b: worker directories

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 862, exact task ID M1-01b. Status/evidence: row `M1-01b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-01a.
- Nearest pending prerequisites: M0-22.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Create Python security-worker and Node redteam-worker package skeletons.

**Original verification:** Each worker starts a no-op health command.

- [ ] **M1-01b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-01b and locate the existing worker directories implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-01a). Prepare bounded inputs and expected observations for this task's criterion: Each worker starts a no-op health command. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-01b.deliver** (depends on: M1-01b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create Python security-worker and Node redteam-worker package skeletons.
  Output: Create Python security-worker and Node redteam-worker package skeletons.

- [ ] **M1-01b.verify** (depends on: M1-01b.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Each worker starts a no-op health command. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Each worker starts a no-op health command.

- [ ] **M1-01b.release** (depends on: M1-01b.verify, M1-01a, M0-22, SHIP-GATE). Have the batch reviewer map M1-01b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-01c"></a>
## M1-01c: web and CLI directories

Class: **component-only**. Owner: **T10-product-ui**. Lane: **L3**. Batch: **agent-ui**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 868, exact task ID M1-01c. Status/evidence: row `M1-01c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-01b.
- Nearest pending prerequisites: M1-01b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `app/features/securityagents`, `apps/web/api`, `openapi/openapi.yaml`, `cmd/agentsecctl`.
- Consumes: Versioned product API/OpenAPI responses and current authorization contracts.
- Produces: API-backed simulator, ordered plan/step detail, approvals and scoped navigation.

**Original deliverable:** Create Next.js web shell and agentsecctl command skeleton.

**Original verification:** Web build and agentsecctl version command succeed.

- [ ] **M1-01c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-01c and locate the existing web and CLI directories implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-01b). Prepare bounded inputs and expected observations for this task's criterion: Web build and agentsecctl version command succeed. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-01c.deliver** (depends on: M1-01c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create Next.js web shell and agentsecctl command skeleton.
  Output: Create Next.js web shell and agentsecctl command skeleton.

- [ ] **M1-01c.verify** (depends on: M1-01c.deliver). Run or reuse eligible candidate-bound evidence in the agent-ui feature batch. Required assertion: Web build and agentsecctl version command succeed. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Web build and agentsecctl version command succeed.

- [ ] **M1-01c.release** (depends on: M1-01c.verify, M1-01b, SHIP-GATE). Have the batch reviewer map M1-01c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-30a"></a>
## M1-30a: local product manifests

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1072, exact task ID M1-30a. Status/evidence: row `M1-30a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-29.
- Nearest pending prerequisites: M1-01c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Create local Kubernetes manifests for product API, worker, event-ingest and runtime-gateway stubs.

**Original verification:** All four pods become Ready in local Kubernetes.

- [ ] **M1-30a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-30a and locate the existing local product manifests implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-29). Prepare bounded inputs and expected observations for this task's criterion: All four pods become Ready in local Kubernetes. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-30a.deliver** (depends on: M1-30a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create local Kubernetes manifests for product API, worker, event-ingest and runtime-gateway stubs.
  Output: Create local Kubernetes manifests for product API, worker, event-ingest and runtime-gateway stubs.

- [ ] **M1-30a.verify** (depends on: M1-30a.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: All four pods become Ready in local Kubernetes. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: All four pods become Ready in local Kubernetes.

- [ ] **M1-30a.release** (depends on: M1-30a.verify, M1-29, M1-01c, SHIP-GATE). Have the batch reviewer map M1-30a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-30b"></a>
## M1-30b: local graph manifest

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1078, exact task ID M1-30b. Status/evidence: row `M1-30b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-30a.
- Nearest pending prerequisites: M1-30a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Add local Neo4j service and persistent test volume configuration.

**Original verification:** Graph health is reachable only inside the local cluster.

- [ ] **M1-30b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-30b and locate the existing local graph manifest implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-30a). Prepare bounded inputs and expected observations for this task's criterion: Graph health is reachable only inside the local cluster. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-30b.deliver** (depends on: M1-30b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add local Neo4j service and persistent test volume configuration.
  Output: Add local Neo4j service and persistent test volume configuration.

- [ ] **M1-30b.verify** (depends on: M1-30b.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Graph health is reachable only inside the local cluster. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Graph health is reachable only inside the local cluster.

- [ ] **M1-30b.release** (depends on: M1-30b.verify, M1-30a, SHIP-GATE). Have the batch reviewer map M1-30b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-30c"></a>
## M1-30c: local observability manifest

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1084, exact task ID M1-30c. Status/evidence: row `M1-30c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-30b.
- Nearest pending prerequisites: M1-30b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Add local OpenTelemetry Collector with a no-egress debug/test sink.

**Original verification:** A test span reaches the local sink.

- [ ] **M1-30c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-30c and locate the existing local observability manifest implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-30b). Prepare bounded inputs and expected observations for this task's criterion: A test span reaches the local sink. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-30c.deliver** (depends on: M1-30c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add local OpenTelemetry Collector with a no-egress debug/test sink.
  Output: Add local OpenTelemetry Collector with a no-egress debug/test sink.

- [ ] **M1-30c.verify** (depends on: M1-30c.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: A test span reaches the local sink. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: A test span reaches the local sink.

- [ ] **M1-30c.release** (depends on: M1-30c.verify, M1-30b, SHIP-GATE). Have the batch reviewer map M1-30c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-30d"></a>
## M1-30d: local AWS emulator manifest

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1090, exact task ID M1-30d. Status/evidence: row `M1-30d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-30c.
- Nearest pending prerequisites: M1-30c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Add LocalStack service and endpoint environment variables for local AWS clients.

**Original verification:** A test S3 call uses the LocalStack endpoint.

- [ ] **M1-30d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-30d and locate the existing local AWS emulator manifest implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-30c). Prepare bounded inputs and expected observations for this task's criterion: A test S3 call uses the LocalStack endpoint. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-30d.deliver** (depends on: M1-30d.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add LocalStack service and endpoint environment variables for local AWS clients.
  Output: Add LocalStack service and endpoint environment variables for local AWS clients.

- [ ] **M1-30d.verify** (depends on: M1-30d.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: A test S3 call uses the LocalStack endpoint. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: A test S3 call uses the LocalStack endpoint.

- [ ] **M1-30d.release** (depends on: M1-30d.verify, M1-30c, SHIP-GATE). Have the batch reviewer map M1-30d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-30"></a>
## M1-30: local dev manifests

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1096, exact task ID M1-30. Status/evidence: row `M1-30` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-30d.
- Nearest pending prerequisites: M1-30d.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Add one local start target for the assembled manifests.

**Original verification:** Local environment starts without vendor dashboards exposed.

- [ ] **M1-30.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-30 and locate the existing local dev manifests implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-30d). Prepare bounded inputs and expected observations for this task's criterion: Local environment starts without vendor dashboards exposed. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-30.deliver** (depends on: M1-30.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add one local start target for the assembled manifests.
  Output: Add one local start target for the assembled manifests.

- [ ] **M1-30.verify** (depends on: M1-30.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Local environment starts without vendor dashboards exposed. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Local environment starts without vendor dashboards exposed.

- [ ] **M1-30.release** (depends on: M1-30.verify, M1-30d, SHIP-GATE). Have the batch reviewer map M1-30 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-31"></a>
## M1-31: LocalStack client factory

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1102, exact task ID M1-31. Status/evidence: row `M1-31` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-30.
- Nearest pending prerequisites: M1-30.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Add AWS endpoint override in product AWS client factory for local/CI only.

**Original verification:** Test points SQS/S3/KMS/Secrets/OpenSearch clients at LocalStack.

- [ ] **M1-31.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-31 and locate the existing LocalStack client factory implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-30). Prepare bounded inputs and expected observations for this task's criterion: Test points SQS/S3/KMS/Secrets/OpenSearch clients at LocalStack. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-31.deliver** (depends on: M1-31.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add AWS endpoint override in product AWS client factory for local/CI only.
  Output: Add AWS endpoint override in product AWS client factory for local/CI only.

- [ ] **M1-31.verify** (depends on: M1-31.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Test points SQS/S3/KMS/Secrets/OpenSearch clients at LocalStack. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Test points SQS/S3/KMS/Secrets/OpenSearch clients at LocalStack.

- [ ] **M1-31.release** (depends on: M1-31.verify, M1-30, SHIP-GATE). Have the batch reviewer map M1-31 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-33"></a>
## M1-33: SQS queue definitions

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1114, exact task ID M1-33. Status/evidence: row `M1-33` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-32.
- Nearest pending prerequisites: M1-31.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Define three queues and DLQs with message schema/retention settings.

**Original verification:** LocalStack provision test sees all queues/DLQs.

- [ ] **M1-33.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-33 and locate the existing SQS queue definitions implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-32). Prepare bounded inputs and expected observations for this task's criterion: LocalStack provision test sees all queues/DLQs. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-33.deliver** (depends on: M1-33.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Reuse the reviewed original three-queue/DLQ repair after verifying exact current source hashes and settings. Close candidate-bound release/publication evidence; do not rewrite queue definitions or treat LocalStack as live AWS parity.
  Output: Define three queues and DLQs with message schema/retention settings.

- [ ] **M1-33.verify** (depends on: M1-33.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: LocalStack provision test sees all queues/DLQs. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: LocalStack provision test sees all queues/DLQs.

- [ ] **M1-33.release** (depends on: M1-33.verify, M1-32, M1-31, SHIP-GATE). Have the batch reviewer map M1-33 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-34"></a>
## M1-34: S3 bucket layout

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1120, exact task ID M1-34. Status/evidence: row `M1-34` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-33.
- Nearest pending prerequisites: M1-33.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Define evidence/export/policy key prefixes and KMS configuration contract.

**Original verification:** Artifact key builder cannot escape organization/workspace prefix.

- [ ] **M1-34.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-34 and locate the existing S3 bucket layout implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-33). Prepare bounded inputs and expected observations for this task's criterion: Artifact key builder cannot escape organization/workspace prefix. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-34.deliver** (depends on: M1-34.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Define evidence/export/policy key prefixes and KMS configuration contract.
  Output: Define evidence/export/policy key prefixes and KMS configuration contract.

- [ ] **M1-34.verify** (depends on: M1-34.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Artifact key builder cannot escape organization/workspace prefix. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Artifact key builder cannot escape organization/workspace prefix.

- [ ] **M1-34.release** (depends on: M1-34.verify, M1-33, SHIP-GATE). Have the batch reviewer map M1-34 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1-36e"></a>
## M1-36e: M1 local infrastructure smoke

Class: **component-only**. Owner: **T04-discovery-worker**. Lane: **L2**. Batch: **discovery-sync**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1156, exact task ID M1-36e. Status/evidence: row `M1-36e` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-36d.
- Nearest pending prerequisites: M1-34.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/queuedefinition/definitions.go`, `services/platform/agentsec-worker`, `services/event-ingest`, `deploy/staging/product`.
- Consumes: Canonical Organization-scoped inventory/event/job contracts and existing queues.
- Produces: Discover/sync/freshness and durable scoped queue/storage observations.

**Original deliverable:** Run local Kubernetes and LocalStack smoke checks.

**Original verification:** Required local dependencies report healthy.

- [ ] **M1-36e.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1-36e and locate the existing M1 local infrastructure smoke implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-36d). Prepare bounded inputs and expected observations for this task's criterion: Required local dependencies report healthy. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1-36e.deliver** (depends on: M1-36e.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Run local Kubernetes and LocalStack smoke checks.
  Output: Run local Kubernetes and LocalStack smoke checks.

- [ ] **M1-36e.verify** (depends on: M1-36e.deliver). Run or reuse eligible candidate-bound evidence in the discovery-sync feature batch. Required assertion: Required local dependencies report healthy. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Required local dependencies report healthy.

- [ ] **M1-36e.release** (depends on: M1-36e.verify, M1-36d, M1-34, SHIP-GATE). Have the batch reviewer map M1-36e to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-01"></a>
## M1A-01: staging VPC module

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1248, exact task ID M1A-01. Status/evidence: row `M1A-01` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-36.
- Nearest pending prerequisites: M1-36e, M1-01c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Create minimal VPC/private-subnet Terraform module for the shared non-production SaaS staging environment.

**Original verification:** `terraform validate` passes and subnet outputs exist.

- [ ] **M1A-01.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-01 and locate the existing staging VPC module implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-36). Prepare bounded inputs and expected observations for this task's criterion: `terraform validate` passes and subnet outputs exist. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-01.deliver** (depends on: M1A-01.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create minimal VPC/private-subnet Terraform module for the shared non-production SaaS staging environment.
  Output: Create minimal VPC/private-subnet Terraform module for the shared non-production SaaS staging environment.

- [ ] **M1A-01.verify** (depends on: M1A-01.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: `terraform validate` passes and subnet outputs exist. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: `terraform validate` passes and subnet outputs exist.

- [ ] **M1A-01.release** (depends on: M1A-01.verify, M1-36, M1-36e, M1-01c, SHIP-GATE). Have the batch reviewer map M1A-01 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-02"></a>
## M1A-02: staging EKS module

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1254, exact task ID M1A-02. Status/evidence: row `M1A-02` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1A-01.
- Nearest pending prerequisites: M1A-01.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add minimal EKS cluster module consuming the staging VPC outputs.

**Original verification:** `terraform validate` passes and cluster outputs exist.

- [ ] **M1A-02.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-02 and locate the existing staging EKS module implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1A-01). Prepare bounded inputs and expected observations for this task's criterion: `terraform validate` passes and cluster outputs exist. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-02.deliver** (depends on: M1A-02.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add minimal EKS cluster module consuming the staging VPC outputs.
  Output: Add minimal EKS cluster module consuming the staging VPC outputs.

- [ ] **M1A-02.verify** (depends on: M1A-02.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: `terraform validate` passes and cluster outputs exist. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: `terraform validate` passes and cluster outputs exist.

- [ ] **M1A-02.release** (depends on: M1A-02.verify, M1A-01, SHIP-GATE). Have the batch reviewer map M1A-02 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-03"></a>
## M1A-03: staging S3 KMS Secrets

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1260, exact task ID M1A-03. Status/evidence: row `M1A-03` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1A-02.
- Nearest pending prerequisites: M1A-02.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add staging evidence/event-archive bucket, KMS key and Secrets Manager entries.

**Original verification:** Terraform plan shows encryption and no public bucket access.

- [ ] **M1A-03.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-03 and locate the existing staging S3 KMS Secrets implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1A-02). Prepare bounded inputs and expected observations for this task's criterion: Terraform plan shows encryption and no public bucket access. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-03.deliver** (depends on: M1A-03.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add staging evidence/event-archive bucket, KMS key and Secrets Manager entries.
  Output: Add staging evidence/event-archive bucket, KMS key and Secrets Manager entries.

- [ ] **M1A-03.verify** (depends on: M1A-03.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Terraform plan shows encryption and no public bucket access. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Terraform plan shows encryption and no public bucket access.

- [ ] **M1A-03.release** (depends on: M1A-03.verify, M1A-02, SHIP-GATE). Have the batch reviewer map M1A-03 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-04"></a>
## M1A-04: staging SQS DLQ

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1266, exact task ID M1A-04. Status/evidence: row `M1A-04` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1A-03.
- Nearest pending prerequisites: M1A-03.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add the three staging queues and DLQs using the product queue contract.

**Original verification:** Terraform plan has redrive policies and queue outputs.

- [ ] **M1A-04.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-04 and locate the existing staging SQS DLQ implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1A-03). Prepare bounded inputs and expected observations for this task's criterion: Terraform plan has redrive policies and queue outputs. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-04.deliver** (depends on: M1A-04.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add the three staging queues and DLQs using the product queue contract.
  Output: Add the three staging queues and DLQs using the product queue contract.

- [ ] **M1A-04.verify** (depends on: M1A-04.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Terraform plan has redrive policies and queue outputs. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Terraform plan has redrive policies and queue outputs.

- [ ] **M1A-04.release** (depends on: M1A-04.verify, M1A-03, SHIP-GATE). Have the batch reviewer map M1A-04 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-05"></a>
## M1A-05: staging OpenSearch

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1272, exact task ID M1A-05. Status/evidence: row `M1A-05` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1A-04.
- Nearest pending prerequisites: M1A-04.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add private staging OpenSearch domain using the current EventStore contract.

**Original verification:** Terraform plan has VPC-only access and encryption.

- [ ] **M1A-05.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-05 and locate the existing staging OpenSearch implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1A-04). Prepare bounded inputs and expected observations for this task's criterion: Terraform plan has VPC-only access and encryption. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-05.deliver** (depends on: M1A-05.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add private staging OpenSearch domain using the current EventStore contract.
  Output: Add private staging OpenSearch domain using the current EventStore contract.

- [ ] **M1A-05.verify** (depends on: M1A-05.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Terraform plan has VPC-only access and encryption. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Terraform plan has VPC-only access and encryption.

- [ ] **M1A-05.release** (depends on: M1A-05.verify, M1A-04, SHIP-GATE). Have the batch reviewer map M1A-05 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-06"></a>
## M1A-06: staging IAM IRSA

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1278, exact task ID M1A-06. Status/evidence: row `M1A-06` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1A-05.
- Nearest pending prerequisites: M1A-05.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add minimum IAM/IRSA roles for product stubs to reach staging S3, SQS and OpenSearch.

**Original verification:** Policy test denies unrelated write actions.

- [ ] **M1A-06.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-06 and locate the existing staging IAM IRSA implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1A-05). Prepare bounded inputs and expected observations for this task's criterion: Policy test denies unrelated write actions. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-06.deliver** (depends on: M1A-06.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add minimum IAM/IRSA roles for product stubs to reach staging S3, SQS and OpenSearch.
  Output: Add minimum IAM/IRSA roles for product stubs to reach staging S3, SQS and OpenSearch.

- [ ] **M1A-06.verify** (depends on: M1A-06.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Policy test denies unrelated write actions. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Policy test denies unrelated write actions.

- [ ] **M1A-06.release** (depends on: M1A-06.verify, M1A-05, SHIP-GATE). Have the batch reviewer map M1A-06 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-07"></a>
## M1A-07: staging product stub deploy

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1284, exact task ID M1A-07. Status/evidence: row `M1A-07` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1A-06.
- Nearest pending prerequisites: M1A-06.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Deploy web/API/worker/event-ingest stubs from M1 into the staging EKS cluster.

**Original verification:** Product endpoints become Ready without exposing vendor dashboards.

- [ ] **M1A-07.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-07 and locate the existing staging product stub deploy implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1A-06). Prepare bounded inputs and expected observations for this task's criterion: Product endpoints become Ready without exposing vendor dashboards. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-07.deliver** (depends on: M1A-07.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Deploy web/API/worker/event-ingest stubs from M1 into the staging EKS cluster.
  Output: Deploy web/API/worker/event-ingest stubs from M1 into the staging EKS cluster.

- [ ] **M1A-07.verify** (depends on: M1A-07.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Product endpoints become Ready without exposing vendor dashboards. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Product endpoints become Ready without exposing vendor dashboards.

- [ ] **M1A-07.release** (depends on: M1A-07.verify, M1A-06, SHIP-GATE). Have the batch reviewer map M1A-07 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-08"></a>
## M1A-08: staging AWS dependency smoke

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1290, exact task ID M1A-08. Status/evidence: row `M1A-08` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1A-07.
- Nearest pending prerequisites: M1A-07.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Exercise one scoped S3, SQS and OpenSearch operation from a product pod.

**Original verification:** All three calls succeed through IRSA and emit OTLP health evidence.

- [ ] **M1A-08.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-08 and locate the existing staging AWS dependency smoke implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1A-07). Prepare bounded inputs and expected observations for this task's criterion: All three calls succeed through IRSA and emit OTLP health evidence. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-08.deliver** (depends on: M1A-08.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Exercise one scoped S3, SQS and OpenSearch operation from a product pod.
  Output: Exercise one scoped S3, SQS and OpenSearch operation from a product pod.

- [ ] **M1A-08.verify** (depends on: M1A-08.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: All three calls succeed through IRSA and emit OTLP health evidence. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: All three calls succeed through IRSA and emit OTLP health evidence.

- [ ] **M1A-08.release** (depends on: M1A-08.verify, M1A-07, SHIP-GATE). Have the batch reviewer map M1A-08 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-09"></a>
## M1A-09: staging deployment evidence

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1296, exact task ID M1A-09. Status/evidence: row `M1A-09` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1A-08.
- Nearest pending prerequisites: M1A-08.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Record Terraform revision, cluster/version and product image hashes for later milestone smoke tests.

**Original verification:** Evidence record contains no credentials and is reproducible.

- [ ] **M1A-09.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-09 and locate the existing staging deployment evidence implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1A-08). Prepare bounded inputs and expected observations for this task's criterion: Evidence record contains no credentials and is reproducible. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-09.deliver** (depends on: M1A-09.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Record Terraform revision, cluster/version and product image hashes for later milestone smoke tests.
  Output: Record Terraform revision, cluster/version and product image hashes for later milestone smoke tests.

- [ ] **M1A-09.verify** (depends on: M1A-09.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Evidence record contains no credentials and is reproducible. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Evidence record contains no credentials and is reproducible.

- [ ] **M1A-09.release** (depends on: M1A-09.verify, M1A-08, SHIP-GATE). Have the batch reviewer map M1A-09 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m1a-10"></a>
## M1A-10: M1A gate

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1302, exact task ID M1A-10. Status/evidence: row `M1A-10` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1A-09.
- Nearest pending prerequisites: M1A-09.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Write the M1A gate result for minimal real-AWS staging readiness.

**Original verification:** Gate is PASS only when product stubs reach all required staging dependencies with private endpoints.

- [ ] **M1A-10.prepare** (depends on: none; preparation only). Read the current ledger evidence for M1A-10 and locate the existing M1A gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1A-09). Prepare bounded inputs and expected observations for this task's criterion: Gate is PASS only when product stubs reach all required staging dependencies with private endpoints. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M1A-10.deliver** (depends on: M1A-10.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Write the M1A gate result for minimal real-AWS staging readiness.
  Output: Write the M1A gate result for minimal real-AWS staging readiness.

- [ ] **M1A-10.verify** (depends on: M1A-10.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Gate is PASS only when product stubs reach all required staging dependencies with private endpoints. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Gate is PASS only when product stubs reach all required staging dependencies with private endpoints.

- [ ] **M1A-10.release** (depends on: M1A-10.verify, M1A-09, SHIP-GATE). Have the batch reviewer map M1A-10 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m2-33"></a>
## M2-33: API updateGroupMappings

Class: **component-only**. Owner: **T11-identity-admin**. Lane: **L3**. Batch: **identity-audit**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1544, exact task ID M2-33. Status/evidence: row `M2-33` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M2-32.
- Nearest pending prerequisites: M1-36e, M1-01c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/apiserver`, `services/platform/audit`, `app/features/administration/AdminOperationsView.tsx`.
- Consumes: Stytch session/current membership and existing admin/audit API contracts.
- Produces: Current-authority admin mutations, scoped audit jobs and actual downloaded bytes.

**Original deliverable:** Implement OpenAPI operation `updateGroupMappings` for `PATCH /api/v1/admin/group-mappings` using the existing service/store contract.

**Original verification:** Handler test covers authorized success plus one stable product error.

- [ ] **M2-33.prepare** (depends on: none; preparation only). Read the current ledger evidence for M2-33 and locate the existing API updateGroupMappings implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M2-32). Prepare bounded inputs and expected observations for this task's criterion: Handler test covers authorized success plus one stable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M2-33.deliver** (depends on: M2-33.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Reuse reviewed registered-role group-mapping update and deadlock correction if unchanged. Verify current candidate wiring and release evidence for permission change/session-token revocation; do not rebuild the accepted handler.
  Output: Implement OpenAPI operation `updateGroupMappings` for `PATCH /api/v1/admin/group-mappings` using the existing service/store contract.

- [ ] **M2-33.verify** (depends on: M2-33.deliver). Run or reuse eligible candidate-bound evidence in the identity-audit feature batch. Required assertion: Handler test covers authorized success plus one stable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Handler test covers authorized success plus one stable product error.

- [ ] **M2-33.release** (depends on: M2-33.verify, M2-32, M1-36e, M1-01c, SHIP-GATE). Have the batch reviewer map M2-33 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m2-41"></a>
## M2-41: API createAuditExport

Class: **component-only**. Owner: **T11-identity-admin**. Lane: **L3**. Batch: **identity-audit**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1604, exact task ID M2-41. Status/evidence: row `M2-41` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M2-40.
- Nearest pending prerequisites: M2-33.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/apiserver`, `services/platform/audit`, `app/features/administration/AdminOperationsView.tsx`.
- Consumes: Stytch session/current membership and existing admin/audit API contracts.
- Produces: Current-authority admin mutations, scoped audit jobs and actual downloaded bytes.

**Original deliverable:** Implement OpenAPI operation `createAuditExport` for `POST /api/v1/audit-exports` using the existing service/store contract.

**Original verification:** Handler test covers authorized success plus one stable product error.

- [ ] **M2-41.prepare** (depends on: none; preparation only). Read the current ledger evidence for M2-41 and locate the existing API createAuditExport implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M2-40). Prepare bounded inputs and expected observations for this task's criterion: Handler test covers authorized success plus one stable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M2-41.deliver** (depends on: M2-41.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Implement OpenAPI operation `createAuditExport` for `POST /api/v1/audit-exports` using the existing service/store contract.
  Output: Implement OpenAPI operation `createAuditExport` for `POST /api/v1/audit-exports` using the existing service/store contract.

- [ ] **M2-41.verify** (depends on: M2-41.deliver). Run or reuse eligible candidate-bound evidence in the identity-audit feature batch. Required assertion: Handler test covers authorized success plus one stable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Handler test covers authorized success plus one stable product error.

- [ ] **M2-41.release** (depends on: M2-41.verify, M2-40, M2-33, SHIP-GATE). Have the batch reviewer map M2-41 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m2-42"></a>
## M2-42: API getAuditExport

Class: **component-only**. Owner: **T11-identity-admin**. Lane: **L3**. Batch: **identity-audit**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1610, exact task ID M2-42. Status/evidence: row `M2-42` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M2-41.
- Nearest pending prerequisites: M2-41.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/apiserver`, `services/platform/audit`, `app/features/administration/AdminOperationsView.tsx`.
- Consumes: Stytch session/current membership and existing admin/audit API contracts.
- Produces: Current-authority admin mutations, scoped audit jobs and actual downloaded bytes.

**Original deliverable:** Implement OpenAPI operation `getAuditExport` for `GET /api/v1/audit-exports/{id}` using the existing service/store contract.

**Original verification:** Handler test covers authorized success plus one stable product error.

- [ ] **M2-42.prepare** (depends on: none; preparation only). Read the current ledger evidence for M2-42 and locate the existing API getAuditExport implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M2-41). Prepare bounded inputs and expected observations for this task's criterion: Handler test covers authorized success plus one stable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M2-42.deliver** (depends on: M2-42.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Implement OpenAPI operation `getAuditExport` for `GET /api/v1/audit-exports/{id}` using the existing service/store contract.
  Output: Implement OpenAPI operation `getAuditExport` for `GET /api/v1/audit-exports/{id}` using the existing service/store contract.

- [ ] **M2-42.verify** (depends on: M2-42.deliver). Run or reuse eligible candidate-bound evidence in the identity-audit feature batch. Required assertion: Handler test covers authorized success plus one stable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Handler test covers authorized success plus one stable product error.

- [ ] **M2-42.release** (depends on: M2-42.verify, M2-41, SHIP-GATE). Have the batch reviewer map M2-42 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m2-47"></a>
## M2-47: M2 gate

Class: **component-only**. Owner: **T11-identity-admin**. Lane: **L3**. Batch: **identity-audit**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1736, exact task ID M2-47. Status/evidence: row `M2-47` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M2-47e, M2-50.
- Nearest pending prerequisites: M2-42, M1-36e, M1-01c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/apiserver`, `services/platform/audit`, `app/features/administration/AdminOperationsView.tsx`.
- Consumes: Stytch session/current membership and existing admin/audit API contracts.
- Produces: Current-authority admin mutations, scoped audit jobs and actual downloaded bytes.

**Original deliverable:** Write the M2 gate result from identity/admin checks.

**Original verification:** Gate record is PASS without any direct Stytch dashboard dependency.

- [ ] **M2-47.prepare** (depends on: none; preparation only). Read the current ledger evidence for M2-47 and locate the existing M2 gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M2-47e, M2-50). Prepare bounded inputs and expected observations for this task's criterion: Gate record is PASS without any direct Stytch dashboard dependency. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M2-47.deliver** (depends on: M2-47.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Write the M2 gate result from identity/admin checks.
  Output: Write the M2 gate result from identity/admin checks.

- [ ] **M2-47.verify** (depends on: M2-47.deliver). Run or reuse eligible candidate-bound evidence in the identity-audit feature batch. Required assertion: Gate record is PASS without any direct Stytch dashboard dependency. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Gate record is PASS without any direct Stytch dashboard dependency.

- [ ] **M2-47.release** (depends on: M2-47.verify, M2-47e, M2-50, M2-42, M1-36e, M1-01c, SHIP-GATE). Have the batch reviewer map M2-47 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m3-14"></a>
## M3-14: AWS credential adapter

Class: **blocked/external**. Owner: **EXT-live-aws**. Lane: **L6**. Batch: **aws-parity**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 1828, exact task ID M3-14. Status/evidence: row `M3-14` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M3-13, M1A-10.
- Nearest pending prerequisites: M1-36e, M1-01c, M1A-10.
- External gate: EXT-live-aws.
- Primary source surfaces: `deploy/staging`, `cmd/agentsecctl`, `services/platform/connectors`.
- Consumes: Authorized isolated AWS account, exact role trust and bounded resource scope.
- Produces: Actual STS/IRSA allowed/denied observations and resource cleanup record.

**Original deliverable:** Implement AWS role-assumption/identity check using customer integration config.

**Original verification:** Local fixture plus real-AWS denial fixture pass.

- [ ] **M3-14.prepare** (depends on: none; preparation only). Read the current ledger evidence for M3-14 and locate the existing AWS credential adapter implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M3-13, M1A-10). Prepare bounded inputs and expected observations for this task's criterion: Local fixture plus real-AWS denial fixture pass. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M3-14.deliver** (depends on: M3-14.prepare, DISPATCH-GATE, EXT-live-aws). After the external prerequisite (Authorized isolated AWS account, exact role trust and bounded resource scope) is available: Implement AWS role-assumption/identity check using customer integration config.
  Output: Implement AWS role-assumption/identity check using customer integration config.

- [ ] **M3-14.verify** (depends on: M3-14.deliver). Run or reuse eligible candidate-bound evidence in the aws-parity feature batch. Required assertion: Local fixture plus real-AWS denial fixture pass. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Local fixture plus real-AWS denial fixture pass.

- [ ] **M3-14.release** (depends on: M3-14.verify, M3-13, M1A-10, M1-36e, M1-01c, SHIP-GATE). Have the batch reviewer map M3-14 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m3-52"></a>
## M3-52: M3 gate

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 2188, exact task ID M3-52. Status/evidence: row `M3-52` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M3-52e.
- Nearest pending prerequisites: M3-14.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Write the M3 gate result from connector, sensor, ingest, queue/index and freshness checks.

**Original verification:** Gate record is PASS only when all independent checks passed.

- [ ] **M3-52.prepare** (depends on: none; preparation only). Read the current ledger evidence for M3-52 and locate the existing M3 gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M3-52e). Prepare bounded inputs and expected observations for this task's criterion: Gate record is PASS only when all independent checks passed. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M3-52.deliver** (depends on: M3-52.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Write the M3 gate result from connector, sensor, ingest, queue/index and freshness checks.
  Output: Write the M3 gate result from connector, sensor, ingest, queue/index and freshness checks.

- [ ] **M3-52.verify** (depends on: M3-52.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: Gate record is PASS only when all independent checks passed. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Gate record is PASS only when all independent checks passed.

- [ ] **M3-52.release** (depends on: M3-52.verify, M3-52e, M3-14, SHIP-GATE). Have the batch reviewer map M3-52 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-08"></a>
## M7-08: compliance control model

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3222, exact task ID M7-08. Status/evidence: row `M7-08` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-07.
- Nearest pending prerequisites: M2-47, M3-52, M1A-10.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Define MVP SOC 2 Security/HIPAA safeguard mapping objects and evidence freshness.

**Original verification:** Mapping references product evidence IDs, not screenshots.

- [ ] **M7-08.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-08 and locate the existing compliance control model implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-07). Prepare bounded inputs and expected observations for this task's criterion: Mapping references product evidence IDs, not screenshots. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-08.deliver** (depends on: M7-08.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Define MVP SOC 2 Security/HIPAA safeguard mapping objects and evidence freshness.
  Output: Define MVP SOC 2 Security/HIPAA safeguard mapping objects and evidence freshness.

- [ ] **M7-08.verify** (depends on: M7-08.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Mapping references product evidence IDs, not screenshots. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Mapping references product evidence IDs, not screenshots.

- [ ] **M7-08.release** (depends on: M7-08.verify, M7-07, M2-47, M3-52, M1A-10, SHIP-GATE). Have the batch reviewer map M7-08 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-09"></a>
## M7-09: compliance evidence assembler

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3228, exact task ID M7-09. Status/evidence: row `M7-09` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-08.
- Nearest pending prerequisites: M7-08.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Assemble current audit/finding/policy/test/config evidence for one control.

**Original verification:** Stale evidence is explicitly marked.

- [ ] **M7-09.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-09 and locate the existing compliance evidence assembler implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-08). Prepare bounded inputs and expected observations for this task's criterion: Stale evidence is explicitly marked. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-09.deliver** (depends on: M7-09.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Assemble current audit/finding/policy/test/config evidence for one control.
  Output: Assemble current audit/finding/policy/test/config evidence for one control.

- [ ] **M7-09.verify** (depends on: M7-09.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Stale evidence is explicitly marked. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Stale evidence is explicitly marked.

- [ ] **M7-09.release** (depends on: M7-09.verify, M7-08, SHIP-GATE). Have the batch reviewer map M7-09 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-10"></a>
## M7-10: API listComplianceControls

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3234, exact task ID M7-10. Status/evidence: row `M7-10` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-09.
- Nearest pending prerequisites: M7-09.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Implement OpenAPI operation `listComplianceControls` for `GET /api/v1/compliance/controls` using the existing service/store contract.

**Original verification:** Handler test covers authorized success plus one stable product error.

- [ ] **M7-10.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-10 and locate the existing API listComplianceControls implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-09). Prepare bounded inputs and expected observations for this task's criterion: Handler test covers authorized success plus one stable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-10.deliver** (depends on: M7-10.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Implement OpenAPI operation `listComplianceControls` for `GET /api/v1/compliance/controls` using the existing service/store contract.
  Output: Implement OpenAPI operation `listComplianceControls` for `GET /api/v1/compliance/controls` using the existing service/store contract.

- [ ] **M7-10.verify** (depends on: M7-10.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Handler test covers authorized success plus one stable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Handler test covers authorized success plus one stable product error.

- [ ] **M7-10.release** (depends on: M7-10.verify, M7-09, SHIP-GATE). Have the batch reviewer map M7-10 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-11"></a>
## M7-11: API listComplianceEvidence

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3240, exact task ID M7-11. Status/evidence: row `M7-11` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-10.
- Nearest pending prerequisites: M7-10.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Implement OpenAPI operation `listComplianceEvidence` for `GET /api/v1/compliance/evidence` using the existing service/store contract.

**Original verification:** Handler test covers authorized success plus one stable product error.

- [ ] **M7-11.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-11 and locate the existing API listComplianceEvidence implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-10). Prepare bounded inputs and expected observations for this task's criterion: Handler test covers authorized success plus one stable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-11.deliver** (depends on: M7-11.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Implement OpenAPI operation `listComplianceEvidence` for `GET /api/v1/compliance/evidence` using the existing service/store contract.
  Output: Implement OpenAPI operation `listComplianceEvidence` for `GET /api/v1/compliance/evidence` using the existing service/store contract.

- [ ] **M7-11.verify** (depends on: M7-11.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Handler test covers authorized success plus one stable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Handler test covers authorized success plus one stable product error.

- [ ] **M7-11.release** (depends on: M7-11.verify, M7-10, SHIP-GATE). Have the batch reviewer map M7-11 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-12"></a>
## M7-12: API createComplianceExport

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3246, exact task ID M7-12. Status/evidence: row `M7-12` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-11.
- Nearest pending prerequisites: M7-11.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Implement OpenAPI operation `createComplianceExport` for `POST /api/v1/compliance/exports` using the existing service/store contract.

**Original verification:** Handler test covers authorized success plus one stable product error.

- [ ] **M7-12.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-12 and locate the existing API createComplianceExport implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-11). Prepare bounded inputs and expected observations for this task's criterion: Handler test covers authorized success plus one stable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-12.deliver** (depends on: M7-12.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Implement OpenAPI operation `createComplianceExport` for `POST /api/v1/compliance/exports` using the existing service/store contract.
  Output: Implement OpenAPI operation `createComplianceExport` for `POST /api/v1/compliance/exports` using the existing service/store contract.

- [ ] **M7-12.verify** (depends on: M7-12.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Handler test covers authorized success plus one stable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Handler test covers authorized success plus one stable product error.

- [ ] **M7-12.release** (depends on: M7-12.verify, M7-11, SHIP-GATE). Have the batch reviewer map M7-12 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-13"></a>
## M7-13: API getComplianceExport

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3252, exact task ID M7-13. Status/evidence: row `M7-13` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-12.
- Nearest pending prerequisites: M7-12.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Implement OpenAPI operation `getComplianceExport` for `GET /api/v1/compliance/exports/{id}` using the existing service/store contract.

**Original verification:** Handler test covers authorized success plus one stable product error.

- [ ] **M7-13.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-13 and locate the existing API getComplianceExport implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-12). Prepare bounded inputs and expected observations for this task's criterion: Handler test covers authorized success plus one stable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-13.deliver** (depends on: M7-13.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Implement OpenAPI operation `getComplianceExport` for `GET /api/v1/compliance/exports/{id}` using the existing service/store contract.
  Output: Implement OpenAPI operation `getComplianceExport` for `GET /api/v1/compliance/exports/{id}` using the existing service/store contract.

- [ ] **M7-13.verify** (depends on: M7-13.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Handler test covers authorized success plus one stable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Handler test covers authorized success plus one stable product error.

- [ ] **M7-13.release** (depends on: M7-13.verify, M7-12, SHIP-GATE). Have the batch reviewer map M7-13 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-14"></a>
## M7-14: compliance export artifact

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3258, exact task ID M7-14. Status/evidence: row `M7-14` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-13.
- Nearest pending prerequisites: M7-13.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Create JSON/CSV plus human-readable evidence package in S3.

**Original verification:** Package links evidence IDs/timestamps and avoids certification language.

- [ ] **M7-14.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-14 and locate the existing compliance export artifact implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-13). Prepare bounded inputs and expected observations for this task's criterion: Package links evidence IDs/timestamps and avoids certification language. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-14.deliver** (depends on: M7-14.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create JSON/CSV plus human-readable evidence package in S3.
  Output: Create JSON/CSV plus human-readable evidence package in S3.

- [ ] **M7-14.verify** (depends on: M7-14.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Package links evidence IDs/timestamps and avoids certification language. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Package links evidence IDs/timestamps and avoids certification language.

- [ ] **M7-14.release** (depends on: M7-14.verify, M7-13, SHIP-GATE). Have the batch reviewer map M7-14 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-15a"></a>
## M7-15a: Compliance framework/control list

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3264, exact task ID M7-15a. Status/evidence: row `M7-15a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-14.
- Nearest pending prerequisites: M7-14.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Build SOC 2 Security and HIPAA safeguard control list.

**Original verification:** Fixture renders mapped controls without certification language.

- [ ] **M7-15a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-15a and locate the existing Compliance framework/control list implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-14). Prepare bounded inputs and expected observations for this task's criterion: Fixture renders mapped controls without certification language. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-15a.deliver** (depends on: M7-15a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Build SOC 2 Security and HIPAA safeguard control list.
  Output: Build SOC 2 Security and HIPAA safeguard control list.

- [ ] **M7-15a.verify** (depends on: M7-15a.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Fixture renders mapped controls without certification language. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Fixture renders mapped controls without certification language.

- [ ] **M7-15a.release** (depends on: M7-15a.verify, M7-14, SHIP-GATE). Have the batch reviewer map M7-15a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-15b"></a>
## M7-15b: Compliance evidence table

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3270, exact task ID M7-15b. Status/evidence: row `M7-15b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-15a.
- Nearest pending prerequisites: M7-15a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Build evidence rows with asset/source/timestamp links.

**Original verification:** Click opens product evidence target.

- [ ] **M7-15b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-15b and locate the existing Compliance evidence table implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-15a). Prepare bounded inputs and expected observations for this task's criterion: Click opens product evidence target. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-15b.deliver** (depends on: M7-15b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Build evidence rows with asset/source/timestamp links.
  Output: Build evidence rows with asset/source/timestamp links.

- [ ] **M7-15b.verify** (depends on: M7-15b.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Click opens product evidence target. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Click opens product evidence target.

- [ ] **M7-15b.release** (depends on: M7-15b.verify, M7-15a, SHIP-GATE). Have the batch reviewer map M7-15b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-15d"></a>
## M7-15d: Compliance export action

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3282, exact task ID M7-15d. Status/evidence: row `M7-15d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-15c.
- Nearest pending prerequisites: M7-15b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Add evidence export trigger and job-status UI.

**Original verification:** Queued/completed/error states render.

- [ ] **M7-15d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-15d and locate the existing Compliance export action implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-15c). Prepare bounded inputs and expected observations for this task's criterion: Queued/completed/error states render. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-15d.deliver** (depends on: M7-15d.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add evidence export trigger and job-status UI.
  Output: Add evidence export trigger and job-status UI.

- [ ] **M7-15d.verify** (depends on: M7-15d.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: Queued/completed/error states render. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Queued/completed/error states render.

- [ ] **M7-15d.release** (depends on: M7-15d.verify, M7-15c, M7-15b, SHIP-GATE). Have the batch reviewer map M7-15d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-15"></a>
## M7-15: Compliance Evidence UI

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **compliance-export**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3288, exact task ID M7-15. Status/evidence: row `M7-15` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-15d.
- Nearest pending prerequisites: M7-15d.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Compose Compliance Evidence list, freshness and export interaction.

**Original verification:** E2E filter/export flow passes.

- [ ] **M7-15.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-15 and locate the existing Compliance Evidence UI implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-15d). Prepare bounded inputs and expected observations for this task's criterion: E2E filter/export flow passes. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-15.deliver** (depends on: M7-15.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Compose Compliance Evidence list, freshness and export interaction.
  Output: Compose Compliance Evidence list, freshness and export interaction.

- [ ] **M7-15.verify** (depends on: M7-15.deliver). Run or reuse eligible candidate-bound evidence in the compliance-export feature batch. Required assertion: E2E filter/export flow passes. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: E2E filter/export flow passes.

- [ ] **M7-15.release** (depends on: M7-15.verify, M7-15d, SHIP-GATE). Have the batch reviewer map M7-15 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-19"></a>
## M7-19: retention worker

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3312, exact task ID M7-19. Status/evidence: row `M7-19` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-18.
- Nearest pending prerequisites: M7-15.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Delete/expire product-controlled event/evidence references according to data class policy.

**Original verification:** Fixture deletes expired test data and audits admin policy change.

- [ ] **M7-19.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-19 and locate the existing retention worker implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-18). Prepare bounded inputs and expected observations for this task's criterion: Fixture deletes expired test data and audits admin policy change. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-19.deliver** (depends on: M7-19.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Delete/expire product-controlled event/evidence references according to data class policy.
  Output: Delete/expire product-controlled event/evidence references according to data class policy.

- [ ] **M7-19.verify** (depends on: M7-19.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Fixture deletes expired test data and audits admin policy change. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Fixture deletes expired test data and audits admin policy change.

- [ ] **M7-19.release** (depends on: M7-19.verify, M7-18, M7-15, SHIP-GATE). Have the batch reviewer map M7-19 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-22"></a>
## M7-22: API updateExternalDataFlows

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3330, exact task ID M7-22. Status/evidence: row `M7-22` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-21.
- Nearest pending prerequisites: M7-19.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Implement OpenAPI operation `updateExternalDataFlows` for `PATCH /api/v1/settings/external-data-flows` using the existing service/store contract.

**Original verification:** Handler test covers authorized success plus one stable product error.

- [ ] **M7-22.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-22 and locate the existing API updateExternalDataFlows implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-21). Prepare bounded inputs and expected observations for this task's criterion: Handler test covers authorized success plus one stable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-22.deliver** (depends on: M7-22.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Implement OpenAPI operation `updateExternalDataFlows` for `PATCH /api/v1/settings/external-data-flows` using the existing service/store contract.
  Output: Implement OpenAPI operation `updateExternalDataFlows` for `PATCH /api/v1/settings/external-data-flows` using the existing service/store contract.

- [ ] **M7-22.verify** (depends on: M7-22.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Handler test covers authorized success plus one stable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Handler test covers authorized success plus one stable product error.

- [ ] **M7-22.release** (depends on: M7-22.verify, M7-21, M7-19, SHIP-GATE). Have the batch reviewer map M7-22 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-22a"></a>
## M7-22a: required external-flow guard

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3336, exact task ID M7-22a. Status/evidence: row `M7-22a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-22.
- Nearest pending prerequisites: M7-22.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Prevent the External Data Flows API from disabling required Stytch or Neon dependencies while allowing optional PostHog, OpenRouter and remote OTLP changes.

**Original verification:** Required-service disable fixture is rejected; optional-service disable fixture succeeds and is audited.

- [ ] **M7-22a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-22a and locate the existing required external-flow guard implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-22). Prepare bounded inputs and expected observations for this task's criterion: Required-service disable fixture is rejected; optional-service disable fixture succeeds and is audited. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-22a.deliver** (depends on: M7-22a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Prevent the External Data Flows API from disabling required Stytch or Neon dependencies while allowing optional PostHog, OpenRouter and remote OTLP changes.
  Output: Prevent the External Data Flows API from disabling required Stytch or Neon dependencies while allowing optional PostHog, OpenRouter and remote OTLP changes.

- [ ] **M7-22a.verify** (depends on: M7-22a.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Required-service disable fixture is rejected; optional-service disable fixture succeeds and is audited. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Required-service disable fixture is rejected; optional-service disable fixture succeeds and is audited.

- [ ] **M7-22a.release** (depends on: M7-22a.verify, M7-22, SHIP-GATE). Have the batch reviewer map M7-22a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-23"></a>
## M7-23: PostHog serializer

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3342, exact task ID M7-23. Status/evidence: row `M7-23` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-22a.
- Nearest pending prerequisites: M7-22a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Create allowlist-only product event serializer.

**Original verification:** Prompt/tool args/secrets/IP/raw evidence fixtures fail serialization.

- [ ] **M7-23.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-23 and locate the existing PostHog serializer implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-22a). Prepare bounded inputs and expected observations for this task's criterion: Prompt/tool args/secrets/IP/raw evidence fixtures fail serialization. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-23.deliver** (depends on: M7-23.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create allowlist-only product event serializer.
  Output: Create allowlist-only product event serializer.

- [ ] **M7-23.verify** (depends on: M7-23.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Prompt/tool args/secrets/IP/raw evidence fixtures fail serialization. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Prompt/tool args/secrets/IP/raw evidence fixtures fail serialization.

- [ ] **M7-23.release** (depends on: M7-23.verify, M7-22a, SHIP-GATE). Have the batch reviewer map M7-23 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-24"></a>
## M7-24: PostHog flag cache

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3348, exact task ID M7-24. Status/evidence: row `M7-24` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-23.
- Nearest pending prerequisites: M7-23.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Implement server-side flag cache with explicit code defaults/max age.

**Original verification:** PostHog outage returns deterministic defaults.

- [ ] **M7-24.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-24 and locate the existing PostHog flag cache implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-23). Prepare bounded inputs and expected observations for this task's criterion: PostHog outage returns deterministic defaults. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-24.deliver** (depends on: M7-24.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Implement server-side flag cache with explicit code defaults/max age.
  Output: Implement server-side flag cache with explicit code defaults/max age.

- [ ] **M7-24.verify** (depends on: M7-24.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: PostHog outage returns deterministic defaults. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: PostHog outage returns deterministic defaults.

- [ ] **M7-24.release** (depends on: M7-24.verify, M7-23, SHIP-GATE). Have the batch reviewer map M7-24 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-25"></a>
## M7-25: OpenRouter redaction

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3354, exact task ID M7-25. Status/evidence: row `M7-25` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-24.
- Nearest pending prerequisites: M7-24.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Redact prohibited fields for approved AI explanation purposes.

**Original verification:** Seeded secret/PII/PHI fixture is absent at fake endpoint.

- [ ] **M7-25.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-25 and locate the existing OpenRouter redaction implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-24). Prepare bounded inputs and expected observations for this task's criterion: Seeded secret/PII/PHI fixture is absent at fake endpoint. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-25.deliver** (depends on: M7-25.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Redact prohibited fields for approved AI explanation purposes.
  Output: Redact prohibited fields for approved AI explanation purposes.

- [ ] **M7-25.verify** (depends on: M7-25.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Seeded secret/PII/PHI fixture is absent at fake endpoint. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Seeded secret/PII/PHI fixture is absent at fake endpoint.

- [ ] **M7-25.release** (depends on: M7-25.verify, M7-24, SHIP-GATE). Have the batch reviewer map M7-25 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-26a"></a>
## M7-26a: OpenRouter purpose and model policy

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3360, exact task ID M7-26a. Status/evidence: row `M7-26a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-25.
- Nearest pending prerequisites: M7-25.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Reject AI requests whose purpose, model or provider is not allowlisted.

**Original verification:** Unapproved purpose/model/provider fails before egress.

- [ ] **M7-26a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-26a and locate the existing OpenRouter purpose and model policy implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-25). Prepare bounded inputs and expected observations for this task's criterion: Unapproved purpose/model/provider fails before egress. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-26a.deliver** (depends on: M7-26a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Reject AI requests whose purpose, model or provider is not allowlisted.
  Output: Reject AI requests whose purpose, model or provider is not allowlisted.

- [ ] **M7-26a.verify** (depends on: M7-26a.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Unapproved purpose/model/provider fails before egress. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Unapproved purpose/model/provider fails before egress.

- [ ] **M7-26a.release** (depends on: M7-26a.verify, M7-25, SHIP-GATE). Have the batch reviewer map M7-26a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-26b"></a>
## M7-26b: OpenRouter request limits

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3366, exact task ID M7-26b. Status/evidence: row `M7-26b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-26a.
- Nearest pending prerequisites: M7-26a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Enforce per-request token, cost, deadline and concurrency limits.

**Original verification:** Over-limit fixture is rejected before provider request.

- [ ] **M7-26b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-26b and locate the existing OpenRouter request limits implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-26a). Prepare bounded inputs and expected observations for this task's criterion: Over-limit fixture is rejected before provider request. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-26b.deliver** (depends on: M7-26b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Enforce per-request token, cost, deadline and concurrency limits.
  Output: Enforce per-request token, cost, deadline and concurrency limits.

- [ ] **M7-26b.verify** (depends on: M7-26b.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Over-limit fixture is rejected before provider request. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Over-limit fixture is rejected before provider request.

- [ ] **M7-26b.release** (depends on: M7-26b.verify, M7-26a, SHIP-GATE). Have the batch reviewer map M7-26b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-26c"></a>
## M7-26c: OpenRouter data policy metadata

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3372, exact task ID M7-26c. Status/evidence: row `M7-26c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-26b.
- Nearest pending prerequisites: M7-26b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Attach configured data-policy/ZDR requirement metadata to provider selection.

**Original verification:** Provider selection excludes a fixture that violates the required data policy.

- [ ] **M7-26c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-26c and locate the existing OpenRouter data policy metadata implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-26b). Prepare bounded inputs and expected observations for this task's criterion: Provider selection excludes a fixture that violates the required data policy. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-26c.deliver** (depends on: M7-26c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Attach configured data-policy/ZDR requirement metadata to provider selection.
  Output: Attach configured data-policy/ZDR requirement metadata to provider selection.

- [ ] **M7-26c.verify** (depends on: M7-26c.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Provider selection excludes a fixture that violates the required data policy. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Provider selection excludes a fixture that violates the required data policy.

- [ ] **M7-26c.release** (depends on: M7-26c.verify, M7-26b, SHIP-GATE). Have the batch reviewer map M7-26c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-26"></a>
## M7-26: OpenRouter governance

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3378, exact task ID M7-26. Status/evidence: row `M7-26` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-26c.
- Nearest pending prerequisites: M7-26c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Wire AI governance checks into the AIGateway request path.

**Original verification:** Approved request passes all guards and records governed request metadata.

- [ ] **M7-26.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-26 and locate the existing OpenRouter governance implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-26c). Prepare bounded inputs and expected observations for this task's criterion: Approved request passes all guards and records governed request metadata. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-26.deliver** (depends on: M7-26.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Wire AI governance checks into the AIGateway request path.
  Output: Wire AI governance checks into the AIGateway request path.

- [ ] **M7-26.verify** (depends on: M7-26.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Approved request passes all guards and records governed request metadata. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Approved request passes all guards and records governed request metadata.

- [ ] **M7-26.release** (depends on: M7-26.verify, M7-26c, SHIP-GATE). Have the batch reviewer map M7-26 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-27"></a>
## M7-27: API createAIExplanation

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3384, exact task ID M7-27. Status/evidence: row `M7-27` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-26.
- Nearest pending prerequisites: M7-26.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Implement OpenAPI operation `createAIExplanation` for `POST /api/v1/ai/explanations` using the existing service/store contract.

**Original verification:** Handler test covers authorized success plus one stable product error.

- [ ] **M7-27.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-27 and locate the existing API createAIExplanation implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-26). Prepare bounded inputs and expected observations for this task's criterion: Handler test covers authorized success plus one stable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-27.deliver** (depends on: M7-27.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Implement OpenAPI operation `createAIExplanation` for `POST /api/v1/ai/explanations` using the existing service/store contract.
  Output: Implement OpenAPI operation `createAIExplanation` for `POST /api/v1/ai/explanations` using the existing service/store contract.

- [ ] **M7-27.verify** (depends on: M7-27.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Handler test covers authorized success plus one stable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Handler test covers authorized success plus one stable product error.

- [ ] **M7-27.release** (depends on: M7-27.verify, M7-26, SHIP-GATE). Have the batch reviewer map M7-27 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-28"></a>
## M7-28: AI explanation UI

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3390, exact task ID M7-28. Status/evidence: row `M7-28` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-27.
- Nearest pending prerequisites: M7-27.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Create evidence-aware Explain with AI panel and unavailable state.

**Original verification:** E2E displays sent-field notice and deterministic content stays usable on failure.

- [ ] **M7-28.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-28 and locate the existing AI explanation UI implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-27). Prepare bounded inputs and expected observations for this task's criterion: E2E displays sent-field notice and deterministic content stays usable on failure. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-28.deliver** (depends on: M7-28.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create evidence-aware Explain with AI panel and unavailable state.
  Output: Create evidence-aware Explain with AI panel and unavailable state.

- [ ] **M7-28.verify** (depends on: M7-28.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: E2E displays sent-field notice and deterministic content stays usable on failure. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: E2E displays sent-field notice and deterministic content stays usable on failure.

- [ ] **M7-28.release** (depends on: M7-28.verify, M7-27, SHIP-GATE). Have the batch reviewer map M7-28 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-36"></a>
## M7-36: Audit Log UI

Class: **component-only**. Owner: **T11-identity-admin**. Lane: **L3**. Batch: **identity-audit**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3438, exact task ID M7-36. Status/evidence: row `M7-36` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-35.
- Nearest pending prerequisites: M7-28.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/apiserver`, `services/platform/audit`, `app/features/administration/AdminOperationsView.tsx`.
- Consumes: Stytch session/current membership and existing admin/audit API contracts.
- Produces: Current-authority admin mutations, scoped audit jobs and actual downloaded bytes.

**Original deliverable:** Create filterable audit page and export action.

**Original verification:** E2E shows SSO/config/policy/test mutations.

- [ ] **M7-36.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-36 and locate the existing Audit Log UI implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-35). Prepare bounded inputs and expected observations for this task's criterion: E2E shows SSO/config/policy/test mutations. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-36.deliver** (depends on: M7-36.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Complete the real native saved-file audit export proof, including selected filters, exact byte/hash match and scoped history. Exercise bounded large-export memory and response-loss/storage fault cases; preserve redaction and revoked-user denial.
  Output: Create filterable audit page and export action.

- [ ] **M7-36.verify** (depends on: M7-36.deliver). Run or reuse eligible candidate-bound evidence in the identity-audit feature batch. Required assertion: E2E shows SSO/config/policy/test mutations. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: E2E shows SSO/config/policy/test mutations.

- [ ] **M7-36.release** (depends on: M7-36.verify, M7-35, M7-28, SHIP-GATE). Have the batch reviewer map M7-36 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-39a"></a>
## M7-39a: stale connector UX

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **degraded-experience**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3456, exact task ID M7-39a. Status/evidence: row `M7-39a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-38.
- Nearest pending prerequisites: M7-36.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Add E2E fixture for stale connector data on Inventory and Findings.

**Original verification:** UI shows stale state and never renders a false zero-risk result.

- [ ] **M7-39a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-39a and locate the existing stale connector UX implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-38). Prepare bounded inputs and expected observations for this task's criterion: UI shows stale state and never renders a false zero-risk result. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-39a.deliver** (depends on: M7-39a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add E2E fixture for stale connector data on Inventory and Findings.
  Output: Add E2E fixture for stale connector data on Inventory and Findings.

- [ ] **M7-39a.verify** (depends on: M7-39a.deliver). Run or reuse eligible candidate-bound evidence in the degraded-experience feature batch. Required assertion: UI shows stale state and never renders a false zero-risk result. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: UI shows stale state and never renders a false zero-risk result.

- [ ] **M7-39a.release** (depends on: M7-39a.verify, M7-38, M7-36, SHIP-GATE). Have the batch reviewer map M7-39a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-39b"></a>
## M7-39b: graph outage UX

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **degraded-experience**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3462, exact task ID M7-39b. Status/evidence: row `M7-39b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-39a.
- Nearest pending prerequisites: M7-39a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Add E2E fixture for Neo4j unavailable on capability and attack-path screens.

**Original verification:** Affected screens show Degraded instead of empty/safe.

- [ ] **M7-39b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-39b and locate the existing graph outage UX implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-39a). Prepare bounded inputs and expected observations for this task's criterion: Affected screens show Degraded instead of empty/safe. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-39b.deliver** (depends on: M7-39b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add E2E fixture for Neo4j unavailable on capability and attack-path screens.
  Output: Add E2E fixture for Neo4j unavailable on capability and attack-path screens.

- [ ] **M7-39b.verify** (depends on: M7-39b.deliver). Run or reuse eligible candidate-bound evidence in the degraded-experience feature batch. Required assertion: Affected screens show Degraded instead of empty/safe. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Affected screens show Degraded instead of empty/safe.

- [ ] **M7-39b.release** (depends on: M7-39b.verify, M7-39a, SHIP-GATE). Have the batch reviewer map M7-39b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-39c"></a>
## M7-39c: event index outage UX

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **degraded-experience**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3468, exact task ID M7-39c. Status/evidence: row `M7-39c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-39b.
- Nearest pending prerequisites: M7-39b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Add E2E fixture for OpenSearch unavailable on session activity.

**Original verification:** Session activity shows Degraded and preserves known metadata.

- [ ] **M7-39c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-39c and locate the existing event index outage UX implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-39b). Prepare bounded inputs and expected observations for this task's criterion: Session activity shows Degraded and preserves known metadata. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-39c.deliver** (depends on: M7-39c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add E2E fixture for OpenSearch unavailable on session activity.
  Output: Add E2E fixture for OpenSearch unavailable on session activity.

- [ ] **M7-39c.verify** (depends on: M7-39c.deliver). Run or reuse eligible candidate-bound evidence in the degraded-experience feature batch. Required assertion: Session activity shows Degraded and preserves known metadata. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Session activity shows Degraded and preserves known metadata.

- [ ] **M7-39c.release** (depends on: M7-39c.verify, M7-39b, SHIP-GATE). Have the batch reviewer map M7-39c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-39d"></a>
## M7-39d: AI outage UX

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **degraded-experience**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3474, exact task ID M7-39d. Status/evidence: row `M7-39d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-39c.
- Nearest pending prerequisites: M7-39c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Add E2E fixture for OpenRouter unavailable on Explain with AI.

**Original verification:** AI action reports unavailable while deterministic evidence remains usable.

- [ ] **M7-39d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-39d and locate the existing AI outage UX implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-39c). Prepare bounded inputs and expected observations for this task's criterion: AI action reports unavailable while deterministic evidence remains usable. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-39d.deliver** (depends on: M7-39d.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add E2E fixture for OpenRouter unavailable on Explain with AI.
  Output: Add E2E fixture for OpenRouter unavailable on Explain with AI.

- [ ] **M7-39d.verify** (depends on: M7-39d.deliver). Run or reuse eligible candidate-bound evidence in the degraded-experience feature batch. Required assertion: AI action reports unavailable while deterministic evidence remains usable. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: AI action reports unavailable while deterministic evidence remains usable.

- [ ] **M7-39d.release** (depends on: M7-39d.verify, M7-39c, SHIP-GATE). Have the batch reviewer map M7-39d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-39e"></a>
## M7-39e: OTLP outage UX

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **degraded-experience**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3480, exact task ID M7-39e. Status/evidence: row `M7-39e` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-39d.
- Nearest pending prerequisites: M7-39d.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Add E2E fixture for optional remote OTLP unavailable.

**Original verification:** System Health reports exporter degradation without marking the security plane unhealthy.

- [ ] **M7-39e.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-39e and locate the existing OTLP outage UX implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-39d). Prepare bounded inputs and expected observations for this task's criterion: System Health reports exporter degradation without marking the security plane unhealthy. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-39e.deliver** (depends on: M7-39e.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add E2E fixture for optional remote OTLP unavailable.
  Output: Add E2E fixture for optional remote OTLP unavailable.

- [ ] **M7-39e.verify** (depends on: M7-39e.deliver). Run or reuse eligible candidate-bound evidence in the degraded-experience feature batch. Required assertion: System Health reports exporter degradation without marking the security plane unhealthy. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: System Health reports exporter degradation without marking the security plane unhealthy.

- [ ] **M7-39e.release** (depends on: M7-39e.verify, M7-39d, SHIP-GATE). Have the batch reviewer map M7-39e to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-39"></a>
## M7-39: degraded-state E2E

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **degraded-experience**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3486, exact task ID M7-39. Status/evidence: row `M7-39` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-39e.
- Nearest pending prerequisites: M7-39e.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Register the five degraded-state fixtures in the milestone E2E suite.

**Original verification:** Suite reports each degradation independently with product-owned errors.

- [ ] **M7-39.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-39 and locate the existing degraded-state E2E implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-39e). Prepare bounded inputs and expected observations for this task's criterion: Suite reports each degradation independently with product-owned errors. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-39.deliver** (depends on: M7-39.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Register the five degraded-state fixtures in the milestone E2E suite.
  Output: Register the five degraded-state fixtures in the milestone E2E suite.

- [ ] **M7-39.verify** (depends on: M7-39.deliver). Run or reuse eligible candidate-bound evidence in the degraded-experience feature batch. Required assertion: Suite reports each degradation independently with product-owned errors. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Suite reports each degradation independently with product-owned errors.

- [ ] **M7-39.release** (depends on: M7-39.verify, M7-39e, SHIP-GATE). Have the batch reviewer map M7-39 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-40e"></a>
## M7-40e: M7 AI degrade E2E

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **degraded-experience**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3516, exact task ID M7-40e. Status/evidence: row `M7-40e` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-40d.
- Nearest pending prerequisites: M7-39.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Run finding explanation with OpenRouter unavailable.

**Original verification:** Deterministic finding actions remain enabled.

- [ ] **M7-40e.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-40e and locate the existing M7 AI degrade E2E implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-40d). Prepare bounded inputs and expected observations for this task's criterion: Deterministic finding actions remain enabled. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-40e.deliver** (depends on: M7-40e.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Run finding explanation with OpenRouter unavailable.
  Output: Run finding explanation with OpenRouter unavailable.

- [ ] **M7-40e.verify** (depends on: M7-40e.deliver). Run or reuse eligible candidate-bound evidence in the degraded-experience feature batch. Required assertion: Deterministic finding actions remain enabled. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Deterministic finding actions remain enabled.

- [ ] **M7-40e.release** (depends on: M7-40e.verify, M7-40d, M7-39, SHIP-GATE). Have the batch reviewer map M7-40e to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7-40"></a>
## M7-40: M7 gate

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **degraded-experience**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3528, exact task ID M7-40. Status/evidence: row `M7-40` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7-40f.
- Nearest pending prerequisites: M7-40e.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Write the M7 gate result from the six independent E2E checks.

**Original verification:** Gate record is PASS only when all checks passed.

- [ ] **M7-40.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7-40 and locate the existing M7 gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7-40f). Prepare bounded inputs and expected observations for this task's criterion: Gate record is PASS only when all checks passed. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7-40.deliver** (depends on: M7-40.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Write the M7 gate result from the six independent E2E checks.
  Output: Write the M7 gate result from the six independent E2E checks.

- [ ] **M7-40.verify** (depends on: M7-40.deliver). Run or reuse eligible candidate-bound evidence in the degraded-experience feature batch. Required assertion: Gate record is PASS only when all checks passed. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Gate record is PASS only when all checks passed.

- [ ] **M7-40.release** (depends on: M7-40.verify, M7-40f, M7-40e, SHIP-GATE). Have the batch reviewer map M7-40 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-21"></a>
## M7A-21: Action: run existing test

Class: **component-only**. Owner: **T08-supervised-agent**. Lane: **L1**. Batch: **agent-actions**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3680, exact task ID M7A-21. Status/evidence: row `M7A-21` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-20, M5-35.
- Nearest pending prerequisites: M7-40, M2-47, M3-52, M1A-10.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent/action_readiness.go`, `services/platform/apiserver`, `services/platform/agentsec-api`, `services/platform/agentsec-worker`, `services/platform/migrations`.
- Consumes: Current activated definition, typed plan and existing test/export/sandbox/destination authorities.
- Produces: Reachable approved action with durable receipt, retry/restart settlement and verification.

**Original deliverable:** Register `run_test`/`rerun_test` against an existing TestDefinition.

**Original verification:** Action cannot create arbitrary new target/prompt content.

- [ ] **M7A-21.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-21 and locate the existing Action: run existing test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-20, M5-35). Prepare bounded inputs and expected observations for this task's criterion: Action cannot create arbitrary new target/prompt content. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-21.deliver** (depends on: M7A-21.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Finish the production existing-test dispatch lost-reply path: persist original dispatch authority so a cleared lease can replay its original receipt without re-executing the target. Exercise public activation -> run/approval -> runner -> comparison settlement across response loss, restart and cancellation with the actual saved TestDefinition.
  Output: Register `run_test`/`rerun_test` against an existing TestDefinition.

- [ ] **M7A-21.verify** (depends on: M7A-21.deliver). Run or reuse eligible candidate-bound evidence in the agent-actions feature batch. Required assertion: Action cannot create arbitrary new target/prompt content. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Action cannot create arbitrary new target/prompt content.

- [ ] **M7A-21.release** (depends on: M7A-21.verify, M7A-20, M5-35, M7-40, M2-47, M3-52, M1A-10, SHIP-GATE). Have the batch reviewer map M7A-21 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-22"></a>
## M7A-22: Action: start Attack Lab verification

Class: **component-only**. Owner: **T08-supervised-agent**. Lane: **L1**. Batch: **agent-actions**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3686, exact task ID M7A-22. Status/evidence: row `M7A-22` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-21, M5-35.
- Nearest pending prerequisites: M7A-21, M2-47, M3-52, M1A-10.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent/action_readiness.go`, `services/platform/apiserver`, `services/platform/agentsec-api`, `services/platform/agentsec-worker`, `services/platform/migrations`.
- Consumes: Current activated definition, typed plan and existing test/export/sandbox/destination authorities.
- Produces: Reachable approved action with durable receipt, retry/restart settlement and verification.

**Original deliverable:** Register `start_attack_lab` only for a preflight-approved non-production/test target.

**Original verification:** Production-write target fails before job enqueue.

- [ ] **M7A-22.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-22 and locate the existing Action: start Attack Lab verification implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-21, M5-35). Prepare bounded inputs and expected observations for this task's criterion: Production-write target fails before job enqueue. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-22.deliver** (depends on: M7A-22.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Reuse accepted controlled-browser/worker evidence; check exact installed/runtime readiness and approval floors on the candidate revision. Obtain the required non-production Fargate canary and direct-egress denial evidence; retain cleanup and restart receipts.
  Output: Register `start_attack_lab` only for a preflight-approved non-production/test target.

- [ ] **M7A-22.verify** (depends on: M7A-22.deliver). Run or reuse eligible candidate-bound evidence in the agent-actions feature batch. Required assertion: Production-write target fails before job enqueue. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Production-write target fails before job enqueue.

- [ ] **M7A-22.release** (depends on: M7A-22.verify, M7A-21, M5-35, M2-47, M3-52, M1A-10, SHIP-GATE). Have the batch reviewer map M7A-22 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-23"></a>
## M7A-23: Action: evidence export

Class: **component-only**. Owner: **T08-supervised-agent**. Lane: **L1**. Batch: **agent-actions**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3692, exact task ID M7A-23. Status/evidence: row `M7A-23` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-22, M7-40.
- Nearest pending prerequisites: M7A-22, M7-40.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent/action_readiness.go`, `services/platform/apiserver`, `services/platform/agentsec-api`, `services/platform/agentsec-worker`, `services/platform/migrations`.
- Consumes: Current activated definition, typed plan and existing test/export/sandbox/destination authorities.
- Produces: Reachable approved action with durable receipt, retry/restart settlement and verification.

**Original deliverable:** Register `create_evidence_export` using existing export service.

**Original verification:** Export references only run-scoped evidence IDs.

- [ ] **M7A-23.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-23 and locate the existing Action: evidence export implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-22, M7-40). Prepare bounded inputs and expected observations for this task's criterion: Export references only run-scoped evidence IDs. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-23.deliver** (depends on: M7A-23.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Review the frozen manual SQL batch and fix only findings; preserve original provenance and tenant/current-authority checks. Wire public definition activation, action controls/catalog readiness and configured workers; exercise public start -> plan -> approval -> export worker -> native download with no seeded run or plan.
  Output: Register `create_evidence_export` using existing export service.

- [ ] **M7A-23.verify** (depends on: M7A-23.deliver). Run or reuse eligible candidate-bound evidence in the agent-actions feature batch. Required assertion: Export references only run-scoped evidence IDs. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Export references only run-scoped evidence IDs.

- [ ] **M7A-23.release** (depends on: M7A-23.verify, M7A-22, M7-40, SHIP-GATE). Have the batch reviewer map M7A-23 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-24"></a>
## M7A-24: Action: signed webhook handoff

Class: **component-only**. Owner: **T08-supervised-agent**. Lane: **L1**. Batch: **agent-actions**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3698, exact task ID M7A-24. Status/evidence: row `M7A-24` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-23.
- Nearest pending prerequisites: M7A-23.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent/action_readiness.go`, `services/platform/apiserver`, `services/platform/agentsec-api`, `services/platform/agentsec-worker`, `services/platform/migrations`.
- Consumes: Current activated definition, typed plan and existing test/export/sandbox/destination authorities.
- Produces: Reachable approved action with durable receipt, retry/restart settlement and verification.

**Original deliverable:** Register `send_response_webhook` using configured allowlisted webhook destination.

**Original verification:** Arbitrary URL argument is rejected; payload is redacted and signed.

- [ ] **M7A-24.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-24 and locate the existing Action: signed webhook handoff implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-23). Prepare bounded inputs and expected observations for this task's criterion: Arbitrary URL argument is rejected; payload is redacted and signed. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-24.deliver** (depends on: M7A-24.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Bind the typed action to a saved same-scope allowlisted destination; never accept a planner URL. Persist a redacted signed delivery intent and acknowledgement; prove timeout/restart/replay cannot invent success or duplicate an acknowledged delivery.
  Output: Register `send_response_webhook` using configured allowlisted webhook destination.

- [ ] **M7A-24.verify** (depends on: M7A-24.deliver). Run or reuse eligible candidate-bound evidence in the agent-actions feature batch. Required assertion: Arbitrary URL argument is rejected; payload is redacted and signed. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Arbitrary URL argument is rejected; payload is redacted and signed.

- [ ] **M7A-24.release** (depends on: M7A-24.verify, M7A-23, SHIP-GATE). Have the batch reviewer map M7A-24 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-49"></a>
## M7A-49: Security Agent run budget

Class: **component-only**. Owner: **T07-security-agent-authority**. Lane: **L1**. Batch: **agent-budget**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 3872, exact task ID M7A-49. Status/evidence: row `M7A-49` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-48.
- Nearest pending prerequisites: M7A-24, M7-40, M7-27.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent`, `services/platform/agentsec-worker`, `services/platform/apiserver`, `services/platform/migrations`.
- Consumes: Immutable prepared plan, actual pricing policy, current lease, Organization budget and action controls.
- Produces: Bounded typed plans and accounted execution; no action after a budget stop.

**Original deliverable:** Enforce max steps, wall-clock deadline, AI cost/token cap and Organization concurrency limit.

**Original verification:** Budget breach moves run to Needs human/Failed without new action.

- [ ] **M7A-49.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-49 and locate the existing Security Agent run budget implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-48). Prepare bounded inputs and expected observations for this task's criterion: Budget breach moves run to Needs human/Failed without new action. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-49.deliver** (depends on: M7A-49.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Reconcile the accepted prepared-request/accounting receipts against every enabled action and stop/reclaim path. Bind approved model pricing and Organization concurrency to admission; prove no step starts after time/token/cost/step exhaustion, including concurrent requests.
  Output: Enforce max steps, wall-clock deadline, AI cost/token cap and Organization concurrency limit.

- [ ] **M7A-49.verify** (depends on: M7A-49.deliver). Run or reuse eligible candidate-bound evidence in the agent-budget feature batch. Required assertion: Budget breach moves run to Needs human/Failed without new action. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Budget breach moves run to Needs human/Failed without new action.

- [ ] **M7A-49.release** (depends on: M7A-49.verify, M7A-48, M7A-24, M7-40, M7-27, SHIP-GATE). Have the batch reviewer map M7A-49 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-84"></a>
## M7A-84: Security Agent builder Simulate UI

Class: **component-only**. Owner: **T10-product-ui**. Lane: **L3**. Batch: **agent-ui**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4082, exact task ID M7A-84. Status/evidence: row `M7A-84` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-83, M7A-69.
- Nearest pending prerequisites: M7A-49, M2-47.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `app/features/securityagents`, `apps/web/api`, `openapi/openapi.yaml`, `cmd/agentsecctl`.
- Consumes: Versioned product API/OpenAPI responses and current authorization contracts.
- Produces: API-backed simulator, ordered plan/step detail, approvals and scoped navigation.

**Original deliverable:** Show matched evidence, proposed plan and approval points without side effects.

**Original verification:** E2E simulator shows authorization result per proposed step.

- [ ] **M7A-84.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-84 and locate the existing Security Agent builder Simulate UI implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-83, M7A-69). Prepare bounded inputs and expected observations for this task's criterion: E2E simulator shows authorization result per proposed step. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-84.deliver** (depends on: M7A-84.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Show matched evidence, proposed plan and approval points without side effects.
  Output: Show matched evidence, proposed plan and approval points without side effects.

- [ ] **M7A-84.verify** (depends on: M7A-84.deliver). Run or reuse eligible candidate-bound evidence in the agent-ui feature batch. Required assertion: E2E simulator shows authorization result per proposed step. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: E2E simulator shows authorization result per proposed step.

- [ ] **M7A-84.release** (depends on: M7A-84.verify, M7A-83, M7A-69, M7A-49, M2-47, SHIP-GATE). Have the batch reviewer map M7A-84 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-86"></a>
## M7A-86: Security Agent run plan UI

Class: **component-only**. Owner: **T10-product-ui**. Lane: **L3**. Batch: **agent-ui**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4094, exact task ID M7A-86. Status/evidence: row `M7A-86` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-85.
- Nearest pending prerequisites: M7A-84.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `app/features/securityagents`, `apps/web/api`, `openapi/openapi.yaml`, `cmd/agentsecctl`.
- Consumes: Versioned product API/OpenAPI responses and current authorization contracts.
- Produces: API-backed simulator, ordered plan/step detail, approvals and scoped navigation.

**Original deliverable:** Show trigger/evidence, AI rationale summary and ordered plan with deterministic authorization labels.

**Original verification:** Rationale is visually distinct from authorization/evidence.

- [ ] **M7A-86.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-86 and locate the existing Security Agent run plan UI implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-85). Prepare bounded inputs and expected observations for this task's criterion: Rationale is visually distinct from authorization/evidence. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-86.deliver** (depends on: M7A-86.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Show trigger/evidence, AI rationale summary and ordered plan with deterministic authorization labels.
  Output: Show trigger/evidence, AI rationale summary and ordered plan with deterministic authorization labels.

- [ ] **M7A-86.verify** (depends on: M7A-86.deliver). Run or reuse eligible candidate-bound evidence in the agent-ui feature batch. Required assertion: Rationale is visually distinct from authorization/evidence. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Rationale is visually distinct from authorization/evidence.

- [ ] **M7A-86.release** (depends on: M7A-86.verify, M7A-85, M7A-84, SHIP-GATE). Have the batch reviewer map M7A-86 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-87"></a>
## M7A-87: Security Agent run action UI

Class: **component-only**. Owner: **T10-product-ui**. Lane: **L3**. Batch: **agent-ui**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4100, exact task ID M7A-87. Status/evidence: row `M7A-87` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-86.
- Nearest pending prerequisites: M7A-86.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `app/features/securityagents`, `apps/web/api`, `openapi/openapi.yaml`, `cmd/agentsecctl`.
- Consumes: Versioned product API/OpenAPI responses and current authorization contracts.
- Produces: API-backed simulator, ordered plan/step detail, approvals and scoped navigation.

**Original deliverable:** Show each step state, redacted arguments, result, TTL/rollback and verification.

**Original verification:** Protected arguments never render.

- [ ] **M7A-87.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-87 and locate the existing Security Agent run action UI implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-86). Prepare bounded inputs and expected observations for this task's criterion: Protected arguments never render. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-87.deliver** (depends on: M7A-87.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Show each step state, redacted arguments, result, TTL/rollback and verification.
  Output: Show each step state, redacted arguments, result, TTL/rollback and verification.

- [ ] **M7A-87.verify** (depends on: M7A-87.deliver). Run or reuse eligible candidate-bound evidence in the agent-ui feature batch. Required assertion: Protected arguments never render. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Protected arguments never render.

- [ ] **M7A-87.release** (depends on: M7A-87.verify, M7A-86, SHIP-GATE). Have the batch reviewer map M7A-87 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-88"></a>
## M7A-88: Security Agent Approvals list UI

Class: **component-only**. Owner: **T10-product-ui**. Lane: **L3**. Batch: **agent-ui**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4106, exact task ID M7A-88. Status/evidence: row `M7A-88` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-87.
- Nearest pending prerequisites: M7A-87.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `app/features/securityagents`, `apps/web/api`, `openapi/openapi.yaml`, `cmd/agentsecctl`.
- Consumes: Versioned product API/OpenAPI responses and current authorization contracts.
- Produces: API-backed simulator, ordered plan/step detail, approvals and scoped navigation.

**Original deliverable:** Add Protect -> Approvals list with action, agent, target, expiry and requester/run context.

**Original verification:** Unauthorized approvals are absent.

- [ ] **M7A-88.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-88 and locate the existing Security Agent Approvals list UI implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-87). Prepare bounded inputs and expected observations for this task's criterion: Unauthorized approvals are absent. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-88.deliver** (depends on: M7A-88.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add Protect -> Approvals list with action, agent, target, expiry and requester/run context.
  Output: Add Protect -> Approvals list with action, agent, target, expiry and requester/run context.

- [ ] **M7A-88.verify** (depends on: M7A-88.deliver). Run or reuse eligible candidate-bound evidence in the agent-ui feature batch. Required assertion: Unauthorized approvals are absent. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Unauthorized approvals are absent.

- [ ] **M7A-88.release** (depends on: M7A-88.verify, M7A-87, SHIP-GATE). Have the batch reviewer map M7A-88 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-89"></a>
## M7A-89: Security Agent Approval detail UI

Class: **component-only**. Owner: **T10-product-ui**. Lane: **L3**. Batch: **agent-ui**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4112, exact task ID M7A-89. Status/evidence: row `M7A-89` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-88.
- Nearest pending prerequisites: M7A-88.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `app/features/securityagents`, `apps/web/api`, `openapi/openapi.yaml`, `cmd/agentsecctl`.
- Consumes: Versioned product API/OpenAPI responses and current authorization contracts.
- Produces: API-backed simulator, ordered plan/step detail, approvals and scoped navigation.

**Original deliverable:** Show reason, evidence, expected side effect, risk, reversibility/TTL and Approve/Deny/Cancel.

**Original verification:** Sensitive approval invokes fresh-auth flow before decision.

- [ ] **M7A-89.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-89 and locate the existing Security Agent Approval detail UI implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-88). Prepare bounded inputs and expected observations for this task's criterion: Sensitive approval invokes fresh-auth flow before decision. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-89.deliver** (depends on: M7A-89.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Show reason, evidence, expected side effect, risk, reversibility/TTL and Approve/Deny/Cancel.
  Output: Show reason, evidence, expected side effect, risk, reversibility/TTL and Approve/Deny/Cancel.

- [ ] **M7A-89.verify** (depends on: M7A-89.deliver). Run or reuse eligible candidate-bound evidence in the agent-ui feature batch. Required assertion: Sensitive approval invokes fresh-auth flow before decision. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Sensitive approval invokes fresh-auth flow before decision.

- [ ] **M7A-89.release** (depends on: M7A-89.verify, M7A-88, SHIP-GATE). Have the batch reviewer map M7A-89 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-90"></a>
## M7A-90: Security Agent activity links

Class: **component-only**. Owner: **T10-product-ui**. Lane: **L3**. Batch: **agent-ui**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4118, exact task ID M7A-90. Status/evidence: row `M7A-90` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-89.
- Nearest pending prerequisites: M7A-89.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `app/features/securityagents`, `apps/web/api`, `openapi/openapi.yaml`, `cmd/agentsecctl`.
- Consumes: Versioned product API/OpenAPI responses and current authorization contracts.
- Produces: API-backed simulator, ordered plan/step detail, approvals and scoped navigation.

**Original deliverable:** Link finding/path/session/audit records to Security Agent run and back.

**Original verification:** E2E navigation preserves scoped entity IDs.

- [ ] **M7A-90.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-90 and locate the existing Security Agent activity links implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-89). Prepare bounded inputs and expected observations for this task's criterion: E2E navigation preserves scoped entity IDs. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-90.deliver** (depends on: M7A-90.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Reuse accepted scoped relation/navigation proofs after source validation. Complete action-plan, concurrent/shared-target/high-fan-out coverage and reference-load measurements; retain latency/query-plan evidence without counting a serial no-plan fixture as production load.
  Output: Link finding/path/session/audit records to Security Agent run and back.

- [ ] **M7A-90.verify** (depends on: M7A-90.deliver). Run or reuse eligible candidate-bound evidence in the agent-ui feature batch. Required assertion: E2E navigation preserves scoped entity IDs. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: E2E navigation preserves scoped entity IDs.

- [ ] **M7A-90.release** (depends on: M7A-90.verify, M7A-89, SHIP-GATE). Have the batch reviewer map M7A-90 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-94"></a>
## M7A-94: Cross-tenant planner reference test

Class: **component-only**. Owner: **T09-agent-actions**. Lane: **L5**. Batch: **agent-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4166, exact task ID M7A-94. Status/evidence: row `M7A-94` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-93.
- Nearest pending prerequisites: M7A-90, M3-14.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent`, `services/platform/agentsec-worker`, `services/platform/apiserver`, `scripts`.
- Consumes: L1 action/budget contracts and two isolated Organization identities.
- Produces: Tenant isolation, budget enforcement and complete autonomous/approved responder evidence.

**Original deliverable:** Seed planner output with another Organization's valid-looking asset UUID.

**Original verification:** Plan is rejected before authorization/execution.

- [ ] **M7A-94.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-94 and locate the existing Cross-tenant planner reference test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-93). Prepare bounded inputs and expected observations for this task's criterion: Plan is rejected before authorization/execution. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-94.deliver** (depends on: M7A-94.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Seed planner output with another Organization's valid-looking asset UUID.
  Output: Seed planner output with another Organization's valid-looking asset UUID.

- [ ] **M7A-94.verify** (depends on: M7A-94.deliver). Run or reuse eligible candidate-bound evidence in the agent-acceptance feature batch. Required assertion: Plan is rejected before authorization/execution. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Plan is rejected before authorization/execution.

- [ ] **M7A-94.release** (depends on: M7A-94.verify, M7A-93, M7A-90, M3-14, SHIP-GATE). Have the batch reviewer map M7A-94 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-95"></a>
## M7A-95: Security Agent action budget test

Class: **component-only**. Owner: **T09-agent-actions**. Lane: **L5**. Batch: **agent-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4172, exact task ID M7A-95. Status/evidence: row `M7A-95` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-94.
- Nearest pending prerequisites: M7A-94.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent`, `services/platform/agentsec-worker`, `services/platform/apiserver`, `scripts`.
- Consumes: L1 action/budget contracts and two isolated Organization identities.
- Produces: Tenant isolation, budget enforcement and complete autonomous/approved responder evidence.

**Original deliverable:** Exceed action/time/cost budget in fixture.

**Original verification:** No step starts after budget stop.

- [ ] **M7A-95.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-95 and locate the existing Security Agent action budget test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-94). Prepare bounded inputs and expected observations for this task's criterion: No step starts after budget stop. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-95.deliver** (depends on: M7A-95.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Exceed action/time/cost budget in fixture.
  Output: Exceed action/time/cost budget in fixture.

- [ ] **M7A-95.verify** (depends on: M7A-95.deliver). Run or reuse eligible candidate-bound evidence in the agent-acceptance feature batch. Required assertion: No step starts after budget stop. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: No step starts after budget stop.

- [ ] **M7A-95.release** (depends on: M7A-95.verify, M7A-94, SHIP-GATE). Have the batch reviewer map M7A-95 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-96"></a>
## M7A-96: Security Agent auto-response E2E

Class: **component-only**. Owner: **T09-agent-actions**. Lane: **L5**. Batch: **agent-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4178, exact task ID M7A-96. Status/evidence: row `M7A-96` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-95.
- Nearest pending prerequisites: M7A-95.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent`, `services/platform/agentsec-worker`, `services/platform/apiserver`, `scripts`.
- Consumes: L1 action/budget contracts and two isolated Organization identities.
- Produces: Tenant isolation, budget enforcement and complete autonomous/approved responder evidence.

**Original deliverable:** Trigger injection responder, auto-create temporary Block and re-test.

**Original verification:** Run ends Contained/Remediated only after policy evidence plus re-test verification.

- [ ] **M7A-96.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-96 and locate the existing Security Agent auto-response E2E implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-95). Prepare bounded inputs and expected observations for this task's criterion: Run ends Contained/Remediated only after policy evidence plus re-test verification. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-96.deliver** (depends on: M7A-96.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Trigger injection responder, auto-create temporary Block and re-test.
  Output: Trigger injection responder, auto-create temporary Block and re-test.

- [ ] **M7A-96.verify** (depends on: M7A-96.deliver). Run or reuse eligible candidate-bound evidence in the agent-acceptance feature batch. Required assertion: Run ends Contained/Remediated only after policy evidence plus re-test verification. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Run ends Contained/Remediated only after policy evidence plus re-test verification.

- [ ] **M7A-96.release** (depends on: M7A-96.verify, M7A-95, SHIP-GATE). Have the batch reviewer map M7A-96 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-100"></a>
## M7A-100: Security Agent single-tenant profile E2E

Class: **component-only**. Owner: **T09-agent-actions**. Lane: **L5**. Batch: **agent-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4202, exact task ID M7A-100. Status/evidence: row `M7A-100` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-99.
- Nearest pending prerequisites: M7A-96.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent`, `services/platform/agentsec-worker`, `services/platform/apiserver`, `scripts`.
- Consumes: L1 action/budget contracts and two isolated Organization identities.
- Produces: Tenant isolation, budget enforcement and complete autonomous/approved responder evidence.

**Original deliverable:** Execute the same responder flow in dedicated single-tenant profile.

**Original verification:** Same API/UI/action contracts pass without topology-specific product behavior.

- [ ] **M7A-100.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-100 and locate the existing Security Agent single-tenant profile E2E implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-99). Prepare bounded inputs and expected observations for this task's criterion: Same API/UI/action contracts pass without topology-specific product behavior. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-100.deliver** (depends on: M7A-100.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Execute the same responder flow in dedicated single-tenant profile.
  Output: Execute the same responder flow in dedicated single-tenant profile.

- [ ] **M7A-100.verify** (depends on: M7A-100.deliver). Run or reuse eligible candidate-bound evidence in the agent-acceptance feature batch. Required assertion: Same API/UI/action contracts pass without topology-specific product behavior. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Same API/UI/action contracts pass without topology-specific product behavior.

- [ ] **M7A-100.release** (depends on: M7A-100.verify, M7A-99, M7A-96, SHIP-GATE). Have the batch reviewer map M7A-100 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m7a-101"></a>
## M7A-101: M7A gate

Class: **component-only**. Owner: **T09-agent-actions**. Lane: **L5**. Batch: **agent-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4208, exact task ID M7A-101. Status/evidence: row `M7A-101` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-100.
- Nearest pending prerequisites: M7A-100.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/securityagent`, `services/platform/agentsec-worker`, `services/platform/apiserver`, `scripts`.
- Consumes: L1 action/budget contracts and two isolated Organization identities.
- Produces: Tenant isolation, budget enforcement and complete autonomous/approved responder evidence.

**Original deliverable:** Write Security Agent MVP gate result covering automatic trigger, simulate, plan, authorize, auto-act, approval, execute, temporary-control expiry cleanup, verify, Home attention UX, audit, outage and tenant isolation.

**Original verification:** PASS only when all preceding Security Agent E2E/security/degraded checks pass.

- [ ] **M7A-101.prepare** (depends on: none; preparation only). Read the current ledger evidence for M7A-101 and locate the existing M7A gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-100). Prepare bounded inputs and expected observations for this task's criterion: PASS only when all preceding Security Agent E2E/security/degraded checks pass. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M7A-101.deliver** (depends on: M7A-101.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Write Security Agent MVP gate result covering automatic trigger, simulate, plan, authorize, auto-act, approval, execute, temporary-control expiry cleanup, verify, Home attention UX, audit, outage and tenant isolation.
  Output: Write Security Agent MVP gate result covering automatic trigger, simulate, plan, authorize, auto-act, approval, execute, temporary-control expiry cleanup, verify, Home attention UX, audit, outage and tenant isolation.

- [ ] **M7A-101.verify** (depends on: M7A-101.deliver). Run or reuse eligible candidate-bound evidence in the agent-acceptance feature batch. Required assertion: PASS only when all preceding Security Agent E2E/security/degraded checks pass. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: PASS only when all preceding Security Agent E2E/security/degraded checks pass.

- [ ] **M7A-101.release** (depends on: M7A-101.verify, M7A-100, SHIP-GATE). Have the batch reviewer map M7A-101 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-01a"></a>
## M8-01a: production overlay VPC review

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4216, exact task ID M8-01a. Status/evidence: row `M8-01a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M7A-101, M1A-10.
- Nearest pending prerequisites: M7A-101, M1A-10.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add release overlay settings to the existing M1A VPC module for production CIDRs, endpoints and availability-zone topology without creating a second module.

**Original verification:** Terraform plan remains private and reuses the M1A module.

- [ ] **M8-01a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-01a and locate the existing production overlay VPC review implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M7A-101, M1A-10). Prepare bounded inputs and expected observations for this task's criterion: Terraform plan remains private and reuses the M1A module. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-01a.deliver** (depends on: M8-01a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add release overlay settings to the existing M1A VPC module for production CIDRs, endpoints and availability-zone topology without creating a second module.
  Output: Add release overlay settings to the existing M1A VPC module for production CIDRs, endpoints and availability-zone topology without creating a second module.

- [ ] **M8-01a.verify** (depends on: M8-01a.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Terraform plan remains private and reuses the M1A module. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Terraform plan remains private and reuses the M1A module.

- [ ] **M8-01a.release** (depends on: M8-01a.verify, M7A-101, M1A-10, SHIP-GATE). Have the batch reviewer map M8-01a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-01b"></a>
## M8-01b: production overlay EKS review

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4222, exact task ID M8-01b. Status/evidence: row `M8-01b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-01a.
- Nearest pending prerequisites: M8-01a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add production replica, node-pool and private-endpoint settings to the existing M1A EKS module.

**Original verification:** Terraform plan reuses the same module and contains no public Kubernetes API exposure beyond approved configuration.

- [ ] **M8-01b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-01b and locate the existing production overlay EKS review implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-01a). Prepare bounded inputs and expected observations for this task's criterion: Terraform plan reuses the same module and contains no public Kubernetes API exposure beyond approved configuration. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-01b.deliver** (depends on: M8-01b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add production replica, node-pool and private-endpoint settings to the existing M1A EKS module.
  Output: Add production replica, node-pool and private-endpoint settings to the existing M1A EKS module.

- [ ] **M8-01b.verify** (depends on: M8-01b.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Terraform plan reuses the same module and contains no public Kubernetes API exposure beyond approved configuration. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Terraform plan reuses the same module and contains no public Kubernetes API exposure beyond approved configuration.

- [ ] **M8-01b.release** (depends on: M8-01b.verify, M8-01a, SHIP-GATE). Have the batch reviewer map M8-01b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-01c"></a>
## M8-01c: release Terraform root

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4228, exact task ID M8-01c. Status/evidence: row `M8-01c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-01b.
- Nearest pending prerequisites: M8-01b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add the production/SaaS release values to the same Terraform root used by staging.

**Original verification:** `terraform validate` passes with staging and release tfvars and module addresses remain stable.

- [ ] **M8-01c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-01c and locate the existing release Terraform root implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-01b). Prepare bounded inputs and expected observations for this task's criterion: `terraform validate` passes with staging and release tfvars and module addresses remain stable. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-01c.deliver** (depends on: M8-01c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add the production/SaaS release values to the same Terraform root used by staging.
  Output: Add the production/SaaS release values to the same Terraform root used by staging.

- [ ] **M8-01c.verify** (depends on: M8-01c.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: `terraform validate` passes with staging and release tfvars and module addresses remain stable. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: `terraform validate` passes with staging and release tfvars and module addresses remain stable.

- [ ] **M8-01c.release** (depends on: M8-01c.verify, M8-01b, SHIP-GATE). Have the batch reviewer map M8-01c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-01"></a>
## M8-01: AWS production overlay gate

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4234, exact task ID M8-01. Status/evidence: row `M8-01` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-01c.
- Nearest pending prerequisites: M8-01c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Run the release Terraform plan against the reusable M1A modules and record drift.

**Original verification:** No duplicate AWS foundation module or destructive unexpected replacement appears.

- [ ] **M8-01.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-01 and locate the existing AWS production overlay gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-01c). Prepare bounded inputs and expected observations for this task's criterion: No duplicate AWS foundation module or destructive unexpected replacement appears. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-01.deliver** (depends on: M8-01.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Run the release Terraform plan against the reusable M1A modules and record drift.
  Output: Run the release Terraform plan against the reusable M1A modules and record drift.

- [ ] **M8-01.verify** (depends on: M8-01.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: No duplicate AWS foundation module or destructive unexpected replacement appears. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: No duplicate AWS foundation module or destructive unexpected replacement appears.

- [ ] **M8-01.release** (depends on: M8-01.verify, M8-01c, SHIP-GATE). Have the batch reviewer map M8-01 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-02"></a>
## M8-02: AWS S3/KMS/Secrets hardening

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4240, exact task ID M8-02. Status/evidence: row `M8-02` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-01.
- Nearest pending prerequisites: M8-01.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Apply versioning, retention/lifecycle, encryption and least-privilege production settings to the existing M1A S3/KMS/Secrets resources.

**Original verification:** Terraform plan shows no public access and event archive/evidence prefixes use the intended KMS key.

- [ ] **M8-02.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-02 and locate the existing AWS S3/KMS/Secrets hardening implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-01). Prepare bounded inputs and expected observations for this task's criterion: Terraform plan shows no public access and event archive/evidence prefixes use the intended KMS key. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-02.deliver** (depends on: M8-02.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Apply versioning, retention/lifecycle, encryption and least-privilege production settings to the existing M1A S3/KMS/Secrets resources.
  Output: Apply versioning, retention/lifecycle, encryption and least-privilege production settings to the existing M1A S3/KMS/Secrets resources.

- [ ] **M8-02.verify** (depends on: M8-02.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Terraform plan shows no public access and event archive/evidence prefixes use the intended KMS key. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Terraform plan shows no public access and event archive/evidence prefixes use the intended KMS key.

- [ ] **M8-02.release** (depends on: M8-02.verify, M8-01, SHIP-GATE). Have the batch reviewer map M8-02 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-03"></a>
## M8-03: AWS SQS/DLQ hardening

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4246, exact task ID M8-03. Status/evidence: row `M8-03` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-02.
- Nearest pending prerequisites: M8-02.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Apply production visibility timeout, retention, DLQ and encryption settings to the existing M1A queues.

**Original verification:** Terraform plan preserves queue identities and has bounded redrive settings.

- [ ] **M8-03.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-03 and locate the existing AWS SQS/DLQ hardening implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-02). Prepare bounded inputs and expected observations for this task's criterion: Terraform plan preserves queue identities and has bounded redrive settings. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-03.deliver** (depends on: M8-03.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Apply production visibility timeout, retention, DLQ and encryption settings to the existing M1A queues.
  Output: Apply production visibility timeout, retention, DLQ and encryption settings to the existing M1A queues.

- [ ] **M8-03.verify** (depends on: M8-03.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Terraform plan preserves queue identities and has bounded redrive settings. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Terraform plan preserves queue identities and has bounded redrive settings.

- [ ] **M8-03.release** (depends on: M8-03.verify, M8-02, SHIP-GATE). Have the batch reviewer map M8-03 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-04"></a>
## M8-04: AWS OpenSearch hardening

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4252, exact task ID M8-04. Status/evidence: row `M8-04` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-03.
- Nearest pending prerequisites: M8-03.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Apply production capacity, encryption, VPC-only access and snapshot/retention settings to the existing M1A OpenSearch module.

**Original verification:** Terraform plan has no public endpoint and uses the same EventStore endpoint contract.

- [ ] **M8-04.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-04 and locate the existing AWS OpenSearch hardening implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-03). Prepare bounded inputs and expected observations for this task's criterion: Terraform plan has no public endpoint and uses the same EventStore endpoint contract. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-04.deliver** (depends on: M8-04.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Apply production capacity, encryption, VPC-only access and snapshot/retention settings to the existing M1A OpenSearch module.
  Output: Apply production capacity, encryption, VPC-only access and snapshot/retention settings to the existing M1A OpenSearch module.

- [ ] **M8-04.verify** (depends on: M8-04.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Terraform plan has no public endpoint and uses the same EventStore endpoint contract. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Terraform plan has no public endpoint and uses the same EventStore endpoint contract.

- [ ] **M8-04.release** (depends on: M8-04.verify, M8-03, SHIP-GATE). Have the batch reviewer map M8-04 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-05"></a>
## M8-05: AWS IRSA least-privilege hardening

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4258, exact task ID M8-05. Status/evidence: row `M8-05` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-04.
- Nearest pending prerequisites: M8-04.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Tighten M1A service/connector IAM policies to production resource ARNs and document approved cross-account connector actions.

**Original verification:** Policy tests allow required calls and deny unrelated write actions.

- [ ] **M8-05.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-05 and locate the existing AWS IRSA least-privilege hardening implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-04). Prepare bounded inputs and expected observations for this task's criterion: Policy tests allow required calls and deny unrelated write actions. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-05.deliver** (depends on: M8-05.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Tighten M1A service/connector IAM policies to production resource ARNs and document approved cross-account connector actions.
  Output: Tighten M1A service/connector IAM policies to production resource ARNs and document approved cross-account connector actions.

- [ ] **M8-05.verify** (depends on: M8-05.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Policy tests allow required calls and deny unrelated write actions. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Policy tests allow required calls and deny unrelated write actions.

- [ ] **M8-05.release** (depends on: M8-05.verify, M8-04, SHIP-GATE). Have the batch reviewer map M8-05 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-06"></a>
## M8-06: Fargate profile

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4264, exact task ID M8-06. Status/evidence: row `M8-06` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-05.
- Nearest pending prerequisites: M8-05.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add dedicated Attack Lab Fargate profile, namespace selector and Pod execution role.

**Original verification:** Terraform/EKS plan selects only Attack Lab namespace/labels.

- [ ] **M8-06.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-06 and locate the existing Fargate profile implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-05). Prepare bounded inputs and expected observations for this task's criterion: Terraform/EKS plan selects only Attack Lab namespace/labels. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-06.deliver** (depends on: M8-06.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add dedicated Attack Lab Fargate profile, namespace selector and Pod execution role.
  Output: Add dedicated Attack Lab Fargate profile, namespace selector and Pod execution role.

- [ ] **M8-06.verify** (depends on: M8-06.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Terraform/EKS plan selects only Attack Lab namespace/labels. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Terraform/EKS plan selects only Attack Lab namespace/labels.

- [ ] **M8-06.release** (depends on: M8-06.verify, M8-05, SHIP-GATE). Have the batch reviewer map M8-06 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-07"></a>
## M8-07: Attack Lab security group

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4270, exact task ID M8-07. Status/evidence: row `M8-07` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-06.
- Nearest pending prerequisites: M8-06.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add security group and SecurityGroupPolicy prerequisites for Fargate runs.

**Original verification:** Default run path reaches required cluster/proxy endpoints only.

- [ ] **M8-07.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-07 and locate the existing Attack Lab security group implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-06). Prepare bounded inputs and expected observations for this task's criterion: Default run path reaches required cluster/proxy endpoints only. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-07.deliver** (depends on: M8-07.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add security group and SecurityGroupPolicy prerequisites for Fargate runs.
  Output: Add security group and SecurityGroupPolicy prerequisites for Fargate runs.

- [ ] **M8-07.verify** (depends on: M8-07.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Default run path reaches required cluster/proxy endpoints only. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Default run path reaches required cluster/proxy endpoints only.

- [ ] **M8-07.release** (depends on: M8-07.verify, M8-06, SHIP-GATE). Have the batch reviewer map M8-07 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-16"></a>
## M8-16: preflight base

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4360, exact task ID M8-16. Status/evidence: row `M8-16` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-15.
- Nearest pending prerequisites: M8-07.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Create `agentsecctl preflight` command and result model.

**Original verification:** Command returns product pass/warn/fail sections and nonzero on blockers.

- [ ] **M8-16.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-16 and locate the existing preflight base implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-15). Prepare bounded inputs and expected observations for this task's criterion: Command returns product pass/warn/fail sections and nonzero on blockers. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-16.deliver** (depends on: M8-16.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create `agentsecctl preflight` command and result model.
  Output: Create `agentsecctl preflight` command and result model.

- [ ] **M8-16.verify** (depends on: M8-16.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Command returns product pass/warn/fail sections and nonzero on blockers. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Command returns product pass/warn/fail sections and nonzero on blockers.

- [ ] **M8-16.release** (depends on: M8-16.verify, M8-15, M8-07, SHIP-GATE). Have the batch reviewer map M8-16 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-17a"></a>
## M8-17a: preflight IAM IRSA

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4366, exact task ID M8-17a. Status/evidence: row `M8-17a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-16.
- Nearest pending prerequisites: M8-16.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check required IAM roles, trust and IRSA bindings.

**Original verification:** Missing trust permission returns the exact product remediation hint.

- [ ] **M8-17a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-17a and locate the existing preflight IAM IRSA implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-16). Prepare bounded inputs and expected observations for this task's criterion: Missing trust permission returns the exact product remediation hint. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-17a.deliver** (depends on: M8-17a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check required IAM roles, trust and IRSA bindings.
  Output: Check required IAM roles, trust and IRSA bindings.

- [ ] **M8-17a.verify** (depends on: M8-17a.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Missing trust permission returns the exact product remediation hint. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Missing trust permission returns the exact product remediation hint.

- [ ] **M8-17a.release** (depends on: M8-17a.verify, M8-16, SHIP-GATE). Have the batch reviewer map M8-17a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-17b"></a>
## M8-17b: preflight S3 KMS Secrets

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4372, exact task ID M8-17b. Status/evidence: row `M8-17b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-17a.
- Nearest pending prerequisites: M8-17a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check S3 evidence bucket, KMS key and Secrets Manager access.

**Original verification:** Denied fixture identifies the failing AWS permission.

- [ ] **M8-17b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-17b and locate the existing preflight S3 KMS Secrets implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-17a). Prepare bounded inputs and expected observations for this task's criterion: Denied fixture identifies the failing AWS permission. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-17b.deliver** (depends on: M8-17b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check S3 evidence bucket, KMS key and Secrets Manager access.
  Output: Check S3 evidence bucket, KMS key and Secrets Manager access.

- [ ] **M8-17b.verify** (depends on: M8-17b.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Denied fixture identifies the failing AWS permission. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Denied fixture identifies the failing AWS permission.

- [ ] **M8-17b.release** (depends on: M8-17b.verify, M8-17a, SHIP-GATE). Have the batch reviewer map M8-17b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-17c"></a>
## M8-17c: preflight SQS

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4378, exact task ID M8-17c. Status/evidence: row `M8-17c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-17b.
- Nearest pending prerequisites: M8-17b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check required SQS queues/DLQs and producer/consumer permissions.

**Original verification:** Missing queue or permission is reported before install.

- [ ] **M8-17c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-17c and locate the existing preflight SQS implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-17b). Prepare bounded inputs and expected observations for this task's criterion: Missing queue or permission is reported before install. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-17c.deliver** (depends on: M8-17c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check required SQS queues/DLQs and producer/consumer permissions.
  Output: Check required SQS queues/DLQs and producer/consumer permissions.

- [ ] **M8-17c.verify** (depends on: M8-17c.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Missing queue or permission is reported before install. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Missing queue or permission is reported before install.

- [ ] **M8-17c.release** (depends on: M8-17c.verify, M8-17b, SHIP-GATE). Have the batch reviewer map M8-17c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-17d"></a>
## M8-17d: preflight OpenSearch

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4384, exact task ID M8-17d. Status/evidence: row `M8-17d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-17c.
- Nearest pending prerequisites: M8-17c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check OpenSearch endpoint reachability and required index permissions.

**Original verification:** Denied fixture reports an actionable product error.

- [ ] **M8-17d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-17d and locate the existing preflight OpenSearch implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-17c). Prepare bounded inputs and expected observations for this task's criterion: Denied fixture reports an actionable product error. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-17d.deliver** (depends on: M8-17d.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check OpenSearch endpoint reachability and required index permissions.
  Output: Check OpenSearch endpoint reachability and required index permissions.

- [ ] **M8-17d.verify** (depends on: M8-17d.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Denied fixture reports an actionable product error. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Denied fixture reports an actionable product error.

- [ ] **M8-17d.release** (depends on: M8-17d.verify, M8-17c, SHIP-GATE). Have the batch reviewer map M8-17d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-17e"></a>
## M8-17e: preflight EKS Fargate

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4390, exact task ID M8-17e. Status/evidence: row `M8-17e` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-17d.
- Nearest pending prerequisites: M8-17d.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check EKS version, Attack Lab Fargate profile/namespace and required networking prerequisites.

**Original verification:** Missing Fargate prerequisite blocks Attack Lab readiness only.

- [ ] **M8-17e.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-17e and locate the existing preflight EKS Fargate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-17d). Prepare bounded inputs and expected observations for this task's criterion: Missing Fargate prerequisite blocks Attack Lab readiness only. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-17e.deliver** (depends on: M8-17e.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check EKS version, Attack Lab Fargate profile/namespace and required networking prerequisites.
  Output: Check EKS version, Attack Lab Fargate profile/namespace and required networking prerequisites.

- [ ] **M8-17e.verify** (depends on: M8-17e.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Missing Fargate prerequisite blocks Attack Lab readiness only. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Missing Fargate prerequisite blocks Attack Lab readiness only.

- [ ] **M8-17e.release** (depends on: M8-17e.verify, M8-17d, SHIP-GATE). Have the batch reviewer map M8-17e to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-17"></a>
## M8-17: preflight AWS

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4396, exact task ID M8-17. Status/evidence: row `M8-17` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-17e.
- Nearest pending prerequisites: M8-17e.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Assemble AWS preflight results into one product readiness report.

**Original verification:** Report separates blocking core prerequisites from optional/feature-specific prerequisites.

- [ ] **M8-17.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-17 and locate the existing preflight AWS implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-17e). Prepare bounded inputs and expected observations for this task's criterion: Report separates blocking core prerequisites from optional/feature-specific prerequisites. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-17.deliver** (depends on: M8-17.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Assemble AWS preflight results into one product readiness report.
  Output: Assemble AWS preflight results into one product readiness report.

- [ ] **M8-17.verify** (depends on: M8-17.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Report separates blocking core prerequisites from optional/feature-specific prerequisites. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Report separates blocking core prerequisites from optional/feature-specific prerequisites.

- [ ] **M8-17.release** (depends on: M8-17.verify, M8-17e, SHIP-GATE). Have the batch reviewer map M8-17 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-18"></a>
## M8-18: preflight Neon/Stytch

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4402, exact task ID M8-18. Status/evidence: row `M8-18` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-17.
- Nearest pending prerequisites: M8-17.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check Neon migration/pool connectivity and Stytch project/session reachability.

**Original verification:** Dependency failure is clearly labeled required.

- [ ] **M8-18.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-18 and locate the existing preflight Neon/Stytch implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-17). Prepare bounded inputs and expected observations for this task's criterion: Dependency failure is clearly labeled required. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-18.deliver** (depends on: M8-18.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check Neon migration/pool connectivity and Stytch project/session reachability.
  Output: Check Neon migration/pool connectivity and Stytch project/session reachability.

- [ ] **M8-18.verify** (depends on: M8-18.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Dependency failure is clearly labeled required. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Dependency failure is clearly labeled required.

- [ ] **M8-18.release** (depends on: M8-18.verify, M8-17, SHIP-GATE). Have the batch reviewer map M8-18 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-19"></a>
## M8-19: preflight sensor

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4408, exact task ID M8-19. Status/evidence: row `M8-19` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-18.
- Nearest pending prerequisites: M8-18.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check kernel/BTF/Tetragon prerequisites on selected EC2 node pool.

**Original verification:** Unsupported kernel returns warning/block based on selected sensor mode.

- [ ] **M8-19.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-19 and locate the existing preflight sensor implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-18). Prepare bounded inputs and expected observations for this task's criterion: Unsupported kernel returns warning/block based on selected sensor mode. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-19.deliver** (depends on: M8-19.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check kernel/BTF/Tetragon prerequisites on selected EC2 node pool.
  Output: Check kernel/BTF/Tetragon prerequisites on selected EC2 node pool.

- [ ] **M8-19.verify** (depends on: M8-19.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Unsupported kernel returns warning/block based on selected sensor mode. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Unsupported kernel returns warning/block based on selected sensor mode.

- [ ] **M8-19.release** (depends on: M8-19.verify, M8-18, SHIP-GATE). Have the batch reviewer map M8-19 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-22a"></a>
## M8-22a: upgrade version check

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4474, exact task ID M8-22a. Status/evidence: row `M8-22a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-21.
- Nearest pending prerequisites: M8-19.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check current and target product version compatibility before upgrade.

**Original verification:** Unsupported version jump is rejected before mutation.

- [ ] **M8-22a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-22a and locate the existing upgrade version check implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-21). Prepare bounded inputs and expected observations for this task's criterion: Unsupported version jump is rejected before mutation. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-22a.deliver** (depends on: M8-22a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check current and target product version compatibility before upgrade.
  Output: Check current and target product version compatibility before upgrade.

- [ ] **M8-22a.verify** (depends on: M8-22a.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Unsupported version jump is rejected before mutation. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Unsupported version jump is rejected before mutation.

- [ ] **M8-22a.release** (depends on: M8-22a.verify, M8-21, M8-19, SHIP-GATE). Have the batch reviewer map M8-22a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-22b"></a>
## M8-22b: upgrade migration check

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4480, exact task ID M8-22b. Status/evidence: row `M8-22b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-22a.
- Nearest pending prerequisites: M8-22a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check Neon schema migration compatibility before upgrade.

**Original verification:** Incompatible migration fixture blocks upgrade.

- [ ] **M8-22b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-22b and locate the existing upgrade migration check implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-22a). Prepare bounded inputs and expected observations for this task's criterion: Incompatible migration fixture blocks upgrade. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-22b.deliver** (depends on: M8-22b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check Neon schema migration compatibility before upgrade.
  Output: Check Neon schema migration compatibility before upgrade.

- [ ] **M8-22b.verify** (depends on: M8-22b.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Incompatible migration fixture blocks upgrade. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Incompatible migration fixture blocks upgrade.

- [ ] **M8-22b.release** (depends on: M8-22b.verify, M8-22a, SHIP-GATE). Have the batch reviewer map M8-22b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-22c"></a>
## M8-22c: upgrade bundle check

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4486, exact task ID M8-22c. Status/evidence: row `M8-22c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-22b.
- Nearest pending prerequisites: M8-22b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check policy/content bundle format compatibility before upgrade.

**Original verification:** Unsupported bundle format blocks upgrade.

- [ ] **M8-22c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-22c and locate the existing upgrade bundle check implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-22b). Prepare bounded inputs and expected observations for this task's criterion: Unsupported bundle format blocks upgrade. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-22c.deliver** (depends on: M8-22c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check policy/content bundle format compatibility before upgrade.
  Output: Check policy/content bundle format compatibility before upgrade.

- [ ] **M8-22c.verify** (depends on: M8-22c.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Unsupported bundle format blocks upgrade. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Unsupported bundle format blocks upgrade.

- [ ] **M8-22c.release** (depends on: M8-22c.verify, M8-22b, SHIP-GATE). Have the batch reviewer map M8-22c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-22d"></a>
## M8-22d: upgrade rollback check

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4492, exact task ID M8-22d. Status/evidence: row `M8-22d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-22c.
- Nearest pending prerequisites: M8-22c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check that required rollback artifact and backup/recovery reference exist.

**Original verification:** Missing rollback prerequisite blocks upgrade.

- [ ] **M8-22d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-22d and locate the existing upgrade rollback check implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-22c). Prepare bounded inputs and expected observations for this task's criterion: Missing rollback prerequisite blocks upgrade. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-22d.deliver** (depends on: M8-22d.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check that required rollback artifact and backup/recovery reference exist.
  Output: Check that required rollback artifact and backup/recovery reference exist.

- [ ] **M8-22d.verify** (depends on: M8-22d.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Missing rollback prerequisite blocks upgrade. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Missing rollback prerequisite blocks upgrade.

- [ ] **M8-22d.release** (depends on: M8-22d.verify, M8-22c, SHIP-GATE). Have the batch reviewer map M8-22d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-22"></a>
## M8-22: upgrade preflight

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4498, exact task ID M8-22. Status/evidence: row `M8-22` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-22d.
- Nearest pending prerequisites: M8-22d.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Assemble upgrade checks into one read-only preflight command.

**Original verification:** Incompatible fixture blocks upgrade before any mutation.

- [ ] **M8-22.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-22 and locate the existing upgrade preflight implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-22d). Prepare bounded inputs and expected observations for this task's criterion: Incompatible fixture blocks upgrade before any mutation. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-22.deliver** (depends on: M8-22.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Assemble upgrade checks into one read-only preflight command.
  Output: Assemble upgrade checks into one read-only preflight command.

- [ ] **M8-22.verify** (depends on: M8-22.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Incompatible fixture blocks upgrade before any mutation. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Incompatible fixture blocks upgrade before any mutation.

- [ ] **M8-22.release** (depends on: M8-22.verify, M8-22d, SHIP-GATE). Have the batch reviewer map M8-22 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-23a"></a>
## M8-23a: Start upgrade fixture

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4504, exact task ID M8-23a. Status/evidence: row `M8-23a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-22.
- Nearest pending prerequisites: M8-22.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Deploy previous-supported-version fixture into disposable environment.

**Original verification:** Fixture reports ready version before timebox ends.

- [ ] **M8-23a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-23a and locate the existing Start upgrade fixture implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-22). Prepare bounded inputs and expected observations for this task's criterion: Fixture reports ready version before timebox ends. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-23a.deliver** (depends on: M8-23a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Deploy previous-supported-version fixture into disposable environment.
  Output: Deploy previous-supported-version fixture into disposable environment.

- [ ] **M8-23a.verify** (depends on: M8-23a.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Fixture reports ready version before timebox ends. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Fixture reports ready version before timebox ends.

- [ ] **M8-23a.release** (depends on: M8-23a.verify, M8-22, SHIP-GATE). Have the batch reviewer map M8-23a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-23b"></a>
## M8-23b: Run upgrade

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4510, exact task ID M8-23b. Status/evidence: row `M8-23b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-23a.
- Nearest pending prerequisites: M8-23a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Start current-version upgrade and record migration/release IDs.

**Original verification:** Upgrade reaches success or tracked failure state.

- [ ] **M8-23b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-23b and locate the existing Run upgrade implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-23a). Prepare bounded inputs and expected observations for this task's criterion: Upgrade reaches success or tracked failure state. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-23b.deliver** (depends on: M8-23b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Start current-version upgrade and record migration/release IDs.
  Output: Start current-version upgrade and record migration/release IDs.

- [ ] **M8-23b.verify** (depends on: M8-23b.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Upgrade reaches success or tracked failure state. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Upgrade reaches success or tracked failure state.

- [ ] **M8-23b.release** (depends on: M8-23b.verify, M8-23a, SHIP-GATE). Have the batch reviewer map M8-23b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-23c"></a>
## M8-23c: Inject rollback condition

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4516, exact task ID M8-23c. Status/evidence: row `M8-23c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-23b.
- Nearest pending prerequisites: M8-23b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Trigger the documented rollback path in disposable fixture.

**Original verification:** Rollback command targets the recorded release/version only.

- [ ] **M8-23c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-23c and locate the existing Inject rollback condition implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-23b). Prepare bounded inputs and expected observations for this task's criterion: Rollback command targets the recorded release/version only. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-23c.deliver** (depends on: M8-23c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Trigger the documented rollback path in disposable fixture.
  Output: Trigger the documented rollback path in disposable fixture.

- [ ] **M8-23c.verify** (depends on: M8-23c.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Rollback command targets the recorded release/version only. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Rollback command targets the recorded release/version only.

- [ ] **M8-23c.release** (depends on: M8-23c.verify, M8-23b, SHIP-GATE). Have the batch reviewer map M8-23c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-23d"></a>
## M8-23d: Validate rollback state

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4522, exact task ID M8-23d. Status/evidence: row `M8-23d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-23c.
- Nearest pending prerequisites: M8-23c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Compare product version, schema compatibility and sampled policy/evidence state.

**Original verification:** Validator reports no silent data loss.

- [ ] **M8-23d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-23d and locate the existing Validate rollback state implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-23c). Prepare bounded inputs and expected observations for this task's criterion: Validator reports no silent data loss. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-23d.deliver** (depends on: M8-23d.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Compare product version, schema compatibility and sampled policy/evidence state.
  Output: Compare product version, schema compatibility and sampled policy/evidence state.

- [ ] **M8-23d.verify** (depends on: M8-23d.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Validator reports no silent data loss. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Validator reports no silent data loss.

- [ ] **M8-23d.release** (depends on: M8-23d.verify, M8-23c, SHIP-GATE). Have the batch reviewer map M8-23d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-23"></a>
## M8-23: upgrade rollback test

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4528, exact task ID M8-23. Status/evidence: row `M8-23` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-23d.
- Nearest pending prerequisites: M8-23d.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Record upgrade/rollback rehearsal result.

**Original verification:** Release evidence links upgrade, rollback and state-validation artifacts.

- [ ] **M8-23.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-23 and locate the existing upgrade rollback test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-23d). Prepare bounded inputs and expected observations for this task's criterion: Release evidence links upgrade, rollback and state-validation artifacts. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-23.deliver** (depends on: M8-23.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Record upgrade/rollback rehearsal result.
  Output: Record upgrade/rollback rehearsal result.

- [ ] **M8-23.verify** (depends on: M8-23.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Release evidence links upgrade, rollback and state-validation artifacts. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Release evidence links upgrade, rollback and state-validation artifacts.

- [ ] **M8-23.release** (depends on: M8-23.verify, M8-23d, SHIP-GATE). Have the batch reviewer map M8-23 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-24"></a>
## M8-24: diagnostics bundle

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4534, exact task ID M8-24. Status/evidence: row `M8-24` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-23.
- Nearest pending prerequisites: M8-23.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Create redacted `agentsecctl diagnostics` bundle with health/config versions and bounded logs.

**Original verification:** Seeded secrets/vendor tokens are absent.

- [ ] **M8-24.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-24 and locate the existing diagnostics bundle implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-23). Prepare bounded inputs and expected observations for this task's criterion: Seeded secrets/vendor tokens are absent. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-24.deliver** (depends on: M8-24.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create redacted `agentsecctl diagnostics` bundle with health/config versions and bounded logs.
  Output: Create redacted `agentsecctl diagnostics` bundle with health/config versions and bounded logs.

- [ ] **M8-24.verify** (depends on: M8-24.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Seeded secrets/vendor tokens are absent. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Seeded secrets/vendor tokens are absent.

- [ ] **M8-24.release** (depends on: M8-24.verify, M8-23, SHIP-GATE). Have the batch reviewer map M8-24 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-25"></a>
## M8-25: real AWS parity IAM

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4540, exact task ID M8-25. Status/evidence: row `M8-25` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-24.
- Nearest pending prerequisites: M8-24.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Run bounded IAM/STS/IRSA parity tests in isolated AWS account.

**Original verification:** Results match intended deny/allow semantics, independent of LocalStack.

- [ ] **M8-25.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-25 and locate the existing real AWS parity IAM implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-24). Prepare bounded inputs and expected observations for this task's criterion: Results match intended deny/allow semantics, independent of LocalStack. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-25.deliver** (depends on: M8-25.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Run bounded IAM/STS/IRSA parity tests in isolated AWS account.
  Output: Run bounded IAM/STS/IRSA parity tests in isolated AWS account.

- [ ] **M8-25.verify** (depends on: M8-25.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Results match intended deny/allow semantics, independent of LocalStack. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Results match intended deny/allow semantics, independent of LocalStack.

- [ ] **M8-25.release** (depends on: M8-25.verify, M8-24, SHIP-GATE). Have the batch reviewer map M8-25 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-26"></a>
## M8-26: real AWS parity storage

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4546, exact task ID M8-26. Status/evidence: row `M8-26` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-25.
- Nearest pending prerequisites: M8-25.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Run S3/KMS/Secrets/SQS/OpenSearch parity smoke in isolated AWS account.

**Original verification:** Critical operations match LocalStack-backed expectations.

- [ ] **M8-26.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-26 and locate the existing real AWS parity storage implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-25). Prepare bounded inputs and expected observations for this task's criterion: Critical operations match LocalStack-backed expectations. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-26.deliver** (depends on: M8-26.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Run S3/KMS/Secrets/SQS/OpenSearch parity smoke in isolated AWS account.
  Output: Run S3/KMS/Secrets/SQS/OpenSearch parity smoke in isolated AWS account.

- [ ] **M8-26.verify** (depends on: M8-26.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Critical operations match LocalStack-backed expectations. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Critical operations match LocalStack-backed expectations.

- [ ] **M8-26.release** (depends on: M8-26.verify, M8-25, SHIP-GATE). Have the batch reviewer map M8-26 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-27"></a>
## M8-27: real AWS Fargate parity

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4552, exact task ID M8-27. Status/evidence: row `M8-27` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-26.
- Nearest pending prerequisites: M8-26.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Run Attack Lab Fargate/SG/proxy canary in isolated AWS account.

**Original verification:** Direct egress denied, proxy-allowed destination succeeds, run cleans up.

- [ ] **M8-27.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-27 and locate the existing real AWS Fargate parity implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-26). Prepare bounded inputs and expected observations for this task's criterion: Direct egress denied, proxy-allowed destination succeeds, run cleans up. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-27.deliver** (depends on: M8-27.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Run Attack Lab Fargate/SG/proxy canary in isolated AWS account.
  Output: Run Attack Lab Fargate/SG/proxy canary in isolated AWS account.

- [ ] **M8-27.verify** (depends on: M8-27.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Direct egress denied, proxy-allowed destination succeeds, run cleans up. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Direct egress denied, proxy-allowed destination succeeds, run cleans up.

- [ ] **M8-27.release** (depends on: M8-27.verify, M8-26, SHIP-GATE). Have the batch reviewer map M8-27 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-28"></a>
## M8-28: Stytch outage test

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4558, exact task ID M8-28. Status/evidence: row `M8-28` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-27.
- Nearest pending prerequisites: M8-27.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Inject Stytch API failure after valid session/policy deployment.

**Original verification:** New login degrades; runtime enforcement remains active; JWT is not extended beyond normal validity.

- [ ] **M8-28.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-28 and locate the existing Stytch outage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-27). Prepare bounded inputs and expected observations for this task's criterion: New login degrades; runtime enforcement remains active; JWT is not extended beyond normal validity. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-28.deliver** (depends on: M8-28.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Inject Stytch API failure after valid session/policy deployment.
  Output: Inject Stytch API failure after valid session/policy deployment.

- [ ] **M8-28.verify** (depends on: M8-28.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: New login degrades; runtime enforcement remains active; JWT is not extended beyond normal validity. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: New login degrades; runtime enforcement remains active; JWT is not extended beyond normal validity.

- [ ] **M8-28.release** (depends on: M8-28.verify, M8-27, SHIP-GATE). Have the batch reviewer map M8-28 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-29"></a>
## M8-29: Neon outage test

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4564, exact task ID M8-29. Status/evidence: row `M8-29` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-28.
- Nearest pending prerequisites: M8-28.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Inject Neon failure during control-plane mutation and runtime traffic.

**Original verification:** Mutation fails fast; runtime gateway continues from cached bundle.

- [ ] **M8-29.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-29 and locate the existing Neon outage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-28). Prepare bounded inputs and expected observations for this task's criterion: Mutation fails fast; runtime gateway continues from cached bundle. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-29.deliver** (depends on: M8-29.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Inject Neon failure during control-plane mutation and runtime traffic.
  Output: Inject Neon failure during control-plane mutation and runtime traffic.

- [ ] **M8-29.verify** (depends on: M8-29.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Mutation fails fast; runtime gateway continues from cached bundle. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Mutation fails fast; runtime gateway continues from cached bundle.

- [ ] **M8-29.release** (depends on: M8-29.verify, M8-28, SHIP-GATE). Have the batch reviewer map M8-29 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-30"></a>
## M8-30: Nango outage test

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4570, exact task ID M8-30. Status/evidence: row `M8-30` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-29.
- Nearest pending prerequisites: M8-29.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Stop Nango during long-tail connection usage.

**Original verification:** Core launch connectors, inventory, paths and runtime policy continue.

- [ ] **M8-30.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-30 and locate the existing Nango outage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-29). Prepare bounded inputs and expected observations for this task's criterion: Core launch connectors, inventory, paths and runtime policy continue. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-30.deliver** (depends on: M8-30.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Stop Nango during long-tail connection usage.
  Output: Stop Nango during long-tail connection usage.

- [ ] **M8-30.verify** (depends on: M8-30.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Core launch connectors, inventory, paths and runtime policy continue. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Core launch connectors, inventory, paths and runtime policy continue.

- [ ] **M8-30.release** (depends on: M8-30.verify, M8-29, SHIP-GATE). Have the batch reviewer map M8-30 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-31"></a>
## M8-31: optional vendor outage test

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4576, exact task ID M8-31. Status/evidence: row `M8-31` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-30.
- Nearest pending prerequisites: M8-30.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Fail PostHog, OpenRouter and remote OTLP concurrently.

**Original verification:** Golden deterministic security flow still passes except optional UX.

- [ ] **M8-31.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-31 and locate the existing optional vendor outage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-30). Prepare bounded inputs and expected observations for this task's criterion: Golden deterministic security flow still passes except optional UX. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-31.deliver** (depends on: M8-31.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Fail PostHog, OpenRouter and remote OTLP concurrently.
  Output: Fail PostHog, OpenRouter and remote OTLP concurrently.

- [ ] **M8-31.verify** (depends on: M8-31.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Golden deterministic security flow still passes except optional UX. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Golden deterministic security flow still passes except optional UX.

- [ ] **M8-31.release** (depends on: M8-31.verify, M8-30, SHIP-GATE). Have the batch reviewer map M8-31 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-32"></a>
## M8-32: OpenSearch outage test

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4582, exact task ID M8-32. Status/evidence: row `M8-32` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-31.
- Nearest pending prerequisites: M8-31.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Fail OpenSearch while event batches arrive.

**Original verification:** Search degrades, SQS backlog is visible and runtime policy continues.

- [ ] **M8-32.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-32 and locate the existing OpenSearch outage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-31). Prepare bounded inputs and expected observations for this task's criterion: Search degrades, SQS backlog is visible and runtime policy continues. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-32.deliver** (depends on: M8-32.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Fail OpenSearch while event batches arrive.
  Output: Fail OpenSearch while event batches arrive.

- [ ] **M8-32.verify** (depends on: M8-32.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Search degrades, SQS backlog is visible and runtime policy continues. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Search degrades, SQS backlog is visible and runtime policy continues.

- [ ] **M8-32.release** (depends on: M8-32.verify, M8-31, SHIP-GATE). Have the batch reviewer map M8-32 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-33"></a>
## M8-33: Neo4j outage test

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4588, exact task ID M8-33. Status/evidence: row `M8-33` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-32.
- Nearest pending prerequisites: M8-32.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Fail graph backend during inventory reads.

**Original verification:** Path/capability shows Degraded and basic inventory remains.

- [ ] **M8-33.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-33 and locate the existing Neo4j outage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-32). Prepare bounded inputs and expected observations for this task's criterion: Path/capability shows Degraded and basic inventory remains. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-33.deliver** (depends on: M8-33.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Fail graph backend during inventory reads.
  Output: Fail graph backend during inventory reads.

- [ ] **M8-33.verify** (depends on: M8-33.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Path/capability shows Degraded and basic inventory remains. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Path/capability shows Degraded and basic inventory remains.

- [ ] **M8-33.release** (depends on: M8-33.verify, M8-32, SHIP-GATE). Have the batch reviewer map M8-33 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-34"></a>
## M8-34: SQS saturation test

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4594, exact task ID M8-34. Status/evidence: row `M8-34` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-33.
- Nearest pending prerequisites: M8-33.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Throttle SQS/event worker and observe backlog/drop behavior.

**Original verification:** No unbounded process memory growth and queue age is visible.

- [ ] **M8-34.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-34 and locate the existing SQS saturation test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-33). Prepare bounded inputs and expected observations for this task's criterion: No unbounded process memory growth and queue age is visible. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-34.deliver** (depends on: M8-34.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Throttle SQS/event worker and observe backlog/drop behavior.
  Output: Throttle SQS/event worker and observe backlog/drop behavior.

- [ ] **M8-34.verify** (depends on: M8-34.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: No unbounded process memory growth and queue age is visible. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: No unbounded process memory growth and queue age is visible.

- [ ] **M8-34.release** (depends on: M8-34.verify, M8-33, SHIP-GATE). Have the batch reviewer map M8-34 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-35"></a>
## M8-35: runtime latency test

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4600, exact task ID M8-35. Status/evidence: row `M8-35` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-34.
- Nearest pending prerequisites: M8-34.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Run metadata policy benchmark at reference concurrency.

**Original verification:** p95 <=25 ms or release gate fails with measured exception.

- [ ] **M8-35.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-35 and locate the existing runtime latency test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-34). Prepare bounded inputs and expected observations for this task's criterion: p95 <=25 ms or release gate fails with measured exception. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-35.deliver** (depends on: M8-35.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Run metadata policy benchmark at reference concurrency.
  Output: Run metadata policy benchmark at reference concurrency.

- [ ] **M8-35.verify** (depends on: M8-35.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: p95 <=25 ms or release gate fails with measured exception. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: p95 <=25 ms or release gate fails with measured exception.

- [ ] **M8-35.release** (depends on: M8-35.verify, M8-34, SHIP-GATE). Have the batch reviewer map M8-35 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-36a"></a>
## M8-36a: API load scenario

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4606, exact task ID M8-36a. Status/evidence: row `M8-36a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-35.
- Nearest pending prerequisites: M8-35.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Define bounded representative API workload and success thresholds.

**Original verification:** Scenario lints and contains no unbounded endpoint/query.

- [ ] **M8-36a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-36a and locate the existing API load scenario implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-35). Prepare bounded inputs and expected observations for this task's criterion: Scenario lints and contains no unbounded endpoint/query. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-36a.deliver** (depends on: M8-36a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Define bounded representative API workload and success thresholds.
  Output: Define bounded representative API workload and success thresholds.

- [ ] **M8-36a.verify** (depends on: M8-36a.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Scenario lints and contains no unbounded endpoint/query. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Scenario lints and contains no unbounded endpoint/query.

- [ ] **M8-36a.release** (depends on: M8-36a.verify, M8-35, SHIP-GATE). Have the batch reviewer map M8-36a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-36b"></a>
## M8-36b: Run API load

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4612, exact task ID M8-36b. Status/evidence: row `M8-36b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-36a.
- Nearest pending prerequisites: M8-36a.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Run the bounded workload for <=5 minutes on reference deployment.

**Original verification:** Run produces latency/error artifact.

- [ ] **M8-36b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-36b and locate the existing Run API load implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-36a). Prepare bounded inputs and expected observations for this task's criterion: Run produces latency/error artifact. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-36b.deliver** (depends on: M8-36b.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Run the bounded workload for <=5 minutes on reference deployment.
  Output: Run the bounded workload for <=5 minutes on reference deployment.

- [ ] **M8-36b.verify** (depends on: M8-36b.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Run produces latency/error artifact. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Run produces latency/error artifact.

- [ ] **M8-36b.release** (depends on: M8-36b.verify, M8-36a, SHIP-GATE). Have the batch reviewer map M8-36b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-36c"></a>
## M8-36c: Evaluate API load

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4618, exact task ID M8-36c. Status/evidence: row `M8-36c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-36b.
- Nearest pending prerequisites: M8-36b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Calculate p50/p95/p99/error rate from artifact.

**Original verification:** Gate result is deterministic and linked to reference profile.

- [ ] **M8-36c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-36c and locate the existing Evaluate API load implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-36b). Prepare bounded inputs and expected observations for this task's criterion: Gate result is deterministic and linked to reference profile. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-36c.deliver** (depends on: M8-36c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Calculate p50/p95/p99/error rate from artifact.
  Output: Calculate p50/p95/p99/error rate from artifact.

- [ ] **M8-36c.verify** (depends on: M8-36c.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Gate result is deterministic and linked to reference profile. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Gate result is deterministic and linked to reference profile.

- [ ] **M8-36c.release** (depends on: M8-36c.verify, M8-36b, SHIP-GATE). Have the batch reviewer map M8-36c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-36"></a>
## M8-36: API reference load

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4624, exact task ID M8-36. Status/evidence: row `M8-36` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-36c.
- Nearest pending prerequisites: M8-36c.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Record API reference-load gate result.

**Original verification:** Measured p95 comparison is stored in release evidence.

- [ ] **M8-36.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-36 and locate the existing API reference load implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-36c). Prepare bounded inputs and expected observations for this task's criterion: Measured p95 comparison is stored in release evidence. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-36.deliver** (depends on: M8-36.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Record API reference-load gate result.
  Output: Record API reference-load gate result.

- [ ] **M8-36.verify** (depends on: M8-36.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Measured p95 comparison is stored in release evidence. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Measured p95 comparison is stored in release evidence.

- [ ] **M8-36.release** (depends on: M8-36.verify, M8-36c, SHIP-GATE). Have the batch reviewer map M8-36 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-37"></a>
## M8-37: graph bounded load

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4630, exact task ID M8-37. Status/evidence: row `M8-37` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-36.
- Nearest pending prerequisites: M8-36.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Run bounded path/neighborhood fixtures at reference graph size.

**Original verification:** Supported query returns <=3 s and depth/result limits hold.

- [ ] **M8-37.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-37 and locate the existing graph bounded load implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-36). Prepare bounded inputs and expected observations for this task's criterion: Supported query returns <=3 s and depth/result limits hold. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-37.deliver** (depends on: M8-37.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Run bounded path/neighborhood fixtures at reference graph size.
  Output: Run bounded path/neighborhood fixtures at reference graph size.

- [ ] **M8-37.verify** (depends on: M8-37.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Supported query returns <=3 s and depth/result limits hold. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Supported query returns <=3 s and depth/result limits hold.

- [ ] **M8-37.release** (depends on: M8-37.verify, M8-36, SHIP-GATE). Have the batch reviewer map M8-37 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-38a"></a>
## M8-38a: Event load generator

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4636, exact task ID M8-38a. Status/evidence: row `M8-38a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-37.
- Nearest pending prerequisites: M8-37.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Create relevant normalized-event batch generator and bounded run config.

**Original verification:** Generator produces scoped batches at requested rate.

- [ ] **M8-38a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-38a and locate the existing Event load generator implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-37). Prepare bounded inputs and expected observations for this task's criterion: Generator produces scoped batches at requested rate. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-38a.deliver** (depends on: M8-38a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create relevant normalized-event batch generator and bounded run config.
  Output: Create relevant normalized-event batch generator and bounded run config.

- [ ] **M8-38a.verify** (depends on: M8-38a.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Generator produces scoped batches at requested rate. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Generator produces scoped batches at requested rate.

- [ ] **M8-38a.release** (depends on: M8-38a.verify, M8-37, SHIP-GATE). Have the batch reviewer map M8-38a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-38b"></a>
## M8-38b: Run event floor load

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4642, exact task ID M8-38b. Status/evidence: row `M8-38b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-38a.
- Nearest pending prerequisites: M8-38a.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Run 5k relevant events/sec for <=5 minutes.

**Original verification:** Run produces queue/index/drop metrics artifact.

- [ ] **M8-38b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-38b and locate the existing Run event floor load implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-38a). Prepare bounded inputs and expected observations for this task's criterion: Run produces queue/index/drop metrics artifact. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-38b.deliver** (depends on: M8-38b.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Run 5k relevant events/sec for <=5 minutes.
  Output: Run 5k relevant events/sec for <=5 minutes.

- [ ] **M8-38b.verify** (depends on: M8-38b.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Run produces queue/index/drop metrics artifact. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Run produces queue/index/drop metrics artifact.

- [ ] **M8-38b.release** (depends on: M8-38b.verify, M8-38a, SHIP-GATE). Have the batch reviewer map M8-38b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-38c"></a>
## M8-38c: Evaluate event floor load

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4648, exact task ID M8-38c. Status/evidence: row `M8-38c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-38b.
- Nearest pending prerequisites: M8-38b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Check backlog recovery, indexing and observed drops/retries.

**Original verification:** Gate reports pass/fail with exact measured values.

- [ ] **M8-38c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-38c and locate the existing Evaluate event floor load implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-38b). Prepare bounded inputs and expected observations for this task's criterion: Gate reports pass/fail with exact measured values. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-38c.deliver** (depends on: M8-38c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Check backlog recovery, indexing and observed drops/retries.
  Output: Check backlog recovery, indexing and observed drops/retries.

- [ ] **M8-38c.verify** (depends on: M8-38c.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Gate reports pass/fail with exact measured values. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Gate reports pass/fail with exact measured values.

- [ ] **M8-38c.release** (depends on: M8-38c.verify, M8-38b, SHIP-GATE). Have the batch reviewer map M8-38c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-38"></a>
## M8-38: event floor load

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4654, exact task ID M8-38. Status/evidence: row `M8-38` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-38c.
- Nearest pending prerequisites: M8-38c.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Record event-floor gate result.

**Original verification:** Measured rate/backlog/drop result is stored in release evidence.

- [ ] **M8-38.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-38 and locate the existing event floor load implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-38c). Prepare bounded inputs and expected observations for this task's criterion: Measured rate/backlog/drop result is stored in release evidence. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-38.deliver** (depends on: M8-38.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Record event-floor gate result.
  Output: Record event-floor gate result.

- [ ] **M8-38.verify** (depends on: M8-38.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Measured rate/backlog/drop result is stored in release evidence. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Measured rate/backlog/drop result is stored in release evidence.

- [ ] **M8-38.release** (depends on: M8-38.verify, M8-38c, SHIP-GATE). Have the batch reviewer map M8-38 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-39"></a>
## M8-39: sensor overhead measurement

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4660, exact task ID M8-39. Status/evidence: row `M8-39` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-38.
- Nearest pending prerequisites: M8-38.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Measure Tetragon/product adapter CPU/memory on representative workload.

**Original verification:** Result is documented without universal unsupported percentage claim.

- [ ] **M8-39.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-39 and locate the existing sensor overhead measurement implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-38). Prepare bounded inputs and expected observations for this task's criterion: Result is documented without universal unsupported percentage claim. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-39.deliver** (depends on: M8-39.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Measure Tetragon/product adapter CPU/memory on representative workload.
  Output: Measure Tetragon/product adapter CPU/memory on representative workload.

- [ ] **M8-39.verify** (depends on: M8-39.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Result is documented without universal unsupported percentage claim. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Result is documented without universal unsupported percentage claim.

- [ ] **M8-39.release** (depends on: M8-39.verify, M8-38, SHIP-GATE). Have the batch reviewer map M8-39 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-40a"></a>
## M8-40a: API tenant isolation security test

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4666, exact task ID M8-40a. Status/evidence: row `M8-40a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-39.
- Nearest pending prerequisites: M8-39.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Attempt cross-Organization and cross-Workspace REST API reads and mutations.

**Original verification:** Every request fails server-side with the stable tenant-boundary error and no foreign data.

- [ ] **M8-40a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-40a and locate the existing API tenant isolation security test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-39). Prepare bounded inputs and expected observations for this task's criterion: Every request fails server-side with the stable tenant-boundary error and no foreign data. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-40a.deliver** (depends on: M8-40a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Attempt cross-Organization and cross-Workspace REST API reads and mutations.
  Output: Attempt cross-Organization and cross-Workspace REST API reads and mutations.

- [ ] **M8-40a.verify** (depends on: M8-40a.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Every request fails server-side with the stable tenant-boundary error and no foreign data. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Every request fails server-side with the stable tenant-boundary error and no foreign data.

- [ ] **M8-40a.release** (depends on: M8-40a.verify, M8-39, SHIP-GATE). Have the batch reviewer map M8-40a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-40b"></a>
## M8-40b: graph tenant isolation security test

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4672, exact task ID M8-40b. Status/evidence: row `M8-40b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-40a.
- Nearest pending prerequisites: M8-40a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Attempt a bounded graph read/path query from Organization A against Organization B fixture nodes.

**Original verification:** Query returns no cross-Organization node or edge and records the denial/guard result.

- [ ] **M8-40b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-40b and locate the existing graph tenant isolation security test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-40a). Prepare bounded inputs and expected observations for this task's criterion: Query returns no cross-Organization node or edge and records the denial/guard result. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-40b.deliver** (depends on: M8-40b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Attempt a bounded graph read/path query from Organization A against Organization B fixture nodes.
  Output: Attempt a bounded graph read/path query from Organization A against Organization B fixture nodes.

- [ ] **M8-40b.verify** (depends on: M8-40b.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Query returns no cross-Organization node or edge and records the denial/guard result. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Query returns no cross-Organization node or edge and records the denial/guard result.

- [ ] **M8-40b.release** (depends on: M8-40b.verify, M8-40a, SHIP-GATE). Have the batch reviewer map M8-40b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-40c"></a>
## M8-40c: OpenSearch tenant isolation security test

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4678, exact task ID M8-40c. Status/evidence: row `M8-40c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-40b.
- Nearest pending prerequisites: M8-40b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Attempt Organization A session/activity searches against Organization B indexed fixtures.

**Original verification:** Search returns no foreign hit and the test records the scoped filter used.

- [ ] **M8-40c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-40c and locate the existing OpenSearch tenant isolation security test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-40b). Prepare bounded inputs and expected observations for this task's criterion: Search returns no foreign hit and the test records the scoped filter used. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-40c.deliver** (depends on: M8-40c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Attempt Organization A session/activity searches against Organization B indexed fixtures.
  Output: Attempt Organization A session/activity searches against Organization B indexed fixtures.

- [ ] **M8-40c.verify** (depends on: M8-40c.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Search returns no foreign hit and the test records the scoped filter used. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Search returns no foreign hit and the test records the scoped filter used.

- [ ] **M8-40c.release** (depends on: M8-40c.verify, M8-40b, SHIP-GATE). Have the batch reviewer map M8-40c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-40d"></a>
## M8-40d: S3 tenant isolation security test

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4684, exact task ID M8-40d. Status/evidence: row `M8-40d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-40c.
- Nearest pending prerequisites: M8-40c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Attempt Organization A evidence/export access against Organization B object keys through product APIs.

**Original verification:** Access is denied and no presigned URL/object body for Organization B is returned.

- [ ] **M8-40d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-40d and locate the existing S3 tenant isolation security test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-40c). Prepare bounded inputs and expected observations for this task's criterion: Access is denied and no presigned URL/object body for Organization B is returned. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-40d.deliver** (depends on: M8-40d.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Attempt Organization A evidence/export access against Organization B object keys through product APIs.
  Output: Attempt Organization A evidence/export access against Organization B object keys through product APIs.

- [ ] **M8-40d.verify** (depends on: M8-40d.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Access is denied and no presigned URL/object body for Organization B is returned. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Access is denied and no presigned URL/object body for Organization B is returned.

- [ ] **M8-40d.release** (depends on: M8-40d.verify, M8-40c, SHIP-GATE). Have the batch reviewer map M8-40d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-40"></a>
## M8-40: Organization/Workspace isolation security result

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4690, exact task ID M8-40. Status/evidence: row `M8-40` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-40d.
- Nearest pending prerequisites: M8-40d.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Record the API, graph, OpenSearch and S3 tenant-isolation results in one release-evidence record.

**Original verification:** Release evidence names every tested boundary and all four results are passing.

- [ ] **M8-40.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-40 and locate the existing Organization/Workspace isolation security result implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-40d). Prepare bounded inputs and expected observations for this task's criterion: Release evidence names every tested boundary and all four results are passing. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-40.deliver** (depends on: M8-40.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Record the API, graph, OpenSearch and S3 tenant-isolation results in one release-evidence record.
  Output: Record the API, graph, OpenSearch and S3 tenant-isolation results in one release-evidence record.

- [ ] **M8-40.verify** (depends on: M8-40.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Release evidence names every tested boundary and all four results are passing. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Release evidence names every tested boundary and all four results are passing.

- [ ] **M8-40.release** (depends on: M8-40.verify, M8-40d, SHIP-GATE). Have the batch reviewer map M8-40 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-41"></a>
## M8-41: connector SSRF security test

Class: **component-only**. Owner: **T03-launch-connectors**. Lane: **L2**. Batch: **connectors**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4696, exact task ID M8-41. Status/evidence: row `M8-41` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-40.
- Nearest pending prerequisites: M8-40.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/connectors`, `services/platform/integration`, `workers/security-python`, `deploy/production`.
- Consumes: Saved connection configuration, scoped credentials and allowlisted destinations.
- Produces: Real connection/auth/proxy/discovery receipts and denied-egress evidence.

**Original deliverable:** Attempt Nango/proxy/provider URL override to arbitrary destination.

**Original verification:** Request is blocked and audited.

- [ ] **M8-41.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-41 and locate the existing connector SSRF security test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-40). Prepare bounded inputs and expected observations for this task's criterion: Request is blocked and audited. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-41.deliver** (depends on: M8-41.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Attempt Nango/proxy/provider URL override to arbitrary destination.
  Output: Attempt Nango/proxy/provider URL override to arbitrary destination.

- [ ] **M8-41.verify** (depends on: M8-41.deliver). Run or reuse eligible candidate-bound evidence in the connectors feature batch. Required assertion: Request is blocked and audited. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Request is blocked and audited.

- [ ] **M8-41.release** (depends on: M8-41.verify, M8-40, SHIP-GATE). Have the batch reviewer map M8-41 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-42a"></a>
## M8-42a: log secret leakage test

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4702, exact task ID M8-42a. Status/evidence: row `M8-42a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-41.
- Nearest pending prerequisites: M8-41.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Seed a known secret through representative request/error paths and inspect structured logs.

**Original verification:** Seeded value never appears in logs.

- [ ] **M8-42a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-42a and locate the existing log secret leakage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-41). Prepare bounded inputs and expected observations for this task's criterion: Seeded value never appears in logs. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-42a.deliver** (depends on: M8-42a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Seed a known secret through representative request/error paths and inspect structured logs.
  Output: Seed a known secret through representative request/error paths and inspect structured logs.

- [ ] **M8-42a.verify** (depends on: M8-42a.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Seeded value never appears in logs. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Seeded value never appears in logs.

- [ ] **M8-42a.release** (depends on: M8-42a.verify, M8-41, SHIP-GATE). Have the batch reviewer map M8-42a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-42b"></a>
## M8-42b: PostHog secret leakage test

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4708, exact task ID M8-42b. Status/evidence: row `M8-42b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-42a.
- Nearest pending prerequisites: M8-42a.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Attempt to serialize seeded secret and sensitive security fields to PostHog.

**Original verification:** Serializer rejects the event before egress.

- [ ] **M8-42b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-42b and locate the existing PostHog secret leakage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-42a). Prepare bounded inputs and expected observations for this task's criterion: Serializer rejects the event before egress. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-42b.deliver** (depends on: M8-42b.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Attempt to serialize seeded secret and sensitive security fields to PostHog.
  Output: Attempt to serialize seeded secret and sensitive security fields to PostHog.

- [ ] **M8-42b.verify** (depends on: M8-42b.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Serializer rejects the event before egress. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Serializer rejects the event before egress.

- [ ] **M8-42b.release** (depends on: M8-42b.verify, M8-42a, SHIP-GATE). Have the batch reviewer map M8-42b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-42c"></a>
## M8-42c: AI secret leakage test

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4714, exact task ID M8-42c. Status/evidence: row `M8-42c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-42b.
- Nearest pending prerequisites: M8-42b.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Send seeded secret/PII/PHI fixture through AI redaction pipeline to fake provider.

**Original verification:** Prohibited fixture values are absent at the provider endpoint.

- [ ] **M8-42c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-42c and locate the existing AI secret leakage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-42b). Prepare bounded inputs and expected observations for this task's criterion: Prohibited fixture values are absent at the provider endpoint. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-42c.deliver** (depends on: M8-42c.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Send seeded secret/PII/PHI fixture through AI redaction pipeline to fake provider.
  Output: Send seeded secret/PII/PHI fixture through AI redaction pipeline to fake provider.

- [ ] **M8-42c.verify** (depends on: M8-42c.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Prohibited fixture values are absent at the provider endpoint. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Prohibited fixture values are absent at the provider endpoint.

- [ ] **M8-42c.release** (depends on: M8-42c.verify, M8-42b, SHIP-GATE). Have the batch reviewer map M8-42c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-42d"></a>
## M8-42d: OTLP secret leakage test

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4720, exact task ID M8-42d. Status/evidence: row `M8-42d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-42c.
- Nearest pending prerequisites: M8-42c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Emit seeded sensitive attributes through application telemetry to local Collector.

**Original verification:** Redaction/filter pipeline removes prohibited values before exporter.

- [ ] **M8-42d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-42d and locate the existing OTLP secret leakage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-42c). Prepare bounded inputs and expected observations for this task's criterion: Redaction/filter pipeline removes prohibited values before exporter. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-42d.deliver** (depends on: M8-42d.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Emit seeded sensitive attributes through application telemetry to local Collector.
  Output: Emit seeded sensitive attributes through application telemetry to local Collector.

- [ ] **M8-42d.verify** (depends on: M8-42d.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Redaction/filter pipeline removes prohibited values before exporter. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Redaction/filter pipeline removes prohibited values before exporter.

- [ ] **M8-42d.release** (depends on: M8-42d.verify, M8-42c, SHIP-GATE). Have the batch reviewer map M8-42d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-42e"></a>
## M8-42e: support bundle leakage test

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4726, exact task ID M8-42e. Status/evidence: row `M8-42e` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-42d.
- Nearest pending prerequisites: M8-42d.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Generate support bundle from fixture cluster containing seeded secret.

**Original verification:** Bundle contains no seeded value.

- [ ] **M8-42e.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-42e and locate the existing support bundle leakage test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-42d). Prepare bounded inputs and expected observations for this task's criterion: Bundle contains no seeded value. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-42e.deliver** (depends on: M8-42e.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Generate support bundle from fixture cluster containing seeded secret.
  Output: Generate support bundle from fixture cluster containing seeded secret.

- [ ] **M8-42e.verify** (depends on: M8-42e.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Bundle contains no seeded value. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Bundle contains no seeded value.

- [ ] **M8-42e.release** (depends on: M8-42e.verify, M8-42d, SHIP-GATE). Have the batch reviewer map M8-42e to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-42f"></a>
## M8-42f: evidence leakage policy test

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4732, exact task ID M8-42f. Status/evidence: row `M8-42f` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-42e.
- Nearest pending prerequisites: M8-42e.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Store fixture evidence under metadata-only collection mode.

**Original verification:** Raw seeded content is not durably stored.

- [ ] **M8-42f.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-42f and locate the existing evidence leakage policy test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-42e). Prepare bounded inputs and expected observations for this task's criterion: Raw seeded content is not durably stored. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-42f.deliver** (depends on: M8-42f.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Store fixture evidence under metadata-only collection mode.
  Output: Store fixture evidence under metadata-only collection mode.

- [ ] **M8-42f.verify** (depends on: M8-42f.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Raw seeded content is not durably stored. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Raw seeded content is not durably stored.

- [ ] **M8-42f.release** (depends on: M8-42f.verify, M8-42e, SHIP-GATE). Have the batch reviewer map M8-42f to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-42"></a>
## M8-42: secret leakage security test

Class: **component-only**. Owner: **T14-data-workflows**. Lane: **L3**. Batch: **privacy-ai-retention**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4738, exact task ID M8-42. Status/evidence: row `M8-42` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-42f.
- Nearest pending prerequisites: M8-42f.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `services/platform/sessioncontrol`, `services/platform/aigateway`, `services/platform/producttelemetry`, `services/platform/apiserver`, `app/features/sessions`.
- Consumes: Current scoped evidence and external-flow policy; existing export worker/storage contracts.
- Produces: Current-source compliance/export, bounded privacy-safe AI/telemetry and honest degraded states.

**Original deliverable:** Write the secret-leakage gate result from all egress/storage checks.

**Original verification:** Gate record is PASS only when every sink is clean.

- [ ] **M8-42.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-42 and locate the existing secret leakage security test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-42f). Prepare bounded inputs and expected observations for this task's criterion: Gate record is PASS only when every sink is clean. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-42.deliver** (depends on: M8-42.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Write the secret-leakage gate result from all egress/storage checks.
  Output: Write the secret-leakage gate result from all egress/storage checks.

- [ ] **M8-42.verify** (depends on: M8-42.deliver). Run or reuse eligible candidate-bound evidence in the privacy-ai-retention feature batch. Required assertion: Gate record is PASS only when every sink is clean. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Gate record is PASS only when every sink is clean.

- [ ] **M8-42.release** (depends on: M8-42.verify, M8-42f, SHIP-GATE). Have the batch reviewer map M8-42 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-45"></a>
## M8-45: SBOM generation

Class: **blocked/external**. Owner: **EXT-image-attestation**. Lane: **L4**. Batch: **supply-chain**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4756, exact task ID M8-45. Status/evidence: row `M8-45` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-44.
- Nearest pending prerequisites: M8-42.
- External gate: EXT-image-attestation.
- Primary source surfaces: `deploy/production`, `.github/workflows`.
- Consumes: Exact candidate image digests, approved registry/signing identity and scanner tooling.
- Produces: Candidate-bound SBOMs, signatures and unsigned/tampered denial results.

**Original deliverable:** Generate SPDX/CycloneDX SBOM for every shipped image.

**Original verification:** Release artifacts contain SBOM with pinned OSS versions.

- [ ] **M8-45.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-45 and locate the existing SBOM generation implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-44). Prepare bounded inputs and expected observations for this task's criterion: Release artifacts contain SBOM with pinned OSS versions. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-45.deliver** (depends on: M8-45.prepare, DISPATCH-GATE, EXT-image-attestation). After the external prerequisite (Exact candidate image digests, approved registry/signing identity and scanner tooling) is available: Generate SPDX/CycloneDX SBOM for every shipped image.
  Output: Generate SPDX/CycloneDX SBOM for every shipped image.

- [ ] **M8-45.verify** (depends on: M8-45.deliver). Run or reuse eligible candidate-bound evidence in the supply-chain feature batch. Required assertion: Release artifacts contain SBOM with pinned OSS versions. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Release artifacts contain SBOM with pinned OSS versions.

- [ ] **M8-45.release** (depends on: M8-45.verify, M8-44, M8-42, SHIP-GATE). Have the batch reviewer map M8-45 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-46"></a>
## M8-46: image signing

Class: **blocked/external**. Owner: **EXT-image-attestation**. Lane: **L4**. Batch: **supply-chain**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4762, exact task ID M8-46. Status/evidence: row `M8-46` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-45.
- Nearest pending prerequisites: M8-45.
- External gate: EXT-image-attestation.
- Primary source surfaces: `deploy/production`, `.github/workflows`.
- Consumes: Exact candidate image digests, approved registry/signing identity and scanner tooling.
- Produces: Candidate-bound SBOMs, signatures and unsigned/tampered denial results.

**Original deliverable:** Sign release images and verify signatures in install path/policy.

**Original verification:** Tampered/unsigned fixture fails verification where enforced.

- [ ] **M8-46.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-46 and locate the existing image signing implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-45). Prepare bounded inputs and expected observations for this task's criterion: Tampered/unsigned fixture fails verification where enforced. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-46.deliver** (depends on: M8-46.prepare, DISPATCH-GATE, EXT-image-attestation). After the external prerequisite (Exact candidate image digests, approved registry/signing identity and scanner tooling) is available: Sign release images and verify signatures in install path/policy.
  Output: Sign release images and verify signatures in install path/policy.

- [ ] **M8-46.verify** (depends on: M8-46.deliver). Run or reuse eligible candidate-bound evidence in the supply-chain feature batch. Required assertion: Tampered/unsigned fixture fails verification where enforced. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Tampered/unsigned fixture fails verification where enforced.

- [ ] **M8-46.release** (depends on: M8-46.verify, M8-45, SHIP-GATE). Have the batch reviewer map M8-46 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-47"></a>
## M8-47: dependency vulnerability gate

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4768, exact task ID M8-47. Status/evidence: row `M8-47` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-46.
- Nearest pending prerequisites: M8-46.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Run dependency/image scanner and define severity/exception policy.

**Original verification:** Unaccepted critical vulnerability blocks release.

- [ ] **M8-47.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-47 and locate the existing dependency vulnerability gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-46). Prepare bounded inputs and expected observations for this task's criterion: Unaccepted critical vulnerability blocks release. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-47.deliver** (depends on: M8-47.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Resolve the recorded advisory-disclosure authorization gate for the exact lockfile and shipped image inventory; do not substitute another endpoint or offline zero counters. Run actual dependency and image scans, apply severity/expiry policy, and make unaccepted critical findings block the candidate.
  Output: Run dependency/image scanner and define severity/exception policy.

- [ ] **M8-47.verify** (depends on: M8-47.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Unaccepted critical vulnerability blocks release. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Unaccepted critical vulnerability blocks release.

- [ ] **M8-47.release** (depends on: M8-47.verify, M8-46, SHIP-GATE). Have the batch reviewer map M8-47 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-51a"></a>
## M8-51a: Golden stage deploy/discover

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4792, exact task ID M8-51a. Status/evidence: row `M8-51a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-50.
- Nearest pending prerequisites: M8-47.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Execute install/preflight/connect/sensor/discover stage on release candidate.

**Original verification:** Stage artifact records successful Agent inventory and source freshness.

- [ ] **M8-51a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-51a and locate the existing Golden stage deploy/discover implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-50). Prepare bounded inputs and expected observations for this task's criterion: Stage artifact records successful Agent inventory and source freshness. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-51a.deliver** (depends on: M8-51a.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Execute install/preflight/connect/sensor/discover stage on release candidate.
  Output: Execute install/preflight/connect/sensor/discover stage on release candidate.

- [ ] **M8-51a.verify** (depends on: M8-51a.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Stage artifact records successful Agent inventory and source freshness. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Stage artifact records successful Agent inventory and source freshness.

- [ ] **M8-51a.release** (depends on: M8-51a.verify, M8-50, M8-47, SHIP-GATE). Have the batch reviewer map M8-51a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-51b"></a>
## M8-51b: Golden stage exposure/test

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4798, exact task ID M8-51b. Status/evidence: row `M8-51b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-51a.
- Nearest pending prerequisites: M8-51a.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Open credible path and run curated staging Red Team case.

**Original verification:** Stage artifact records successful high-impact attempt/evidence.

- [ ] **M8-51b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-51b and locate the existing Golden stage exposure/test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-51a). Prepare bounded inputs and expected observations for this task's criterion: Stage artifact records successful high-impact attempt/evidence. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-51b.deliver** (depends on: M8-51b.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Open credible path and run curated staging Red Team case.
  Output: Open credible path and run curated staging Red Team case.

- [ ] **M8-51b.verify** (depends on: M8-51b.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Stage artifact records successful high-impact attempt/evidence. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Stage artifact records successful high-impact attempt/evidence.

- [ ] **M8-51b.release** (depends on: M8-51b.verify, M8-51a, SHIP-GATE). Have the batch reviewer map M8-51b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-51c"></a>
## M8-51c: Golden stage Attack Lab

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4804, exact task ID M8-51c. Status/evidence: row `M8-51c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-51b.
- Nearest pending prerequisites: M8-51b.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Run Fargate verification with canary/test resources.

**Original verification:** Stage artifact records Verified or a release-blocking failure.

- [ ] **M8-51c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-51c and locate the existing Golden stage Attack Lab implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-51b). Prepare bounded inputs and expected observations for this task's criterion: Stage artifact records Verified or a release-blocking failure. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-51c.deliver** (depends on: M8-51c.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Run Fargate verification with canary/test resources.
  Output: Run Fargate verification with canary/test resources.

- [ ] **M8-51c.verify** (depends on: M8-51c.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Stage artifact records Verified or a release-blocking failure. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Stage artifact records Verified or a release-blocking failure.

- [ ] **M8-51c.release** (depends on: M8-51c.verify, M8-51b, SHIP-GATE). Have the batch reviewer map M8-51c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-51d"></a>
## M8-51d: Golden stage policy/retest

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4810, exact task ID M8-51d. Status/evidence: row `M8-51d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-51c.
- Nearest pending prerequisites: M8-51c.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Create, simulate, enforce Block and re-run the supported test.

**Original verification:** Stage artifact records observed Blocked decision.

- [ ] **M8-51d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-51d and locate the existing Golden stage policy/retest implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-51c). Prepare bounded inputs and expected observations for this task's criterion: Stage artifact records observed Blocked decision. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-51d.deliver** (depends on: M8-51d.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Create, simulate, enforce Block and re-run the supported test.
  Output: Create, simulate, enforce Block and re-run the supported test.

- [ ] **M8-51d.verify** (depends on: M8-51d.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Stage artifact records observed Blocked decision. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Stage artifact records observed Blocked decision.

- [ ] **M8-51d.release** (depends on: M8-51d.verify, M8-51c, SHIP-GATE). Have the batch reviewer map M8-51d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-51e"></a>
## M8-51e: Golden stage investigate/audit

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4816, exact task ID M8-51e. Status/evidence: row `M8-51e` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-51d.
- Nearest pending prerequisites: M8-51d.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Open resulting Session and Audit/Compliance evidence.

**Original verification:** Stage artifact links session timeline and audit records.

- [ ] **M8-51e.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-51e and locate the existing Golden stage investigate/audit implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-51d). Prepare bounded inputs and expected observations for this task's criterion: Stage artifact links session timeline and audit records. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-51e.deliver** (depends on: M8-51e.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Open resulting Session and Audit/Compliance evidence.
  Output: Open resulting Session and Audit/Compliance evidence.

- [ ] **M8-51e.verify** (depends on: M8-51e.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Stage artifact links session timeline and audit records. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Stage artifact links session timeline and audit records.

- [ ] **M8-51e.release** (depends on: M8-51e.verify, M8-51d, SHIP-GATE). Have the batch reviewer map M8-51e to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-51"></a>
## M8-51: golden E2E

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4822, exact task ID M8-51. Status/evidence: row `M8-51` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-51e.
- Nearest pending prerequisites: M8-51e.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Assemble golden-flow stage artifacts into one release gate record.

**Original verification:** Every golden stage is linked; no stage is rerun inside this task.

- [ ] **M8-51.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-51 and locate the existing golden E2E implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-51e). Prepare bounded inputs and expected observations for this task's criterion: Every golden stage is linked; no stage is rerun inside this task. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-51.deliver** (depends on: M8-51.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Assemble golden-flow stage artifacts into one release gate record.
  Output: Assemble golden-flow stage artifacts into one release gate record.

- [ ] **M8-51.verify** (depends on: M8-51.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Every golden stage is linked; no stage is rerun inside this task. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Every golden stage is linked; no stage is rerun inside this task.

- [ ] **M8-51.release** (depends on: M8-51.verify, M8-51e, SHIP-GATE). Have the batch reviewer map M8-51 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-52a"></a>
## M8-52a: Usability fresh-install setup

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4828, exact task ID M8-52a. Status/evidence: row `M8-52a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-51.
- Nearest pending prerequisites: M8-51.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Prepare a clean documented reference install target and observer checklist.

**Original verification:** Target is ready without undocumented bootstrap step.

- [ ] **M8-52a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-52a and locate the existing Usability fresh-install setup implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-51). Prepare bounded inputs and expected observations for this task's criterion: Target is ready without undocumented bootstrap step. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-52a.deliver** (depends on: M8-52a.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Prepare a clean documented reference install target and observer checklist.
  Output: Prepare a clean documented reference install target and observer checklist.

- [ ] **M8-52a.verify** (depends on: M8-52a.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: Target is ready without undocumented bootstrap step. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Target is ready without undocumented bootstrap step.

- [ ] **M8-52a.release** (depends on: M8-52a.verify, M8-51, SHIP-GATE). Have the batch reviewer map M8-52a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-52b"></a>
## M8-52b: Usability install observation

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4834, exact task ID M8-52b. Status/evidence: row `M8-52b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-52a.
- Nearest pending prerequisites: M8-52a.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Have a platform engineer run only documented install/preflight steps for <=15 minutes.

**Original verification:** Observer records blockers and exact product messages.

- [ ] **M8-52b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-52b and locate the existing Usability install observation implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-52a). Prepare bounded inputs and expected observations for this task's criterion: Observer records blockers and exact product messages. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-52b.deliver** (depends on: M8-52b.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Have a platform engineer run only documented install/preflight steps for <=15 minutes.
  Output: Have a platform engineer run only documented install/preflight steps for <=15 minutes.

- [ ] **M8-52b.verify** (depends on: M8-52b.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: Observer records blockers and exact product messages. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Observer records blockers and exact product messages.

- [ ] **M8-52b.release** (depends on: M8-52b.verify, M8-52a, SHIP-GATE). Have the batch reviewer map M8-52b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-52c"></a>
## M8-52c: Usability failure diagnosis

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4840, exact task ID M8-52c. Status/evidence: row `M8-52c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-52b.
- Nearest pending prerequisites: M8-52b.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Inject one documented dependency/config failure and have engineer use System Health/preflight.

**Original verification:** Engineer identifies product action without vendor dashboard.

- [ ] **M8-52c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-52c and locate the existing Usability failure diagnosis implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-52b). Prepare bounded inputs and expected observations for this task's criterion: Engineer identifies product action without vendor dashboard. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-52c.deliver** (depends on: M8-52c.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Inject one documented dependency/config failure and have engineer use System Health/preflight.
  Output: Inject one documented dependency/config failure and have engineer use System Health/preflight.

- [ ] **M8-52c.verify** (depends on: M8-52c.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: Engineer identifies product action without vendor dashboard. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Engineer identifies product action without vendor dashboard.

- [ ] **M8-52c.release** (depends on: M8-52c.verify, M8-52b, SHIP-GATE). Have the batch reviewer map M8-52c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-52d"></a>
## M8-52d: Usability diagnostics observation

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4846, exact task ID M8-52d. Status/evidence: row `M8-52d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-52c.
- Nearest pending prerequisites: M8-52c.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Have engineer generate diagnostics bundle and follow remediation guidance.

**Original verification:** Bundle is produced/redacted and next action is understandable.

- [ ] **M8-52d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-52d and locate the existing Usability diagnostics observation implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-52c). Prepare bounded inputs and expected observations for this task's criterion: Bundle is produced/redacted and next action is understandable. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-52d.deliver** (depends on: M8-52d.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Have engineer generate diagnostics bundle and follow remediation guidance.
  Output: Have engineer generate diagnostics bundle and follow remediation guidance.

- [ ] **M8-52d.verify** (depends on: M8-52d.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: Bundle is produced/redacted and next action is understandable. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Bundle is produced/redacted and next action is understandable.

- [ ] **M8-52d.release** (depends on: M8-52d.verify, M8-52c, SHIP-GATE). Have the batch reviewer map M8-52d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-52"></a>
## M8-52: single-tenant install usability test

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4852, exact task ID M8-52. Status/evidence: row `M8-52` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-52d.
- Nearest pending prerequisites: M8-52d.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Record single-tenant install-usability findings and classify release blockers.

**Original verification:** Every blocker has product-owned remediation or is explicitly release-blocking.

- [ ] **M8-52.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-52 and locate the existing single-tenant install usability test implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-52d). Prepare bounded inputs and expected observations for this task's criterion: Every blocker has product-owned remediation or is explicitly release-blocking. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-52.deliver** (depends on: M8-52.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Record single-tenant install-usability findings and classify release blockers.
  Output: Record single-tenant install-usability findings and classify release blockers.

- [ ] **M8-52.verify** (depends on: M8-52.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: Every blocker has product-owned remediation or is explicitly release-blocking. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Every blocker has product-owned remediation or is explicitly release-blocking.

- [ ] **M8-52.release** (depends on: M8-52.verify, M8-52d, SHIP-GATE). Have the batch reviewer map M8-52 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-53"></a>
## M8-53: design-partner value gate

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4858, exact task ID M8-53. Status/evidence: row `M8-53` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-52.
- Nearest pending prerequisites: M8-52.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Record whether at least two design partners changed prioritization/remediation because of verified path/runtime evidence.

**Original verification:** Gate is explicitly pass/fail and blocks scope expansion if value is unproven.

- [ ] **M8-53.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-53 and locate the existing design-partner value gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-52). Prepare bounded inputs and expected observations for this task's criterion: Gate is explicitly pass/fail and blocks scope expansion if value is unproven. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-53.deliver** (depends on: M8-53.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Record whether at least two design partners changed prioritization/remediation because of verified path/runtime evidence.
  Output: Record whether at least two design partners changed prioritization/remediation because of verified path/runtime evidence.

- [ ] **M8-53.verify** (depends on: M8-53.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: Gate is explicitly pass/fail and blocks scope expansion if value is unproven. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Gate is explicitly pass/fail and blocks scope expansion if value is unproven.

- [ ] **M8-53.release** (depends on: M8-53.verify, M8-52, SHIP-GATE). Have the batch reviewer map M8-53 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-56"></a>
## M8-56: single-tenant values profile

Class: **component-only**. Owner: **T15-deployment**. Lane: **L4**. Batch: **deployment**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4870, exact task ID M8-56. Status/evidence: row `M8-56` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-55.
- Nearest pending prerequisites: M8-07.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `deploy/staging/main.tf`, `deploy/staging/product`, `deploy/production`, `scripts/production-release-gate.mjs`.
- Consumes: Pinned release images, shared staging modules, explicit account/region and approved scan access.
- Produces: Private same-artifact SaaS/single-tenant topology, least privilege and release security evidence.

**Original deliverable:** Add a single-tenant deployment values profile using the same images with a pinned Organization configuration.

**Original verification:** Helm render differs only in topology/configuration values, not application image or API surface.

- [ ] **M8-56.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-56 and locate the existing single-tenant values profile implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-55). Prepare bounded inputs and expected observations for this task's criterion: Helm render differs only in topology/configuration values, not application image or API surface. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-56.deliver** (depends on: M8-56.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add a single-tenant deployment values profile using the same images with a pinned Organization configuration.
  Output: Add a single-tenant deployment values profile using the same images with a pinned Organization configuration.

- [ ] **M8-56.verify** (depends on: M8-56.deliver). Run or reuse eligible candidate-bound evidence in the deployment feature batch. Required assertion: Helm render differs only in topology/configuration values, not application image or API surface. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Helm render differs only in topology/configuration values, not application image or API surface.

- [ ] **M8-56.release** (depends on: M8-56.verify, M8-55, M8-07, SHIP-GATE). Have the batch reviewer map M8-56 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-58a"></a>
## M8-58a: SaaS quota load fixture

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4900, exact task ID M8-58a. Status/evidence: row `M8-58a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M1-43, M8-38.
- Nearest pending prerequisites: M1-01c, M8-38.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Create a two-Organization bounded load fixture with one Organization intentionally over quota.

**Original verification:** Fixture configuration validates and contains no customer secrets.

- [ ] **M8-58a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-58a and locate the existing SaaS quota load fixture implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M1-43, M8-38). Prepare bounded inputs and expected observations for this task's criterion: Fixture configuration validates and contains no customer secrets. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-58a.deliver** (depends on: M8-58a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Create a two-Organization bounded load fixture with one Organization intentionally over quota.
  Output: Create a two-Organization bounded load fixture with one Organization intentionally over quota.

- [ ] **M8-58a.verify** (depends on: M8-58a.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Fixture configuration validates and contains no customer secrets. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Fixture configuration validates and contains no customer secrets.

- [ ] **M8-58a.release** (depends on: M8-58a.verify, M1-43, M8-38, M1-01c, SHIP-GATE). Have the batch reviewer map M8-58a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-58b"></a>
## M8-58b: SaaS quota load trigger

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4906, exact task ID M8-58b. Status/evidence: row `M8-58b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-58a.
- Nearest pending prerequisites: M8-58a.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Start the bounded quota load job in CI/reference SaaS environment and record the run ID.

**Original verification:** Job starts successfully; this task does not wait for completion.

- [ ] **M8-58b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-58b and locate the existing SaaS quota load trigger implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-58a). Prepare bounded inputs and expected observations for this task's criterion: Job starts successfully; this task does not wait for completion. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-58b.deliver** (depends on: M8-58b.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Start the bounded quota load job in CI/reference SaaS environment and record the run ID.
  Output: Start the bounded quota load job in CI/reference SaaS environment and record the run ID.

- [ ] **M8-58b.verify** (depends on: M8-58b.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Job starts successfully; this task does not wait for completion. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Job starts successfully; this task does not wait for completion.

- [ ] **M8-58b.release** (depends on: M8-58b.verify, M8-58a, SHIP-GATE). Have the batch reviewer map M8-58b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-58"></a>
## M8-58: SaaS Organization quota result

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4912, exact task ID M8-58. Status/evidence: row `M8-58` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-58b.
- Nearest pending prerequisites: M8-58b.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Inspect the completed quota-load result for the recorded run.

**Original verification:** Noisy Organization is bounded while the second Organization remains within the stated reference latency target.

- [ ] **M8-58.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-58 and locate the existing SaaS Organization quota result implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-58b). Prepare bounded inputs and expected observations for this task's criterion: Noisy Organization is bounded while the second Organization remains within the stated reference latency target. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-58.deliver** (depends on: M8-58.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Inspect the completed quota-load result for the recorded run.
  Output: Inspect the completed quota-load result for the recorded run.

- [ ] **M8-58.verify** (depends on: M8-58.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Noisy Organization is bounded while the second Organization remains within the stated reference latency target. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Noisy Organization is bounded while the second Organization remains within the stated reference latency target.

- [ ] **M8-58.release** (depends on: M8-58.verify, M8-58b, SHIP-GATE). Have the batch reviewer map M8-58 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-59a1"></a>
## M8-59a1: SaaS isolation API/Neon fixture references

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4918, exact task ID M8-59a1. Status/evidence: row `M8-59a1` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-40, M2-50, M1-45.
- Nearest pending prerequisites: M8-40, M1-36e, M1-01c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Add the existing API and direct-Neon cross-Organization checks to the release isolation suite manifest.

**Original verification:** Manifest resolves both checks for two isolated Organization fixtures.

- [ ] **M8-59a1.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-59a1 and locate the existing SaaS isolation API/Neon fixture references implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-40, M2-50, M1-45). Prepare bounded inputs and expected observations for this task's criterion: Manifest resolves both checks for two isolated Organization fixtures. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-59a1.deliver** (depends on: M8-59a1.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add the existing API and direct-Neon cross-Organization checks to the release isolation suite manifest.
  Output: Add the existing API and direct-Neon cross-Organization checks to the release isolation suite manifest.

- [ ] **M8-59a1.verify** (depends on: M8-59a1.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Manifest resolves both checks for two isolated Organization fixtures. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Manifest resolves both checks for two isolated Organization fixtures.

- [ ] **M8-59a1.release** (depends on: M8-59a1.verify, M8-40, M2-50, M1-45, M1-36e, M1-01c, SHIP-GATE). Have the batch reviewer map M8-59a1 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-59a2"></a>
## M8-59a2: SaaS isolation graph/search fixture references

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4924, exact task ID M8-59a2. Status/evidence: row `M8-59a2` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-59a1.
- Nearest pending prerequisites: M8-59a1.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Add the existing graph and OpenSearch cross-Organization checks to the release isolation suite manifest.

**Original verification:** Manifest resolves both checks and their expected denial/no-hit outcomes.

- [ ] **M8-59a2.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-59a2 and locate the existing SaaS isolation graph/search fixture references implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-59a1). Prepare bounded inputs and expected observations for this task's criterion: Manifest resolves both checks and their expected denial/no-hit outcomes. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-59a2.deliver** (depends on: M8-59a2.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add the existing graph and OpenSearch cross-Organization checks to the release isolation suite manifest.
  Output: Add the existing graph and OpenSearch cross-Organization checks to the release isolation suite manifest.

- [ ] **M8-59a2.verify** (depends on: M8-59a2.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Manifest resolves both checks and their expected denial/no-hit outcomes. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Manifest resolves both checks and their expected denial/no-hit outcomes.

- [ ] **M8-59a2.release** (depends on: M8-59a2.verify, M8-59a1, SHIP-GATE). Have the batch reviewer map M8-59a2 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-59a3"></a>
## M8-59a3: SaaS isolation S3/queue fixture references

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4930, exact task ID M8-59a3. Status/evidence: row `M8-59a3` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-59a2, M1-41.
- Nearest pending prerequisites: M8-59a2, M1-01c.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Add S3 evidence/export and scoped SQS job-envelope cross-Organization checks to the release isolation suite manifest.

**Original verification:** Manifest resolves both checks and expected denial/rejection outcomes.

- [ ] **M8-59a3.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-59a3 and locate the existing SaaS isolation S3/queue fixture references implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-59a2, M1-41). Prepare bounded inputs and expected observations for this task's criterion: Manifest resolves both checks and expected denial/rejection outcomes. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-59a3.deliver** (depends on: M8-59a3.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Add S3 evidence/export and scoped SQS job-envelope cross-Organization checks to the release isolation suite manifest.
  Output: Add S3 evidence/export and scoped SQS job-envelope cross-Organization checks to the release isolation suite manifest.

- [ ] **M8-59a3.verify** (depends on: M8-59a3.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Manifest resolves both checks and expected denial/rejection outcomes. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Manifest resolves both checks and expected denial/rejection outcomes.

- [ ] **M8-59a3.release** (depends on: M8-59a3.verify, M8-59a2, M1-41, M1-01c, SHIP-GATE). Have the batch reviewer map M8-59a3 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-59a"></a>
## M8-59a: SaaS tenant isolation release fixture

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4936, exact task ID M8-59a. Status/evidence: row `M8-59a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-59a3.
- Nearest pending prerequisites: M8-59a3.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Validate the complete bounded SaaS tenant-isolation release-suite manifest.

**Original verification:** Manifest contains API, Neon, graph, OpenSearch, S3 and queue boundaries for two Organizations with no missing expected outcome.

- [ ] **M8-59a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-59a and locate the existing SaaS tenant isolation release fixture implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-59a3). Prepare bounded inputs and expected observations for this task's criterion: Manifest contains API, Neon, graph, OpenSearch, S3 and queue boundaries for two Organizations with no missing expected outcome. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-59a.deliver** (depends on: M8-59a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Validate the complete bounded SaaS tenant-isolation release-suite manifest.
  Output: Validate the complete bounded SaaS tenant-isolation release-suite manifest.

- [ ] **M8-59a.verify** (depends on: M8-59a.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Manifest contains API, Neon, graph, OpenSearch, S3 and queue boundaries for two Organizations with no missing expected outcome. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Manifest contains API, Neon, graph, OpenSearch, S3 and queue boundaries for two Organizations with no missing expected outcome.

- [ ] **M8-59a.release** (depends on: M8-59a.verify, M8-59a3, SHIP-GATE). Have the batch reviewer map M8-59a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-59b"></a>
## M8-59b: SaaS tenant isolation trigger

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4942, exact task ID M8-59b. Status/evidence: row `M8-59b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-59a.
- Nearest pending prerequisites: M8-59a.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Start the release isolation suite and record the run ID.

**Original verification:** Suite starts in the intended SaaS test environment; this task does not wait for completion.

- [ ] **M8-59b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-59b and locate the existing SaaS tenant isolation trigger implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-59a). Prepare bounded inputs and expected observations for this task's criterion: Suite starts in the intended SaaS test environment; this task does not wait for completion. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-59b.deliver** (depends on: M8-59b.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Start the release isolation suite and record the run ID.
  Output: Start the release isolation suite and record the run ID.

- [ ] **M8-59b.verify** (depends on: M8-59b.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Suite starts in the intended SaaS test environment; this task does not wait for completion. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Suite starts in the intended SaaS test environment; this task does not wait for completion.

- [ ] **M8-59b.release** (depends on: M8-59b.verify, M8-59a, SHIP-GATE). Have the batch reviewer map M8-59b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-59"></a>
## M8-59: SaaS tenant isolation result

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4948, exact task ID M8-59. Status/evidence: row `M8-59` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-59b.
- Nearest pending prerequisites: M8-59b.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Inspect the completed isolation-suite result.

**Original verification:** All cross-Organization reads/writes fail and no fixture evidence leaks into responses or exports.

- [ ] **M8-59.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-59 and locate the existing SaaS tenant isolation result implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-59b). Prepare bounded inputs and expected observations for this task's criterion: All cross-Organization reads/writes fail and no fixture evidence leaks into responses or exports. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-59.deliver** (depends on: M8-59.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Inspect the completed isolation-suite result.
  Output: Inspect the completed isolation-suite result.

- [ ] **M8-59.verify** (depends on: M8-59.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: All cross-Organization reads/writes fail and no fixture evidence leaks into responses or exports. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: All cross-Organization reads/writes fail and no fixture evidence leaks into responses or exports.

- [ ] **M8-59.release** (depends on: M8-59.verify, M8-59b, SHIP-GATE). Have the batch reviewer map M8-59 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-60a"></a>
## M8-60a: SaaS golden fixture

Class: **component-only**. Owner: **T16-recovery-ops**. Lane: **L5**. Batch: **release-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4954, exact task ID M8-60a. Status/evidence: row `M8-60a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-50, M8-55, M8-57, M8-59.
- Nearest pending prerequisites: M8-47, M8-07, M8-59.
- External gate: none on this row; inherited prerequisites and SHIP-GATE still apply.
- Primary source surfaces: `cmd/agentsecctl`, `deploy/production`, `services/platform/apiserver`.
- Consumes: Candidate version/schema/bundle contracts and disposable reference profiles.
- Produces: Preflight, rollback/recovery, measured load and cross-tenant acceptance artifacts.

**Original deliverable:** Prepare the Organization-scoped SaaS golden-flow fixture and test identities/resources.

**Original verification:** Fixture contains no production write credential and all expected resources have cleanup ownership.

- [ ] **M8-60a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-60a and locate the existing SaaS golden fixture implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-50, M8-55, M8-57, M8-59). Prepare bounded inputs and expected observations for this task's criterion: Fixture contains no production write credential and all expected resources have cleanup ownership. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-60a.deliver** (depends on: M8-60a.prepare, DISPATCH-GATE). Complete only the unfulfilled parts of this original deliverable; reuse unchanged accepted work: Prepare the Organization-scoped SaaS golden-flow fixture and test identities/resources.
  Output: Prepare the Organization-scoped SaaS golden-flow fixture and test identities/resources.

- [ ] **M8-60a.verify** (depends on: M8-60a.deliver). Run or reuse eligible candidate-bound evidence in the release-acceptance feature batch. Required assertion: Fixture contains no production write credential and all expected resources have cleanup ownership. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Fixture contains no production write credential and all expected resources have cleanup ownership.

- [ ] **M8-60a.release** (depends on: M8-60a.verify, M8-50, M8-55, M8-57, M8-59, M8-47, M8-07, SHIP-GATE). Have the batch reviewer map M8-60a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-60b"></a>
## M8-60b: SaaS golden trigger

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4960, exact task ID M8-60b. Status/evidence: row `M8-60b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-60a.
- Nearest pending prerequisites: M8-60a.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Start the SaaS golden E2E run and record the run ID.

**Original verification:** The run reaches the first connection stage; this task does not wait for completion.

- [ ] **M8-60b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-60b and locate the existing SaaS golden trigger implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-60a). Prepare bounded inputs and expected observations for this task's criterion: The run reaches the first connection stage; this task does not wait for completion. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-60b.deliver** (depends on: M8-60b.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Start the SaaS golden E2E run and record the run ID.
  Output: Start the SaaS golden E2E run and record the run ID.

- [ ] **M8-60b.verify** (depends on: M8-60b.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: The run reaches the first connection stage; this task does not wait for completion. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: The run reaches the first connection stage; this task does not wait for completion.

- [ ] **M8-60b.release** (depends on: M8-60b.verify, M8-60a, SHIP-GATE). Have the batch reviewer map M8-60b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-60"></a>
## M8-60: SaaS golden result

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4966, exact task ID M8-60. Status/evidence: row `M8-60` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-60b.
- Nearest pending prerequisites: M8-60b.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Inspect the completed SaaS golden E2E result.

**Original verification:** First-Admin bootstrap -> corporate SSO -> launch connectors -> optional edge sensor -> discover -> path -> test -> verify -> Security Agent plan -> deterministic authorization -> auto-action or approval -> verified containment -> TTL cleanup when applicable -> re-test -> session/audit completes using only product UI/API.

- [ ] **M8-60.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-60 and locate the existing SaaS golden result implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-60b). Prepare bounded inputs and expected observations for this task's criterion: First-Admin bootstrap -> corporate SSO -> launch connectors -> optional edge sensor -> discover -> path -> test -> verify -> Security Agent plan -> deterministic authorization -> auto-action or approval -> verified containment -> TTL cleanup when applicable -> re-test -> session/audit completes using only product UI/API. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-60.deliver** (depends on: M8-60.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Inspect the completed SaaS golden E2E result.
  Output: Inspect the completed SaaS golden E2E result.

- [ ] **M8-60.verify** (depends on: M8-60.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: First-Admin bootstrap -> corporate SSO -> launch connectors -> optional edge sensor -> discover -> path -> test -> verify -> Security Agent plan -> deterministic authorization -> auto-action or approval -> verified containment -> TTL cleanup when applicable -> re-test -> session/audit completes using only product UI/API. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: First-Admin bootstrap -> corporate SSO -> launch connectors -> optional edge sensor -> discover -> path -> test -> verify -> Security Agent plan -> deterministic authorization -> auto-action or approval -> verified containment -> TTL cleanup when applicable -> re-test -> session/audit completes using only product UI/API.

- [ ] **M8-60.release** (depends on: M8-60.verify, M8-60b, SHIP-GATE). Have the batch reviewer map M8-60 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-61a"></a>
## M8-61a: single-tenant golden trigger

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4972, exact task ID M8-61a. Status/evidence: row `M8-61a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-56, M8-60.
- Nearest pending prerequisites: M8-56, M8-60.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Start the same golden customer workflow against the single-tenant profile and record the run ID.

**Original verification:** Run starts with the same client/API contract and a pinned Organization.

- [ ] **M8-61a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-61a and locate the existing single-tenant golden trigger implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-56, M8-60). Prepare bounded inputs and expected observations for this task's criterion: Run starts with the same client/API contract and a pinned Organization. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-61a.deliver** (depends on: M8-61a.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Start the same golden customer workflow against the single-tenant profile and record the run ID.
  Output: Start the same golden customer workflow against the single-tenant profile and record the run ID.

- [ ] **M8-61a.verify** (depends on: M8-61a.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Run starts with the same client/API contract and a pinned Organization. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Run starts with the same client/API contract and a pinned Organization.

- [ ] **M8-61a.release** (depends on: M8-61a.verify, M8-56, M8-60, SHIP-GATE). Have the batch reviewer map M8-61a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-61"></a>
## M8-61: single-tenant golden result

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4978, exact task ID M8-61. Status/evidence: row `M8-61` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-61a.
- Nearest pending prerequisites: M8-61a.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Inspect the completed single-tenant golden result.

**Original verification:** Workflow behavior and API shapes match SaaS except deployment/system-health metadata.

- [ ] **M8-61.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-61 and locate the existing single-tenant golden result implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-61a). Prepare bounded inputs and expected observations for this task's criterion: Workflow behavior and API shapes match SaaS except deployment/system-health metadata. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-61.deliver** (depends on: M8-61.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Inspect the completed single-tenant golden result.
  Output: Inspect the completed single-tenant golden result.

- [ ] **M8-61.verify** (depends on: M8-61.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Workflow behavior and API shapes match SaaS except deployment/system-health metadata. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Workflow behavior and API shapes match SaaS except deployment/system-health metadata.

- [ ] **M8-61.release** (depends on: M8-61.verify, M8-61a, SHIP-GATE). Have the batch reviewer map M8-61 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-62a"></a>
## M8-62a: SaaS first-Admin bootstrap usability

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4984, exact task ID M8-62a. Status/evidence: row `M8-62a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-60.
- Nearest pending prerequisites: M8-60.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Observe a fresh designated first Admin complete invite sign-in, default scope bootstrap and reach Identity & Access using only product instructions for <=15 minutes.

**Original verification:** No local-password/bypass login or AgentSec manual database edit is required.

- [ ] **M8-62a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-62a and locate the existing SaaS first-Admin bootstrap usability implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-60). Prepare bounded inputs and expected observations for this task's criterion: No local-password/bypass login or AgentSec manual database edit is required. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-62a.deliver** (depends on: M8-62a.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Observe a fresh designated first Admin complete invite sign-in, default scope bootstrap and reach Identity & Access using only product instructions for <=15 minutes.
  Output: Observe a fresh designated first Admin complete invite sign-in, default scope bootstrap and reach Identity & Access using only product instructions for <=15 minutes.

- [ ] **M8-62a.verify** (depends on: M8-62a.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: No local-password/bypass login or AgentSec manual database edit is required. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: No local-password/bypass login or AgentSec manual database edit is required.

- [ ] **M8-62a.release** (depends on: M8-62a.verify, M8-60, SHIP-GATE). Have the batch reviewer map M8-62a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-62b"></a>
## M8-62b: SaaS AWS setup usability

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4990, exact task ID M8-62b. Status/evidence: row `M8-62b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-62a.
- Nearest pending prerequisites: M8-62a.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Observe the Admin complete AWS Review access -> Configure -> Test connection using product guidance.

**Original verification:** Missing-permission fixture yields an actionable product remediation.

- [ ] **M8-62b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-62b and locate the existing SaaS AWS setup usability implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-62a). Prepare bounded inputs and expected observations for this task's criterion: Missing-permission fixture yields an actionable product remediation. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-62b.deliver** (depends on: M8-62b.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Observe the Admin complete AWS Review access -> Configure -> Test connection using product guidance.
  Output: Observe the Admin complete AWS Review access -> Configure -> Test connection using product guidance.

- [ ] **M8-62b.verify** (depends on: M8-62b.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: Missing-permission fixture yields an actionable product remediation. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Missing-permission fixture yields an actionable product remediation.

- [ ] **M8-62b.release** (depends on: M8-62b.verify, M8-62a, SHIP-GATE). Have the batch reviewer map M8-62b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-62c"></a>
## M8-62c: SaaS Kubernetes setup usability

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 4996, exact task ID M8-62c. Status/evidence: row `M8-62c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-62b.
- Nearest pending prerequisites: M8-62b.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Observe sensor enrollment/Helm setup through first healthy heartbeat.

**Original verification:** User can distinguish inventory, sensor and gateway coverage without OSS console access.

- [ ] **M8-62c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-62c and locate the existing SaaS Kubernetes setup usability implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-62b). Prepare bounded inputs and expected observations for this task's criterion: User can distinguish inventory, sensor and gateway coverage without OSS console access. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-62c.deliver** (depends on: M8-62c.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Observe sensor enrollment/Helm setup through first healthy heartbeat.
  Output: Observe sensor enrollment/Helm setup through first healthy heartbeat.

- [ ] **M8-62c.verify** (depends on: M8-62c.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: User can distinguish inventory, sensor and gateway coverage without OSS console access. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: User can distinguish inventory, sensor and gateway coverage without OSS console access.

- [ ] **M8-62c.release** (depends on: M8-62c.verify, M8-62b, SHIP-GATE). Have the batch reviewer map M8-62c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-62d"></a>
## M8-62d: SaaS GitHub setup usability

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5002, exact task ID M8-62d. Status/evidence: row `M8-62d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-62c.
- Nearest pending prerequisites: M8-62c.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Observe GitHub authorization/install and initial scope validation.

**Original verification:** User can identify selected Organization/repository scope and any missing permission.

- [ ] **M8-62d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-62d and locate the existing SaaS GitHub setup usability implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-62c). Prepare bounded inputs and expected observations for this task's criterion: User can identify selected Organization/repository scope and any missing permission. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-62d.deliver** (depends on: M8-62d.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Observe GitHub authorization/install and initial scope validation.
  Output: Observe GitHub authorization/install and initial scope validation.

- [ ] **M8-62d.verify** (depends on: M8-62d.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: User can identify selected Organization/repository scope and any missing permission. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: User can identify selected Organization/repository scope and any missing permission.

- [ ] **M8-62d.release** (depends on: M8-62d.verify, M8-62c, SHIP-GATE). Have the batch reviewer map M8-62d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-62e"></a>
## M8-62e: SaaS launch-IdP setup usability

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5008, exact task ID M8-62e. Status/evidence: row `M8-62e` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-62d.
- Nearest pending prerequisites: M8-62d.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Observe launch-IdP directory security integration setup, separate from AgentSec SSO configuration.

**Original verification:** User understands the distinction and reaches initial sync without vendor dashboard knowledge.

- [ ] **M8-62e.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-62e and locate the existing SaaS launch-IdP setup usability implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-62d). Prepare bounded inputs and expected observations for this task's criterion: User understands the distinction and reaches initial sync without vendor dashboard knowledge. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-62e.deliver** (depends on: M8-62e.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Observe launch-IdP directory security integration setup, separate from AgentSec SSO configuration.
  Output: Observe launch-IdP directory security integration setup, separate from AgentSec SSO configuration.

- [ ] **M8-62e.verify** (depends on: M8-62e.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: User understands the distinction and reaches initial sync without vendor dashboard knowledge. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: User understands the distinction and reaches initial sync without vendor dashboard knowledge.

- [ ] **M8-62e.release** (depends on: M8-62e.verify, M8-62d, SHIP-GATE). Have the batch reviewer map M8-62e to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-62"></a>
## M8-62: SaaS onboarding usability result

Class: **blocked/external**. Owner: **EXT-human-observation**. Lane: **L6**. Batch: **human-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5014, exact task ID M8-62. Status/evidence: row `M8-62` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-62e.
- Nearest pending prerequisites: M8-62e.
- External gate: EXT-human-observation.
- Primary source surfaces: `docs/internal`, `cmd/agentsecctl`, `app`.
- Consumes: Named consenting engineer/admin/design partners and a working reference environment.
- Produces: Actual observed task outcomes, product errors and explicit release-blocking findings.

**Original deliverable:** Record bootstrap and four launch-connector usability blockers.

**Original verification:** Every blocker has product-owned remediation or is explicitly release-blocking.

- [ ] **M8-62.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-62 and locate the existing SaaS onboarding usability result implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-62e). Prepare bounded inputs and expected observations for this task's criterion: Every blocker has product-owned remediation or is explicitly release-blocking. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-62.deliver** (depends on: M8-62.prepare, DISPATCH-GATE, EXT-human-observation). After the external prerequisite (Named consenting engineer/admin/design partners and a working reference environment) is available: Record bootstrap and four launch-connector usability blockers.
  Output: Record bootstrap and four launch-connector usability blockers.

- [ ] **M8-62.verify** (depends on: M8-62.deliver). Run or reuse eligible candidate-bound evidence in the human-acceptance feature batch. Required assertion: Every blocker has product-owned remediation or is explicitly release-blocking. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Every blocker has product-owned remediation or is explicitly release-blocking.

- [ ] **M8-62.release** (depends on: M8-62.verify, M8-62e, SHIP-GATE). Have the batch reviewer map M8-62 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-63a"></a>
## M8-63a: SaaS DR recovery fixture

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5020, exact task ID M8-63a. Status/evidence: row `M8-63a` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-62, M8-20.
- Nearest pending prerequisites: M8-62, M8-19.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Prepare an isolated SaaS recovery fixture with known Neon state, retained S3 evidence/event archives and derived OpenSearch/graph state.

**Original verification:** Fixture records source timestamps and contains at least two Organization scopes without production credentials.

- [ ] **M8-63a.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-63a and locate the existing SaaS DR recovery fixture implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-62, M8-20). Prepare bounded inputs and expected observations for this task's criterion: Fixture records source timestamps and contains at least two Organization scopes without production credentials. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-63a.deliver** (depends on: M8-63a.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Prepare an isolated SaaS recovery fixture with known Neon state, retained S3 evidence/event archives and derived OpenSearch/graph state.
  Output: Prepare an isolated SaaS recovery fixture with known Neon state, retained S3 evidence/event archives and derived OpenSearch/graph state.

- [ ] **M8-63a.verify** (depends on: M8-63a.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Fixture records source timestamps and contains at least two Organization scopes without production credentials. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Fixture records source timestamps and contains at least two Organization scopes without production credentials.

- [ ] **M8-63a.release** (depends on: M8-63a.verify, M8-62, M8-20, M8-19, SHIP-GATE). Have the batch reviewer map M8-63a to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-63b"></a>
## M8-63b: SaaS DR start recovery

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5026, exact task ID M8-63b. Status/evidence: row `M8-63b` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-63a.
- Nearest pending prerequisites: M8-63a.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Start recovery into disposable infrastructure from the selected Neon recovery point plus versioned Terraform/Helm release.

**Original verification:** Recovery run ID and source recovery timestamp are recorded without waiting for completion.

- [ ] **M8-63b.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-63b and locate the existing SaaS DR start recovery implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-63a). Prepare bounded inputs and expected observations for this task's criterion: Recovery run ID and source recovery timestamp are recorded without waiting for completion. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-63b.deliver** (depends on: M8-63b.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Start recovery into disposable infrastructure from the selected Neon recovery point plus versioned Terraform/Helm release.
  Output: Start recovery into disposable infrastructure from the selected Neon recovery point plus versioned Terraform/Helm release.

- [ ] **M8-63b.verify** (depends on: M8-63b.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Recovery run ID and source recovery timestamp are recorded without waiting for completion. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Recovery run ID and source recovery timestamp are recorded without waiting for completion.

- [ ] **M8-63b.release** (depends on: M8-63b.verify, M8-63a, SHIP-GATE). Have the batch reviewer map M8-63b to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-63c"></a>
## M8-63c: SaaS DR inspect core recovery

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5032, exact task ID M8-63c. Status/evidence: row `M8-63c` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-63b.
- Nearest pending prerequisites: M8-63b.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Inspect recovered Organization/Workspace/policy/finding state and S3 evidence/event archives.

**Original verification:** Expected scoped records are present and no cross-Organization data mix occurs.

- [ ] **M8-63c.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-63c and locate the existing SaaS DR inspect core recovery implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-63b). Prepare bounded inputs and expected observations for this task's criterion: Expected scoped records are present and no cross-Organization data mix occurs. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-63c.deliver** (depends on: M8-63c.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Inspect recovered Organization/Workspace/policy/finding state and S3 evidence/event archives.
  Output: Inspect recovered Organization/Workspace/policy/finding state and S3 evidence/event archives.

- [ ] **M8-63c.verify** (depends on: M8-63c.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Expected scoped records are present and no cross-Organization data mix occurs. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Expected scoped records are present and no cross-Organization data mix occurs.

- [ ] **M8-63c.release** (depends on: M8-63c.verify, M8-63b, SHIP-GATE). Have the batch reviewer map M8-63c to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-63d"></a>
## M8-63d: SaaS DR rebuild derived stores

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5038, exact task ID M8-63d. Status/evidence: row `M8-63d` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-63c.
- Nearest pending prerequisites: M8-63c.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Start bounded OpenSearch replay from retained S3 normalized event archives and graph rebuild from canonical inventory/evidence.

**Original verification:** Rebuild jobs are tracked and do not require raw vendor dashboards.

- [ ] **M8-63d.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-63d and locate the existing SaaS DR rebuild derived stores implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-63c). Prepare bounded inputs and expected observations for this task's criterion: Rebuild jobs are tracked and do not require raw vendor dashboards. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-63d.deliver** (depends on: M8-63d.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Start bounded OpenSearch replay from retained S3 normalized event archives and graph rebuild from canonical inventory/evidence.
  Output: Start bounded OpenSearch replay from retained S3 normalized event archives and graph rebuild from canonical inventory/evidence.

- [ ] **M8-63d.verify** (depends on: M8-63d.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Rebuild jobs are tracked and do not require raw vendor dashboards. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Rebuild jobs are tracked and do not require raw vendor dashboards.

- [ ] **M8-63d.release** (depends on: M8-63d.verify, M8-63c, SHIP-GATE). Have the batch reviewer map M8-63d to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-63e"></a>
## M8-63e: SaaS DR measure objectives

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5044, exact task ID M8-63e. Status/evidence: row `M8-63e` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-63d.
- Nearest pending prerequisites: M8-63d.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Record measured data recovery point and time until core product plus representative session/path queries are usable.

**Original verification:** Result explicitly compares measured RPO/RTO to <=1 hour / <=4 hour MVP objectives.

- [ ] **M8-63e.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-63e and locate the existing SaaS DR measure objectives implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-63d). Prepare bounded inputs and expected observations for this task's criterion: Result explicitly compares measured RPO/RTO to <=1 hour / <=4 hour MVP objectives. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-63e.deliver** (depends on: M8-63e.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Record measured data recovery point and time until core product plus representative session/path queries are usable.
  Output: Record measured data recovery point and time until core product plus representative session/path queries are usable.

- [ ] **M8-63e.verify** (depends on: M8-63e.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: Result explicitly compares measured RPO/RTO to <=1 hour / <=4 hour MVP objectives. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: Result explicitly compares measured RPO/RTO to <=1 hour / <=4 hour MVP objectives.

- [ ] **M8-63e.release** (depends on: M8-63e.verify, M8-63d, SHIP-GATE). Have the batch reviewer map M8-63e to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-63"></a>
## M8-63: SaaS DR gate

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5050, exact task ID M8-63. Status/evidence: row `M8-63` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-63e.
- Nearest pending prerequisites: M8-63e.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Record SaaS disaster-recovery PASS/FAIL and exact gaps; clean disposable recovery resources after evidence capture.

**Original verification:** PASS requires measured objectives, tenant isolation and usable product UI/API without hidden vendor-console recovery steps.

- [ ] **M8-63.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-63 and locate the existing SaaS DR gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-63e). Prepare bounded inputs and expected observations for this task's criterion: PASS requires measured objectives, tenant isolation and usable product UI/API without hidden vendor-console recovery steps. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-63.deliver** (depends on: M8-63.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Record SaaS disaster-recovery PASS/FAIL and exact gaps; clean disposable recovery resources after evidence capture.
  Output: Record SaaS disaster-recovery PASS/FAIL and exact gaps; clean disposable recovery resources after evidence capture.

- [ ] **M8-63.verify** (depends on: M8-63.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: PASS requires measured objectives, tenant isolation and usable product UI/API without hidden vendor-console recovery steps. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: PASS requires measured objectives, tenant isolation and usable product UI/API without hidden vendor-console recovery steps.

- [ ] **M8-63.release** (depends on: M8-63.verify, M8-63e, SHIP-GATE). Have the batch reviewer map M8-63 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.

<a id="m8-54"></a>
## M8-54: M8 release gate

Class: **blocked/external**. Owner: **EXT-cloud-deploy**. Lane: **L6**. Batch: **cloud-acceptance**.

Original source: [v1.5 plan](../agent_security_platform_Technical_Implementation_Plan_v1.5.md), line 5056, exact task ID M8-54. Status/evidence: row `M8-54` in [authoritative TSV](../implementation_production_availability_v1.5.tsv).

- Original direct dependencies: M8-53, M8-58, M8-59, M8-60, M8-61, M8-62, M8-63.
- Nearest pending prerequisites: M8-53, M8-58, M8-59, M8-60, M8-61, M8-62, M8-63.
- External gate: EXT-cloud-deploy.
- Primary source surfaces: `deploy/staging`, `deploy/production`, `cmd/agentsecctl`, `scripts`.
- Consumes: Authorized reference deployment, current exact candidate, provider identities and bounded run budget.
- Produces: Real deployment/outage/load/golden/recovery run IDs and scoped measured artifacts.

**Original deliverable:** Create release-readiness record containing results/exceptions from all M8 gates.

**Original verification:** No unresolved blocker is hidden as a documentation note.

- [ ] **M8-54.prepare** (depends on: none; preparation only). Read the current ledger evidence for M8-54 and locate the existing M8 release gate implementation within the listed source surfaces. Record the exact candidate revision and prerequisite artifact revisions (M8-53, M8-58, M8-59, M8-60, M8-61, M8-62, M8-63). Prepare bounded inputs and expected observations for this task's criterion: No unresolved blocker is hidden as a documentation note. Identify only the missing behavior or evidence; do not rebuild an already accepted component.
  Output: Candidate-bound gap list and bounded inputs; no completion claim from historical status.

- [ ] **M8-54.deliver** (depends on: M8-54.prepare, DISPATCH-GATE, EXT-cloud-deploy). After the external prerequisite (Authorized reference deployment, current exact candidate, provider identities and bounded run budget) is available: Assemble the exact candidate's results for every original M8 dependency, including SaaS/single-tenant golden, quota, isolation, usability and DR. Record PASS only when required gates are satisfied; retain explicit blockers and fail release if evidence is missing.
  Output: Create release-readiness record containing results/exceptions from all M8 gates.

- [ ] **M8-54.verify** (depends on: M8-54.deliver). Run or reuse eligible candidate-bound evidence in the cloud-acceptance feature batch. Required assertion: No unresolved blocker is hidden as a documentation note. Include the relevant tenant/current-authority/failure cases; retain actual command, revision, environment, exit status and artifact identity.
  Output: No unresolved blocker is hidden as a documentation note.

- [ ] **M8-54.release** (depends on: M8-54.verify, M8-53, M8-58, M8-59, M8-60, M8-61, M8-62, M8-63, SHIP-GATE). Have the batch reviewer map M8-54 to its exact evidence and original prerequisite results. Publish through the single integration lane only after required gates pass, then update the authoritative ledger with the resulting commit/deployment evidence.
  Output: An independently reviewed original-task result; no local fixture relabeled as live production.
