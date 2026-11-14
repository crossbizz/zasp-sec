import assert from "node:assert/strict";
import test from "node:test";
import { readFile, readdir } from "node:fs/promises";
import { load } from "js-yaml";
import { renderRelease } from "../production/release-contract.mjs";
import { productionReleaseFixture } from "../production/release-fixture.mjs";

test("legacy migration release has explicit phases and rejects unconfigured forward schemas", async () => {
  const files = await readdir(new URL("../../services/platform/migrations/sql/", import.meta.url));
  const latest = Math.max(...files.filter(name => /^\d+_.*\.up\.sql$/.test(name)).map(name => Number(name.split("_")[0])));
  const values = load(await readFile(new URL("./product/values.yaml", import.meta.url), "utf8"));
  // Source-only and separately profiled migrations do not extend the legacy
  // chart's rollout contract. Pin the known source inventory, then prove every
  // schema beyond60 is refused without its required named profile.
  // Default49 remains deliberate: compatible pods precede the50 hook.
  assert.equal(latest, 81, "new migration sources need an explicit rollout review");
  for (let schemaVersion = 61; schemaVersion <= latest; schemaVersion++) {
    await assert.rejects(renderRelease(productionReleaseFixture, {
      schemaVersion, sessionSearchPhase: "precision-intake", discoveryScheduleReplayPhase: "active",
    }), /release rejected/);
  }
  assert.equal(values.schema.expectedVersion, 49);
  assert.equal(values.runtime.sessionSearchPhase, "compatibility");
  for (const options of [
    { schemaVersion: 48, sessionSearchPhase: "compatibility" },
    { schemaVersion: values.schema.expectedVersion, sessionSearchPhase: values.runtime.sessionSearchPhase },
    { schemaVersion: 50, sessionSearchPhase: "backfill" },
    { schemaVersion: 50, sessionSearchPhase: "query" },
    { schemaVersion: 51, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 51, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 52, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 52, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 53, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 53, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 54, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 54, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 55, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 55, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 56, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 56, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 57, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 57, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 58, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 58, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 59, sessionSearchPhase: "precision-intake", discoveryScheduleReplayPhase: "maintenance" },
    { schemaVersion: 60, sessionSearchPhase: "precision-intake", discoveryScheduleReplayPhase: "active" },
  ]) {
    const resources = await renderRelease(productionReleaseFixture, options);
    const jobs = resources.filter(r => r.kind === "Job" && r.metadata.name.startsWith("agentsec-schema-v"));
    assert.equal(jobs.length, 1);
    assert.equal(jobs[0].metadata.name, `agentsec-schema-v${options.schemaVersion}`);
    const api = resources.find(r => r.kind === "Deployment" && r.metadata.name === "agentsec-api");
    assert.equal(api.spec.template.spec.containers[0].env.find(e => e.name === "ZASP_RUNTIME_SESSION_INDEX").value, options.sessionSearchPhase === "query" || [51, 52, 53, 54, 55, 56, 57, 58, 59, 60].includes(options.schemaVersion) ? "zasp-runtime-sessions-v2" : "zasp-runtime-sessions-v1");
    assert.equal(resources.filter(r => r.kind === "Deployment" && r.metadata.name === "agentsec-runtime-session-index-v2").length, options.schemaVersion >= 50 ? 1 : 0);
    if ([51, 52, 53, 54, 55, 56, 57, 58, 59, 60].includes(options.schemaVersion)) {
      const env = name => resources.find(r => r.kind === "Deployment" && r.metadata.name === name).spec.template.spec.containers[0].env;
      assert.equal(env("agentsec-event-ingest").find(e => e.name === "ZASP_RUNTIME_INGEST_SCHEMA").value, options.sessionSearchPhase === "precision-intake" ? "runtime-event-v2" : "runtime-event-v1");
      for (const name of ["outbox", "coordinator"]) assert.equal(env(`agentsec-runtime-${name}`).find(e => e.name === "ZASP_RUNTIME_DELIVERY_SCHEMA").value, "runtime-event-v2");
      for (const [name, version] of [["archive", 2], ["index", 1], ["correlation", 4], ["projection", 3], ["complete", 3]]) assert.equal(env(`agentsec-runtime-${name}`).find(e => e.name === "ZASP_RUNTIME_STAGE_VERSION").value, `runtime-${name}-v${version}`);
      assert.equal(env("agentsec-runtime-session-index-v2").find(e => e.name === "ZASP_RUNTIME_STAGE_VERSION").value, "runtime-index-v2");
    }
  }
  for (const options of [
    { schemaVersion: 50 },
    { schemaVersion: 49, sessionSearchPhase: "query" },
    { schemaVersion: 50, sessionSearchPhase: "compatibility" },
    { schemaVersion: 50, sessionSearchPhase: "unknown" },
    { schemaVersion: 51, sessionSearchPhase: "query" },
    { schemaVersion: 51 },
    { schemaVersion: 50, sessionSearchPhase: "precision-consumers" },
    { schemaVersion: 50, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 49, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 51, sessionSearchPhase: "precision-active" },
    { schemaVersion: 52 },
    { schemaVersion: 52, sessionSearchPhase: "compatibility" },
    { schemaVersion: 52, sessionSearchPhase: "backfill" },
    { schemaVersion: 52, sessionSearchPhase: "query" },
    { schemaVersion: 52, sessionSearchPhase: "audit-exports" },
    { schemaVersion: 53 },
    { schemaVersion: 53, sessionSearchPhase: "compatibility" },
    { schemaVersion: 54 },
    { schemaVersion: 54, sessionSearchPhase: "compatibility" },
    { schemaVersion: 54, sessionSearchPhase: "backfill" },
    { schemaVersion: 54, sessionSearchPhase: "query" },
    { schemaVersion: 55 },
    { schemaVersion: 55, sessionSearchPhase: "compatibility" },
    { schemaVersion: 55, sessionSearchPhase: "backfill" },
    { schemaVersion: 55, sessionSearchPhase: "query" },
    { schemaVersion: 55, sessionSearchPhase: "precision-active" },
    { schemaVersion: 55, sessionSearchPhase: "unknown" },
    { schemaVersion: 56, sessionSearchPhase: "compatibility" },
    { schemaVersion: 56, sessionSearchPhase: "query" },
    { schemaVersion: 59, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 59, sessionSearchPhase: "precision-intake", discoveryScheduleReplayPhase: "active" },
    { schemaVersion: 60, sessionSearchPhase: "precision-intake" },
    { schemaVersion: 60, sessionSearchPhase: "precision-intake", discoveryScheduleReplayPhase: "maintenance" },
    { schemaVersion: 61, sessionSearchPhase: "precision-intake", discoveryScheduleReplayPhase: "active" },
  ]) await assert.rejects(renderRelease(productionReleaseFixture, options), /release rejected/);
});

import {
  buildStagingDeployment,
  createStagingEvidence,
  evaluateM1AGate,
  inspectStagingDeployment,
  startStagingDeployment,
} from "./gate.mjs";

const digest = (name, character) => `${name}@sha256:${character.repeat(64)}`;
const deployment = {
  cluster: "zasp-staging",
  namespace: "agentsec",
  platformAccountID: "123456789012",
  privateEndpoints: true,
  workloads: [
    { name: "web", image: digest("registry.example/zasp/web", "a"), serviceAccount: "agentsec-web", roleArn: null },
    { name: "agentsec-api", image: digest("registry.example/zasp/api", "b"), serviceAccount: "agentsec-api", roleArn: "arn:aws:iam::123456789012:role/zasp-production-api" },
    { name: "agentsec-discovery-scheduler", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-discovery-scheduler", roleArn: "arn:aws:iam::123456789012:role/zasp-production-discovery-scheduler" },
    { name: "agentsec-discovery-worker", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-discovery-worker", roleArn: "arn:aws:iam::123456789012:role/zasp-production-discovery-worker" },
    { name: "agentsec-security-agent", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-security-agent", roleArn: "arn:aws:iam::123456789012:role/zasp-production-security-agent-worker" },
    { name: "agentsec-security-agent-action", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-security-agent-action", roleArn: "arn:aws:iam::123456789012:role/zasp-production-security-agent-action-worker" },
    { name: "agentsec-policy-deployment", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-policy-deployment", roleArn: "arn:aws:iam::123456789012:role/zasp-production-policy-deployment-worker" },
    { name: "agentsec-outbox-publisher", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-outbox-publisher", roleArn: "arn:aws:iam::123456789012:role/zasp-production-outbox" },
    { name: "agentsec-recovery-backup-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-recovery-backup-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-recovery-backup-outbox" },
    { name: "agentsec-recovery-restore-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-recovery-restore-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-recovery-restore-outbox" },
    { name: "agentsec-recovery-backup", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-recovery-backup", roleArn: "arn:aws:iam::123456789012:role/zasp-production-recovery-backup" },
    { name: "agentsec-recovery-restore", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-recovery-restore", roleArn: "arn:aws:iam::123456789012:role/zasp-production-recovery-restore" },
    { name: "agentsec-red-team-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-red-team-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-red-team-outbox" },
    { name: "agentsec-red-team-worker", image: digest("registry.example/zasp/red-team-worker", "2"), serviceAccount: "zasp-red-team-worker", roleArn: "arn:aws:iam::123456789012:role/zasp-production-red-team-worker" },
    { name: "agentsec-red-team-adapter", image: digest("registry.example/zasp/red-team-worker", "2"), serviceAccount: "zasp-red-team-adapter", roleArn: "arn:aws:iam::123456789012:role/zasp-production-red-team-adapter" },
    { name: "agentsec-attack-lab-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-attack-lab-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-outbox" },
    { name: "agentsec-attack-lab-controller", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-attack-lab-controller", roleArn: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-controller" },
    { name: "agentsec-attack-lab-proxy", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-attack-lab-proxy", roleArn: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-proxy" },
    { name: "agentsec-projection-risk", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-projection-risk", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-risk" },
    { name: "agentsec-projection-graph", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-projection-graph", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-graph" },
    { name: "agentsec-projection-search", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-projection-search", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-search" },
    { name: "agentsec-event-ingest", image: digest("registry.example/zasp/event-ingest", "d"), serviceAccount: "zasp-runtime-ingest", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-ingest" },
    { name: "agentsec-gateway-control", image: digest("registry.example/zasp/gateway-control", "e"), serviceAccount: "zasp-gateway-control", roleArn: "arn:aws:iam::123456789012:role/zasp-production-gateway-control" },
    { name: "agentsec-runtime-outbox", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-outbox", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-outbox" },
    { name: "agentsec-runtime-coordinator", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-coordinator", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-coordinator" },
    { name: "agentsec-runtime-archive", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-archive", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-archive" },
    { name: "agentsec-runtime-index", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-index", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-index" },
    { name: "agentsec-runtime-correlation", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-correlation", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-correlation" },
    { name: "agentsec-runtime-projection", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-projection", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-projection" },
    { name: "agentsec-runtime-complete", image: digest("registry.example/zasp/worker", "c"), serviceAccount: "zasp-runtime-complete", roleArn: "arn:aws:iam::123456789012:role/zasp-production-runtime-complete" },
    { name: "nango", image: "nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed", serviceAccount: "nango", roleArn: null },
    { name: "otel-collector", image: "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5", serviceAccount: "otel-collector", roleArn: null },
  ],
  jobIdentities: [
    { name: "agentsec-schema-v49", serviceAccount: "agentsec-migration", roleArn: "arn:aws:iam::123456789012:role/zasp-production-migration" },
    { name: "agentsec-attack-lab-runner", serviceAccount: "agentsec-attack-lab-runner", roleArn: "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test" },
    { name: "agentsec-projection-graph-init-v1", serviceAccount: "agentsec-projection-graph-init", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-graph-init" },
    { name: "agentsec-projection-search-init-v1", serviceAccount: "agentsec-projection-search-init", roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-search-init" },
    { name: "nango-migrate", serviceAccount: "nango-migrate", roleArn: null },
    { name: "production-readonly-canary", serviceAccount: "agentsec-canary", roleArn: null },
    { name: "zasp-canary-secret-sync", serviceAccount: "agentsec-canary-secret-sync", roleArn: "arn:aws:iam::123456789012:role/zasp-production-canary-secret-sync" },
  ],
};

test("staging deployment binds thirty-two deployments and every init/runner/canary identity to one account", () => {
  assert.deepEqual(buildStagingDeployment(deployment), deployment);
  const runtime = {
    start: () => "deploy-run-1",
    inspect: () => ({ runID: "deploy-run-1", ready: deployment.workloads.map(({ name }) => name), vendorDashboardsExposed: false, privateEndpoints: true }),
  };
  assert.equal(startStagingDeployment(deployment, runtime), "deploy-run-1");
  assert.deepEqual(inspectStagingDeployment("deploy-run-1", runtime).ready, deployment.workloads.map(({ name }) => name));
  assert.throws(() => buildStagingDeployment({ ...deployment, privateEndpoints: false }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, serviceAccount: "shared-release" }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, workloads: [...deployment.workloads, { name: "unsupported-extra", image: digest("registry.example/zasp/extra", "c"), serviceAccount: "shared-release", roleArn: "arn:aws:iam::123456789012:role/zasp-production" }] }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, workloads: deployment.workloads.map((workload) => ({ ...workload, serviceAccount: "shared-release" })) }), /rejected/);
  assert.throws(() => buildStagingDeployment({ ...deployment, jobIdentities: deployment.jobIdentities.map((identity) => identity.name === "agentsec-schema-v49" ? { ...identity, roleArn: "arn:aws:iam::210987654321:role/zasp-production-migration" } : identity) }), /rejected/);
});

test("staging evidence is deterministic and credential-free without admitting the M1A gate", () => {
  const evidence = createStagingEvidence({
    terraformRevision: "a".repeat(40),
    clusterVersion: "1.35.5",
    cluster: "zasp-staging",
    platformAccountID: deployment.platformAccountID,
    images: deployment.workloads.map(({ name, image }) => ({ name, image })),
    identities: [...deployment.workloads, ...deployment.jobIdentities].map(({ name, serviceAccount, roleArn }) => ({ name, serviceAccount, roleArn })),
    deploymentRunID: "deploy-run-1",
  });
  assert.deepEqual(evidence.images.map(({ name }) => name), deployment.workloads.map(({ name }) => name).sort());
  assert.throws(() => evaluateM1AGate({ deploymentReady: true, privateEndpoints: true, perWorkloadIAM: true, evidence }), /staging gate rejected/);
  assert.throws(() => createStagingEvidence({ ...evidence, accessKey: "forbidden" }), /rejected/);
  assert.throws(() => evaluateM1AGate({ deploymentReady: true, privateEndpoints: false, perWorkloadIAM: true, evidence }), /rejected/);
  assert.throws(() => evaluateM1AGate({ deploymentReady: true, dependenciesReady: true, privateEndpoints: true, perWorkloadIAM: true, evidence }), /rejected/);
});

test("staging deployment forbids missing and inherited sandbox roles", () => {
  for (const roleArn of [null, "arn:aws:iam::123456789012:role/zasp-production-discovery-worker"]) {
    assert.throws(() => buildStagingDeployment({ ...deployment, jobIdentities: deployment.jobIdentities.map((identity) => identity.name === "agentsec-attack-lab-runner" ? { ...identity, roleArn } : identity) }), /rejected/);
  }
});

test("boolean readiness cannot substitute for actual same-run dependency and OTLP collection", () => {
  const evidence = createStagingEvidence({
    terraformRevision: "a".repeat(40), clusterVersion: "1.35.5", cluster: "zasp-staging",
    platformAccountID: deployment.platformAccountID,
    images: deployment.workloads.map(({ name, image }) => ({ name, image })),
    identities: [...deployment.workloads, ...deployment.jobIdentities].map(({ name, serviceAccount, roleArn }) => ({ name, serviceAccount, roleArn })),
    deploymentRunID: "deploy-run-1",
  });
  assert.throws(() => evaluateM1AGate({ deploymentReady: true, privateEndpoints: true, perWorkloadIAM: true, evidence }), /staging gate rejected/);
});

// Microsoft and Salesforce are optional discovery providers. These checks read
// the chart and the Terraform as text: they hold without Helm or Terraform.
test("optional discovery providers are disabled by default and gated by their collector version", async () => {
  const read = (name) => readFile(new URL(name, import.meta.url), "utf8");
  const values = load(await read("./product/values.yaml"));
  assert.equal(values.discovery.microsoftCollectorVersion, "");
  assert.equal(values.discovery.salesforceCollectorVersion, "");
  assert.deepEqual(values.network.connectorEgressCIDRs.microsoft, []);
  assert.deepEqual(values.network.connectorEgressCIDRs.salesforce, []);
  // No other values file turns either provider on.
  for (const name of ["./product/values-saas.yaml", "./product/values-single-tenant.yaml", "./product/values-customer-edge.yaml", "../production/values-production.example.yaml"]) {
    const overlay = load(await read(name)) ?? {};
    assert.ok(!overlay.discovery?.microsoftCollectorVersion && !overlay.discovery?.salesforceCollectorVersion, name);
    assert.deepEqual(overlay.network?.connectorEgressCIDRs?.microsoft ?? [], [], name);
    assert.deepEqual(overlay.network?.connectorEgressCIDRs?.salesforce ?? [], [], name);
  }

  const workloads = await read("./product/templates/workloads.yaml");
  for (const [provider, variable] of [["microsoft", "ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION"], ["salesforce", "ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION"]]) {
    // The variable is rendered twice, for the API and for the discovery
    // worker, and each time only inside a block its version value opens.
    const gated = new RegExp(`\\{\\{- with \\$?(?:root)?\\.Values\\.discovery\\.${provider}CollectorVersion \\}\\}\\n\\s+- \\{ name: ${variable}, value: \\{\\{ \\. \\| quote \\}\\} \\}\\n\\s+\\{\\{- end \\}\\}`, "g");
    assert.equal(workloads.match(gated)?.length, 2, variable);
    assert.equal(workloads.split(variable).length - 1, 2, `${variable} is rendered outside its gate`);
  }

  const network = await read("./product/templates/resilience.yaml");
  for (const [provider, variable] of [["microsoft", "$connectorMicrosoft"], ["salesforce", "$connectorSalesforce"]]) {
    // The address list starts empty, is read only under the provider's
    // version, and is then required.
    const definition = `{{- ${variable} := list }}\n{{- if .Values.discovery.${provider}CollectorVersion }}\n{{- ${variable} = .Values.network.connectorEgressCIDRs.${provider} | default list }}\n{{- if not ${variable} }}{{ fail "network.connectorEgressCIDRs.${provider} is required when discovery.${provider}CollectorVersion is set" }}{{ end }}\n{{- end }}`;
    assert.ok(network.includes(definition), `${provider} egress gate`);
    assert.equal(network.split(`.Values.network.connectorEgressCIDRs.${provider}`).length - 1, 1, `${provider} addresses are read outside the gate`);
  }
  // Exactly the API and the discovery worker may reach the providers.
  const policies = network.split("\n---\n").filter((document) => document.includes("$connectorMicrosoft $connectorSalesforce }}"));
  assert.equal(network.split("$connectorMicrosoft $connectorSalesforce }}").length - 1, 2);
  const selectors = policies.map((document) => /podSelector: \{ matchLabels: \{ app\.kubernetes\.io\/name: ([a-z-]+) \} \}/.exec(document)?.[1]).sort();
  assert.deepEqual(selectors, ["agentsec-api", "agentsec-discovery-worker"]);
  for (const document of policies) {
    assert.match(document, /zasp\.io\/network-policy-boundary: native-cidr-snapshot/);
    assert.match(document, /concat [^\n]*\$connectorMicrosoft \$connectorSalesforce \}\}\n\s+- ipBlock: \{ cidr: \{\{ \$cidr \| quote \}\} \}\n\s+\{\{- end \}\}\n\s+ports: \[\{ protocol: TCP, port: 443 \}\]/);
    assert.doesNotMatch(document, /0\.0\.0\.0\/0|::\/0|toFQDNs|namespaceSelector: \{\}/);
  }

  const variables = await read("./variables.tf");
  const optional = variables.slice(variables.indexOf('variable "discovery_optional_providers"'), variables.indexOf('variable "kubernetes_connector_egress_cidrs"'));
  assert.match(optional, /default = \{\}/);
  for (const attribute of ["microsoft_collector", "microsoft_client_secret_id", "salesforce_collector", "salesforce_client_secret_id"]) assert.match(optional, new RegExp(`${attribute}\\s*= optional\\(string, ""\\)`));
  for (const attribute of ["microsoft_egress_cidrs", "salesforce_egress_cidrs"]) assert.match(optional, new RegExp(`${attribute}\\s*= optional\\(list\\(string\\), \\[\\]\\)`));
  const tfvars = await Promise.all(["./release.tfvars", "../production/example.tfvars"].map(read));
  for (const text of tfvars) assert.doesNotMatch(text, /discovery_optional_providers/);

  const terraform = await read("./main.tf");
  // A client-secret reference exists only for an enabled provider, and the
  // API and worker policies reach it through the one connector_reference set.
  assert.match(terraform, /optional_connector_reference_secret_names = \{\s+for key, value in \{[\s\S]*?microsoft\/client-secret\/\$\{var\.discovery_optional_providers\.microsoft_client_secret_id\}[\s\S]*?enabled\s+= var\.discovery_optional_providers\.microsoft_collector != ""[\s\S]*?salesforce\/client-secret\/\$\{var\.discovery_optional_providers\.salesforce_client_secret_id\}[\s\S]*?enabled\s+= var\.discovery_optional_providers\.salesforce_collector != ""[\s\S]*?\} : key => \{ name = value\.name, credential_class = value\.credential_class \} if value\.enabled\n/);
  assert.match(terraform, /connector_reference_secret_names = merge\(local\.required_connector_reference_secret_names, local\.optional_connector_reference_secret_names\)/);
  assert.doesNotMatch(terraform, /secret:\$\{local\.connector_secret_root\}\/(?:microsoft|salesforce)\/\*/);

  const outputs = await read("./outputs.tf");
  assert.match(outputs, /ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION\s+= var\.discovery_optional_providers\.microsoft_collector\n\s+ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION = var\.discovery_optional_providers\.salesforce_collector\n\s+\} : name => version if version != ""/);
});

// Azure OpenAI and AI Foundry are read by the Microsoft collector when
// ZASP_DISCOVERY_MICROSOFT_AZURE is "enabled". Text-level, like the checks
// above: off by default, only with the Microsoft collector, and Resource
// Manager is reachable by the discovery worker alone.
test("the Azure setting of the Microsoft collector is off by default and reaches only the discovery worker", async () => {
  const read = (name) => readFile(new URL(name, import.meta.url), "utf8");
  const values = load(await read("./product/values.yaml"));
  assert.equal(values.discovery.microsoftAzure, false);
  assert.deepEqual(values.network.connectorEgressCIDRs.azure, []);
  for (const name of ["./product/values-saas.yaml", "./product/values-single-tenant.yaml", "./product/values-customer-edge.yaml", "../production/values-production.example.yaml"]) {
    const overlay = load(await read(name)) ?? {};
    assert.ok(!overlay.discovery?.microsoftAzure, name);
    assert.deepEqual(overlay.network?.connectorEgressCIDRs?.azure ?? [], [], name);
  }

  // The variable is rendered once, for the discovery worker, with the one
  // value the worker accepts, inside the gate, which fails a render that
  // sets it without the Microsoft collector.
  const workloads = await read("./product/templates/workloads.yaml");
  const gate = `{{- if .Values.discovery.microsoftAzure }}\n            {{- if not .Values.discovery.microsoftCollectorVersion }}{{ fail "discovery.microsoftAzure needs discovery.microsoftCollectorVersion" }}{{ end }}\n            - { name: ZASP_DISCOVERY_MICROSOFT_AZURE, value: "enabled" }\n            {{- end }}`;
  assert.ok(workloads.includes(gate), "worker gate");
  assert.equal(workloads.split("ZASP_DISCOVERY_MICROSOFT_AZURE").length - 1, 1);
  assert.equal(workloads.split(".Values.discovery.microsoftAzure").length - 1, 1);
  const worker = workloads.split("\n---\n").filter((document) => document.includes("ZASP_DISCOVERY_MICROSOFT_AZURE"));
  assert.equal(worker.length, 1);
  assert.match(worker[0], /name: agentsec-discovery-worker\n/);

  const network = await read("./product/templates/resilience.yaml");
  const definition = `{{- $connectorAzure := list }}\n{{- if .Values.discovery.microsoftAzure }}\n{{- $connectorAzure = .Values.network.connectorEgressCIDRs.azure | default list }}\n{{- if not $connectorAzure }}{{ fail "network.connectorEgressCIDRs.azure is required when discovery.microsoftAzure is set" }}{{ end }}\n{{- end }}`;
  assert.ok(network.includes(definition), "azure egress gate");
  assert.equal(network.split(".Values.network.connectorEgressCIDRs.azure").length - 1, 1);
  const policies = network.split("\n---\n").filter((document) => /concat [^\n]*\$connectorAzure/.test(document));
  assert.equal(policies.length, 1);
  assert.match(policies[0], /podSelector: \{ matchLabels: \{ app\.kubernetes\.io\/name: agentsec-discovery-worker \} \}/);
  assert.match(policies[0], /concat [^\n]*\$connectorAzure \$connectorMicrosoft \$connectorSalesforce \}\}\n\s+- ipBlock: \{ cidr: \{\{ \$cidr \| quote \}\} \}\n\s+\{\{- end \}\}\n\s+ports: \[\{ protocol: TCP, port: 443 \}\]/);
  assert.match(policies[0], /\{\{ if \$connectorAzure \}\},azure-resource-manager\{\{ end \}\}/);
  assert.equal(network.split("$connectorAzure").length - 1, 5);

  const variables = await read("./variables.tf");
  const optional = variables.slice(variables.indexOf('variable "discovery_optional_providers"'), variables.indexOf('variable "kubernetes_connector_egress_cidrs"'));
  assert.match(optional, /microsoft_azure\s+= optional\(bool, false\)/);
  assert.match(optional, /azure_egress_cidrs\s+= optional\(list\(string\), \[\]\)/);
  assert.match(optional, /var\.discovery_optional_providers\.microsoft_azure \?\n\s+var\.discovery_optional_providers\.microsoft_collector != "" &&\n\s+length\(var\.discovery_optional_providers\.azure_egress_cidrs\) >= 1 && length\(var\.discovery_optional_providers\.azure_egress_cidrs\) <= 16 /);
  assert.match(optional, /for cidr in var\.discovery_optional_providers\.azure_egress_cidrs : [^\n]*cidr != "0\.0\.0\.0\/0" && cidr != "::\/0"\n\s+\]\) :\n\s+length\(var\.discovery_optional_providers\.azure_egress_cidrs\) == 0\n/);

  const outputs = await read("./outputs.tf");
  assert.match(outputs, /var\.discovery_optional_providers\.microsoft_azure \? \{ ZASP_DISCOVERY_MICROSOFT_AZURE = "enabled" \} : \{\}/);
  const production = await read("./production.tf");
  assert.match(production, /microsoftAzure\s+= var\.discovery_optional_providers\.microsoft_azure\n/);
  assert.match(production, /azure\s+= var\.discovery_optional_providers\.azure_egress_cidrs\n/);
});
