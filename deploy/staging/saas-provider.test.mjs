import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { load } from "js-yaml";

// The generic saas discovery provider reads SaaS platforms through Nango. It
// is optional. These checks read the chart and the Terraform as text: they
// hold without Helm or Terraform.
test("the saas discovery provider is disabled by default and alone gives the discovery worker Nango", async () => {
  const read = (name) => readFile(new URL(name, import.meta.url), "utf8");
  const values = load(await read("./product/values.yaml"));
  assert.equal(values.discovery.saasCollectorVersion, "");
  for (const name of ["./product/values-saas.yaml", "./product/values-single-tenant.yaml", "./product/values-customer-edge.yaml", "../production/values-production.example.yaml"]) {
    const overlay = load(await read(name)) ?? {};
    assert.ok(!overlay.discovery?.saasCollectorVersion, name);
  }

  const workloads = await read("./product/templates/workloads.yaml");
  // The version is rendered for the API and for the discovery worker, each
  // time as the first line of a block its value opens.
  const gated = /\{\{- with \$?(?:root)?\.Values\.discovery\.saasCollectorVersion \}\}\n\s+- \{ name: ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION, value: \{\{ \. \| quote \}\} \}\n/g;
  assert.equal(workloads.match(gated)?.length, 2);
  assert.equal(workloads.split("ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION").length - 1, 2);
  // The worker receives the Nango settings, the service key mount and its
  // volume only inside that gate. The API has its own, unconditional ones.
  const worker = workloads.slice(workloads.indexOf("name: agentsec-discovery-worker"), workloads.indexOf("name: agentsec-projection-risk"));
  const block = /\{\{- with \.Values\.discovery\.saasCollectorVersion \}\}\n([\s\S]*?)\{\{- end \}\}/.exec(worker)?.[1] ?? "";
  for (const variable of ["ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION", "ZASP_NANGO_BASE_URL", "ZASP_NANGO_SERVICE_SECRET_REFERENCE", "ZASP_NANGO_ENVIRONMENT"]) {
    assert.equal(block.split(variable).length - 1, 1, variable);
    assert.equal(worker.split(variable).length - 1, 1, `${variable} is rendered outside the saas gate`);
  }
  assert.match(block, /ZASP_NANGO_BASE_URL, value: "http:\/\/nango\.\{\{ \$\.Release\.Namespace \}\}\.svc\.cluster\.local:3003"/);
  assert.match(worker, /\{\{- if \.Values\.discovery\.saasCollectorVersion \}\}\n\s+- \{ name: nango-service-key, mountPath: \/var\/run\/secrets\/zasp-nango, readOnly: true \}\n\s+\{\{- end \}\}/);
  assert.match(worker, /\{\{- if \.Values\.discovery\.saasCollectorVersion \}\}\n\s+- name: nango-service-key\n\s+secret:\n\s+secretName: [^\n]+nango\.storageSecretName[^\n]+\n\s+defaultMode: 288\n\s+items: \[\{ key: service-key, path: service-key, mode: 288 \}\]\n\s+\{\{- end \}\}/);
  assert.equal(worker.split("nango-service-key").length - 1, 2);
  // Only the service key of the Nango secret is mounted: never the database URL or the encryption key.
  assert.doesNotMatch(worker, /database-url|encryption-key/);

  const nango = await read("./product/templates/nango.yaml");
  // The worker may reach Nango, and Nango admits it, only under the gate.
  assert.match(nango, /\{\{- if \.Values\.discovery\.saasCollectorVersion \}\}\n---\n[^\n]*\napiVersion: networking\.k8s\.io\/v1\nkind: NetworkPolicy\nmetadata:\n  name: discovery-worker-to-nango\n[\s\S]*?podSelector: \{ matchLabels: \{ app\.kubernetes\.io\/name: agentsec-discovery-worker \} \}\n  policyTypes: \[Egress\]\n  egress:\n    - to: \[\{ podSelector: \{ matchLabels: \{ app\.kubernetes\.io\/name: nango \} \} \}\]\n      ports: \[\{ protocol: TCP, port: 3003 \}\]\n\{\{- end \}\}/);
  assert.match(nango, /\{\{- if \.Values\.discovery\.saasCollectorVersion \}\}\n    - from: \[\{ podSelector: \{ matchLabels: \{ app\.kubernetes\.io\/name: agentsec-discovery-worker \} \} \}\]\n      ports: \[\{ protocol: TCP, port: 3003 \}\]\n    \{\{- end \}\}/);
  assert.equal(nango.split("agentsec-discovery-worker").length - 1, 3);
  // The worker gets no route to a SaaS provider: Nango reaches them.
  const network = await read("./product/templates/resilience.yaml");
  assert.doesNotMatch(network, /saasCollectorVersion|connectorEgressCIDRs\.saas/);

  const variables = await read("./variables.tf");
  const optional = variables.slice(variables.indexOf('variable "discovery_optional_providers"'), variables.indexOf('variable "kubernetes_connector_egress_cidrs"'));
  assert.match(optional, /saas_collector\s*= optional\(string, ""\)/);
  assert.match(optional, /var\.discovery_optional_providers\.saas_collector == "" \|\| can\(regex\("\^\[a-z\]\[a-z0-9_\.-\]\{1,63\}\$", var\.discovery_optional_providers\.saas_collector\)\)/);
  assert.match(await read("./production.tf"), /saasCollectorVersion\s+= var\.discovery_optional_providers\.saas_collector\n/);
  assert.match(await read("./outputs.tf"), /ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION\s+= var\.discovery_optional_providers\.saas_collector\n/);
  for (const text of await Promise.all(["./release.tfvars", "../production/example.tfvars"].map(read))) assert.doesNotMatch(text, /saas_collector/);
});
