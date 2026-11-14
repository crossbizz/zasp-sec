import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { load } from "js-yaml";

// Google Cloud is an optional discovery provider. These checks read the
// chart and the Terraform as text: they hold without Helm or Terraform.
test("the Google Cloud discovery provider is disabled by default and gated by its collector version", async () => {
  const read = (name) => readFile(new URL(name, import.meta.url), "utf8");
  const values = load(await read("./product/values.yaml"));
  assert.equal(values.discovery.gcpCollectorVersion, "");
  assert.deepEqual(values.network.connectorEgressCIDRs.gcp, []);
  for (const name of ["./product/values-saas.yaml", "./product/values-single-tenant.yaml", "./product/values-customer-edge.yaml", "../production/values-production.example.yaml"]) {
    const overlay = load(await read(name)) ?? {};
    assert.ok(!overlay.discovery?.gcpCollectorVersion, name);
    assert.ok(!(overlay.network?.connectorEgressCIDRs?.gcp ?? []).length, name);
  }

  // The version is rendered for the API (which proves an authorization) and
  // for the discovery worker, each time only inside its own gate. Neither
  // receives a Google credential: there is none to give.
  const workloads = await read("./product/templates/workloads.yaml");
  const gated = /\{\{- with \$?(?:root)?\.Values\.discovery\.gcpCollectorVersion \}\}\n\s+- \{ name: ZASP_DISCOVERY_GCP_COLLECTOR_VERSION, value: \{\{ \. \| quote \}\} \}\n\s+\{\{- end \}\}/g;
  assert.equal(workloads.match(gated)?.length, 2);
  assert.equal(workloads.split("ZASP_DISCOVERY_GCP_COLLECTOR_VERSION").length - 1, 2);
  assert.doesNotMatch(workloads, /GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_CLOUD|service-account-key/);

  // Google's API addresses are admitted for the API and the worker only
  // under the gate, and are then required.
  const network = await read("./product/templates/resilience.yaml");
  assert.match(network, /\{\{- \$connectorGCP := list \}\}\n\{\{- if \.Values\.discovery\.gcpCollectorVersion \}\}\n\{\{- \$connectorGCP = \.Values\.network\.connectorEgressCIDRs\.gcp \| default list \}\}\n\{\{- if not \$connectorGCP \}\}\{\{ fail "network\.connectorEgressCIDRs\.gcp is required when discovery\.gcpCollectorVersion is set" \}\}\{\{ end \}\}\n\{\{- end \}\}/);
  assert.equal(network.split("connectorEgressCIDRs.gcp").length - 1, 2);
  // Declared once, then used by the API policy and the worker policy: the
  // endpoint group annotation and the address list of each.
  assert.equal(network.split("$connectorGCP").length - 1, 7);
  const policy = (name) => {
    const start = network.indexOf(`  name: ${name}\n`);
    return network.slice(start, network.indexOf("\n---", start));
  };
  for (const name of ["api-connector-egress", "discovery-worker-dependencies"]) {
    const text = policy(name);
    assert.match(text, /\{\{ if \$connectorGCP \}\},google-apis\{\{ end \}\}/, name);
    assert.match(text, /range \$cidr := concat [^\n]*\$connectorGCP [^\n]*\$connectorMicrosoft \$connectorSalesforce \}\}\n\s+- ipBlock: \{ cidr: \{\{ \$cidr \| quote \}\} \}\n\s+\{\{- end \}\}\n\s+ports: \[\{ protocol: TCP, port: 443 \}\]/, name);
    assert.doesNotMatch(text, /0\.0\.0\.0\/0|::\/0|toFQDNs/, name);
  }

  const variables = await read("./variables.tf");
  const optional = variables.slice(variables.indexOf('variable "discovery_optional_providers"'), variables.indexOf('variable "kubernetes_connector_egress_cidrs"'));
  assert.match(optional, /gcp_collector\s*= optional\(string, ""\)/);
  assert.match(optional, /gcp_egress_cidrs\s*= optional\(list\(string\), \[\]\)/);
  assert.match(optional, /gcp_service_account_key_id\s*= optional\(string, ""\)/);
  // Disabled sets nothing; enabled needs addresses; a key is optional.
  assert.match(optional, /var\.discovery_optional_providers\.gcp_collector == "" \?\n\s+length\(var\.discovery_optional_providers\.gcp_egress_cidrs\) == 0 && var\.discovery_optional_providers\.gcp_service_account_key_id == "" :/);
  assert.match(optional, /length\(var\.discovery_optional_providers\.gcp_egress_cidrs\) >= 1 && length\(var\.discovery_optional_providers\.gcp_egress_cidrs\) <= 64/);
  const main = await read("./main.tf");
  assert.match(main, /gcp_service_account_key = \{\n\s+name\s+= "\$\{local\.connector_secret_root\}\/gcp\/service-account-key\/\$\{var\.discovery_optional_providers\.gcp_service_account_key_id\}"\n\s+credential_class = "gcp_service_account_key_reference"\n\s+enabled\s+= var\.discovery_optional_providers\.gcp_collector != "" && var\.discovery_optional_providers\.gcp_service_account_key_id != ""\n/);
  const production = await read("./production.tf");
  assert.match(production, /gcpCollectorVersion\s+= var\.discovery_optional_providers\.gcp_collector\n/);
  assert.match(production, /gcp\s+= var\.discovery_optional_providers\.gcp_egress_cidrs\n/);
  assert.match(await read("./outputs.tf"), /ZASP_DISCOVERY_GCP_COLLECTOR_VERSION\s+= var\.discovery_optional_providers\.gcp_collector\n/);
  for (const text of await Promise.all(["./release.tfvars", "../production/example.tfvars"].map(read))) assert.doesNotMatch(text, /gcp_collector/);
});
