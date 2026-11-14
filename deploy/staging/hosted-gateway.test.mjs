import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { load } from "js-yaml";

// The hosted gateway is served by the API and is optional. These checks read
// the chart and the Terraform as text: they hold without Helm or Terraform,
// and they do not prove that either renders or applies.
const read = (name) => readFile(new URL(name, import.meta.url), "utf8");
const count = (text, part) => text.split(part).length - 1;
const gate = "{{- if .Values.hostedGateway.enabled }}";

test("the hosted gateway is disabled by default in every values file", async () => {
  const values = load(await read("./product/values.yaml"));
  assert.deepEqual(values.hostedGateway, {
    enabled: false, timeoutSeconds: 300, decisionRetentionDays: 90, egressCIDRs: [],
    egressExceptCIDRs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8"],
  });
  for (const name of ["./product/values-saas.yaml", "./product/values-single-tenant.yaml", "./product/values-customer-edge.yaml", "../production/values-production.example.yaml"]) {
    const overlay = load(await read(name)) ?? {};
    assert.equal(overlay.hostedGateway, undefined, name);
  }
  for (const text of await Promise.all(["./release.tfvars", "../production/example.tfvars"].map(read))) assert.doesNotMatch(text, /hosted_gateway/);
});

test("only the API is told to host the gateway, and only inside the gate", async () => {
  const workloads = await read("./product/templates/workloads.yaml");
  for (const variable of ["ZASP_HOSTED_GATEWAY_ENABLED", "ZASP_HOSTED_GATEWAY_TIMEOUT"]) assert.equal(count(workloads, variable), 1, variable);
  const block = /\{\{- if \$root\.Values\.hostedGateway\.enabled \}\}\n([\s\S]*?)\{\{- end \}\}/.exec(workloads)?.[1] ?? "";
  assert.match(block, /- \{ name: ZASP_HOSTED_GATEWAY_ENABLED, value: "true" \}\n/);
  assert.match(block, /- \{ name: ZASP_HOSTED_GATEWAY_TIMEOUT, value: "\{\{ int \(required "hostedGateway\.timeoutSeconds is required" \$root\.Values\.hostedGateway\.timeoutSeconds\) \}\}s" \}\n/);
  assert.equal(count(block, "name: ZASP_"), 2);
  // The block is in the API's own environment: after the API's request
  // timeout and before the settings that follow it.
  const api = workloads.slice(workloads.indexOf('{{- if eq .name "agentsec-api" }}'), workloads.indexOf("ZASP_DATABASE_AUTHORITY"));
  assert.equal(count(api, "$root.Values.hostedGateway.enabled"), 1);
  assert.ok(api.indexOf("ZASP_REQUEST_TIMEOUT") < api.indexOf("ZASP_HOSTED_GATEWAY_ENABLED"));
  // No upstream credential is configured anywhere: the gateway holds none.
  assert.doesNotMatch(workloads, /HOSTED_GATEWAY[A-Z_]*(KEY|SECRET|TOKEN|CREDENTIAL)/);
});

test("the scheduler is told how long gateway decisions are kept, and nothing else is", async () => {
  const workloads = await read("./product/templates/workloads.yaml");
  assert.equal(count(workloads, "ZASP_GATEWAY_DECISION_RETENTION_DAYS"), 1);
  const scheduler = workloads.slice(workloads.indexOf("name: agentsec-discovery-scheduler"));
  const environment = scheduler.slice(scheduler.indexOf('- { name: ZASP_WORKER_MODE, value: "scheduler" }'), scheduler.indexOf("volumeMounts:"));
  assert.match(environment, /- \{ name: ZASP_GATEWAY_DECISION_RETENTION_DAYS, value: \{\{ int \(required "hostedGateway\.decisionRetentionDays is required" \.Values\.hostedGateway\.decisionRetentionDays\) \| quote \}\} \}\n/);
  // The scheduler is not told to host the gateway and gets no address of it.
  assert.doesNotMatch(environment, /HOSTED_GATEWAY/);
  const terraform = await read("./production.tf");
  assert.match(terraform, /decisionRetentionDays = var\.hosted_gateway\.decision_retention_days\n/);
  const variables = await read("./variables.tf");
  assert.match(variables, /decision_retention_days = optional\(number, 90\)/);
  assert.match(variables, /var\.hosted_gateway\.decision_retention_days >= 1 && var\.hosted_gateway\.decision_retention_days <= 3650 && floor\(var\.hosted_gateway\.decision_retention_days\) == var\.hosted_gateway\.decision_retention_days/);
});

test("the gateway's egress exists only inside the gate, on port 443, without the non-public ranges", async () => {
  const resilience = await read("./product/templates/resilience.yaml");
  assert.equal(count(resilience, gate), 1);
  assert.equal(count(resilience, "api-hosted-gateway-egress"), 1);
  const start = resilience.indexOf(gate);
  const block = resilience.slice(start, resilience.indexOf("kind: NetworkPolicy\nmetadata: { name: schema-database", start));
  assert.match(block, /required "hostedGateway\.egressCIDRs is required when hostedGateway\.enabled is set" \.Values\.hostedGateway\.egressCIDRs/);
  assert.match(block, /\{\{- if not \$gatewayEgress \}\}\{\{ fail "hostedGateway\.egressCIDRs is required when hostedGateway\.enabled is set" \}\}\{\{ end \}\}/);
  assert.match(block, /podSelector: \{ matchLabels: \{ app\.kubernetes\.io\/name: agentsec-api \} \}\n {2}policyTypes: \[Egress\]\n {2}egress:\n/);
  assert.equal(count(block, "podSelector"), 1);
  // One egress rule, to the listed ranges, on TCP 443 and nothing else.
  assert.equal(count(block, "ports:"), 1);
  assert.match(block, /ports: \[\{ protocol: TCP, port: 443 \}\]\n\{\{- end \}\}\n/);
  assert.doesNotMatch(block, /port: (?!443)/);
  // The whole internet is admitted only with the exceptions carved out.
  assert.match(block, /cidr: \{\{ \$cidr \| quote \}\}\n\s+\{\{- if eq \$cidr "0\.0\.0\.0\/0" \}\}\n\s+except:\n\s+\{\{- range \$except := \$\.Values\.hostedGateway\.egressExceptCIDRs \}\}\n\s+- \{\{ \$except \| quote \}\}\n/);
  assert.doesNotMatch(block, /ingress|Ingress/);
  // The API's other egress policies are as they were.
  assert.equal(count(resilience, "name: api-connector-egress"), 1);
  assert.equal(count(resilience, "name: api-dependencies"), 1);
});

test("the gateway's ingress exists only inside the gate and covers only its two traffic prefixes", async () => {
  const ingress = await read("./product/templates/ingress.yaml");
  assert.equal(count(ingress, gate), 1);
  assert.equal(count(ingress, "name: zasp-hosted-gateway"), 1);
  const start = ingress.indexOf(gate);
  const block = ingress.slice(start, ingress.indexOf("{{- end }}", start));
  assert.match(block, /proxy-body-size: "4m"/);
  assert.match(block, /proxy-buffering: "off"/);
  for (const annotation of ["proxy-read-timeout", "proxy-send-timeout"]) {
    assert.match(block, new RegExp(`${annotation}: \\{\\{ add \\(int \\.Values\\.hostedGateway\\.timeoutSeconds\\) 45 \\| quote \\}\\}`));
  }
  const paths = [...block.matchAll(/- path: (\S+)\n\s+pathType: Prefix\n\s+backend: \{ service: \{ name: agentsec-api, port: \{ number: 8080 \} \} \}/g)].map((match) => match[1]);
  assert.deepEqual(paths, ["/api/v1/gateway/mcp/", "/api/v1/gateway/llm/"]);
  assert.equal(count(block, "- path:"), 2);
  // The product API's own ingress keeps its small body and short timeout.
  const product = ingress.slice(ingress.indexOf("name: zasp-product"), start);
  assert.match(product, /proxy-body-size: "16k"/);
  assert.match(product, /proxy-read-timeout: "30"/);
});

test("Terraform passes the gateway's setting to the chart and adds no resource for it", async () => {
  const [production, variables, ...others] = await Promise.all(["./production.tf", "./variables.tf", "./main.tf", "./outputs.tf", "./security_agent_remediation.tf"].map(read));
  assert.match(production, /hostedGateway = \{\n\s+enabled\s+= var\.hosted_gateway\.enabled\n\s+timeoutSeconds\s+= var\.hosted_gateway\.timeout_seconds\n\s+egressCIDRs\s+= var\.hosted_gateway\.egress_cidrs\n\s+decisionRetentionDays = var\.hosted_gateway\.decision_retention_days\n\s+\}/);
  assert.equal(count(production, "hosted_gateway"), 5);
  const variable = variables.slice(variables.indexOf('variable "hosted_gateway" {'), variables.indexOf('variable "discovery_optional_providers" {'));
  assert.match(variable, /enabled\s+= optional\(bool, false\)/);
  assert.match(variable, /timeout_seconds\s+= optional\(number, 300\)/);
  assert.match(variable, /egress_cidrs\s+= optional\(list\(string\), \[\]\)/);
  assert.match(variable, /default = \{\}/);
  // Enabled exactly when egress is named.
  assert.match(variable, /var\.hosted_gateway\.enabled == \(length\(var\.hosted_gateway\.egress_cidrs\) > 0\)/);
  for (const text of others) assert.doesNotMatch(text, /hosted_gateway/);
});
