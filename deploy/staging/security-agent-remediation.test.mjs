import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { load } from "js-yaml";

// Provider remediations give the Security Agent action worker an AWS identity
// of its own. They are optional. These checks read the chart and the
// Terraform as text: they hold without Helm or Terraform, and they do not
// prove that either renders or applies.
const read = (name) => readFile(new URL(name, import.meta.url), "utf8");
const count = (text, part) => text.split(part).length - 1;
const variables = ["ZASP_SECURITY_AGENT_REMEDIATION_ROLE_ARN", "ZASP_SECURITY_AGENT_REMEDIATION_WEB_IDENTITY_TOKEN_FILE", "ZASP_SECURITY_AGENT_REMEDIATION_SECRET_PREFIX"];

test("provider remediations are disabled by default in every values file", async () => {
  const values = load(await read("./product/values.yaml"));
  assert.deepEqual(values.securityAgentRemediation, { enabled: false, roleArn: "", awsRegion: "", secretPrefix: "" });
  for (const name of ["./product/values-saas.yaml", "./product/values-single-tenant.yaml", "./product/values-customer-edge.yaml", "../production/values-production.example.yaml"]) {
    const overlay = load(await read(name)) ?? {};
    assert.equal(overlay.securityAgentRemediation, undefined, name);
  }
  for (const text of await Promise.all(["./release.tfvars", "../production/example.tfvars"].map(read))) assert.doesNotMatch(text, /security_agent_remediation/);
});

test("only the action worker receives the remediation identity, and only inside the gate", async () => {
  const workloads = await read("./product/templates/workloads.yaml");
  const start = workloads.indexOf("name: agentsec-security-agent-action\n");
  const action = workloads.slice(start, workloads.indexOf("\n---\n", start));
  const gate = "{{- if .Values.securityAgentRemediation.enabled }}";
  assert.equal(count(workloads, gate), 3);
  assert.equal(count(action, gate), 3);
  // The three settings the worker takes together, and the Region, are
  // rendered once, in one gated block of the action worker's environment.
  const environment = new RegExp(`${gate.replace(/[.{}|$-]/g, "\\$&")}\\n([\\s\\S]*?)\\{\\{- end \\}\\}`).exec(action)?.[1] ?? "";
  for (const variable of [...variables, "ZASP_AWS_REGION"]) {
    assert.equal(count(environment, variable), 1, variable);
    assert.equal(count(action, variable), 1, `${variable} is rendered outside the gate`);
  }
  for (const variable of variables) assert.equal(count(workloads, variable), 1, `${variable} is given to another workload`);
  assert.match(environment, /ZASP_SECURITY_AGENT_REMEDIATION_ROLE_ARN, value: \{\{ required "securityAgentRemediation\.roleArn is required" \.Values\.securityAgentRemediation\.roleArn \| quote \}\}/);
  assert.match(environment, /ZASP_SECURITY_AGENT_REMEDIATION_SECRET_PREFIX, value: \{\{ required "securityAgentRemediation\.secretPrefix is required" \.Values\.securityAgentRemediation\.secretPrefix \| quote \}\}/);
  assert.match(environment, /ZASP_AWS_REGION, value: \{\{ required "securityAgentRemediation\.awsRegion is required" \.Values\.securityAgentRemediation\.awsRegion \| quote \}\}/);
  // The token file is the fixed path the worker accepts, and the token mounted
  // there is a short-lived one for STS: the pod's API token stays unmounted.
  assert.match(environment, /ZASP_SECURITY_AGENT_REMEDIATION_WEB_IDENTITY_TOKEN_FILE, value: \/var\/run\/secrets\/eks\.amazonaws\.com\/serviceaccount\/token \}/);
  assert.match(action, /automountServiceAccountToken: false/);
  assert.match(action, /\{\{- if \.Values\.securityAgentRemediation\.enabled \}\}\n\s+- \{ name: remediation-web-identity, mountPath: \/var\/run\/secrets\/eks\.amazonaws\.com\/serviceaccount, readOnly: true \}\n\s+\{\{- end \}\}/);
  assert.match(action, /\{\{- if \.Values\.securityAgentRemediation\.enabled \}\}\n\s+- name: remediation-web-identity\n\s+projected:\n\s+defaultMode: 256\n\s+sources:\n\s+- serviceAccountToken: \{ audience: sts\.amazonaws\.com, expirationSeconds: 900, path: token \}\n\s+\{\{- end \}\}/);
  assert.equal(count(workloads, "remediation-web-identity"), 2);
  // Without the gate the worker keeps the one mount and the one volume it had.
  assert.match(action, /volumeMounts:\n\s+- \{ name: security-agent-action-secrets, mountPath: \/var\/run\/secrets\/zasp-security-agent-action, readOnly: true \}\n/);
  // The discovery identity is not given to the action worker.
  assert.doesNotMatch(action, /ZASP_DISCOVERY_ROLE_ARN|discovery\.roleArn|discovery-web-identity/);
});

test("the action worker reaches AWS only while remediations are enabled", async () => {
  const network = await read("./product/templates/resilience.yaml");
  const policy = /\{\{- if \.Values\.securityAgentRemediation\.enabled \}\}\n---\n(?:#[^\n]*\n)+apiVersion: networking\.k8s\.io\/v1\nkind: NetworkPolicy\nmetadata:\n  name: security-agent-action-remediation\n([\s\S]*?)\{\{- end \}\}\n---\n/.exec(network)?.[1] ?? "";
  assert.match(policy, /podSelector: \{ matchLabels: \{ app\.kubernetes\.io\/name: agentsec-security-agent-action \} \}\n  policyTypes: \[Egress\]\n  egress:\n    - to:\n      \{\{- range \$cidr := required "network\.connectorEgressCIDRs\.aws is required" \.Values\.network\.connectorEgressCIDRs\.aws \}\}\n        - ipBlock: \{ cidr: \{\{ \$cidr \| quote \}\} \}\n      \{\{- end \}\}\n      ports: \[\{ protocol: TCP, port: 443 \}\]\n$/);
  assert.equal(count(network, "securityAgentRemediation"), 1);
  assert.equal(count(network, "name: security-agent-action-remediation"), 1);
  // The policy the worker always has still admits the database and nothing else.
  assert.match(network, /metadata: \{ name: security-agent-action-database, labels: \{ app\.kubernetes\.io\/part-of: zasp \} \}\nspec:\n  podSelector: \{ matchLabels: \{ app\.kubernetes\.io\/name: agentsec-security-agent-action \} \}\n  policyTypes: \[Egress\]\n  egress:\n    - to: \[\{ ipBlock: \{ cidr: \{\{ required "network\.postgresCIDR is required" \.Values\.network\.postgresCIDR \| quote \}\} \} \}\]\n      ports: \[\{ protocol: TCP, port: 5432 \}\]\n\{\{- if/);
});

test("Terraform creates the remediation identity only when asked, for exact customer roles", async () => {
  const variablesText = await read("./variables.tf");
  const variable = variablesText.slice(variablesText.indexOf('variable "security_agent_remediation"'), variablesText.indexOf('variable "discovery_optional_providers"'));
  assert.match(variable, /enabled\s+= optional\(bool, false\)/);
  assert.match(variable, /customer_role_arns = optional\(set\(string\), \[\]\)/);
  assert.match(variable, /default = \{\}/);
  // Enabled exactly when roles are named; each is an exact role and never a role discovery reads with.
  assert.match(variable, /var\.security_agent_remediation\.enabled == \(length\(var\.security_agent_remediation\.customer_role_arns\) > 0\)/);
  assert.match(variable, /!strcontains\(role, "\*"\) && !contains\(var\.aws_reference_role_arns, role\)/);

  const identity = await read("./security_agent_remediation.tf");
  assert.equal(count(identity, "count = var.security_agent_remediation.enabled ? 1 : 0"), 2);
  assert.equal(count(identity, 'resource "'), 2);
  assert.match(identity, /resource "aws_iam_role" "security_agent_remediation" \{/);
  assert.match(identity, /:sub" = "system:serviceaccount:agentsec:zasp-security-agent-action"/);
  assert.match(identity, /:aud" = "sts\.amazonaws\.com"/);
  // Exactly three statements: assume the named customer roles, read the one
  // external ID secret, decrypt it through Secrets Manager.
  const statements = identity.slice(identity.indexOf('resource "aws_iam_role_policy" "security_agent_remediation"'));
  assert.equal(count(statements, 'Effect = "Allow"'), 3);
  assert.match(statements, /Action = \["sts:AssumeRole"\], Resource = sort\(tolist\(var\.security_agent_remediation\.customer_role_arns\)\)/);
  assert.match(statements, /Action = \["secretsmanager:GetSecretValue"\], Resource = aws_secretsmanager_secret\.connector_reference\["aws_external_id"\]\.arn/);
  assert.match(statements, /Action = \["kms:Decrypt"\], Resource = aws_kms_key\.connector_oauth\.arn/);
  assert.match(statements, /"kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret\.connector_reference\["aws_external_id"\]\.arn/);
  // No wildcard, no customer-account action, no read role.
  assert.doesNotMatch(identity.replace(/^#.*$/gm, ""), /"\*"|bedrock:|iam:|aws_reference_role_arns|aws_iam_role\.worker/);

  const production = await read("./production.tf");
  assert.match(production, /securityAgentRemediation = \{\n\s+enabled\s+= var\.security_agent_remediation\.enabled\n\s+roleArn\s+= var\.security_agent_remediation\.enabled \? aws_iam_role\.security_agent_remediation\[0\]\.arn : ""\n\s+awsRegion\s+= var\.region\n\s+secretPrefix = local\.connector_secret_root\n\s+\}/);
  // The same secret prefix discovery uses, so the worker finds the integration's external ID.
  assert.match(production, /roleArn\s+= aws_iam_role\.worker\.arn\n\s+secretPrefix\s+= local\.connector_secret_root\n/);
  assert.match(await read("./outputs.tf"), /output "security_agent_remediation_role_arn" \{\n[^\n]*\n\s+value\s+= var\.security_agent_remediation\.enabled \? aws_iam_role\.security_agent_remediation\[0\]\.arn : ""\n\}/);
  // The action worker's own role is unchanged: remediations add no permission to it.
  const main = await read("./main.tf");
  const actionPolicy = main.slice(main.indexOf('resource "aws_iam_role_policy" "security_agent_action_worker"'), main.indexOf('resource "aws_iam_role" "policy_deployment_worker"'));
  assert.doesNotMatch(actionPolicy, /sts:AssumeRole|connector_reference|remediation/);
});

test("the worker reads exactly the settings the chart renders", async () => {
  const config = await readFile(new URL("../../services/platform/agentsec-worker/runtime_config.go", import.meta.url), "utf8");
  for (const variable of variables) assert.equal(count(config, `getenv("${variable}")`), 1, variable);
  const factory = await readFile(new URL("../../services/platform/agentsec-worker/security_agent_remediation_production.go", import.meta.url), "utf8");
  assert.match(factory, /config\.RemediationTokenFile == "\/var\/run\/secrets\/eks\.amazonaws\.com\/serviceaccount\/token"/);
});
