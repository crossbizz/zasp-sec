import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { inspectContainerBuilds, renderRelease } from "./release-contract.mjs";

const digest = (name, value) => `registry.example/zasp/${name}@sha256:${value.repeat(64)}`;
const release = Object.freeze({
  host: "app.zasp.example",
  tlsSecretName: "zasp-product-tls",
  secretProviderClass: "zasp-production-secrets",
  discovery: Object.freeze({ parserVersion: "inventory-parser-2026.08.20", toolVersion: "collector-tool-2026.08.20" }),
  projectionSearch: Object.freeze({
    awsRegion: "us-west-2", endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", index: "zasp-inventory-v1",
    roleArn: "arn:aws:iam::123456789012:role/zasp-production-projection-search", webIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
  }),
  outbox: Object.freeze({
    awsRegion: "us-west-2", queueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs",
    roleArn: "arn:aws:iam::123456789012:role/zasp-production-outbox", webIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    egressCIDRs: Object.freeze(["10.70.0.0/28"]),
  }),
  connectors: Object.freeze({
    awsRegion: "us-west-2",
    roleArn: "arn:aws:iam::123456789012:role/zasp-production-api-connectors",
    awsCustomerRolePrefixes: Object.freeze(["arn:aws:iam::111111111111:role/zasp,reference/", "arn:aws:iam::222222222222:role/zasp-reference/"]),
    awsCustomerRoleARNs: Object.freeze(["arn:aws:iam::111111111111:role/zasp,reference/customer-0001", "arn:aws:iam::222222222222:role/zasp-reference/customer-0002"]),
    webIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    kmsKeyArn: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
    secretPrefix: "zasp-production/connectors/oauth",
    githubClientID: "Iv1.1234567890abcdef",
    githubClientSecretReference: "ref:github/client-secret",
    githubAppID: "123456",
    githubPrivateKeyReference: "ref:github/app-private-key",
    oktaClientID: "0oa1234567890abcdef",
    oktaClientSecretReference: "ref:okta/client-secret",
  }),
  connectorEgressCIDRs: Object.freeze({
    aws: Object.freeze(["10.50.0.0/28"]),
    github: Object.freeze(["192.0.2.0/28"]),
    okta: Object.freeze(["198.51.100.0/28"]),
    kubernetes: Object.freeze(["203.0.113.0/28"]),
  }),
  images: Object.freeze({
    web: digest("web", "a"), agentsecApi: digest("api", "b"), agentsecWorker: digest("worker", "c"),
  }),
});

test("production container builds are exact, non-root, health-bound, and secret-free", async () => {
  const builds = await inspectContainerBuilds();
  assert.deepEqual(builds.map(({ name, user, port }) => ({ name, user, port })), [
    { name: "web", user: "65532:65532", port: 3000 },
    { name: "agentsec-api", user: "65532:65532", port: 8080 },
    { name: "agentsec-worker", user: "65532:65532", port: 8081 },
  ]);
  for (const build of builds) {
    assert.equal(build.readOnlyCompatible, true);
    assert.equal(build.containsSecret, false);
    assert.match(build.healthcheck, /127\.0\.0\.1/);
    assert.equal(build.digestPinned, true);
  }
  const webDockerfile = await readFile(new URL("./web.Dockerfile", import.meta.url), "utf8");
  assert.doesNotMatch(webDockerfile, /(?:ARG|ENV)\s+.*(?:SECRET|TOKEN|PASSWORD|DSN)/i);
  assert.match(webDockerfile, /\/src\/dist\/standalone/);
  assert.doesNotMatch(webDockerfile, /\/src\/node_modules/);
  assert.match(await readFile(new URL("../../next.config.ts", import.meta.url), "utf8"), /output:\s*["']standalone["']/);
});

test("release renders one TLS origin, split ports, private internals, and migration/schema gates", async () => {
  const resources = await renderRelease(release);
  const ingress = one(resources, "Ingress", "zasp-product");
  assert.equal(ingress.spec.tls[0].secretName, release.tlsSecretName);
  assert.deepEqual(ingress.spec.rules[0].http.paths.map(({ path, backend }) => [path, backend.service.name, backend.service.port.number]), [
    ["/api/v1", "agentsec-api", 8080], ["/", "web", 3000],
  ]);
  const annotations = ingress.metadata.annotations;
  for (const value of ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]) {
    assert.match(annotations["nginx.ingress.kubernetes.io/configuration-snippet"], new RegExp(value));
  }
  assert.deepEqual(one(resources, "Service", "agentsec-api").spec.ports.map(({ name, port }) => [name, port]), [["product", 8080], ["internal", 8081]]);
  assert.equal(resources.some(({ kind, metadata }) => kind === "Ingress" && metadata?.name !== "zasp-product"), false);
  assert.equal(resources.some(({ kind, metadata }) => kind === "Service" && ["neo4j", "nango", "otel-collector"].includes(metadata.name) && metadata.annotations?.["service.beta.kubernetes.io/aws-load-balancer-type"]), false);
  assert.equal(one(resources, "Job", "agentsec-schema-v13").metadata.annotations["helm.sh/hook"], "pre-install,pre-upgrade");
  assert.match(one(resources, "Job", "agentsec-schema-v13").spec.template.spec.containers[0].args[0], /exec \/app\/agentsec-migrate up/);
  const migration = one(resources, "Job", "agentsec-schema-v13");
  assert.equal(migration.spec.template.spec.serviceAccountName, "agentsec-migration");
  assert.equal(migration.spec.template.spec.containers[0].env.some(({ valueFrom }) => valueFrom?.secretKeyRef), false);
  assert.equal(migration.spec.template.spec.containers[0].volumeMounts[0].mountPath, "/var/run/secrets/zasp-migration");
  assert.deepEqual(Object.fromEntries(migration.spec.template.spec.containers[0].env.map(({ name, value }) => [name, value])), {
    ZASP_MIGRATION_TIMEOUT: "10m",
    ZASP_MIGRATION_DB_PRINCIPAL: "zasp_migration",
    ZASP_DISCOVERY_API_DB_PRINCIPAL: "zasp_api_runtime",
    ZASP_DISCOVERY_WORKER_DB_PRINCIPAL: "zasp_discovery_runtime",
    ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL: "zasp_scheduler_runtime",
    ZASP_PROJECTION_RISK_DB_PRINCIPAL: "zasp_projection_risk_runtime",
    ZASP_PROJECTION_GRAPH_DB_PRINCIPAL: "zasp_projection_graph_runtime",
    ZASP_PROJECTION_SEARCH_DB_PRINCIPAL: "zasp_projection_search_runtime",
    ZASP_RUNTIME_INGEST_DB_PRINCIPAL: "zasp_ingest_runtime",
    ZASP_RUNTIME_WORKER_DB_PRINCIPAL: "zasp_runtime_worker_runtime",
    ZASP_OUTBOX_WORKER_DB_PRINCIPAL: "zasp_outbox_runtime",
    ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL: "zasp_gateway_runtime",
  });
  for (const [kind, name, weight] of [["ServiceAccount", "agentsec-migration", "-30"], ["SecretProviderClass", "zasp-production-migration-secrets", "-20"], ["Job", "agentsec-schema-v13", "-10"]]) {
    const resource = one(resources, kind, name);
    assert.equal(resource.metadata.annotations["helm.sh/hook"], "pre-install,pre-upgrade");
    assert.equal(resource.metadata.annotations["helm.sh/hook-weight"], weight);
  }
  assert.equal(one(resources, "Deployment", "agentsec-api").spec.template.metadata.annotations["zasp.io/schema-version"], "13");
  assert.equal(one(resources, "Deployment", "agentsec-api").spec.template.spec.containers[0].env.find(({ name }) => name === "ZASP_EXPECTED_SCHEMA_VERSION").value, "13");
  assert.equal(one(resources, "Deployment", "agentsec-api").spec.template.spec.containers[0].env.find(({ name }) => name === "ZASP_DATABASE_AUTHORITY").value, "zasp_discovery_api");
  assert.equal(one(resources, "SecretProviderClass", release.secretProviderClass).spec.secretObjects[0].data.length, 7);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-migration-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-worker-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-scheduler-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-canary-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(one(resources, "ServiceAccount", "agentsec-api").metadata.annotations["eks.amazonaws.com/role-arn"], "arn:aws:iam::123456789012:role/zasp-production-api");
  assert.equal(one(resources, "ServiceAccount", "agentsec-migration").metadata.annotations["eks.amazonaws.com/role-arn"], "arn:aws:iam::123456789012:role/zasp-production-migration");
  assert.equal(one(resources, "ServiceAccount", "zasp-discovery-worker").metadata.annotations["eks.amazonaws.com/role-arn"], "arn:aws:iam::123456789012:role/zasp-production-worker");
  assert.equal(one(resources, "ServiceAccount", "zasp-discovery-scheduler").metadata.annotations["eks.amazonaws.com/role-arn"], "arn:aws:iam::123456789012:role/zasp-production-discovery-scheduler");
  const rendered = JSON.stringify(resources);
  assert.match(rendered, /zasp\/production\/postgres-api-dsn/);
  assert.match(rendered, /zasp\/production\/postgres-worker-dsn/);
  assert.match(rendered, /zasp\/production\/postgres-scheduler-dsn/);
  assert.match(rendered, /zasp\/production\/postgres-migration-dsn/);
  assert.doesNotMatch(rendered, /zasp\/production\/postgres-dsn"/);
  for (const name of ["agentsec-web", "agentsec-canary"]) {
    assert.equal(one(resources, "ServiceAccount", name).metadata.annotations?.["eks.amazonaws.com/role-arn"], undefined);
  }
});

test("release applies non-root rollout, zone and host spread, drain, PDB, and default-deny policies", async () => {
  const resources = await renderRelease(release);
  assert.deepEqual(resources.filter(({ kind }) => kind === "Deployment").map(({ metadata }) => metadata.name).sort(), ["agentsec-api", "agentsec-discovery-scheduler", "agentsec-outbox-publisher", "agentsec-projection-search", "web"]);
  assert.deepEqual(resources.filter(({ kind }) => kind === "Service").map(({ metadata }) => metadata.name).sort(), ["agentsec-api", "web"]);
  for (const name of ["web", "agentsec-api", "agentsec-discovery-scheduler", "agentsec-outbox-publisher", "agentsec-projection-search"]) {
    const deployment = one(resources, "Deployment", name);
    assert.deepEqual(deployment.spec.strategy.rollingUpdate, { maxSurge: 1, maxUnavailable: 0 });
    assert.equal(deployment.spec.template.spec.securityContext.seccompProfile.type, "RuntimeDefault");
    assert.equal(deployment.spec.template.spec.containers[0].securityContext.runAsUser, 65532);
    assert.equal(deployment.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem, true);
    assert.equal(deployment.spec.template.spec.containers[0].lifecycle.preStop.exec.command.at(-1), "sleep 10");
	if (name !== "web") {
	  const shutdown = deployment.spec.template.spec.containers[0].env.find(({ name: key }) => key === "ZASP_SHUTDOWN_TIMEOUT");
	  assert.equal(shutdown.value, "15s");
	  assert.ok(10 + Number.parseInt(shutdown.value, 10) + 5 <= deployment.spec.template.spec.terminationGracePeriodSeconds);
	}
    assert.deepEqual(deployment.spec.template.spec.topologySpreadConstraints.map(({ topologyKey }) => topologyKey), ["topology.kubernetes.io/zone", "kubernetes.io/hostname"]);
    assert.equal(one(resources, "PodDisruptionBudget", name).spec.minAvailable, 1);
  }
  const policies = resources.filter(({ kind }) => kind === "NetworkPolicy");
  assert.ok(policies.some(({ metadata }) => metadata.name === "default-deny"));
  assert.ok(policies.some(({ metadata }) => metadata.name === "web-from-ingress"));
  assert.ok(policies.some(({ metadata }) => metadata.name === "api-from-ingress"));
  assert.ok(policies.some(({ metadata }) => metadata.name === "internal-monitoring"));
  const scheduler = one(resources, "Deployment", "agentsec-discovery-scheduler");
  const schedulerEnv = Object.fromEntries(scheduler.spec.template.spec.containers[0].env.map(({ name, value }) => [name, value]));
  assert.equal(schedulerEnv.ZASP_WORKER_MODE, "scheduler");
  assert.equal(schedulerEnv.ZASP_DATABASE_AUTHORITY, "zasp_discovery_scheduler");
  assert.equal(schedulerEnv.ZASP_DISCOVERY_PARSER_VERSION, release.discovery.parserVersion);
  assert.equal(schedulerEnv.ZASP_DISCOVERY_TOOL_VERSION, release.discovery.toolVersion);
  assert.equal(scheduler.spec.template.spec.containers[0].env.find(({ name }) => name === "ZASP_WORKER_ID").valueFrom.fieldRef.fieldPath, "metadata.name");
  assert.doesNotMatch(JSON.stringify(scheduler), /ZASP_DISCOVERY_QUEUE_URL|ZASP_OPENSEARCH_ENDPOINT|ZASP_NEO4J_URI|ZASP_CONNECTOR_/);
  const search = one(resources, "Deployment", "agentsec-projection-search");
  const searchEnv = Object.fromEntries(search.spec.template.spec.containers[0].env.map(({ name, value }) => [name, value]));
  assert.deepEqual(Object.fromEntries(Object.entries(searchEnv).filter(([name]) => name !== "ZASP_WORKER_ID")), {
    ZASP_WORKER_MODE: "projection-search", ZASP_DATABASE_AUTHORITY: "zasp_projection_search_worker", ZASP_POLL_INTERVAL: "1s", ZASP_LEASE_DURATION: "30s", ZASP_BATCH_SIZE: "8", ZASP_SHUTDOWN_TIMEOUT: "15s",
    ZASP_AWS_REGION: release.projectionSearch.awsRegion, ZASP_PROJECTION_ROLE_ARN: release.projectionSearch.roleArn, ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE: release.projectionSearch.webIdentityTokenFile,
    ZASP_OPENSEARCH_ENDPOINT: release.projectionSearch.endpoint, ZASP_OPENSEARCH_INDEX: release.projectionSearch.index,
  });
  assert.equal(search.spec.template.spec.serviceAccountName, "zasp-projection-search");
  assert.equal(one(resources, "ServiceAccount", "zasp-projection-search").metadata.annotations["eks.amazonaws.com/role-arn"], release.projectionSearch.roleArn);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-projection-search-secrets").spec.secretObjects[0].data.length, 1);
  assert.doesNotMatch(JSON.stringify(search), /ZASP_NEO4J|ZASP_CONNECTOR_|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/);
  assert.equal(JSON.stringify(resources).includes("event-ingest"), false);
  assert.equal(JSON.stringify(resources).includes("runtime-gateway"), false);
  assert.equal(JSON.stringify(resources).includes("4317"), false);
});

test("release isolates the discovery outbox publisher behind exact DB, queue, and web-identity authority", async () => {
  const resources = await renderRelease(release);
  const deployment = one(resources, "Deployment", "agentsec-outbox-publisher");
  const pod = deployment.spec.template.spec;
  const container = pod.containers[0];
  const env = Object.fromEntries(container.env.map(({ name, value }) => [name, value]));
  assert.deepEqual(Object.fromEntries(Object.entries(env).filter(([name]) => name !== "ZASP_WORKER_ID")), {
    ZASP_WORKER_MODE: "outbox", ZASP_DATABASE_AUTHORITY: "zasp_outbox_worker", ZASP_POLL_INTERVAL: "1s", ZASP_LEASE_DURATION: "30s", ZASP_BATCH_SIZE: "10", ZASP_SHUTDOWN_TIMEOUT: "15s",
    ZASP_DISCOVERY_QUEUE_URL: release.outbox.queueURL, ZASP_AWS_REGION: release.outbox.awsRegion, ZASP_OUTBOX_ROLE_ARN: release.outbox.roleArn, ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE: release.outbox.webIdentityTokenFile,
  });
  assert.equal(pod.serviceAccountName, "zasp-outbox-publisher");
  assert.equal(one(resources, "ServiceAccount", "zasp-outbox-publisher").metadata.annotations["eks.amazonaws.com/role-arn"], release.outbox.roleArn);
  assert.equal(one(resources, "SecretProviderClass", "zasp-production-outbox-secrets").spec.secretObjects[0].data.length, 1);
  assert.equal(container.env.find(({ name }) => name === "ZASP_WORKER_ID").valueFrom.fieldRef.fieldPath, "metadata.name");
  assert.equal(pod.automountServiceAccountToken, false);
  assert.deepEqual(container.volumeMounts.find(({ name }) => name === "outbox-web-identity"), { name: "outbox-web-identity", mountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount", readOnly: true });
  assert.deepEqual(one(resources, "NetworkPolicy", "outbox-dependencies").spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr)).sort(), ["10.30.0.0/24", ...release.outbox.egressCIDRs].sort());
  assert.doesNotMatch(JSON.stringify(deployment), /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|ZASP_PROJECTION_|ZASP_CONNECTOR_/);
});

test("release gives only API an explicit connector identity, reference-only config, and bounded provider egress", async () => {
  const resources = await renderRelease(release);
  const api = one(resources, "Deployment", "agentsec-api");
  const pod = api.spec.template.spec;
  const container = pod.containers[0];
  const env = Object.fromEntries(container.env.map(({ name, value }) => [name, value]));
  assert.deepEqual(Object.fromEntries(Object.entries(env).filter(([name]) => name.startsWith("ZASP_CONNECTOR_") || name.startsWith("ZASP_GITHUB_") || name.startsWith("ZASP_OKTA_") || name === "ZASP_AWS_CUSTOMER_ROLE_PREFIXES" || name === "ZASP_AWS_CUSTOMER_ROLE_ARNS" || name === "ZASP_KUBERNETES_EGRESS_CIDRS")), {
    ZASP_CONNECTOR_AWS_REGION: release.connectors.awsRegion,
    ZASP_CONNECTOR_ROLE_ARN: release.connectors.roleArn,
    ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE: release.connectors.webIdentityTokenFile,
    ZASP_CONNECTOR_KMS_KEY_ARN: release.connectors.kmsKeyArn,
    ZASP_CONNECTOR_SECRET_PREFIX: release.connectors.secretPrefix,
    ZASP_AWS_CUSTOMER_ROLE_PREFIXES: JSON.stringify(release.connectors.awsCustomerRolePrefixes),
    ZASP_AWS_CUSTOMER_ROLE_ARNS: JSON.stringify(release.connectors.awsCustomerRoleARNs),
    ZASP_KUBERNETES_EGRESS_CIDRS: release.connectorEgressCIDRs.kubernetes.join(","),
    ZASP_GITHUB_CLIENT_ID: release.connectors.githubClientID,
    ZASP_GITHUB_CLIENT_SECRET_REFERENCE: release.connectors.githubClientSecretReference,
    ZASP_GITHUB_APP_ID: release.connectors.githubAppID,
    ZASP_GITHUB_PRIVATE_KEY_REFERENCE: release.connectors.githubPrivateKeyReference,
    ZASP_OKTA_CLIENT_ID: release.connectors.oktaClientID,
    ZASP_OKTA_CLIENT_SECRET_REFERENCE: release.connectors.oktaClientSecretReference,
  });
  for (const ambient of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_REGION"]) assert.equal(Object.hasOwn(env, ambient), false, ambient);
  assert.equal(pod.automountServiceAccountToken, false);
  assert.deepEqual(container.volumeMounts.find(({ name }) => name === "connector-web-identity"), {
    name: "connector-web-identity",
    mountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount",
    readOnly: true,
  });
  assert.deepEqual(pod.volumes.find(({ name }) => name === "connector-web-identity"), {
    name: "connector-web-identity",
    projected: {
      defaultMode: 256,
      sources: [{ serviceAccountToken: { audience: "sts.amazonaws.com", expirationSeconds: 900, path: "token" } }],
    },
  });
  for (const account of resources.filter(({ kind }) => kind === "ServiceAccount")) {
    assert.doesNotMatch(JSON.stringify(account.metadata.annotations ?? {}), new RegExp(release.connectors.roleArn.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), account.metadata.name);
  }
  for (const workload of resources.filter(({ kind }) => ["Deployment", "Job", "CronJob"].includes(kind))) {
    if (workload.metadata.name === "agentsec-api") continue;
    assert.doesNotMatch(JSON.stringify(workload), /connector-web-identity|ZASP_CONNECTOR_|ZASP_GITHUB_|ZASP_OKTA_/, workload.metadata.name);
  }

  const connectorEgress = one(resources, "NetworkPolicy", "api-connector-egress");
  assert.deepEqual(connectorEgress.spec.podSelector.matchLabels, { "app.kubernetes.io/name": "agentsec-api" });
  assert.equal(connectorEgress.metadata.annotations["zasp.io/network-policy-boundary"], "native-cidr-snapshot");
  assert.deepEqual(connectorEgress.spec.egress.flatMap(({ to }) => to.map(({ ipBlock }) => ipBlock.cidr)).sort(), [
    ...release.connectorEgressCIDRs.aws,
    ...release.connectorEgressCIDRs.github,
    ...release.connectorEgressCIDRs.okta,
    ...release.connectorEgressCIDRs.kubernetes,
  ].sort());
  assert.ok(connectorEgress.spec.egress.every(({ ports }) => JSON.stringify(ports) === JSON.stringify([{ protocol: "TCP", port: 443 }])));
  assert.doesNotMatch(JSON.stringify(connectorEgress), /0\.0\.0\.0\/0|::\/0/);

  const rendered = JSON.stringify(resources);
  assert.doesNotMatch(rendered, /kind":"(?:Deployment|Service|Ingress)"[^}]*"name":"nango"/);
  assert.doesNotMatch(rendered, /ZASP_NANGO_|NANGO_SECRET|nango.*ready/i);
  assert.doesNotMatch(rendered, /github-client-secret-value|okta-client-secret-value/);
  assert.equal(one(resources, "SecretProviderClass", release.secretProviderClass).spec.secretObjects[0].data.length, 7);
});

test("release renders read-only synthetic and exact SLO budgets without credential values", async () => {
  const resources = await renderRelease(release);
  const canary = one(resources, "CronJob", "production-readonly-canary");
  assert.equal(canary.spec.concurrencyPolicy, "Forbid");
  assert.equal(canary.spec.jobTemplate.spec.activeDeadlineSeconds, 60);
  const container = canary.spec.jobTemplate.spec.template.spec.containers[0];
  assert.equal(canary.spec.jobTemplate.spec.template.spec.serviceAccountName, "agentsec-canary");
  assert.match(container.args[0], /\/sign-in/);
  assert.match(container.args[0], /\/api\/v1\/home\/summary/);
  assert.deepEqual(container.env[1].valueFrom.secretKeyRef, { name: "zasp-canary-secrets", key: "ZASP_CANARY_READ_TOKEN" });
  assert.doesNotMatch(JSON.stringify(canary), /Bearer [A-Za-z0-9_-]{16}/);
  const monitor = one(resources, "ServiceMonitor", "agentsec-api");
  assert.deepEqual(monitor.spec.endpoints, [{ interval: "30s", path: "/metrics", port: "internal", scrapeTimeout: "5s" }]);
  const rules = one(resources, "PrometheusRule", "zasp-production-slos");
  const rendered = JSON.stringify(rules);
  for (const budget of ["0.01", "0.5", "ZaspAPIErrorBudgetBurn", "ZaspAPIReadLatencyBudget", "ZaspAPIMutationLatencyBudget", "ZaspWebUnavailable", "ZaspAPIUnavailable"]) assert.match(rendered, new RegExp(budget));
  assert.match(rendered, /zasp_http_slo_request_duration_seconds_bucket/);
  assert.doesNotMatch(rendered, /http_server_request_duration_seconds_bucket/);
  const errorBudget = rules.spec.groups.flatMap(({ rules: groupRules }) => groupRules).find(({ alert }) => alert === "ZaspAPIErrorBudgetBurn");
  assert.match(errorBudget.expr, /zasp_http_slo_requests_total/);
  assert.doesNotMatch(errorBudget.expr, /clamp_min/);
  assert.match(errorBudget.expr, /sum\(rate\(zasp_http_slo_requests_total\[5m\]\)\) > 0/);
  for (const [alert, workload] of [["ZaspWebUnavailable", "web"], ["ZaspAPIUnavailable", "agentsec-api"]]) {
    const availability = rules.spec.groups.flatMap(({ rules: groupRules }) => groupRules).find((rule) => rule.alert === alert);
    assert.match(availability.expr, new RegExp(`deployment="${workload}"`));
    assert.match(availability.expr, /absent\(/);
  }
});

test("release rejects unpinned images and hostile public identifiers", async () => {
  await assert.doesNotReject(() => renderRelease({ ...release, connectors: { ...release.connectors, kmsKeyArn: "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab" } }));
  await assert.rejects(() => renderRelease({ ...release, host: "app.zasp.example\nmalicious: true" }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, images: { ...release.images, web: "zasp/web:latest" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, discovery: { ...release.discovery, parserVersion: "parser-v1" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, tlsSecretName: "" }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, roleArn: "arn:aws:iam::123456789012:role/zasp-production-api" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, webIdentityTokenFile: "/tmp/token" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, githubClientSecretReference: "raw-secret" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, awsCustomerRolePrefixes: ["arn:aws:iam::123456789012:role/*"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, awsCustomerRolePrefixes: [release.connectors.awsCustomerRolePrefixes[0], release.connectors.awsCustomerRolePrefixes[0]] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, awsCustomerRoleARNs: ["arn:aws:iam::333333333333:role/zasp-reference/unprovisioned"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectors: { ...release.connectors, awsCustomerRolePrefixes: Array.from({ length: 65 }, (_, index) => `arn:aws:iam::${String(index + 1).padStart(12, "0")}:role/zasp-reference/`) } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectorEgressCIDRs: { ...release.connectorEgressCIDRs, github: ["0.0.0.0/0"] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectorEgressCIDRs: { ...release.connectorEgressCIDRs, okta: [] } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, connectorEgressCIDRs: { ...release.connectorEgressCIDRs, kubernetes: [] } }), /release rejected/);
});

test("terraform binds each shipped secret consumer to one exact least-privilege IRSA role", async () => {
  const terraform = await readFile(new URL("../staging/main.tf", import.meta.url), "utf8");
  assert.doesNotMatch(terraform, /aws_iam_role"\s+"product"|system:serviceaccount:agentsec:agentsec-product/);
  assert.doesNotMatch(terraform, /Principal\s*=\s*\{\s*AWS\s*=\s*aws_iam_role\.api\.arn/);
  for (const [role, account, secret] of [
    ["api", "agentsec-api", "api_secret_names"],
    ["worker", "zasp-discovery-worker", "postgres-worker-dsn"],
    ["scheduler", "zasp-discovery-scheduler", "postgres-scheduler-dsn"],
    ["outbox", "zasp-outbox-publisher", "postgres-outbox-worker-dsn"],
    ["projection_search", "zasp-projection-search", "postgres-projection-search-dsn"],
    ["migration", "agentsec-migration", "postgres-migration-dsn"],
    ["canary_secret_sync", "agentsec-canary-secret-sync", "canary-read-token"],
  ]) {
    assert.match(terraform, new RegExp(`resource "aws_iam_role" "${role}"`));
    assert.match(terraform, new RegExp(`system:serviceaccount:agentsec:${account}`));
    assert.match(terraform, new RegExp(secret));
  }
  for (const policy of ["api", "worker", "scheduler", "migration", "canary_secret_sync"]) {
    const block = terraform.slice(terraform.indexOf(`resource "aws_iam_role_policy" "${policy}"`));
    assert.match(block.slice(0, block.indexOf("\n}\n") + 3), /secretsmanager:DescribeSecret.*secretsmanager:GetSecretValue/s);
    assert.doesNotMatch(block.slice(0, block.indexOf("\n}\n") + 3), /s3:|sqs:|es:|kms:Encrypt|kms:GenerateDataKey/);
  }
  const projectionPolicyStart = terraform.indexOf('resource "aws_iam_role_policy" "projection_search"');
  const projectionPolicy = terraform.slice(projectionPolicyStart, terraform.indexOf("\nresource ", projectionPolicyStart + 1));
  assert.match(projectionPolicy, /secretsmanager:DescribeSecret.*secretsmanager:GetSecretValue/s);
  assert.match(projectionPolicy, /es:ESHttpGet.*es:ESHttpPost.*es:ESHttpPut/s);
  assert.match(projectionPolicy, /aws_opensearch_domain\.events\.arn/);
  assert.doesNotMatch(projectionPolicy, /es:\*|Resource\s*=\s*"\*"|s3:|sqs:/);
  const outboxPolicyStart = terraform.indexOf('resource "aws_iam_role_policy" "outbox"');
  const outboxPolicy = terraform.slice(outboxPolicyStart, terraform.indexOf("\nresource ", outboxPolicyStart + 1));
  assert.match(outboxPolicy, /sqs:SendMessage/);
  assert.match(outboxPolicy, /aws_sqs_queue\.work\["discovery-jobs"\]\.arn/);
  assert.match(outboxPolicy, /kms:ViaService[\s\S]*sqs\.\$\{var\.region\}\.amazonaws\.com/);
  assert.doesNotMatch(outboxPolicy, /sqs:\*|Resource\s*=\s*"\*"|sqs:ReceiveMessage|sqs:DeleteMessage/);
  const apiSecrets = terraform.slice(terraform.indexOf("api_secret_names"), terraform.indexOf("queue_contract"));
  assert.match(apiSecrets, /postgres-api-dsn/);
  assert.doesNotMatch(apiSecrets, /postgres-worker-dsn|postgres-migration-dsn/);
  assert.match(terraform, /database_principals\s*=\s*\{/);
  for (const principal of ["migration", "api", "discovery_worker", "runtime_ingest", "runtime_worker", "outbox_worker", "runtime_gateway", "discovery_scheduler", "projection_risk", "projection_graph", "projection_search"]) {
    assert.match(terraform, new RegExp(`${principal}\\s*=\\s*var\\.database_principals`));
  }
  assert.match(terraform, /DatabasePrincipal/);
});

test("terraform isolates connector mutation and reference authorization behind one API-only web-identity role", async () => {
  const [terraform, variables, outputs] = await Promise.all([
    readFile(new URL("../staging/main.tf", import.meta.url), "utf8"),
    readFile(new URL("../staging/variables.tf", import.meta.url), "utf8"),
    readFile(new URL("../staging/outputs.tf", import.meta.url), "utf8"),
  ]);
  for (const resource of [
    'resource "aws_kms_key" "connector_oauth"',
    'resource "aws_kms_alias" "connector_oauth"',
    'resource "aws_secretsmanager_secret" "connector_provider"',
    'resource "aws_secretsmanager_secret" "connector_reference"',
    'resource "aws_iam_role" "api_connectors"',
    'resource "aws_iam_role_policy" "api_connectors"',
  ]) assert.match(terraform, new RegExp(resource.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  for (const [key, suffix, credentialClass] of [
    ["github_client_secret", "github/client-secret", "github_oauth_client_secret"],
    ["github_app_private_key", "github/app-private-key", "github_app_private_key"],
    ["okta_client_secret", "okta/client-secret", "okta_oauth_client_secret"],
  ]) {
    assert.match(terraform, new RegExp(`${key}\\s*=\\s*\\{[\\s\\S]*?name\\s*=\\s*"\\$\\{local\\.connector_secret_root\\}/${suffix}"[\\s\\S]*?credential_class\\s*=\\s*"${credentialClass}"`));
  }
  assert.match(terraform, /tags\s*=\s*\{ CredentialClass = each\.value\.credential_class \}/);
  const role = terraform.slice(terraform.indexOf('resource "aws_iam_role" "api_connectors"'), terraform.indexOf('resource "aws_iam_role_policy" "api_connectors"'));
  assert.match(role, /system:serviceaccount:agentsec:agentsec-api/);
  assert.match(role, /sts:AssumeRoleWithWebIdentity/);
  const policyStart = terraform.indexOf('resource "aws_iam_role_policy" "api_connectors"');
  const policy = terraform.slice(policyStart, terraform.indexOf("\nresource ", policyStart + 1));
  const actions = [...policy.matchAll(/Action\s*=\s*\[([\s\S]*?)\]/g)].flatMap(([, list]) => [...list.matchAll(/"([^"]+)"/g)].map(([, action]) => action)).sort();
  assert.deepEqual(actions, ["kms:Decrypt", "kms:Decrypt", "kms:GenerateDataKey", "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue", "secretsmanager:GetSecretValue", "secretsmanager:GetSecretValue", "sts:AssumeRole"].sort());
  assert.match(policy, /Action\s*=\s*\["secretsmanager:GetSecretValue"\][\s\S]*?Resource\s*=\s*\[for secret in aws_secretsmanager_secret\.connector_provider : secret\.arn\]/);
  assert.doesNotMatch(policy, /secret:\$\{local\.connector_secret_root\}\/github\/\*/);
  assert.doesNotMatch(policy, /secret:\$\{local\.connector_secret_root\}\/okta\/\*/);
  assert.match(policy, /Action\s*=\s*\["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"\][\s\S]*?Resource\s*=\s*\[for secret in aws_secretsmanager_secret\.connector_reference : secret\.arn\]/);
  assert.match(policy, /Action\s*=\s*\["sts:AssumeRole"\][\s\S]*?Resource\s*=\s*var\.aws_reference_role_arns/);
  assert.match(policy, /kms:EncryptionContext:SecretARN/);
  for (const namespace of [
    "secret:${local.connector_secret_prefix}/*",
    "secret:${local.connector_secret_root}/github/effect-manifest/*",
    "secret:${local.connector_secret_root}/github/effect-outcome/*",
    "secret:${local.connector_secret_root}/github/revoked-installation/*",
    "secret:${local.connector_secret_root}/okta/effect-manifest/*",
    "secret:${local.connector_secret_root}/okta/effect-access/*",
    "secret:${local.connector_secret_root}/okta/effect-outcome/*",
    "secret:${local.connector_secret_root}/okta/refresh/*",
    "secret:${local.connector_secret_root}/okta/revoked-refresh/*",
  ]) assert.match(policy, new RegExp(namespace.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(policy, /aws_kms_key\.connector_oauth\.arn/);
  assert.match(terraform, /connector_secret_root\s*=\s*"\$\{var\.cluster_name\}\/connectors"/);
  assert.match(terraform, /connector_secret_prefix\s*=\s*"\$\{local\.connector_secret_root\}\/oauth"/);
  for (const name of ["api", "worker", "migration", "canary_secret_sync"]) {
    const start = terraform.indexOf(`resource "aws_iam_role_policy" "${name}"`);
    const block = terraform.slice(start, terraform.indexOf("\nresource ", start + 1));
    assert.doesNotMatch(block, /aws_kms_key\.connector_oauth\.arn|connector_secret_prefix|connector_secret_root/, name);
  }
  assert.match(variables, /variable "connector_client_ids"/);
  assert.match(variables, /variable "aws_reference_role_prefixes"/);
  assert.match(variables, /variable "aws_reference_role_arns"/);
  assert.match(variables, /variable "connector_reference_ids"/);
  assert.match(outputs, /output "connector_role_arn"/);
  assert.match(outputs, /output "connector_kms_key_arn"/);
  assert.match(outputs, /output "connector_secret_prefix"/);
  assert.match(outputs, /output "connector_runtime_config"/);
  for (const name of ["ZASP_CONNECTOR_AWS_REGION", "ZASP_CONNECTOR_ROLE_ARN", "ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE", "ZASP_CONNECTOR_KMS_KEY_ARN", "ZASP_CONNECTOR_SECRET_PREFIX", "ZASP_AWS_CUSTOMER_ROLE_PREFIXES", "ZASP_AWS_CUSTOMER_ROLE_ARNS", "ZASP_KUBERNETES_EGRESS_CIDRS", "ZASP_GITHUB_CLIENT_ID", "ZASP_GITHUB_CLIENT_SECRET_REFERENCE", "ZASP_GITHUB_APP_ID", "ZASP_GITHUB_PRIVATE_KEY_REFERENCE", "ZASP_OKTA_CLIENT_ID", "ZASP_OKTA_CLIENT_SECRET_REFERENCE"]) assert.match(outputs, new RegExp(name));
  assert.doesNotMatch(terraform, /aws_secretsmanager_secret_version|secret_string|secret_binary/i);
});

function one(resources, kind, name) {
  const found = resources.filter((resource) => resource.kind === kind && resource.metadata?.name === name);
  assert.equal(found.length, 1, `${kind}/${name} count`);
  return found[0];
}
