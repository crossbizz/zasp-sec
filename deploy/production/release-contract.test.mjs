import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { inspectContainerBuilds, renderRelease } from "./release-contract.mjs";

const digest = (name, value) => `registry.example/zasp/${name}@sha256:${value.repeat(64)}`;
const release = Object.freeze({
  host: "app.zasp.example",
  tlsSecretName: "zasp-product-tls",
  secretProviderClass: "zasp-production-secrets",
  images: Object.freeze({
    web: digest("web", "a"), agentsecApi: digest("api", "b"),
    agentsecWorker: digest("worker", "c"), eventIngest: digest("ingest", "d"),
    runtimeGateway: digest("gateway", "e"),
  }),
});

test("production container builds are exact, non-root, health-bound, and secret-free", async () => {
  const builds = await inspectContainerBuilds();
  assert.deepEqual(builds.map(({ name, user, port }) => ({ name, user, port })), [
    { name: "web", user: "65532:65532", port: 3000 },
    { name: "agentsec-api", user: "65532:65532", port: 8080 },
  ]);
  for (const build of builds) {
    assert.equal(build.readOnlyCompatible, true);
    assert.equal(build.containsSecret, false);
    assert.match(build.healthcheck, /127\.0\.0\.1/);
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
  assert.equal(one(resources, "Job", "agentsec-schema-v9").metadata.annotations["helm.sh/hook"], "pre-install,pre-upgrade");
  assert.deepEqual(one(resources, "Job", "agentsec-schema-v9").spec.template.spec.containers[0].args, ["up"]);
  assert.equal(one(resources, "SecretProviderClass", release.secretProviderClass).spec.provider, "aws");
  assert.equal(one(resources, "ServiceAccount", "agentsec-product").metadata.annotations["eks.amazonaws.com/role-arn"], "arn:aws:iam::123456789012:role/zasp-production-product");
  assert.equal(one(resources, "SecretProviderClass", release.secretProviderClass).spec.secretObjects[0].data.length, 8);
});

test("release applies non-root rollout, zone and host spread, drain, PDB, and default-deny policies", async () => {
  const resources = await renderRelease(release);
  for (const name of ["web", "agentsec-api", "agentsec-worker", "event-ingest", "runtime-gateway"]) {
    const deployment = one(resources, "Deployment", name);
    assert.deepEqual(deployment.spec.strategy.rollingUpdate, { maxSurge: 1, maxUnavailable: 0 });
    assert.equal(deployment.spec.template.spec.securityContext.seccompProfile.type, "RuntimeDefault");
    assert.equal(deployment.spec.template.spec.containers[0].securityContext.runAsUser, 65532);
    assert.equal(deployment.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem, true);
    assert.equal(deployment.spec.template.spec.containers[0].lifecycle.preStop.exec.command.at(-1), "sleep 10");
    assert.deepEqual(deployment.spec.template.spec.topologySpreadConstraints.map(({ topologyKey }) => topologyKey), ["topology.kubernetes.io/zone", "kubernetes.io/hostname"]);
    assert.equal(one(resources, "PodDisruptionBudget", name).spec.minAvailable, 1);
  }
  const policies = resources.filter(({ kind }) => kind === "NetworkPolicy");
  assert.ok(policies.some(({ metadata }) => metadata.name === "default-deny"));
  assert.ok(policies.some(({ metadata }) => metadata.name === "web-from-ingress"));
  assert.ok(policies.some(({ metadata }) => metadata.name === "api-from-ingress"));
  assert.ok(policies.some(({ metadata }) => metadata.name === "internal-monitoring"));
});

test("release renders read-only synthetic and exact SLO budgets without credential values", async () => {
  const resources = await renderRelease(release);
  const canary = one(resources, "CronJob", "production-readonly-canary");
  assert.equal(canary.spec.concurrencyPolicy, "Forbid");
  assert.equal(canary.spec.jobTemplate.spec.activeDeadlineSeconds, 60);
  const container = canary.spec.jobTemplate.spec.template.spec.containers[0];
  assert.match(container.args[0], /\/sign-in/);
  assert.match(container.args[0], /\/api\/v1\/home\/summary/);
  assert.deepEqual(container.env[1].valueFrom.secretKeyRef, { name: "zasp-runtime-secrets", key: "ZASP_CANARY_READ_TOKEN" });
  assert.doesNotMatch(JSON.stringify(canary), /Bearer [A-Za-z0-9_-]{16}/);
  const rules = one(resources, "PrometheusRule", "zasp-production-slos");
  const rendered = JSON.stringify(rules);
  for (const budget of ["0.01", "0.5", "ZaspAPIErrorBudgetBurn", "ZaspAPIReadLatencyBudget", "ZaspAPIMutationLatencyBudget", "ZaspWorkloadUnavailable"]) assert.match(rendered, new RegExp(budget));
});

test("release rejects unpinned images and hostile public identifiers", async () => {
  await assert.rejects(() => renderRelease({ ...release, host: "app.zasp.example\nmalicious: true" }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, images: { ...release.images, web: "zasp/web:latest" } }), /release rejected/);
  await assert.rejects(() => renderRelease({ ...release, tlsSecretName: "" }), /release rejected/);
});

function one(resources, kind, name) {
  const found = resources.filter((resource) => resource.kind === kind && resource.metadata?.name === name);
  assert.equal(found.length, 1, `${kind}/${name} count`);
  return found[0];
}
