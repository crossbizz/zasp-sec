import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  BUSYBOX_IMAGE,
  COLLECTOR_IMAGE,
  OBSERVABILITY_CONSTANTS,
  buildObservabilityCoreResources,
  buildObservabilityResources,
  buildObservabilitySpanResources,
  buildSyntheticObservabilitySpan,
  parseObservabilityManifest,
  parseObservabilitySink,
  renderObservabilityCoreManifest,
  renderObservabilitySpanManifest,
  validateObservabilityResources,
} from "./observability-manifest.mjs";

const collectorImage = "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5";
const busyboxImage = "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9";

function clone(value) {
  return structuredClone(value);
}

test("builds the exact split observability resources and committed bytes", async () => {
  assert.equal(COLLECTOR_IMAGE, collectorImage);
  assert.equal(BUSYBOX_IMAGE, busyboxImage);
  assert.deepEqual(OBSERVABILITY_CONSTANTS, {
    namespace: "zasp-local",
    collectorName: "otel-collector",
    configName: "otel-collector-config",
    spanJobName: "otel-test-span",
    sinkPath: "/sink/traces.json",
    sinkByteLimit: 65_536,
  });

  const all = buildObservabilityResources();
  const core = buildObservabilityCoreResources();
  const span = buildObservabilitySpanResources();
  assert.deepEqual(all.map(({ kind }) => kind), ["ConfigMap", "Deployment", "Service", "Job"]);
  assert.deepEqual(core, all.slice(0, 3));
  assert.deepEqual(span, all.slice(3));
  assert.ok(Object.isFrozen(all));
  assert.throws(() => buildObservabilityResources("caller-input"), TypeError);
  assert.throws(() => buildObservabilityCoreResources({}), TypeError);
  assert.throws(() => buildObservabilitySpanResources([]), TypeError);

  const [coreText, spanText] = await Promise.all([
    readFile(new URL("./observability.yaml", import.meta.url), "utf8"),
    readFile(new URL("./observability-span.yaml", import.meta.url), "utf8"),
  ]);
  assert.equal(renderObservabilityCoreManifest(core), coreText);
  assert.equal(renderObservabilitySpanManifest(span), spanText);
  assert.deepEqual(parseObservabilityManifest(coreText, "core"), core);
  assert.deepEqual(parseObservabilityManifest(spanText, "span"), span);
  assert.throws(() => parseObservabilityManifest(coreText, "span"), TypeError);
  assert.throws(() => parseObservabilityManifest(spanText, "core"), TypeError);
  assert.deepEqual(validateObservabilityResources(all), all);
});

test("pins the local-only collector pipeline and one-shot span job", () => {
  const [config, deployment, service, job] = buildObservabilityResources();
  assert.deepEqual(Object.keys(config.data), ["config.yaml", "span.json", "response.json"]);
  assert.equal(config.data["span.json"], `${JSON.stringify(buildSyntheticObservabilitySpan())}\n`);
  assert.equal(config.data["response.json"], "{\"partialSuccess\":{}}");

  const collectorConfiguration = config.data["config.yaml"];
  for (const required of [
    "endpoint: 0.0.0.0:4318",
    "endpoint: 0.0.0.0:13133",
    "memory_limiter:",
    "send_batch_size: 1",
    "send_batch_max_size: 1",
    "path: /sink/traces.json",
    "format: json",
    "level: error",
    "level: none",
    "exporters: [file]",
  ]) assert.match(collectorConfiguration, new RegExp(required.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  for (const prohibited of ["otlphttp", "kafka", "authorization", "credential", "${env:", "proxy", "backend", "https://"]) {
    assert.doesNotMatch(collectorConfiguration.toLowerCase(), new RegExp(prohibited.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  }

  assert.equal(deployment.spec.template.spec.hostNetwork, false);
  assert.equal(deployment.spec.template.spec.hostPID, false);
  assert.equal(deployment.spec.template.spec.hostIPC, false);
  assert.equal(deployment.spec.template.spec.automountServiceAccountToken, false);
  assert.equal(deployment.spec.template.spec.containers.length, 2);
  assert.deepEqual(deployment.spec.template.spec.containers.map(({ image }) => image), [collectorImage, busyboxImage]);
  for (const container of deployment.spec.template.spec.containers) {
    assert.equal(container.securityContext.allowPrivilegeEscalation, false);
    assert.equal(container.securityContext.privileged, false);
    assert.equal(container.securityContext.readOnlyRootFilesystem, true);
    assert.deepEqual(container.securityContext.capabilities, { drop: ["ALL"] });
  }

  assert.equal(service.spec.type, "ClusterIP");
  assert.equal(service.spec.ports.length, 1);
  assert.equal(service.spec.ports[0].port, 4318);
  assert.equal("nodePort" in service.spec.ports[0], false);
  assert.equal("externalIPs" in service.spec, false);

  assert.equal(job.spec.activeDeadlineSeconds, 30);
  assert.equal(job.spec.backoffLimit, 0);
  assert.equal(job.spec.parallelism, 1);
  assert.equal(job.spec.completions, 1);
  assert.equal(job.spec.podReplacementPolicy, "Failed");
  assert.equal(job.spec.template.spec.restartPolicy, "Never");
  const command = job.spec.template.spec.containers[0].command.join(" ");
  assert.match(command, /wget -q -t 1 -T 5/u);
  assert.equal((command.match(/\/v1\/traces/gu) ?? []).length, 1);
  assert.doesNotMatch(command, /until|while|retry/u);
});

test("binds one exact M1-21 resource and one exact synthetic span", () => {
  const request = buildSyntheticObservabilitySpan();
  const resourceSpans = request.resourceSpans;
  assert.equal(resourceSpans.length, 1);
  const attributes = resourceSpans[0].resource.attributes;
  assert.deepEqual(attributes, [
    { key: "service.namespace", value: { stringValue: "agentsec" } },
    { key: "service.name", value: { stringValue: "agentsec-api" } },
    { key: "service.version", value: { stringValue: "m1-30c" } },
    { key: "deployment.environment.name", value: { stringValue: "development" } },
    { key: "organization.id", value: { stringValue: "pid_10000000-0000-4000-8000-000000000001" } },
    { key: "workspace.id", value: { stringValue: "pid_20000000-0000-4000-8000-000000000002" } },
    { key: "environment.id", value: { stringValue: "pid_30000000-0000-4000-8000-000000000003" } },
  ]);
  const scopeSpans = resourceSpans[0].scopeSpans;
  assert.equal(scopeSpans.length, 1);
  assert.deepEqual(scopeSpans[0].scope, { name: "zasp.m1-30c.proof", version: "1.0.0" });
  assert.deepEqual(scopeSpans[0].spans, [{
    traceId: "10000000000040008000000000000001",
    spanId: "2000000000000001",
    name: "m1-30c-local-observability",
    kind: 3,
    startTimeUnixNano: "1786932000000000000",
    endTimeUnixNano: "1786932001000000000",
    flags: 1,
    status: { code: 1 },
  }]);
  assert.ok(Object.isFrozen(request));
  assert.throws(() => buildSyntheticObservabilitySpan("caller-input"), TypeError);
});

test("rejects resource, controller, exposure, security, and parser drift", () => {
  const mutations = [
    (value) => { value.push(clone(value[0])); },
    (value) => { value.reverse(); },
    (value) => { value[0].metadata.labels.extra = "value"; },
    (value) => { value[1].spec.template.spec.hostNetwork = true; },
    (value) => { value[1].spec.template.spec.containers[0].env = [{ name: "HTTPS_PROXY", value: "https://example.invalid" }]; },
    (value) => { value[1].spec.template.spec.containers[0].ports[0].hostPort = 43_18; },
    (value) => { value[1].spec.template.spec.volumes.push({ hostPath: { path: "/tmp" }, name: "host" }); },
    (value) => { value[1].spec.template.spec.containers.push(clone(value[1].spec.template.spec.containers[0])); },
    (value) => { value[1].spec.template.spec.containers[0].image = "otel/opentelemetry-collector-contrib:latest"; },
    (value) => { value[1].spec.template.spec.containers[0].securityContext.privileged = true; },
    (value) => { value[1].spec.template.spec.containers[1].securityContext.readOnlyRootFilesystem = false; },
    (value) => { value[1].spec.template.spec.containers[0].securityContext.capabilities.add = ["NET_ADMIN"]; },
    (value) => { value[1].spec.template.spec.securityContext.seccompProfile.type = "Unconfined"; },
    (value) => { value[0].data["config.yaml"] = value[0].data["config.yaml"].replace("exporters: [file]", "exporters: [otlphttp]"); },
    (value) => { value[2].spec.type = "NodePort"; },
    (value) => { value[2].spec.ports[0].nodePort = 31_318; },
    (value) => { value[3].spec.backoffLimit = 1; },
    (value) => { delete value[3].spec.parallelism; },
    (value) => { value[3].spec.completions = 2; },
    (value) => { value[3].spec.podReplacementPolicy = "TerminatingOrFailed"; },
    (value) => { value[3].spec.template.spec.restartPolicy = "OnFailure"; },
    (value) => { value[0].data["span.json"] = value[0].data["span.json"].replace('"spans":[{', '"spans":[{}, {'); },
    (value) => { value[0].data["span.json"] = value[0].data["span.json"].replace("10000000000040008000000000000001", "invalid-trace"); },
    (value) => { value[0].data["span.json"] = value[0].data["span.json"].replace("1786932000000000000", "not-a-time"); },
  ];
  for (const mutate of mutations) {
    const value = clone(buildObservabilityResources());
    mutate(value);
    assert.throws(() => validateObservabilityResources(value), TypeError);
  }

  const core = renderObservabilityCoreManifest(buildObservabilityCoreResources());
  for (const invalid of [
    `${core}---\n{}\n`,
    core.replace("kind: List", "kind: List\nkind: List"),
    core.replace("apiVersion: v1", "apiVersion: &version v1").replace("kind: List", "kind: *version"),
    core.replace("type: ClusterIP", "type: LoadBalancer"),
    `${core}\n# noncanonical\n`,
  ]) assert.throws(() => parseObservabilityManifest(invalid, "core"), TypeError);
  assert.throws(() => parseObservabilityManifest(core, "mixed"), TypeError);
  assert.throws(() => parseObservabilityManifest({ toString() { throw new Error("coercion"); } }, "core"), TypeError);
});

test("rejects non-plain arrays and accessor-backed resource entries without invoking accessors", () => {
  class ForgedResources extends Array {}
  const root = new ForgedResources(...clone(buildObservabilityResources()));
  assert.throws(() => validateObservabilityResources(root), TypeError);

  const nested = clone(buildObservabilityResources());
  Object.setPrototypeOf(nested[1].spec.template.spec.containers, ForgedResources.prototype);
  assert.throws(() => validateObservabilityResources(nested), TypeError);

  let reads = 0;
  const accessor = clone(buildObservabilityResources());
  const first = accessor[0];
  Object.defineProperty(accessor, "0", {
    configurable: true,
    enumerable: true,
    get() { reads += 1; return first; },
  });
  assert.throws(() => validateObservabilityResources(accessor), TypeError);
  assert.equal(reads, 0);
});

test("parses only one bounded duplicate-safe exact sink record", () => {
  const bytes = Buffer.from(`${JSON.stringify(buildSyntheticObservabilitySpan())}\n`, "utf8");
  assert.deepEqual(parseObservabilitySink(bytes), buildSyntheticObservabilitySpan());
  assert.deepEqual(parseObservabilitySink(new Uint8Array(bytes)), buildSyntheticObservabilitySpan());
  for (const invalid of [
    Buffer.from("", "utf8"),
    Buffer.from("null\n", "utf8"),
    Buffer.from(`${JSON.stringify(buildSyntheticObservabilitySpan())}\n{}\n`, "utf8"),
    Buffer.from(JSON.stringify({ ...buildSyntheticObservabilitySpan(), extra: true }), "utf8"),
    Buffer.from('{"resourceSpans":[],"resourceSpans":[]}\n', "utf8"),
    Buffer.alloc(65_537, 0x20),
    new Uint8Array([0xff]),
  ]) assert.throws(() => parseObservabilitySink(invalid), TypeError);
  const multiple = clone(buildSyntheticObservabilitySpan());
  multiple.resourceSpans[0].scopeSpans[0].spans.push(clone(multiple.resourceSpans[0].scopeSpans[0].spans[0]));
  assert.throws(() => parseObservabilitySink(Buffer.from(`${JSON.stringify(multiple)}\n`, "utf8")), TypeError);
  for (const mutate of [
    (value) => { value.resourceSpans[0].scopeSpans[0].spans[0].traceId = "invalid"; },
    (value) => { value.resourceSpans[0].scopeSpans[0].spans[0].startTimeUnixNano = "not-a-time"; },
    (value) => { value.resourceSpans[0].resource.attributes.push({ key: "customer.data", value: { stringValue: "forged" } }); },
  ]) {
    const value = clone(buildSyntheticObservabilitySpan());
    mutate(value);
    assert.throws(() => parseObservabilitySink(Buffer.from(`${JSON.stringify(value)}\n`, "utf8")), TypeError);
  }
  class ForgedBytes extends Uint8Array {}
  assert.throws(() => parseObservabilitySink(new ForgedBytes(bytes)), TypeError);
  assert.throws(() => parseObservabilitySink({ toString() { throw new Error("coercion"); } }), TypeError);
});
