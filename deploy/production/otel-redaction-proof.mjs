import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { dump, load } from "js-yaml";

import { renderRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";

const exec = promisify(execFile);
const proofError = "Collector redaction proof rejected";
const hostileValues = Object.freeze([
  "provider-response-hunter2",
  "status-secret-hunter2",
  "prompt-token-hunter2",
  "tool-argument-hunter2",
  "customer-acme-001",
  "token-hunter2",
  "resource-schema-secret-hunter2",
  "scope-name-secret-hunter2",
  "scope-version-secret-hunter2",
  "scope-schema-secret-hunter2",
  "scope-attribute-secret-hunter2",
  "trace-state-secret-hunter2",
  "link-attribute-secret-hunter2",
  "link-trace-state-secret-hunter2",
  "metric-name-secret-hunter2",
  "metric-description-secret-hunter2",
  "metric-unit-secret-hunter2",
  "metric-metadata-secret-hunter2",
  "datapoint-attribute-secret-hunter2",
  "exemplar-attribute-secret-hunter2",
  "log-event-secret-hunter2",
  "log-severity-secret-hunter2",
  "service-name-secret-hunter2",
  "service-namespace-secret-hunter2",
  "service-version-secret-hunter2",
  "deployment-secret-hunter2",
]);
const hostileResourceAttributes = Object.freeze([
  { key: "service.name", value: { stringValue: hostileValues[22] } },
  { key: "service.namespace", value: { stringValue: hostileValues[23] } },
  { key: "service.version", value: { stringValue: hostileValues[24] } },
  { key: "deployment.environment.name", value: { stringValue: hostileValues[25] } },
]);
const tracePayload = Object.freeze({
  resourceSpans: [{
    schemaUrl: hostileValues[6],
    resource: { attributes: [
      ...hostileResourceAttributes,
      { key: "customer.id", value: { stringValue: hostileValues[4] } },
    ] },
    scopeSpans: [{ schemaUrl: hostileValues[9], scope: { name: hostileValues[7], version: hostileValues[8], attributes: [{ key: "scope.value", value: { stringValue: hostileValues[10] } }] }, spans: [{
      traceId: "11111111111111111111111111111111",
      spanId: "2222222222222222",
      traceState: `proof=${hostileValues[11]}`,
      name: hostileValues[0],
      kind: 1,
      startTimeUnixNano: "1000000000",
      endTimeUnixNano: "2000000000",
      status: { message: hostileValues[1] },
      events: [{ timeUnixNano: "1500000000", name: hostileValues[2], attributes: [{ key: "event.value", value: { stringValue: hostileValues[3] } }] }],
      links: [{ traceId: "33333333333333333333333333333333", spanId: "4444444444444444", traceState: `proof=${hostileValues[13]}`, attributes: [{ key: "link.value", value: { stringValue: hostileValues[12] } }] }],
      attributes: [
        { key: "tool.arguments", value: { stringValue: hostileValues[3] } },
        { key: "token", value: { stringValue: hostileValues[5] } },
      ],
    }, {
      traceId: "77777777777777777777777777777777",
      spanId: "8888888888888888",
      traceState: `proof=${hostileValues[11]}`,
      name: hostileValues[0],
      kind: 1,
      startTimeUnixNano: "1000000000",
      endTimeUnixNano: "2000000000",
      status: { message: hostileValues[1] },
      events: [{ timeUnixNano: "1500000000", name: hostileValues[2], attributes: [{ key: "event.value", value: { stringValue: hostileValues[3] } }] }],
      attributes: [{ key: "token", value: { stringValue: hostileValues[5] } }],
    }] }],
  }],
});
const logPayload = Object.freeze({
  resourceLogs: [{
    schemaUrl: hostileValues[6],
    resource: { attributes: hostileResourceAttributes },
    scopeLogs: [{ schemaUrl: hostileValues[9], scope: { name: hostileValues[7], version: hostileValues[8], attributes: [{ key: "scope.value", value: { stringValue: hostileValues[10] } }] }, logRecords: [
      { timeUnixNano: "1000000000", eventName: hostileValues[20], severityText: hostileValues[21], body: { stringValue: hostileValues[0] }, attributes: [{ key: "token", value: { stringValue: hostileValues[5] } }] },
      { timeUnixNano: "2000000000", severityText: "INFO", body: { kvlistValue: { values: [{ key: "customer", value: { stringValue: hostileValues[4] } }] } } },
    ] }],
  }],
});
const metricPayload = Object.freeze({
  resourceMetrics: [{
    schemaUrl: hostileValues[6],
    resource: { attributes: hostileResourceAttributes },
    scopeMetrics: [{
      schemaUrl: hostileValues[9],
      scope: { name: hostileValues[7], version: hostileValues[8], attributes: [{ key: "scope.value", value: { stringValue: hostileValues[10] } }] },
      metrics: [{
        name: hostileValues[14], description: hostileValues[15], unit: hostileValues[16], metadata: [{ key: "metric.value", value: { stringValue: hostileValues[17] } }],
        gauge: { dataPoints: [{
          timeUnixNano: "3000000000", asDouble: 987654.5,
          attributes: [{ key: "datapoint.value", value: { stringValue: hostileValues[18] } }],
          exemplars: [{ timeUnixNano: "3000000000", asDouble: 1.5, traceId: "55555555555555555555555555555555", spanId: "6666666666666666", filteredAttributes: [{ key: "exemplar.value", value: { stringValue: hostileValues[19] } }] }],
        }] },
      }, {
        name: "agentsec_ready", description: "hostile description is cleared", unit: "1",
        gauge: { dataPoints: [{ timeUnixNano: "3000000000", asDouble: 987654.5 }] },
      }],
    }],
  }],
});

export const collectorImage = "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5";

export async function runOTelRedactionProof() {
  const container = `zasp-otel-redaction-proof-${process.pid}`;
  try {
    const config = await renderedProofConfig();
    await ensureImage();
    await exec("docker", ["run", "-d", "--name", container, "--user", "65532:65532", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864", "-e", `OTEL_CONFIG=${config}`, "-p", "127.0.0.1::4318", collectorImage, "--config=env:OTEL_CONFIG"], commandOptions());
    const origin = await collectorOrigin(container);
    await postUntilReady(`${origin}/v1/traces`, tracePayload);
    await postOnce(`${origin}/v1/logs`, logPayload);
    await postOnce(`${origin}/v1/metrics`, metricPayload);
    const output = await redactedOutput(container);
    if (hostileValues.some((value) => output.includes(value)) || !output.includes("Name: redacted") || !output.includes("Name: agentsec_ready") || !output.includes("Body: Str()")) throw new Error(proofError);
    return Object.freeze({ image: collectorImage, readOnlyRoot: true, redacted: true, runtimeUser: "65532:65532", signals: 3 });
  } catch (error) {
    if (process.env.ZASP_PROOF_DEBUG === "1") {
      const diagnostic = await exec("docker", ["logs", container], commandOptions()).catch(() => null);
      if (diagnostic) process.stderr.write(`${diagnostic.stdout}\n${diagnostic.stderr}`);
    }
    if (error instanceof Error && error.message === proofError) throw error;
    throw new Error(proofError);
  } finally {
    await exec("docker", ["rm", "-f", container], commandOptions()).catch(() => undefined);
  }
}

async function renderedProofConfig() {
  const resources = await renderRelease(productionReleaseFixture);
  const matches = resources.filter(({ kind, metadata }) => kind === "ConfigMap" && metadata?.name === "otel-collector");
  if (matches.length !== 1 || typeof matches[0].data?.["collector.yaml"] !== "string") throw new Error(proofError);
  const config = load(matches[0].data["collector.yaml"]);
  if (!config || typeof config !== "object" || !config.exporters?.nop || !config.service?.pipelines) throw new Error(proofError);
  config.exporters = { debug: { verbosity: "detailed" } };
  for (const pipeline of Object.values(config.service.pipelines)) pipeline.exporters = ["debug"];
  return dump(config, { lineWidth: -1, noRefs: true, sortKeys: false });
}

async function ensureImage() {
  try {
    await exec("docker", ["image", "inspect", collectorImage], commandOptions());
  } catch {
    await exec("docker", ["pull", collectorImage], { ...commandOptions(), timeout: 120_000 });
  }
}

async function collectorOrigin(container) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const result = await exec("docker", ["port", container, "4318/tcp"], commandOptions()).catch(() => null);
    const match = /^127\.0\.0\.1:([1-9][0-9]{0,4})\n?$/.exec(result?.stdout ?? "");
    if (match && Number(match[1]) <= 65535) return `http://127.0.0.1:${match[1]}`;
    await delay(100);
  }
  throw new Error(proofError);
}

async function postUntilReady(url, payload) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (await post(url, payload)) return;
    await delay(100);
  }
  throw new Error(proofError);
}

async function postOnce(url, payload) {
  if (!await post(url, payload)) throw new Error(proofError);
}

async function post(url, payload) {
  try {
    const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload), signal: AbortSignal.timeout(2000) });
    await response.arrayBuffer();
    return response.status === 200;
  } catch {
    return false;
  }
}

async function redactedOutput(container) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = await exec("docker", ["logs", container], commandOptions());
    const output = `${result.stdout}\n${result.stderr}`;
    if (output.includes("Name: redacted") && output.includes("Name: agentsec_ready") && output.includes("Body: Str()") && output.includes("987654")) return output;
    await delay(100);
  }
  throw new Error(proofError);
}

function commandOptions() {
  return { encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 15_000, env: { PATH: process.env.PATH ?? "" } };
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runOTelRedactionProof().then(() => {
    process.stdout.write("Collector redaction proof passed.\n");
  }).catch(() => {
    process.stdout.write("Collector redaction proof failed.\n");
    process.exitCode = 1;
  });
}
