import { dump, loadAll, JSON_SCHEMA } from "js-yaml";

const manifestByteLimit = 262_144;
const maximumJsonDepth = 24;
const maximumJsonCollectionSize = 128;
const maximumJsonStringLength = 8_192;
const commonLabels = Object.freeze({
  "app.kubernetes.io/part-of": "zasp",
  "app.kubernetes.io/component": "observability",
  "zasp.dev/environment": "local",
});

export const COLLECTOR_IMAGE = "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5";
export const BUSYBOX_IMAGE = "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9";
export const OBSERVABILITY_CONSTANTS = deepFreeze({
  namespace: "zasp-local",
  collectorName: "otel-collector",
  configName: "otel-collector-config",
  spanJobName: "otel-test-span",
  sinkPath: "/sink/traces.json",
  sinkByteLimit: 65_536,
});

const collectorConfiguration = `extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 48
    spike_limit_mib: 8
  batch:
    send_batch_size: 1
    send_batch_max_size: 1
    timeout: 1s
exporters:
  file:
    path: /sink/traces.json
    format: json
    append: false
    flush_interval: 100ms
service:
  telemetry:
    logs:
      level: error
    metrics:
      level: none
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [file]
`;

export function buildSyntheticObservabilitySpan(...input) {
  if (input.length !== 0) throw new TypeError("synthetic span accepts no caller input");
  return deepFreeze({
    resourceSpans: [{
      resource: {
        attributes: [
          { key: "service.namespace", value: { stringValue: "agentsec" } },
          { key: "service.name", value: { stringValue: "agentsec-api" } },
          { key: "service.version", value: { stringValue: "m1-30c" } },
          { key: "deployment.environment.name", value: { stringValue: "development" } },
          { key: "organization.id", value: { stringValue: "pid_10000000-0000-4000-8000-000000000001" } },
          { key: "workspace.id", value: { stringValue: "pid_20000000-0000-4000-8000-000000000002" } },
          { key: "environment.id", value: { stringValue: "pid_30000000-0000-4000-8000-000000000003" } },
        ],
      },
      scopeSpans: [{
        scope: { name: "zasp.m1-30c.proof", version: "1.0.0" },
        spans: [{
          traceId: "10000000000040008000000000000001",
          spanId: "2000000000000001",
          name: "m1-30c-local-observability",
          kind: 3,
          startTimeUnixNano: "1786932000000000000",
          endTimeUnixNano: "1786932001000000000",
          flags: 1,
          status: { code: 1 },
        }],
      }],
    }],
  });
}

function buildSyntheticObservabilitySinkSpan() {
  const value = structuredClone(buildSyntheticObservabilitySpan());
  const span = value.resourceSpans[0].scopeSpans[0].spans[0];
  value.resourceSpans[0].scopeSpans[0].spans[0] = {
    traceId: span.traceId,
    spanId: span.spanId,
    flags: span.flags,
    name: span.name,
    kind: span.kind,
    startTimeUnixNano: span.startTimeUnixNano,
    endTimeUnixNano: span.endTimeUnixNano,
    status: span.status,
  };
  return deepFreeze(value);
}

export function buildObservabilityResources(...input) {
  if (input.length !== 0) throw new TypeError("observability resources accept no caller input");
  const collectorLabels = { "app.kubernetes.io/name": OBSERVABILITY_CONSTANTS.collectorName, ...commonLabels };
  const spanLabels = { "app.kubernetes.io/name": OBSERVABILITY_CONSTANTS.spanJobName, ...commonLabels };
  const spanJson = `${JSON.stringify(buildSyntheticObservabilitySpan())}\n`;
  return deepFreeze([
    {
      apiVersion: "v1",
      kind: "ConfigMap",
      metadata: {
        labels: { ...commonLabels },
        name: OBSERVABILITY_CONSTANTS.configName,
        namespace: OBSERVABILITY_CONSTANTS.namespace,
      },
      data: {
        "config.yaml": collectorConfiguration,
        "span.json": spanJson,
        "response.json": "{\"partialSuccess\":{}}",
      },
    },
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: {
        labels: collectorLabels,
        name: OBSERVABILITY_CONSTANTS.collectorName,
        namespace: OBSERVABILITY_CONSTANTS.namespace,
      },
      spec: {
        progressDeadlineSeconds: 180,
        replicas: 1,
        revisionHistoryLimit: 1,
        selector: { matchLabels: { "app.kubernetes.io/name": OBSERVABILITY_CONSTANTS.collectorName } },
        strategy: { type: "Recreate" },
        template: {
          metadata: { labels: collectorLabels },
          spec: {
            automountServiceAccountToken: false,
            containers: [
              {
                args: ["--config=/conf/config.yaml"],
                image: COLLECTOR_IMAGE,
                imagePullPolicy: "IfNotPresent",
                livenessProbe: healthProbe(3, 10),
                name: "otel-collector",
                ports: [
                  { containerPort: 4318, name: "otlp-http", protocol: "TCP" },
                  { containerPort: 13133, name: "health", protocol: "TCP" },
                ],
                readinessProbe: healthProbe(3, 2),
                resources: {
                  limits: { cpu: "250m", memory: "256Mi" },
                  requests: { cpu: "25m", memory: "32Mi" },
                },
                securityContext: containerSecurity(10_001),
                startupProbe: healthProbe(60, 2),
                volumeMounts: [
                  { mountPath: "/conf", name: "config", readOnly: true },
                  { mountPath: "/sink", name: "sink", readOnly: false },
                  { mountPath: "/tmp", name: "collector-tmp", readOnly: false },
                ],
              },
              {
                command: ["sh", "-ec", "while true; do sleep 3600; done"],
                image: BUSYBOX_IMAGE,
                imagePullPolicy: "IfNotPresent",
                name: "sink-reader",
                resources: {
                  limits: { cpu: "25m", memory: "16Mi" },
                  requests: { cpu: "5m", memory: "8Mi" },
                },
                securityContext: containerSecurity(65_532),
                volumeMounts: [{ mountPath: "/sink", name: "sink", readOnly: true }],
              },
            ],
            dnsPolicy: "ClusterFirst",
            enableServiceLinks: false,
            hostIPC: false,
            hostNetwork: false,
            hostPID: false,
            restartPolicy: "Always",
            securityContext: {
              fsGroup: 10_001,
              runAsNonRoot: true,
              seccompProfile: { type: "RuntimeDefault" },
            },
            terminationGracePeriodSeconds: 10,
            volumes: [
              { configMap: { defaultMode: 292, name: OBSERVABILITY_CONSTANTS.configName }, name: "config" },
              { emptyDir: { sizeLimit: "64Ki" }, name: "sink" },
              { emptyDir: { sizeLimit: "32Mi" }, name: "collector-tmp" },
            ],
          },
        },
      },
    },
    {
      apiVersion: "v1",
      kind: "Service",
      metadata: {
        labels: collectorLabels,
        name: OBSERVABILITY_CONSTANTS.collectorName,
        namespace: OBSERVABILITY_CONSTANTS.namespace,
      },
      spec: {
        ipFamilies: ["IPv4"],
        ipFamilyPolicy: "SingleStack",
        ports: [{ name: "otlp-http", port: 4318, protocol: "TCP", targetPort: "otlp-http" }],
        selector: { "app.kubernetes.io/name": OBSERVABILITY_CONSTANTS.collectorName },
        sessionAffinity: "None",
        type: "ClusterIP",
      },
    },
    {
      apiVersion: "batch/v1",
      kind: "Job",
      metadata: {
        labels: spanLabels,
        name: OBSERVABILITY_CONSTANTS.spanJobName,
        namespace: OBSERVABILITY_CONSTANTS.namespace,
      },
      spec: {
        activeDeadlineSeconds: 30,
        backoffLimit: 0,
        completions: 1,
        parallelism: 1,
        podReplacementPolicy: "Failed",
        template: {
          metadata: { labels: spanLabels },
          spec: {
            automountServiceAccountToken: false,
            containers: [{
              command: [
                "sh",
                "-ec",
                "body=$(wget -q -t 1 -T 5 --header='Content-Type: application/json' --post-file=/fixture/span.json -O - http://otel-collector.zasp-local.svc.cluster.local:4318/v1/traces); [ \"$body\" = \"$(cat /fixture/response.json)\" ]; printf 'otel-test-span-sent\\n'",
              ],
              image: BUSYBOX_IMAGE,
              imagePullPolicy: "IfNotPresent",
              name: "span-generator",
              resources: {
                limits: { cpu: "50m", memory: "32Mi" },
                requests: { cpu: "5m", memory: "8Mi" },
              },
              securityContext: containerSecurity(65_532),
              volumeMounts: [
                { mountPath: "/fixture", name: "fixture", readOnly: true },
                { mountPath: "/tmp", name: "job-tmp", readOnly: false },
              ],
            }],
            dnsPolicy: "ClusterFirst",
            enableServiceLinks: false,
            hostIPC: false,
            hostNetwork: false,
            hostPID: false,
            restartPolicy: "Never",
            securityContext: {
              runAsGroup: 65_532,
              runAsNonRoot: true,
              runAsUser: 65_532,
              seccompProfile: { type: "RuntimeDefault" },
            },
            terminationGracePeriodSeconds: 5,
            volumes: [
              {
                configMap: {
                  defaultMode: 292,
                  items: [
                    { key: "span.json", path: "span.json" },
                    { key: "response.json", path: "response.json" },
                  ],
                  name: OBSERVABILITY_CONSTANTS.configName,
                },
                name: "fixture",
              },
              { emptyDir: { sizeLimit: "8Mi" }, name: "job-tmp" },
            ],
          },
        },
      },
    },
  ]);
}

export function buildObservabilityCoreResources(...input) {
  if (input.length !== 0) throw new TypeError("observability core resources accept no caller input");
  return deepFreeze(structuredClone(buildObservabilityResources().slice(0, 3)));
}

export function buildObservabilitySpanResources(...input) {
  if (input.length !== 0) throw new TypeError("observability span resources accept no caller input");
  return deepFreeze(structuredClone(buildObservabilityResources().slice(3)));
}

export function validateObservabilityResources(value) {
  requireExactValue(value, buildObservabilityResources(), "observability resources");
  return deepFreeze(structuredClone(value));
}

export function renderObservabilityCoreManifest(value) {
  return renderManifest(value, buildObservabilityCoreResources(), "observability core resources");
}

export function renderObservabilitySpanManifest(value) {
  return renderManifest(value, buildObservabilitySpanResources(), "observability span resources");
}

export function parseObservabilityManifest(text, stage) {
  const expected = stage === "core" ? buildObservabilityCoreResources() :
    stage === "span" ? buildObservabilitySpanResources() : undefined;
  if (expected === undefined || typeof text !== "string" || text.length === 0 ||
      Buffer.byteLength(text, "utf8") > manifestByteLimit ||
      Buffer.from(text, "utf8").toString("utf8") !== text) invalidManifest();
  let documents;
  try {
    documents = [];
    loadAll(text, (document) => documents.push(document), {
      filename: stage === "core" ? "observability.yaml" : "observability-span.yaml",
      json: false,
      onWarning: invalidManifest,
      schema: JSON_SCHEMA,
    });
  } catch {
    invalidManifest();
  }
  if (documents.length !== 1) invalidManifest();
  const document = documents[0];
  requireExactKeys(document, ["apiVersion", "kind", "items"], "observability manifest");
  if (document.apiVersion !== "v1" || document.kind !== "List") invalidManifest();
  requireExactValue(document.items, expected, "observability manifest resources");
  const resources = deepFreeze(structuredClone(document.items));
  const rendered = stage === "core" ? renderObservabilityCoreManifest(resources) : renderObservabilitySpanManifest(resources);
  if (rendered !== text) invalidManifest();
  return resources;
}

export function parseObservabilitySink(bytes) {
  if (!(bytes instanceof Uint8Array) ||
      Object.getPrototypeOf(bytes) !== Uint8Array.prototype && Object.getPrototypeOf(bytes) !== Buffer.prototype ||
      bytes.byteLength === 0 ||
      bytes.byteLength > OBSERVABILITY_CONSTANTS.sinkByteLimit) invalidSink();
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    invalidSink();
  }
  if (!source.endsWith("\n") || source.slice(0, -1).includes("\n") || source.endsWith("\n\n")) invalidSink();
  let value;
  try {
    value = parseUniqueJson(source.slice(0, -1));
  } catch {
    invalidSink();
  }
  requireExactValue(value, buildSyntheticObservabilitySinkSpan(), "observability sink");
  return deepFreeze(structuredClone(value));
}

function renderManifest(value, expected, label) {
  requireExactValue(value, expected, label);
  return dump(
    { apiVersion: "v1", kind: "List", items: value },
    {
      condenseFlow: false,
      forceQuotes: false,
      indent: 2,
      lineWidth: -1,
      noCompatMode: true,
      noRefs: true,
      schema: JSON_SCHEMA,
      skipInvalid: false,
      sortKeys: false,
    },
  );
}

function healthProbe(failureThreshold, periodSeconds) {
  return {
    failureThreshold,
    httpGet: { path: "/", port: "health", scheme: "HTTP" },
    periodSeconds,
    successThreshold: 1,
    timeoutSeconds: 1,
  };
}

function containerSecurity(runAsUser) {
  return {
    allowPrivilegeEscalation: false,
    capabilities: { drop: ["ALL"] },
    privileged: false,
    readOnlyRootFilesystem: true,
    runAsGroup: runAsUser,
    runAsNonRoot: true,
    runAsUser,
  };
}

function requireExactValue(value, expected, label) {
  if (Array.isArray(expected)) {
    if (!Array.isArray(value) || value.length !== expected.length || !exactArrayShape(value)) {
      throw new TypeError(`${label} are invalid`);
    }
    for (let index = 0; index < expected.length; index += 1) {
      requireExactValue(value[index], expected[index], `${label}[${index}]`);
    }
    return;
  }
  if (isPlainObject(expected)) {
    requireExactKeys(value, Object.keys(expected), label);
    for (const key of Object.keys(expected)) requireExactValue(value[key], expected[key], `${label}.${key}`);
    return;
  }
  if (value !== expected || typeof value !== typeof expected) throw new TypeError(`${label} is invalid`);
}

function requireExactKeys(value, keys, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} is invalid`);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new TypeError(`${label} is invalid`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError(`${label} is invalid`);
    }
  }
}

function exactArrayShape(value) {
  if (Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor === undefined || !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0 ||
      lengthDescriptor.enumerable) return false;
  const length = lengthDescriptor.value;
  if (keys.length !== length + 1 || keys[length] !== "length") return false;
  for (let index = 0; index < length; index += 1) {
    if (keys[index] !== String(index)) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) return false;
  }
  return true;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function invalidManifest() {
  throw new TypeError("observability manifest is invalid");
}

function invalidSink() {
  throw new TypeError("observability sink is invalid");
}

function parseUniqueJson(source) {
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\t\n\r ]/u.test(source[index])) index += 1; };
  const parseString = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid JSON string");
    const start = index;
    index += 1;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') {
        index += 1;
        const value = JSON.parse(source.slice(start, index));
        if (value.length > maximumJsonStringLength || hasUnpairedSurrogate(value)) throw new SyntaxError("invalid JSON string");
        return value;
      }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid JSON string");
      if (character !== "\\") {
        index += 1;
        continue;
      }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/u.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError("invalid JSON escape");
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const parseValue = (depth) => {
    if (depth > maximumJsonDepth) throw new SyntaxError("excessive JSON depth");
    whitespace();
    if (source[index] === "{") {
      index += 1;
      whitespace();
      const entries = [];
      const keys = new Set();
      if (source[index] === "}") { index += 1; return {}; }
      while (true) {
        const key = parseString();
        if (keys.has(key)) throw new SyntaxError("duplicate JSON key");
        keys.add(key);
        whitespace();
        if (source[index] !== ":") throw new SyntaxError("missing JSON colon");
        index += 1;
        entries.push([key, parseValue(depth + 1)]);
        if (entries.length > maximumJsonCollectionSize) throw new SyntaxError("oversized JSON object");
        whitespace();
        if (source[index] === "}") { index += 1; return Object.fromEntries(entries); }
        if (source[index] !== ",") throw new SyntaxError("missing JSON comma");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1;
      whitespace();
      const values = [];
      if (source[index] === "]") { index += 1; return values; }
      while (true) {
        values.push(parseValue(depth + 1));
        if (values.length > maximumJsonCollectionSize) throw new SyntaxError("oversized JSON array");
        whitespace();
        if (source[index] === "]") { index += 1; return values; }
        if (source[index] !== ",") throw new SyntaxError("missing JSON comma");
        index += 1;
      }
    }
    if (source[index] === '"') return parseString();
    for (const [token, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(token, index)) { index += token.length; return value; }
    }
    const match = source.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u);
    if (match === null) throw new SyntaxError("invalid JSON value");
    index += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) throw new SyntaxError("invalid JSON number");
    return number;
  };
  const value = parseValue(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError("trailing JSON input");
  return value;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}
