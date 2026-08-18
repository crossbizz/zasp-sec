import { dump, loadAll, JSON_SCHEMA } from "js-yaml";

const manifestByteLimit = 262_144;
const commonLabels = Object.freeze({
  "app.kubernetes.io/part-of": "zasp",
  "app.kubernetes.io/component": "aws-emulator",
  "zasp.dev/environment": "local",
});

export const LOCALSTACK_IMAGE = "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c";
export const AWS_EMULATOR_CONSTANTS = deepFreeze({
  namespace: "zasp-local",
  configName: "local-aws-endpoints",
  localstackName: "localstack",
  s3JobName: "localstack-s3-probe",
  endpoint: "http://localstack.zasp-local.svc.cluster.local:4566",
  port: 4566,
  region: "us-east-1",
  successMarker: "localstack-s3-endpoint-ready",
});

const s3ProbeCommand = "awslocal --endpoint-url http://127.0.0.1:4566 s3api list-buckets --query 'length(Buckets)' --output text >/dev/null 2>&1";
const s3JobScript = `value="$(awslocal --endpoint-url "$AWS_ENDPOINT_URL_S3" s3api list-buckets --query 'length(Buckets)' --output text 2>/dev/null)"
[ "$AWS_ENDPOINT_URL" = "$AWS_ENDPOINT_URL_S3" ]
[ "$value" = "0" ]
printf 'localstack-s3-endpoint-ready\\n'`;

export function buildAwsEmulatorResources(...input) {
  if (input.length !== 0) reject("AWS emulator resources");
  const serverLabels = { "app.kubernetes.io/name": AWS_EMULATOR_CONSTANTS.localstackName, ...commonLabels };
  const jobLabels = { "app.kubernetes.io/name": AWS_EMULATOR_CONSTANTS.s3JobName, ...commonLabels };
  return deepFreeze([
    {
      apiVersion: "v1",
      kind: "ConfigMap",
      metadata: {
        labels: { ...commonLabels },
        name: AWS_EMULATOR_CONSTANTS.configName,
        namespace: AWS_EMULATOR_CONSTANTS.namespace,
      },
      data: {
        AWS_ENDPOINT_URL: AWS_EMULATOR_CONSTANTS.endpoint,
        AWS_ENDPOINT_URL_S3: AWS_EMULATOR_CONSTANTS.endpoint,
      },
    },
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: {
        labels: serverLabels,
        name: AWS_EMULATOR_CONSTANTS.localstackName,
        namespace: AWS_EMULATOR_CONSTANTS.namespace,
      },
      spec: {
        progressDeadlineSeconds: 240,
        replicas: 1,
        revisionHistoryLimit: 1,
        selector: { matchLabels: { "app.kubernetes.io/name": AWS_EMULATOR_CONSTANTS.localstackName } },
        strategy: { type: "Recreate" },
        template: {
          metadata: { labels: serverLabels },
          spec: {
            automountServiceAccountToken: false,
            containers: [{
              env: [
                { name: "AWS_DEFAULT_REGION", value: AWS_EMULATOR_CONSTANTS.region },
                { name: "DEBUG", value: "0" },
                { name: "PERSISTENCE", value: "0" },
                { name: "SERVICES", value: "s3" },
              ],
              image: LOCALSTACK_IMAGE,
              imagePullPolicy: "IfNotPresent",
              livenessProbe: executableProbe(3, 10),
              name: AWS_EMULATOR_CONSTANTS.localstackName,
              ports: [{ containerPort: AWS_EMULATOR_CONSTANTS.port, name: "edge", protocol: "TCP" }],
              readinessProbe: executableProbe(3, 2),
              resources: {
                limits: { cpu: "500m", memory: "512Mi" },
                requests: { cpu: "25m", memory: "64Mi" },
              },
              securityContext: rootContainerSecurity(false),
              startupProbe: executableProbe(90, 2),
              volumeMounts: [
                { mountPath: "/tmp", name: "localstack-tmp", readOnly: false },
                { mountPath: "/var/lib/localstack", name: "localstack-state", readOnly: false },
              ],
            }],
            dnsPolicy: "ClusterFirst",
            enableServiceLinks: false,
            hostIPC: false,
            hostNetwork: false,
            hostPID: false,
            restartPolicy: "Always",
            securityContext: { runAsNonRoot: false, seccompProfile: { type: "RuntimeDefault" } },
            terminationGracePeriodSeconds: 10,
            volumes: [
              { emptyDir: { sizeLimit: "256Mi" }, name: "localstack-state" },
              { emptyDir: { sizeLimit: "128Mi" }, name: "localstack-tmp" },
            ],
          },
        },
      },
    },
    {
      apiVersion: "v1",
      kind: "Service",
      metadata: {
        labels: serverLabels,
        name: AWS_EMULATOR_CONSTANTS.localstackName,
        namespace: AWS_EMULATOR_CONSTANTS.namespace,
      },
      spec: {
        ipFamilies: ["IPv4"],
        ipFamilyPolicy: "SingleStack",
        ports: [{ name: "edge", port: AWS_EMULATOR_CONSTANTS.port, protocol: "TCP", targetPort: "edge" }],
        selector: { "app.kubernetes.io/name": AWS_EMULATOR_CONSTANTS.localstackName },
        sessionAffinity: "None",
        type: "ClusterIP",
      },
    },
    {
      apiVersion: "batch/v1",
      kind: "Job",
      metadata: {
        labels: jobLabels,
        name: AWS_EMULATOR_CONSTANTS.s3JobName,
        namespace: AWS_EMULATOR_CONSTANTS.namespace,
      },
      spec: {
        activeDeadlineSeconds: 30,
        backoffLimit: 0,
        completions: 1,
        parallelism: 1,
        podReplacementPolicy: "Failed",
        template: {
          metadata: { labels: jobLabels },
          spec: {
            automountServiceAccountToken: false,
            containers: [{
              command: ["sh", "-ec", s3JobScript],
              env: [
                { name: "AWS_ACCESS_KEY_ID", value: "test" },
                { name: "AWS_DEFAULT_REGION", value: AWS_EMULATOR_CONSTANTS.region },
                { name: "AWS_EC2_METADATA_DISABLED", value: "true" },
                { name: "AWS_ENDPOINT_URL", valueFrom: { configMapKeyRef: { key: "AWS_ENDPOINT_URL", name: AWS_EMULATOR_CONSTANTS.configName } } },
                { name: "AWS_ENDPOINT_URL_S3", valueFrom: { configMapKeyRef: { key: "AWS_ENDPOINT_URL_S3", name: AWS_EMULATOR_CONSTANTS.configName } } },
                { name: "AWS_REGION", value: AWS_EMULATOR_CONSTANTS.region },
                { name: "AWS_SECRET_ACCESS_KEY", value: "test" },
                { name: "HOME", value: "/tmp" },
              ],
              image: LOCALSTACK_IMAGE,
              imagePullPolicy: "IfNotPresent",
              name: "s3-probe",
              resources: {
                limits: { cpu: "100m", memory: "128Mi" },
                requests: { cpu: "5m", memory: "32Mi" },
              },
              securityContext: rootContainerSecurity(true),
              volumeMounts: [{ mountPath: "/tmp", name: "job-tmp", readOnly: false }],
            }],
            dnsPolicy: "ClusterFirst",
            enableServiceLinks: false,
            hostIPC: false,
            hostNetwork: false,
            hostPID: false,
            restartPolicy: "Never",
            securityContext: { runAsNonRoot: false, seccompProfile: { type: "RuntimeDefault" } },
            terminationGracePeriodSeconds: 5,
            volumes: [{ emptyDir: { sizeLimit: "8Mi" }, name: "job-tmp" }],
          },
        },
        ttlSecondsAfterFinished: 60,
      },
    },
  ]);
}

export function buildAwsEmulatorCoreResources(...input) {
  if (input.length !== 0) reject("AWS emulator core resources");
  return deepFreeze(structuredClone(buildAwsEmulatorResources().slice(0, 3)));
}

export function buildAwsEmulatorS3Resources(...input) {
  if (input.length !== 0) reject("AWS emulator S3 resources");
  return deepFreeze(structuredClone(buildAwsEmulatorResources().slice(3)));
}

export function validateAwsEmulatorResources(value) {
  requireExactValue(value, buildAwsEmulatorResources(), "AWS emulator resources");
  return deepFreeze(structuredClone(value));
}

export function renderAwsEmulatorCoreManifest(value) {
  return renderManifest(value, buildAwsEmulatorCoreResources(), "AWS emulator core resources");
}

export function renderAwsEmulatorS3Manifest(value) {
  return renderManifest(value, buildAwsEmulatorS3Resources(), "AWS emulator S3 resources");
}

export function parseAwsEmulatorManifest(text, stage) {
  const expected = stage === "core" ? buildAwsEmulatorCoreResources() :
    stage === "s3" ? buildAwsEmulatorS3Resources() : undefined;
  if (expected === undefined || typeof text !== "string" || text.length === 0 ||
      Buffer.byteLength(text, "utf8") > manifestByteLimit ||
      Buffer.from(text, "utf8").toString("utf8") !== text) reject("AWS emulator manifest");
  let documents;
  try {
    documents = [];
    loadAll(text, (document) => documents.push(document), {
      filename: stage === "core" ? "aws-emulator.yaml" : "aws-emulator-s3.yaml",
      json: false,
      onWarning: () => reject("AWS emulator manifest"),
      schema: JSON_SCHEMA,
    });
  } catch {
    reject("AWS emulator manifest");
  }
  if (documents.length !== 1) reject("AWS emulator manifest");
  const document = documents[0];
  requireExactKeys(document, ["apiVersion", "kind", "items"], "AWS emulator manifest");
  if (document.apiVersion !== "v1" || document.kind !== "List") reject("AWS emulator manifest");
  requireExactValue(document.items, expected, "AWS emulator manifest resources");
  const resources = deepFreeze(structuredClone(document.items));
  const rendered = stage === "core" ? renderAwsEmulatorCoreManifest(resources) : renderAwsEmulatorS3Manifest(resources);
  if (rendered !== text) reject("AWS emulator manifest");
  return resources;
}

function executableProbe(failureThreshold, periodSeconds) {
  return {
    exec: { command: ["sh", "-ec", s3ProbeCommand] },
    failureThreshold,
    periodSeconds,
    successThreshold: 1,
    timeoutSeconds: 1,
  };
}

function rootContainerSecurity(readOnlyRootFilesystem) {
  return {
    allowPrivilegeEscalation: false,
    capabilities: { drop: ["ALL"] },
    privileged: false,
    readOnlyRootFilesystem,
    runAsNonRoot: false,
    runAsUser: 0,
  };
}

function renderManifest(value, expected, label) {
  requireExactValue(value, expected, label);
  return dump({ apiVersion: "v1", kind: "List", items: value }, {
    condenseFlow: false,
    forceQuotes: false,
    indent: 2,
    lineWidth: -1,
    noCompatMode: true,
    noRefs: true,
    schema: JSON_SCHEMA,
    skipInvalid: false,
    sortKeys: false,
  });
}

function requireExactValue(value, expected, label) {
  if (Array.isArray(expected)) {
    if (!Array.isArray(value) || value.length !== expected.length || !exactArrayShape(value)) reject(label);
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
  if (value !== expected || typeof value !== typeof expected) reject(label);
}

function requireExactKeys(value, keys, label) {
  if (!isPlainObject(value)) reject(label);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) reject(label);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) reject(label);
  }
}

function exactArrayShape(value) {
  if (Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  const length = Object.getOwnPropertyDescriptor(value, "length");
  if (length === undefined || !("value" in length) || !Number.isSafeInteger(length.value) || length.value < 0 || length.enumerable) return false;
  if (keys.length !== length.value + 1 || keys[length.value] !== "length") return false;
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (keys[index] !== String(index) || descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) return false;
  }
  return true;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function reject(label) {
  throw new TypeError(`${label} are invalid`);
}
