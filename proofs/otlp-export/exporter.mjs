import { isDeepStrictEqual } from "node:util";

import {
  FIXTURE,
  normalizeCollectorOtlpTrace,
  normalizeOtlpTrace,
} from "../otlp-ingest/normalizer.mjs";

const sinkNamePattern = /^zasp-m0-22-sink-[0-9a-f]{16}$/;

export const FIRST_FIXTURE = Object.freeze({ ...FIXTURE });
export const SECOND_FIXTURE = Object.freeze({
  ...FIXTURE,
  traceId: "fedcba9876543210fedcba9876543210",
  spanId: "fedcba9876543210",
  startTimeUnixNano: "1786728000200000000",
  endTimeUnixNano: "1786728000300000000",
});

const sinkConfiguration = `receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 64
    spike_limit_mib: 16
  batch:
    timeout: 100ms
    send_batch_size: 1
    send_batch_max_size: 1
exporters:
  file:
    path: /proof/output/export.json
    format: json
    append: false
    flush_interval: 100ms
service:
  telemetry:
    logs:
      level: error
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [file]
`;

export function buildSourceCollectorConfig(sinkName) {
  validateSinkName(sinkName);
  return Buffer.from(`receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 64
    spike_limit_mib: 16
  batch:
    timeout: 100ms
    send_batch_size: 1
    send_batch_max_size: 1
exporters:
  otlp_http:
    endpoint: http://${sinkName}:4318
    sending_queue:
      enabled: true
      num_consumers: 1
      queue_size: 4
    retry_on_failure:
      enabled: true
      initial_interval: 100ms
      max_interval: 250ms
      max_elapsed_time: 2s
service:
  telemetry:
    logs:
      level: error
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp_http]
`);
}

export function buildSinkCollectorConfig() {
  return Buffer.from(sinkConfiguration);
}

export function validateSourceCollectorConfig(bytes, sinkName) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("source Collector configuration must be bytes");
  if (!isDeepStrictEqual(Buffer.from(bytes), buildSourceCollectorConfig(sinkName))) {
    throw new TypeError("source Collector configuration is not exact");
  }
  return true;
}

export function validateSinkCollectorConfig(bytes) {
  if (!(bytes instanceof Uint8Array) || !isDeepStrictEqual(Buffer.from(bytes), buildSinkCollectorConfig())) {
    throw new TypeError("sink Collector configuration is not exact");
  }
  return true;
}

export function validateDeliveredArtifact(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > 65_536) {
    throw new TypeError("delivered artifact is invalid");
  }
  let normalized;
  try {
    normalized = normalizeOtlpTrace(bytes, FIRST_FIXTURE);
  } catch {
    normalized = normalizeCollectorOtlpTrace(bytes, FIRST_FIXTURE);
  }
  if (normalized.identity !== true) throw new TypeError("delivered artifact identity is invalid");
  return normalized;
}

export async function runApplicationOperation(input) {
  if (!isPlainObject(input) || typeof input.apply !== "function" || typeof input.submit !== "function" ||
    !Number.isInteger(input.timeoutMs) || input.timeoutMs <= 0 || input.timeoutMs > 500) {
    throw new TypeError("application operation boundary is invalid");
  }
  const application = input.apply();
  if (application !== null && typeof application === "object" && typeof application.then === "function") {
    throw new TypeError("application operation must be synchronous");
  }

  const controller = new AbortController();
  let timer;
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => {
      resolve({ outcome: "failed" });
      controller.abort();
    }, input.timeoutMs);
  });
  const submission = Promise.resolve()
    .then(() => input.submit({ signal: controller.signal }))
    .then(
      () => ({ outcome: "delivered" }),
      () => ({ outcome: "failed" }),
    );
  const outcome = await Promise.race([submission, deadline]);
  clearTimeout(timer);
  if (outcome.outcome !== "delivered") controller.abort();
  await Promise.race([
    submission,
    new Promise((resolve) => setTimeout(resolve, Math.min(50, input.timeoutMs))),
  ]);
  return Object.freeze({
    operation: true,
    application,
    telemetry: outcome.outcome,
    bounded: true,
  });
}

function validateSinkName(value) {
  if (typeof value !== "string" || !sinkNamePattern.test(value)) {
    throw new TypeError("sink Collector name is invalid");
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
