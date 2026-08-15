import assert from "node:assert/strict";
import test from "node:test";

import {
  FIRST_FIXTURE,
  SECOND_FIXTURE,
  buildSinkCollectorConfig,
  buildSourceCollectorConfig,
  runApplicationOperation,
  validateDeliveredArtifact,
  validateSinkCollectorConfig,
  validateSourceCollectorConfig,
} from "./exporter.mjs";
import { buildSyntheticOtlpTrace } from "../otlp-ingest/normalizer.mjs";

test("builds exact bounded source and sink Collector configurations", () => {
  const source = buildSourceCollectorConfig("zasp-m0-22-sink-0123456789abcdef");
  const sink = buildSinkCollectorConfig();

  assert.equal(validateSourceCollectorConfig(source, "zasp-m0-22-sink-0123456789abcdef"), true);
  assert.equal(validateSinkCollectorConfig(sink), true);
  assert.match(source.toString(), /queue_size: 4/);
  assert.match(source.toString(), /num_consumers: 1/);
  assert.match(source.toString(), /max_elapsed_time: 2s/);
  assert.match(source.toString(), /endpoint: http:\/\/zasp-m0-22-sink-0123456789abcdef:4318/);
  assert.match(sink.toString(), /path: \/proof\/output\/export\.json/);
});

test("rejects source configuration drift and hostile sink names", () => {
  const name = "zasp-m0-22-sink-0123456789abcdef";
  const source = buildSourceCollectorConfig(name);
  for (const mutation of [
    source.toString().replace("queue_size: 4", "queue_size: 5"),
    source.toString().replace("num_consumers: 1", "num_consumers: 2"),
    source.toString().replace("max_elapsed_time: 2s", "max_elapsed_time: 3s"),
    `${source.toString()}exporters:\n`,
  ]) assert.throws(() => validateSourceCollectorConfig(Buffer.from(mutation), name), TypeError);
  for (const hostile of ["sink", "zasp-m0-22-sink-../escape", "zasp-m0-22-sink-0123456789abcdeg", true]) {
    assert.throws(() => buildSourceCollectorConfig(hostile), TypeError);
  }
});

test("rejects sink configuration drift", () => {
  const sink = buildSinkCollectorConfig();
  for (const mutation of [
    sink.toString().replace("append: false", "append: true"),
    sink.toString().replace("level: none", "level: normal"),
    sink.toString().replace("/proof/output/export.json", "/tmp/export.json"),
  ]) assert.throws(() => validateSinkCollectorConfig(Buffer.from(mutation)), TypeError);
});

test("uses two exact distinct synthetic traces", () => {
  assert.notEqual(FIRST_FIXTURE.traceId, SECOND_FIXTURE.traceId);
  assert.notEqual(FIRST_FIXTURE.spanId, SECOND_FIXTURE.spanId);
  assert.equal(FIRST_FIXTURE.organizationId, SECOND_FIXTURE.organizationId);
  assert.doesNotThrow(() => buildSyntheticOtlpTrace(FIRST_FIXTURE));
  assert.doesNotThrow(() => buildSyntheticOtlpTrace(SECOND_FIXTURE));
});

test("accepts only the exact delivered first Collector artifact", () => {
  const body = buildSyntheticOtlpTrace(FIRST_FIXTURE);
  assert.equal(validateDeliveredArtifact(body).identity, true);
  assert.throws(() => validateDeliveredArtifact(buildSyntheticOtlpTrace(SECOND_FIXTURE)), TypeError);
  assert.throws(() => validateDeliveredArtifact(Buffer.from(`${body.toString()}\n{}`)), TypeError);
});

test("changes application state before best-effort telemetry", async () => {
  const order = [];
  const result = await runApplicationOperation({
    apply: () => { order.push("application"); return { revision: 1 }; },
    submit: async () => { order.push("telemetry"); throw new Error("exporter unavailable"); },
    timeoutMs: 50,
  });
  assert.deepEqual(order, ["application", "telemetry"]);
  assert.deepEqual(result, {
    operation: true,
    application: { revision: 1 },
    telemetry: "failed",
    bounded: true,
  });
});

test("bounds a hanging telemetry submission without blocking application success", async () => {
  const started = performance.now();
  let state = 0;
  const result = await runApplicationOperation({
    apply: () => { state += 1; return state; },
    submit: ({ signal }) => new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true })),
    timeoutMs: 25,
  });
  assert.equal(state, 1);
  assert.equal(result.operation, true);
  assert.equal(result.telemetry, "failed");
  assert.ok(performance.now() - started < 250);
});

test("reports successful telemetry without changing the operation contract", async () => {
  const result = await runApplicationOperation({
    apply: () => "applied",
    submit: async () => ({ status: 200 }),
    timeoutMs: 50,
  });
  assert.equal(result.operation, true);
  assert.equal(result.application, "applied");
  assert.equal(result.telemetry, "delivered");
  assert.equal(result.bounded, true);
});

test("rejects invalid application operation boundaries", async () => {
  for (const input of [null, {}, { apply() {}, submit() {}, timeoutMs: 0 }, { apply: 1, submit() {}, timeoutMs: 1 }]) {
    await assert.rejects(() => runApplicationOperation(input), TypeError);
  }
  await assert.rejects(() => runApplicationOperation({
    apply: async () => "not synchronous",
    submit: async () => undefined,
    timeoutMs: 10,
  }), TypeError);
});
