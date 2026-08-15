import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  normalizeTetragonProof,
  parseTetragonEvents,
  parseTetragonMetrics,
} from "./normalizer.mjs";

const organizationId = "org_aaaaaaaaaaaaaaaa";
const expected = Object.freeze({
  namespace: "zasp-m0-12-0123456789abcdef",
  podName: "workload",
  podUid: "11111111-2222-4333-8444-555555555555",
  containerName: "workload",
  containerId: `containerd://${"a".repeat(64)}`,
  imageId: `registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:${"a".repeat(64)}`,
  imageName: `sha256:${"b".repeat(64)}`,
  nodeName: "zasp-m0-12-0123456789abcdef-control-plane",
  labels: Object.freeze({
    "app.kubernetes.io/name": "zasp-m0-12-workload",
    "zasp.dev/proof": "m0-12",
    "zasp.dev/run": "0123456789abcdef",
  }),
  execBinary: "/bin/echo",
  execArgument: "zasp-m0-12-exec",
  fileBinary: "/bin/sh",
  filePath: "/tmp/zasp-m0-12-proof.txt",
  filePolicyName: "zasp-m0-12-file",
  networkBinary: "/bin/nc",
  networkPolicyName: "zasp-m0-12-connect",
  sinkAddress: "10.96.0.23",
  sinkPort: 18080,
  sensorVersion: "v1.7.0",
  sensorCommit: "1de2ed8ebea18e56257dc59597aa13bf8f0e471e",
  policyCount: 2,
});

function process(binary, argumentsValue, execId, pid, startTime) {
  return {
    exec_id: execId,
    pid,
    uid: 1000,
    cwd: "/tmp/",
    binary,
    arguments: argumentsValue,
    flags: "execve clone",
    start_time: startTime,
    auid: 4294967295,
    pod: {
      namespace: expected.namespace,
      name: expected.podName,
      uid: expected.podUid,
      container: {
        id: expected.containerId,
        name: expected.containerName,
        image: { id: expected.imageId, name: expected.imageName },
        start_time: "2026-08-14T20:59:00Z",
        pid: 12,
        security_context: {},
      },
      pod_labels: expected.labels,
      workload: "workload",
      workload_kind: "Pod",
    },
    docker: "a".repeat(24),
    parent_exec_id: "parent-exec-id",
    cap: {},
    ns: {},
    tid: pid,
    process_credentials: {},
    in_init_tree: false,
  };
}

function fixtureEvents() {
  const execStart = "2026-08-14T21:00:00.123Z";
  const fileStart = "2026-08-14T21:00:01.123Z";
  const networkStart = "2026-08-14T21:00:02.123Z";
  const exec = {
    process_exec: {
      process: process(expected.execBinary, expected.execArgument, "exec-event-id", 41, execStart),
    },
    node_name: expected.nodeName,
    time: "2026-08-14T21:00:00.123Z",
    cluster_name: expected.namespace,
    node_labels: {},
  };
  const fileExec = {
    process_exec: {
      process: process(expected.fileBinary, "-c fixture", "file-event-id", 42, fileStart),
    },
    node_name: expected.nodeName,
    time: fileStart,
    cluster_name: expected.namespace,
    node_labels: {},
  };
  const networkExec = {
    process_exec: {
      process: process(expected.networkBinary, `${expected.sinkAddress} ${expected.sinkPort}`, "network-event-id", 43, networkStart),
    },
    node_name: expected.nodeName,
    time: networkStart,
    cluster_name: expected.namespace,
    node_labels: {},
  };
  const file = {
    process_kprobe: {
      process: { pid: 42, flags: "unknown", start_time: fileStart },
      function_name: "security_file_permission",
      args: [
        { file_arg: { path: expected.filePath, permission: "-rw-r--r--" } },
        { int_arg: 2 },
      ],
      action: "KPROBE_ACTION_POST",
      policy_name: expected.filePolicyName,
      return_action: "KPROBE_ACTION_POST",
    },
    node_name: expected.nodeName,
    time: "2026-08-14T21:00:01.123Z",
    cluster_name: expected.namespace,
    node_labels: {},
  };
  const network = {
    process_kprobe: {
      process: { pid: 43, flags: "unknown", start_time: networkStart },
      function_name: "tcp_connect",
      args: [{ sock_arg: {
        family: "AF_INET",
        type: "SOCK_STREAM",
        protocol: "IPPROTO_TCP",
        saddr: "10.244.0.8",
        daddr: expected.sinkAddress,
        sport: 45212,
        dport: expected.sinkPort,
        cookie: "0",
        state: "TCP_SYN_SENT",
      } }],
      action: "KPROBE_ACTION_POST",
      policy_name: expected.networkPolicyName,
      return_action: "KPROBE_ACTION_POST",
    },
    node_name: expected.nodeName,
    time: "2026-08-14T21:00:02.123Z",
    cluster_name: expected.namespace,
    node_labels: {},
  };
  return { exec, fileExec, networkExec, file, network };
}

function eventBytes(events = Object.values(fixtureEvents())) {
  return Buffer.from(events.map((event) => JSON.stringify(event)).join("\n") + "\n");
}

function metricText(overrides = {}) {
  const values = {
    ringLost: 0,
    ringErrors: 0,
    queueLost: 0,
    notifyLost: 0,
    exportLost: 0,
    policyCount: expected.policyCount,
    ...overrides,
  };
  return Buffer.from([
    `tetragon_build_info{commit="",go_version="go1.26.2",modified="",time="",version="${expected.sensorVersion}"} 1`,
    `tetragon_tracingpolicy_loaded{state="enabled"} ${values.policyCount}`,
    "tetragon_tracingpolicy_loaded{state=\"disabled\"} 0",
    "tetragon_tracingpolicy_loaded{state=\"error\"} 0",
    "tetragon_tracingpolicy_loaded{state=\"load_error\"} 0",
    `tetragon_observer_ringbuf_events_lost_total ${values.ringLost}`,
    `tetragon_observer_ringbuf_errors_total ${values.ringErrors}`,
    `tetragon_observer_ringbuf_queue_events_lost_total ${values.queueLost}`,
    `tetragon_notify_overflowed_events_total ${values.notifyLost}`,
    `tetragon_export_ratelimit_events_dropped_total ${values.exportLost}`,
    "tetragon_events_total{type=\"PROCESS_EXEC\"} 3",
    "",
  ].join("\n"));
}

const limits = Object.freeze({
  maximumBytes: 65_536,
  maximumLines: 32,
  maximumDepth: 16,
  maximumStringLength: 4096,
  maximumCollectionSize: 32,
});

test("normalizes three exact event classes to one Organization-scoped workload", () => {
  const result = normalizeTetragonProof({
    organizationId,
    expected,
    events: eventBytes(),
    metricsBefore: metricText(),
    metricsAfter: metricText(),
  });
  const digest = createHash("sha256")
    .update(JSON.stringify([organizationId, expected.namespace, expected.podUid, expected.containerId]))
    .digest("hex");

  assert.equal(result.organization_id, organizationId);
  assert.equal(result.workload.id, `${organizationId}:k8s_workload:${digest}`);
  assert.deepEqual(result.classes, ["process", "file", "network"]);
  assert.equal(new Set(result.events.map((event) => event.workload_id)).size, 1);
  assert.deepEqual(result.events.map((event) => event.class), result.classes);
  assert.deepEqual(result.events.map((event) => event.observed_at), [
    "2026-08-14T21:00:00.123Z",
    "2026-08-14T21:00:01.123Z",
    "2026-08-14T21:00:02.123Z",
  ]);
  assert.equal(result.process, true);
  assert.equal(result.file, true);
  assert.equal(result.network, true);
  assert.equal(result.identity, true);
  assert.equal(result.capability, true);
  assert.equal(result.drops, 0);
  assert.equal(result.sensor.version, "v1.7.0");
  assert.equal(result.sensor.commit, expected.sensorCommit);
  assert.equal(result.sensor.policies_loaded, 2);
  assert.deepEqual(result.sensor.drop_counters, {
    export_rate_limit: 0,
    notify_overflow: 0,
    ringbuf_errors: 0,
    ringbuf_lost: 0,
    ringbuf_queue_lost: 0,
  });
});

test("accepts exact enriched provider kprobes and rejects unbound variants", () => {
  const events = fixtureEvents();
  events.file.process_kprobe.process = {
    ...structuredClone(events.fileExec.process_exec.process),
    refcnt: 1,
  };
  events.file.process_kprobe.parent = {};
  events.network.process_kprobe.process = {
    ...structuredClone(events.networkExec.process_exec.process),
    refcnt: 1,
  };
  events.network.process_kprobe.parent = {};

  const input = {
    organizationId,
    expected,
    metricsBefore: metricText(),
    metricsAfter: metricText(),
  };
  const result = normalizeTetragonProof({
    ...input,
    events: eventBytes(Object.values(events)),
  });
  assert.deepEqual(result.events.map((event) => event.source_exec_id), [
    "exec-event-id",
    "file-event-id",
    "network-event-id",
  ]);

  const mismatched = structuredClone(events);
  mismatched.file.process_kprobe.process.pod.uid = "99999999-2222-4333-8444-555555555555";
  assert.throws(() => normalizeTetragonProof({
    ...input,
    events: eventBytes(Object.values(mismatched)),
  }), TypeError);

  const extra = structuredClone(events);
  extra.network.process_kprobe.unexpected = true;
  assert.throws(() => normalizeTetragonProof({
    ...input,
    events: eventBytes(Object.values(extra)),
  }), TypeError);

  const uncorrelated = fixtureEvents();
  uncorrelated.file.process_kprobe.process.pid = 900;
  assert.throws(() => normalizeTetragonProof({
    ...input,
    events: eventBytes(Object.values(uncorrelated)),
  }), TypeError);
});

test("correlates minimal provider kprobes by exact PID, binary, and bounded start time", () => {
  const events = fixtureEvents();
  events.file.process_kprobe.process.start_time = "2026-08-14T21:00:01.124Z";
  events.network.process_kprobe.process.start_time = "2026-08-14T21:00:02.124Z";
  const replacement = structuredClone(events.fileExec);
  replacement.process_exec.process.binary = "/bin/cat";
  replacement.process_exec.process.start_time = "2026-08-14T21:00:01.125Z";
  const ordered = [...Object.values(events), replacement];
  const input = {
    organizationId,
    expected,
    metricsBefore: metricText(),
    metricsAfter: metricText(),
  };

  const result = normalizeTetragonProof({ ...input, events: eventBytes(ordered) });
  assert.deepEqual(result.events.map((event) => event.source_exec_id), [
    "exec-event-id",
    "file-event-id",
    "network-event-id",
  ]);

  events.file.process_kprobe.process.start_time = "2026-08-14T21:00:03.123Z";
  assert.throws(() => normalizeTetragonProof({
    ...input,
    events: eventBytes([...Object.values(events), replacement]),
  }), TypeError);
});

test("Organization scope changes only the deterministic workload identity", () => {
  const input = {
    expected,
    events: eventBytes(),
    metricsBefore: metricText(),
    metricsAfter: metricText(),
  };
  const first = normalizeTetragonProof({ organizationId, ...input });
  const second = normalizeTetragonProof({ organizationId: "org_bbbbbbbbbbbbbbbb", ...input });

  assert.notEqual(first.workload.id, second.workload.id);
  assert.equal(first.events[0].source_exec_id, second.events[0].source_exec_id);
  assert.throws(() => normalizeTetragonProof({ organizationId: "ORG_aaaaaaaaaaaaaaaa", ...input }), TypeError);
});

test("strict event parser rejects malformed representation boundaries", () => {
  const { exec } = fixtureEvents();
  const valid = JSON.stringify(exec);
  const cases = {
    empty: Buffer.alloc(0),
    invalid_utf8: Buffer.from([0xff]),
    trailing_json: Buffer.from(`${valid} true`),
    duplicate_root_key: Buffer.from(valid.replace('"node_name"', `"node_name":"foreign","node_name"`)),
    oversized: Buffer.alloc(limits.maximumBytes + 1, 0x61),
    too_many_lines: Buffer.from(`${valid}\n`.repeat(limits.maximumLines + 1)),
    excessive_depth: Buffer.from(`${'{"x":'.repeat(limits.maximumDepth + 1)}0${"}".repeat(limits.maximumDepth + 1)}`),
    unpaired_surrogate: Buffer.from(valid.replace("exec-event-id", "\\ud800")),
  };

  for (const [name, bytes] of Object.entries(cases)) {
    assert.throws(() => parseTetragonEvents(bytes, limits), TypeError, name);
  }
});

test("rejects missing, extra, aliased, duplicate, and foreign event candidates", () => {
  const base = fixtureEvents();
  const all = Object.values(base);
  const missing = all.filter((event) => event !== base.network);
  const duplicate = [...all, structuredClone(base.exec)];
  const foreign = structuredClone(base.fileExec);
  foreign.process_exec.process.pod.uid = "99999999-2222-4333-8444-555555555555";
  const alias = structuredClone(base.exec);
  alias.processExec = alias.process_exec;
  delete alias.process_exec;
  const extra = structuredClone(base.network);
  extra.unexpected = true;

  for (const [name, events] of Object.entries({
    missing,
    duplicate,
    foreign: all.map((event) => event === base.fileExec ? foreign : event),
    alias: all.map((event) => event === base.exec ? alias : event),
    extra: all.map((event) => event === base.network ? extra : event),
  })) {
    assert.throws(() => normalizeTetragonProof({
      organizationId,
      expected,
      events: eventBytes(events),
      metricsBefore: metricText(),
      metricsAfter: metricText(),
    }), TypeError, name);
  }
});

test("rejects wrong class-specific event metadata", () => {
  const mutations = [
    (events) => { events.exec.process_exec.process.binary = "/bin/false"; },
    (events) => { events.exec.process_exec.process.arguments = "wrong"; },
    (events) => { events.file.process_kprobe.function_name = "security_mmap_file"; },
    (events) => { events.file.process_kprobe.policy_name = "foreign"; },
    (events) => { events.file.process_kprobe.args[0].file_arg.path = "/etc/shadow"; },
    (events) => { events.network.process_kprobe.policy_name = "foreign"; },
    (events) => { events.network.process_kprobe.args[0].sock_arg.daddr = "8.8.8.8"; },
    (events) => { events.network.process_kprobe.args[0].sock_arg.dport = 443; },
  ];

  for (const mutate of mutations) {
    const events = fixtureEvents();
    mutate(events);
    assert.throws(() => normalizeTetragonProof({
      organizationId,
      expected,
      events: eventBytes(Object.values(events)),
      metricsBefore: metricText(),
      metricsAfter: metricText(),
    }), TypeError);
  }
});

test("parses exact build, policy, and drop metrics", () => {
  const parsed = parseTetragonMetrics(metricText(), expected);

  assert.equal(parsed.version, expected.sensorVersion);
  assert.equal(parsed.commit, expected.sensorCommit);
  assert.equal(parsed.policies_loaded, 2);
  assert.deepEqual(parsed.drop_counters, {
    export_rate_limit: 0,
    notify_overflow: 0,
    ringbuf_errors: 0,
    ringbuf_lost: 0,
    ringbuf_queue_lost: 0,
  });
});

test("rejects missing, duplicate, malformed, or false capability metrics", () => {
  const source = metricText().toString("utf8");
  const cases = {
    missing_build: source.split("\n").slice(1).join("\n"),
    duplicate_build: `${source}${source.split("\n")[0]}\n`,
    wrong_version: source.replace('version="v1.7.0"', 'version="v1.6.0"'),
    wrong_commit: source.replace('commit=""', `commit="${"0".repeat(40)}"`),
    build_not_one: source.replace("} 1\n", "} 0\n"),
    wrong_policy_count: source.replace('state="enabled"} 2', 'state="enabled"} 1'),
    disabled_policy: source.replace('state="disabled"} 0', 'state="disabled"} 1'),
    boolean_value: source.replace("ringbuf_events_lost_total 0", "ringbuf_events_lost_total true"),
    negative_value: source.replace("ringbuf_events_lost_total 0", "ringbuf_events_lost_total -1"),
    non_finite: source.replace("ringbuf_events_lost_total 0", "ringbuf_events_lost_total NaN"),
  };

  for (const [name, value] of Object.entries(cases)) {
    assert.throws(() => parseTetragonMetrics(Buffer.from(value), expected), TypeError, name);
  }
});

test("rejects any nonzero loss or reset across the fixture interval", () => {
  const counters = ["ringLost", "ringErrors", "queueLost", "notifyLost", "exportLost"];
  for (const counter of counters) {
    assert.throws(() => normalizeTetragonProof({
      organizationId,
      expected,
      events: eventBytes(),
      metricsBefore: metricText({ [counter]: 0 }),
      metricsAfter: metricText({ [counter]: 1 }),
    }), TypeError, counter);
    assert.throws(() => normalizeTetragonProof({
      organizationId,
      expected,
      events: eventBytes(),
      metricsBefore: metricText({ [counter]: 1 }),
      metricsAfter: metricText({ [counter]: 0 }),
    }), TypeError, `${counter}_reset`);
  }
});

test("rejects hostile primitive and coercion inputs without executing them", () => {
  let coerced = false;
  const hostile = { toString() { coerced = true; throw new Error("coerced"); } };
  const input = {
    organizationId,
    expected,
    events: eventBytes(),
    metricsBefore: metricText(),
    metricsAfter: metricText(),
  };
  for (const value of [null, true, 1, "text", hostile]) {
    assert.throws(() => normalizeTetragonProof({ ...input, expected: value }), TypeError);
  }
  assert.equal(coerced, false);
});
