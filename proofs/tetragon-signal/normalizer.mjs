import { createHash } from "node:crypto";

const defaultEventLimits = Object.freeze({
  maximumBytes: 131_072,
  maximumLines: 64,
  maximumDepth: 32,
  maximumStringLength: 16_384,
  maximumCollectionSize: 128,
});
const maximumMetricsBytes = 1_048_576;
const maximumMetricsLines = 20_000;
const maximumMetricLineBytes = 16_384;
const organizationPattern = /^org_[a-z0-9]{16}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const containerIdPattern = /^containerd:\/\/[0-9a-f]{64}$/;
const commitPattern = /^[0-9a-f]{40}$/;
const ipv4Pattern = /^(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])(?:\.(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])){3}$/;
const metricNamePattern = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const metricLabelNamePattern = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const maximumProcessCorrelationSkewMilliseconds = 1_000;

const processKeys = [
  "exec_id", "pid", "uid", "cwd", "binary", "arguments", "flags",
  "start_time", "auid", "pod", "docker", "parent_exec_id", "cap", "ns",
  "tid", "process_credentials", "in_init_tree",
];
const requiredDropMetrics = Object.freeze({
  tetragon_export_ratelimit_events_dropped_total: "export_rate_limit",
  tetragon_notify_overflowed_events_total: "notify_overflow",
  tetragon_observer_ringbuf_errors_total: "ringbuf_errors",
  tetragon_observer_ringbuf_events_lost_total: "ringbuf_lost",
  tetragon_observer_ringbuf_queue_events_lost_total: "ringbuf_queue_lost",
});

export function parseTetragonEvents(bytes, limits = defaultEventLimits) {
  const safeLimits = validateEventLimits(limits);
  const source = decodeBytes(bytes, safeLimits.maximumBytes, "event stream");
  const rawLines = source.split("\n");
  if (rawLines.at(-1) === "") rawLines.pop();
  if (rawLines.length === 0 || rawLines.length > safeLimits.maximumLines) {
    throw new TypeError("event stream line count is invalid");
  }

  return rawLines.map((line) => {
    if (line.length === 0) throw new TypeError("event stream contains an empty line");
    let parsed;
    try {
      parsed = parseUniqueJson(line, safeLimits);
    } catch (error) {
      const reason = error instanceof Error ? error.message : "invalid representation";
      throw new TypeError(`event stream is not strict JSON: ${reason}`);
    }
    expectObject(parsed, "event");
    return parsed;
  });
}

export function parseTetragonMetrics(bytes, expected) {
  const specification = validateExpected(expected);
  const source = decodeBytes(bytes, maximumMetricsBytes, "metrics");
  const lines = source.split("\n");
  if (lines.length > maximumMetricsLines) throw new TypeError("metrics line count is invalid");

  const requiredNames = new Set([
    "tetragon_build_info",
    "tetragon_tracingpolicy_loaded",
    ...Object.keys(requiredDropMetrics),
  ]);
  const samples = new Map();
  for (const line of lines) {
    if (Buffer.byteLength(line, "utf8") > maximumMetricLineBytes) {
      throw new TypeError("metric line is too large");
    }
    if (line === "" || line.startsWith("#")) continue;
    const nameMatch = /^([a-zA-Z_:][a-zA-Z0-9_:]*)/.exec(line);
    if (!nameMatch || !requiredNames.has(nameMatch[1])) continue;
    const sample = parseMetricSample(line);
    const labelKey = canonicalLabels(sample.labels);
    const sampleKey = `${sample.name}\u0000${labelKey}`;
    if (samples.has(sampleKey)) throw new TypeError("metric sample is duplicated");
    samples.set(sampleKey, sample);
  }

  const build = samplesFor(samples, "tetragon_build_info");
  if (build.length !== 1) throw new TypeError("build metric is invalid");
  expectLabelKeys(build[0].labels, ["commit", "go_version", "modified", "time", "version"], "build metric");
  if (
    build[0].value !== 1 ||
    build[0].labels.version !== specification.sensorVersion ||
    build[0].labels.commit !== "" ||
    build[0].labels.modified !== "" ||
    build[0].labels.go_version !== "go1.26.2" ||
    build[0].labels.time !== ""
  ) {
    throw new TypeError("build metric does not match the sensor");
  }

  const policies = samplesFor(samples, "tetragon_tracingpolicy_loaded");
  const expectedStates = new Map([
    ["disabled", 0],
    ["enabled", specification.policyCount],
    ["error", 0],
    ["load_error", 0],
  ]);
  if (policies.length !== expectedStates.size) throw new TypeError("policy metrics are incomplete");
  for (const sample of policies) {
    expectLabelKeys(sample.labels, ["state"], "policy metric");
    const expectedValue = expectedStates.get(sample.labels.state);
    if (expectedValue === undefined || sample.value !== expectedValue) {
      throw new TypeError("policy metric is invalid");
    }
    expectedStates.delete(sample.labels.state);
  }
  if (expectedStates.size !== 0) throw new TypeError("policy metric state is missing");

  const dropCounters = Object.create(null);
  for (const [metricName, outputName] of Object.entries(requiredDropMetrics)) {
    const matches = samplesFor(samples, metricName);
    if (matches.length !== 1) throw new TypeError("drop metric is missing or duplicated");
    expectLabelKeys(matches[0].labels, [], "drop metric");
    if (!Number.isFinite(matches[0].value) || matches[0].value < 0) {
      throw new TypeError("drop metric value is invalid");
    }
    dropCounters[outputName] = matches[0].value;
  }

  return {
    version: build[0].labels.version,
    commit: specification.sensorCommit,
    image_digest: specification.sensorImageDigest,
    policies_loaded: specification.policyCount,
    drop_counters: { ...dropCounters },
  };
}

export function normalizeTetragonProof(input) {
  expectObject(input, "proof input");
  expectKeys(input, ["organizationId", "expected", "events", "metricsBefore", "metricsAfter"], "proof input");
  const organizationId = validateOrganizationId(input.organizationId);
  const expected = validateExpected(input.expected);
  const events = parseTetragonEvents(input.events);
  const metricsBefore = parseTetragonMetrics(input.metricsBefore, expected);
  const metricsAfter = parseTetragonMetrics(input.metricsAfter, expected);

  const workloadExecs = [];
  const probes = [];
  for (const event of events) {
    if (event.process_kprobe !== undefined) {
      probes.push(event);
      continue;
    }
    if (event.process_exec === undefined) throw new TypeError("event class is unsupported");
    const processValue = event.process_exec?.process;
    if (!isObject(processValue) || !isObject(processValue.pod) || !isObject(processValue.pod.container)) {
      throw new TypeError("exec event process is invalid");
    }
    const pod = processValue.pod;
    const container = pod.container;
    const anyIdentityMatch =
      pod.namespace === expected.namespace ||
      pod.name === expected.podName ||
      pod.uid === expected.podUid ||
      container.name === expected.containerName ||
      container.id === expected.containerId;
    if (!anyIdentityMatch) continue;
    validateExecEnvelope(event, expected);
    validateCandidateIdentity(event, processValue, expected);
    workloadExecs.push({ event, process: processValue });
  }

  const processMatches = workloadExecs.filter(({ process }) =>
    process.binary === expected.execBinary && process.arguments === expected.execArgument);
  if (processMatches.length !== 1) throw new TypeError("expected exactly one process event");
  const classified = [classifyExec(processMatches[0].event, expected)];
  classified.push(...probes.map((event) => classifyKprobe(event, expected, workloadExecs)));
  const counts = new Map();
  for (const event of classified) counts.set(event.class, (counts.get(event.class) ?? 0) + 1);
  for (const name of ["process", "file", "network"]) {
    if (counts.get(name) !== 1) throw new TypeError(`expected exactly one ${name} event`);
  }
  if (classified.length !== 3) throw new TypeError("event candidates are not exact");

  const workloadId = `${organizationId}:k8s_workload:${digest([
    organizationId,
    expected.namespace,
    expected.podUid,
    expected.containerId,
  ])}`;
  const order = new Map([["process", 0], ["file", 1], ["network", 2]]);
  const normalizedEvents = classified
    .sort((left, right) => order.get(left.class) - order.get(right.class))
    .map((event) => ({ ...event, workload_id: workloadId }));

  const beforeDrops = metricsBefore.drop_counters;
  const afterDrops = metricsAfter.drop_counters;
  let totalDrops = 0;
  for (const name of Object.values(requiredDropMetrics)) {
    const before = beforeDrops[name];
    const after = afterDrops[name];
    if (before !== 0 || after !== 0 || after < before) {
      throw new TypeError("sensor loss/drop state is not clean");
    }
    totalDrops += after - before;
  }

  const sensor = {
    version: metricsAfter.version,
    commit: metricsAfter.commit,
    image_digest: metricsAfter.image_digest,
    policies_loaded: metricsAfter.policies_loaded,
    drop_counters: { ...metricsAfter.drop_counters },
  };
  return {
    organization_id: organizationId,
    workload: {
      id: workloadId,
      namespace: expected.namespace,
      pod_name: expected.podName,
      pod_uid: expected.podUid,
      container_name: expected.containerName,
      container_id: expected.containerId,
      node_name: expected.nodeName,
      labels: { ...expected.labels },
    },
    classes: ["process", "file", "network"],
    events: normalizedEvents,
    sensor,
    process: true,
    file: true,
    network: true,
    identity: true,
    capability: true,
    drops: totalDrops,
  };
}

function classifyExec(event, expected) {
  validateExecEnvelope(event, expected);
  const processValue = event.process_exec.process;
  if (
    processValue.binary !== expected.execBinary ||
    processValue.arguments !== expected.execArgument
  ) {
    throw new TypeError("process event does not match the fixture action");
  }
  return {
    class: "process",
    observed_at: validateEventTime(event.time),
    source_exec_id: processValue.exec_id,
    binary: processValue.binary,
    argument: processValue.arguments,
  };
}

function classifyKprobe(event, expected, workloadExecs) {
  expectKeys(event, ["cluster_name", "node_labels", "node_name", "process_kprobe", "time"], "kprobe event");
  const kprobeKeys = Object.keys(event.process_kprobe).sort();
  const minimalKeys = ["action", "args", "function_name", "policy_name", "process", "return_action"].sort();
  const enrichedKeys = [...minimalKeys, "parent"].sort();
  if (!sameStrings(kprobeKeys, minimalKeys) && !sameStrings(kprobeKeys, enrichedKeys)) {
    throw new TypeError("process_kprobe has invalid keys");
  }
  if (Object.hasOwn(event.process_kprobe, "parent") && !isObject(event.process_kprobe.parent)) {
    throw new TypeError("process_kprobe parent is invalid");
  }
  const kprobe = event.process_kprobe;
  const probeProcess = kprobe.process;
  const hasIdentity = isObject(probeProcess?.pod) && isObject(probeProcess.pod.container);
  if (hasIdentity) {
    validateCandidateIdentity(event, probeProcess, expected);
  } else {
    expectKeys(probeProcess, ["flags", "pid", "start_time"], "kprobe process");
    expectUnsignedInteger(probeProcess.pid, "kprobe process.pid");
    if (probeProcess.flags !== "unknown") throw new TypeError("kprobe process flags are invalid");
    validateEventTime(probeProcess.start_time);
  }
  if (
    kprobe.action !== "KPROBE_ACTION_POST" || kprobe.return_action !== "KPROBE_ACTION_POST" ||
    event.node_name !== expected.nodeName || event.cluster_name !== expected.namespace ||
    !isObject(event.node_labels)
  ) throw new TypeError("kprobe envelope is invalid");
  const expectedBinary = kprobe.function_name === "security_file_permission"
    ? expected.fileBinary
    : kprobe.function_name === "tcp_connect"
      ? expected.networkBinary
      : undefined;
  if (expectedBinary === undefined) throw new TypeError("kprobe function is not a required event class");
  let correlatedProcess = probeProcess;
  if (!hasIdentity) {
    const probeStart = Date.parse(probeProcess.start_time);
    const correlated = workloadExecs.filter(({ process }) =>
      process.pid === probeProcess.pid &&
      process.binary === expectedBinary &&
      Math.abs(Date.parse(process.start_time) - probeStart) <= maximumProcessCorrelationSkewMilliseconds);
    if (correlated.length !== 1) throw new TypeError("kprobe process is not exactly correlated");
    correlatedProcess = correlated[0].process;
  }
  if (kprobe.function_name === "security_file_permission") {
    if (
      kprobe.policy_name !== expected.filePolicyName ||
      correlatedProcess.binary !== expected.fileBinary ||
      !Array.isArray(kprobe.args) ||
      kprobe.args.length !== 2
    ) {
      throw new TypeError("file event is invalid");
    }
    const [fileArgument, permissionArgument] = kprobe.args;
    expectKeys(fileArgument, ["file_arg"], "file argument");
    expectKeys(fileArgument.file_arg, ["path", "permission"], "file value");
    expectKeys(permissionArgument, ["int_arg"], "file permission argument");
    if (
      fileArgument.file_arg.path !== expected.filePath ||
      fileArgument.file_arg.permission !== "-rw-r--r--" || permissionArgument.int_arg !== 2
    ) {
      throw new TypeError("file event does not match the fixture path");
    }
    return {
      class: "file",
      observed_at: validateEventTime(event.time),
      source_exec_id: correlatedProcess.exec_id,
      binary: correlatedProcess.binary,
      path: fileArgument.file_arg.path,
      policy: kprobe.policy_name,
    };
  }
  if (kprobe.function_name === "tcp_connect") {
    if (
      kprobe.policy_name !== expected.networkPolicyName ||
      correlatedProcess.binary !== expected.networkBinary ||
      !Array.isArray(kprobe.args) ||
      kprobe.args.length !== 1
    ) {
      throw new TypeError("network event is invalid");
    }
    const [socketArgument] = kprobe.args;
    expectKeys(socketArgument, ["sock_arg"], "socket argument");
    expectKeys(socketArgument.sock_arg, ["cookie", "daddr", "dport", "family", "protocol", "saddr", "sport", "state", "type"], "socket value");
    if (
      socketArgument.sock_arg.family !== "AF_INET" ||
      socketArgument.sock_arg.type !== "SOCK_STREAM" ||
      socketArgument.sock_arg.protocol !== "IPPROTO_TCP" ||
      socketArgument.sock_arg.daddr !== expected.sinkAddress ||
      socketArgument.sock_arg.dport !== expected.sinkPort
    ) {
      throw new TypeError("network event does not match the fixture sink");
    }
    return {
      class: "network",
      observed_at: validateEventTime(event.time),
      source_exec_id: correlatedProcess.exec_id,
      binary: correlatedProcess.binary,
      destination_address: socketArgument.sock_arg.daddr,
      destination_port: socketArgument.sock_arg.dport,
      policy: kprobe.policy_name,
    };
  }
  throw new TypeError("kprobe function is not a required event class");
}

function validateExecEnvelope(event, expected) {
  expectKeys(event, ["cluster_name", "node_labels", "node_name", "process_exec", "time"], "exec event");
  expectKeys(event.process_exec, ["process"], "process_exec");
  if (
    event.node_name !== expected.nodeName || event.cluster_name !== expected.namespace ||
    !isObject(event.node_labels)
  ) throw new TypeError("exec event envelope is invalid");
}

function validateCandidateIdentity(event, processValue, expected) {
  const actualProcessKeys = Object.keys(processValue).sort();
  const baseProcessKeys = [...processKeys].sort();
  const referencedProcessKeys = [...processKeys, "refcnt"].sort();
  if (!sameStrings(actualProcessKeys, baseProcessKeys) && !sameStrings(actualProcessKeys, referencedProcessKeys)) {
    throw new TypeError("process has invalid keys");
  }
  for (const name of ["arguments", "binary", "cwd", "docker", "exec_id", "flags", "parent_exec_id"]) {
    expectBoundedString(processValue[name], `process.${name}`);
  }
  for (const name of ["auid", "pid", "tid", "uid"]) expectUnsignedInteger(processValue[name], `process.${name}`);
  if (Object.hasOwn(processValue, "refcnt")) expectUnsignedInteger(processValue.refcnt, "process.refcnt");
  for (const name of ["cap", "ns", "process_credentials"]) {
    if (!isObject(processValue[name])) throw new TypeError(`process.${name} is invalid`);
  }
  if (typeof processValue.in_init_tree !== "boolean") throw new TypeError("process.in_init_tree is invalid");
  validateEventTime(processValue.start_time);

  const pod = processValue.pod;
  expectKeys(pod, ["container", "name", "namespace", "pod_labels", "uid", "workload", "workload_kind"], "pod");
  const container = pod.container;
  expectKeys(container, ["id", "image", "name", "pid", "security_context", "start_time"], "container");
  expectKeys(container.image, ["id", "name"], "container image");
  expectKeys(container.security_context, [], "container security context");
  expectKeys(pod.pod_labels, Object.keys(expected.labels), "pod labels");
  if (
    pod.namespace !== expected.namespace ||
    pod.name !== expected.podName ||
    pod.uid !== expected.podUid ||
    pod.workload !== expected.podName ||
    pod.workload_kind !== "Pod" ||
    container.id !== expected.containerId ||
    container.name !== expected.containerName ||
    container.image.id !== expected.imageId ||
    container.image.name !== expected.imageName ||
    event.node_name !== expected.nodeName
  ) {
    throw new TypeError("event workload identity is invalid");
  }
  expectUnsignedInteger(container.pid, "container.pid");
  validateEventTime(container.start_time);
  for (const [name, value] of Object.entries(expected.labels)) {
    if (pod.pod_labels[name] !== value) throw new TypeError("event workload labels are invalid");
  }
}

function validateExpected(value) {
  expectObject(value, "expected fixture");
  expectKeys(value, [
    "containerId", "containerName", "execArgument", "execBinary", "fileBinary",
    "filePath", "filePolicyName", "imageId", "imageName", "labels",
    "namespace", "networkBinary", "networkPolicyName", "nodeName", "podName",
    "podUid", "policyCount", "sensorCommit", "sensorImageDigest", "sensorVersion", "sinkAddress",
    "sinkPort",
  ], "expected fixture");
  for (const name of [
    "containerId", "containerName", "execArgument", "execBinary", "fileBinary",
    "filePath", "filePolicyName", "imageId", "imageName", "namespace",
    "networkBinary", "networkPolicyName", "nodeName", "podName", "podUid",
    "sensorCommit", "sensorImageDigest", "sensorVersion", "sinkAddress",
  ]) {
    expectBoundedString(value[name], `expected.${name}`);
  }
  expectKeys(value.labels, ["app.kubernetes.io/name", "zasp.dev/proof", "zasp.dev/run"], "expected labels");
  for (const labelValue of Object.values(value.labels)) expectBoundedString(labelValue, "expected label");
  if (
    !uuidPattern.test(value.podUid) ||
    !containerIdPattern.test(value.containerId) ||
    !commitPattern.test(value.sensorCommit) ||
    !/^sha256:[0-9a-f]{64}$/.test(value.sensorImageDigest) ||
    !/^v\d+\.\d+\.\d+$/.test(value.sensorVersion) ||
    !ipv4Pattern.test(value.sinkAddress) ||
    !Number.isSafeInteger(value.sinkPort) ||
    value.sinkPort < 1 ||
    value.sinkPort > 65535 ||
    !Number.isSafeInteger(value.policyCount) ||
    value.policyCount !== 2
  ) {
    throw new TypeError("expected fixture identity is invalid");
  }
  return value;
}

function validateEventLimits(value) {
  expectObject(value, "event limits");
  expectKeys(value, ["maximumBytes", "maximumCollectionSize", "maximumDepth", "maximumLines", "maximumStringLength"], "event limits");
  for (const number of Object.values(value)) {
    if (!Number.isSafeInteger(number) || number < 1 || number > 2_000_000) {
      throw new TypeError("event limit is invalid");
    }
  }
  return value;
}

function parseMetricSample(line) {
  let offset = 0;
  while (offset < line.length && /[a-zA-Z0-9_:]/.test(line[offset])) offset += 1;
  const name = line.slice(0, offset);
  if (!metricNamePattern.test(name)) throw new TypeError("metric name is invalid");
  let labels = Object.create(null);
  if (line[offset] === "{") {
    const close = findClosingBrace(line, offset);
    labels = parseMetricLabels(line.slice(offset + 1, close));
    offset = close + 1;
  }
  if (line[offset] !== " ") throw new TypeError("metric separator is invalid");
  const numeric = line.slice(offset + 1);
  if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(numeric)) {
    throw new TypeError("metric value is invalid");
  }
  const value = Number(numeric);
  if (!Number.isFinite(value)) throw new TypeError("metric value is not finite");
  return { name, labels, value };
}

function parseMetricLabels(source) {
  const labels = Object.create(null);
  if (source === "") return labels;
  let offset = 0;
  while (offset < source.length) {
    const nameMatch = /^[a-zA-Z_][a-zA-Z0-9_]*/.exec(source.slice(offset));
    if (!nameMatch || !metricLabelNamePattern.test(nameMatch[0])) throw new TypeError("metric label is invalid");
    const name = nameMatch[0];
    offset += name.length;
    if (source.slice(offset, offset + 2) !== '="') throw new TypeError("metric label assignment is invalid");
    offset += 2;
    let raw = "";
    let closed = false;
    while (offset < source.length) {
      const character = source[offset];
      if (character === '"') {
        offset += 1;
        closed = true;
        break;
      }
      if (character === "\\") {
        const escaped = source[offset + 1];
        if (!['\\', '"', "n"].includes(escaped)) throw new TypeError("metric label escape is invalid");
        raw += escaped === "n" ? "\n" : escaped;
        offset += 2;
      } else {
        raw += character;
        offset += 1;
      }
    }
    if (!closed || Object.hasOwn(labels, name)) throw new TypeError("metric label is invalid or duplicated");
    labels[name] = raw;
    if (offset === source.length) break;
    if (source[offset] !== ",") throw new TypeError("metric labels are malformed");
    offset += 1;
  }
  return labels;
}

function findClosingBrace(line, start) {
  let quoted = false;
  let escaped = false;
  for (let index = start + 1; index < line.length; index += 1) {
    const character = line[index];
    if (escaped) {
      escaped = false;
    } else if (character === "\\" && quoted) {
      escaped = true;
    } else if (character === '"') {
      quoted = !quoted;
    } else if (character === "}" && !quoted) {
      return index;
    }
  }
  throw new TypeError("metric labels are unterminated");
}

function samplesFor(samples, name) {
  return [...samples.values()].filter((sample) => sample.name === name);
}

function canonicalLabels(labels) {
  return JSON.stringify(Object.entries(labels).sort(([left], [right]) => left.localeCompare(right)));
}

function expectLabelKeys(labels, expected, context) {
  expectKeys(labels, expected, context);
}

function decodeBytes(value, maximumBytes, context) {
  if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > maximumBytes) {
    throw new TypeError(`${context} size is invalid`);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength),
    );
  } catch {
    throw new TypeError(`${context} is not valid UTF-8`);
  }
}

function parseUniqueJson(source, limits) {
  let index = 0;
  const whitespace = () => {
    while (index < source.length && /[\t\r ]/.test(source[index])) index += 1;
  };
  const parseString = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid string");
    const start = index;
    index += 1;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') {
        index += 1;
        const value = JSON.parse(source.slice(start, index));
        if (value.length > limits.maximumStringLength || hasUnpairedSurrogate(value)) throw new SyntaxError("invalid string");
        return value;
      }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid control character");
      if (character !== "\\") {
        index += 1;
        continue;
      }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) index += 1;
      else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) index += 5;
      else throw new SyntaxError("invalid escape");
    }
    throw new SyntaxError("unterminated string");
  };
  const parseValue = (depth) => {
    if (depth > limits.maximumDepth) throw new SyntaxError("excessive depth");
    whitespace();
    if (source[index] === "{") {
      index += 1;
      whitespace();
      const output = Object.create(null);
      const keys = new Set();
      if (source[index] === "}") { index += 1; return output; }
      while (true) {
        const key = parseString();
        if (keys.has(key) || keys.size >= limits.maximumCollectionSize) throw new SyntaxError("duplicate or excessive object");
        keys.add(key);
        whitespace();
        if (source[index] !== ":") throw new SyntaxError("invalid object");
        index += 1;
        output[key] = parseValue(depth + 1);
        whitespace();
        if (source[index] === "}") { index += 1; return output; }
        if (source[index] !== ",") throw new SyntaxError("invalid object");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1;
      whitespace();
      const output = [];
      if (source[index] === "]") { index += 1; return output; }
      while (true) {
        output.push(parseValue(depth + 1));
        if (output.length > limits.maximumCollectionSize) throw new SyntaxError("excessive array");
        whitespace();
        if (source[index] === "]") { index += 1; return output; }
        if (source[index] !== ",") throw new SyntaxError("invalid array");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === '"') return parseString();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) { index += literal.length; return value; }
    }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(index));
    if (!match) throw new SyntaxError("invalid value");
    index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) throw new SyntaxError("invalid number");
    return value;
  };
  const output = parseValue(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError("trailing JSON");
  return output;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return true;
  }
  return false;
}

function validUtcInstant(value) {
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (year < 1 || second > 59) return false;
  const millisecond = Number(`${match[7] ?? ""}000`.slice(0, 3));
  const instant = new Date(0);
  instant.setUTCFullYear(year, month - 1, day);
  instant.setUTCHours(hour, minute, second, millisecond);
  return instant.getUTCFullYear() === year && instant.getUTCMonth() === month - 1 &&
    instant.getUTCDate() === day && instant.getUTCHours() === hour &&
    instant.getUTCMinutes() === minute && instant.getUTCSeconds() === second;
}

function validateEventTime(value) {
  if (!validUtcInstant(value)) throw new TypeError("event timestamp is invalid");
  return value;
}

function validateOrganizationId(value) {
  if (typeof value !== "string" || !organizationPattern.test(value)) {
    throw new TypeError("organization ID is invalid");
  }
  return value;
}

function expectKeys(value, expected, context) {
  expectObject(value, context);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${context} has invalid keys`);
  }
}

function sameStrings(actual, expected) {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function expectObject(value, context) {
  if (!isObject(value)) throw new TypeError(`${context} must be an object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${context} must be a plain object`);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") throw new TypeError(`${context} has a symbol key`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new TypeError(`${context} must contain enumerable data properties`);
    }
  }
}

function expectBoundedString(value, context) {
  if (typeof value !== "string" || value.length === 0 || value.length > defaultEventLimits.maximumStringLength || hasUnpairedSurrogate(value)) {
    throw new TypeError(`${context} must be a bounded string`);
  }
}

function expectUnsignedInteger(value, context) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${context} must be an unsigned integer`);
}

function digest(parts) {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}
