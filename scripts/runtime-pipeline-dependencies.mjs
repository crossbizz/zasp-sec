import { randomBytes } from "node:crypto";
import { LOCALSTACK_IMAGE } from "../proofs/localstack-storage/run.mjs";
import { OPENSEARCH_IMAGE } from "../proofs/opensearch-event/run.mjs";

const kinds = new Map([["aws", { port: "4566", image: LOCALSTACK_IMAGE }], ["search", { port: "9200", image: OPENSEARCH_IMAGE }]]);
const validMarker = (marker) => typeof marker === "string" && /^[a-f0-9]{16}$/.test(marker);

export function buildRuntimeContainerArguments(kind, marker) {
  const config = kinds.get(kind);
  if (!config || !validMarker(marker)) throw new Error("runtime dependency identity rejected");
  const args = ["run", "--detach", "--rm", "--pull", "never", "--name", `zasp-runtime-pipeline-${kind}-${marker}`, "--publish", `127.0.0.1::${config.port}`, "--label", "zasp.proof=runtime-pipeline", "--label", `zasp.marker=${marker}`];
  if (kind === "aws") args.push("--env", "SERVICES=sqs,s3,kms", "--env", "SQS_ENDPOINT_STRATEGY=dynamic", "--env", "EAGER_SERVICE_LOADING=1");
  else args.push("--env", "discovery.type=single-node", "--env", "DISABLE_SECURITY_PLUGIN=true", "--env", "DISABLE_INSTALL_DEMO_CONFIG=true", "--env", "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m");
  return [...args, config.image];
}

export function createRuntimePipelineDependencies(command, { marker = randomBytes(8).toString("hex") } = {}) {
  if (typeof command !== "function" || !validMarker(marker)) throw new Error("runtime dependency configuration rejected");
  const entries = [];
  let closed = false;
  let closing;
  async function inspect(entry) {
    const result = await command("docker", ["inspect", entry.id ?? entry.name], { timeout: 3_000, reject: false });
    if (result.status !== 0) throw new Error("runtime dependency inspection failed");
    const records = JSON.parse(result.stdout);
    const record = records[0];
    if (records.length !== 1 || !/^[a-f0-9]{64}$/.test(record?.Id ?? "") || (entry.id && record.Id !== entry.id) || record.Name !== `/${entry.name}` || record.Config?.Labels?.["zasp.marker"] !== marker || record.Config?.Labels?.["zasp.proof"] !== "runtime-pipeline") throw new Error("runtime dependency ownership rejected");
    return record;
  }
  return {
    async prepare() {
      if (closed || entries.length) throw new Error("runtime dependency preparation rejected");
      // Pulling only downloads pinned images. It cannot create a container and
      // does not hold the container cleanup path behind a cold registry request.
      await Promise.all([...kinds.values()].map(({ image }) => command("docker", ["pull", image], { timeout: 120_000 })));
      if (closed) throw new Error("runtime dependency preparation interrupted");
    },
    async start(kind) {
      if (closed || !kinds.has(kind) || entries.some((entry) => entry.kind === kind)) throw new Error("runtime dependency start rejected");
      const entry = { kind, name: `zasp-runtime-pipeline-${kind}-${marker}`, id: undefined, pending: undefined };
      entries.push(entry);
      entry.pending = command("docker", buildRuntimeContainerArguments(kind, marker), { timeout: 10_000, reject: false });
      const result = await entry.pending;
      if (result.status !== 0 || !/^[a-f0-9]{64}$/.test(result.stdout.trim())) throw new Error("runtime dependency start failed");
      entry.id = result.stdout.trim();
      const record = await inspect(entry);
      const bindings = record.NetworkSettings?.Ports?.[`${kinds.get(kind).port}/tcp`];
      const port = Number(bindings?.[0]?.HostPort);
      if (closed || bindings?.length !== 1 || bindings[0].HostIp !== "127.0.0.1" || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("runtime dependency binding rejected");
      return `http://127.0.0.1:${port}`;
    },
    close() {
      if (closing) return closing;
      closed = true;
      closing = (async () => {
        await Promise.allSettled(entries.map((entry) => entry.pending));
        const errors = [];
        for (const entry of [...entries].reverse()) {
          try {
            const record = await inspect(entry);
            const result = await command("docker", ["rm", "--force", record.Id], { timeout: 3_000, reject: false });
            if (result.status !== 0) throw new Error("runtime dependency cleanup failed");
          } catch (error) { errors.push(error); }
        }
        if (errors.length) throw new AggregateError(errors, "runtime dependency cleanup incomplete");
      })();
      return closing;
    },
  };
}
