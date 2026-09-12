import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { observeSandboxBackfill, observeSandboxQuery, revalidateSandboxBackfill } from "./compatibility-observation.mjs";

const exec = promisify(execFile);
const schema = "sandbox-query-observation-v1";
const reject = () => { throw new Error("sandbox query observation rejected"); };
const closed = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const version = value => typeof value === "string" && value.length > 0 && Buffer.byteLength(value) <= 256 && [...value].every(character => character.charCodeAt(0) > 32 && character.charCodeAt(0) !== 127);

// Read-only evidence, not release provenance or permission to deploy. The caller
// owns the pinned kubeconfig and the outer process deadline.
export async function observeSandboxQueryRelease(request, { run = exec, now = Date.now } = {}) {
  try {
    const revalidate = request?.operation === "revalidate";
    if (!closed(request, ["schema", "operation", "options", ...(revalidate ? ["previous"] : [])]) || request.schema !== schema || !["observe", "revalidate", "observe-query"].includes(request.operation)) reject();
    if (!closed(request.options, ["kubeconfig", "context", "namespace", "namespaceUID", "expected", "deadlineUnixMs"]) || !Number.isSafeInteger(request.options.deadlineUnixMs)) reject();
    if (revalidate && (!closed(request.previous, ["schema", "observation", "apiResourceVersion"]) || request.previous.schema !== schema || !version(request.previous.apiResourceVersion))) reject();
    // Copy request data before any asynchronous boundary. Capture only the very
    // deployment response that the existing full-consumer observer validates.
    const options = structuredClone(request.options);
    const previous = revalidate ? structuredClone(request.previous) : undefined;
    let deploymentResponse;
    const dependencies = { now, run: async (command, args, bounds) => {
      const result = await run(command, args, bounds);
      if (args[4] === "get" && args[5] === "deployment") deploymentResponse = result.stdout;
      return result;
    } };
    const observation = revalidate
      ? await revalidateSandboxBackfill(previous.observation, options, dependencies)
      : await (request.operation === "observe-query" ? observeSandboxQuery : observeSandboxBackfill)(options, dependencies);
    const api = observation.deployments.find(row => row.name === "agentsec-api");
    const raw = JSON.parse(deploymentResponse).items.find(row => row.metadata.name === "agentsec-api" && row.metadata.uid === api.uid);
    const apiResourceVersion = raw?.metadata?.resourceVersion;
    if (!version(apiResourceVersion) || revalidate && apiResourceVersion !== previous.apiResourceVersion) reject();
    const completedAt = now();
    if (!Number.isSafeInteger(completedAt) || completedAt < observation.observedAt || completedAt >= options.deadlineUnixMs) reject();
    return { schema, observation, apiResourceVersion };
  } catch { reject(); }
}

// Private subprocess protocol for the Go owner. Only stdin JSON is accepted;
// there is no apply operation, ambient configuration or diagnostic data output.
// The Go owner must enforce its deadline and terminate the entire process group.
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  let timer;
  try {
    if (process.argv.length !== 2) reject();
    timer = setTimeout(() => process.stdin.destroy(new Error("observation input expired")), 30000);
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > 4 * 1024 * 1024) reject();
      chunks.push(chunk);
    }
    clearTimeout(timer);
    const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const output = JSON.stringify(await observeSandboxQueryRelease(request));
    if (Buffer.byteLength(output) > 4 * 1024 * 1024) reject();
    process.stdout.write(`${output}\n`);
  } catch {
    process.stdin.destroy();
    process.stderr.write("sandbox query observation rejected\n");
    process.exitCode = 1;
  } finally {
    clearTimeout(timer);
  }
}
