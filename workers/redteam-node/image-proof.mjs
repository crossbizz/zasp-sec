// Executed only inside the pinned, network-isolated integration-test container.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import https from "node:https";
import { buildPromptfooConfiguration } from "./runner.mjs";

assert.equal(process.env.ZASP_RED_TEAM_IMAGE_PROOF, "true");
const input = {
  schema_version: "red-team-runner-input-v1",
  organization_id: "pid_99300001-0000-4000-8000-000000000001",
  workspace_id: "pid_99300002-0000-4000-8000-000000000002",
  environment_id: "pid_99300003-0000-4000-8000-000000000003",
  run_id: "pid_99300004-0000-4000-8000-000000000004",
  definition_id: "pid_99300005-0000-4000-8000-000000000005",
  definition_version: 1,
  target_id: "pid_99300006-0000-4000-8000-000000000006",
  target_kind: "agent_endpoint",
  categories: ["prompt_injection", "tool_abuse"],
  input_digest: "a".repeat(64),
};
const endpoint = "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate";
const token = "isolated-image-proof-token-".repeat(4);
const lease = "b".repeat(32);
const configuration = buildPromptfooConfiguration(input, endpoint);
let mode = "pass";
let requests = [];
const server = https.createServer({key: await readFile("/proof-credentials/key.pem"), cert: await readFile("/proof-credentials/cert.pem")}, async (request, response) => {
  try {
    assert.equal(request.url, "/v1/evaluate");
    assert.equal(request.method, "POST");
    assert.equal(request.headers.authorization, `Bearer ${token}`);
    assert.equal(request.headers["x-zasp-organization-id"], input.organization_id);
    assert.equal(request.headers["x-zasp-workspace-id"], input.workspace_id);
    assert.equal(request.headers["x-zasp-environment-id"], input.environment_id);
    assert.equal(request.headers["x-zasp-run-id"], input.run_id);
    assert.equal(request.headers["x-zasp-run-lease"], lease);
    let body = "";
    for await (const chunk of request) { body += chunk; assert.ok(body.length <= 4096); }
    const value = JSON.parse(body);
    const curated = configuration.tests.find((item) => item.vars.category === value.category);
    assert.ok(curated);
    assert.deepEqual(value, {target_id: input.target_id, target_kind: input.target_kind, category: curated.vars.category, input: curated.vars.prompt});
    requests.push(value.category);
    response.writeHead(mode === "engine_error" ? 503 : 200, {"content-type":"application/json"});
    response.end(JSON.stringify({output: mode === "fail" ? curated.assert[0].value : "Protected boundary"}));
  } catch {
    response.writeHead(400, {"content-type":"application/json"});
    response.end(JSON.stringify({error:"proof request rejected"}));
  }
});
server.listen(443, "127.0.0.1");
await once(server, "listening");
try {
  for (const verdict of ["pass", "fail", "engine_error"]) {
    mode = verdict; requests = [];
    const directory = `/tmp/red-team-image-${verdict}`;
    await mkdir(directory, {mode:0o700});
    await writeFile(`${directory}/input.json`, JSON.stringify(input), {mode:0o600});
    await writeFile(`${directory}/token`, token, {mode:0o600});
    const child = spawn(process.execPath, ["/proof/runner.mjs", "run", `${directory}/input.json`, `${directory}/output.json`], {
      env: {HOME:directory, ZASP_PROMPTFOO_BIN:process.env.ZASP_IMAGE_PROMPTFOO_PATH, ZASP_RED_TEAM_TARGET_ENDPOINT:endpoint, ZASP_RED_TEAM_ADAPTER_TOKEN_FILE:`${directory}/token`, ZASP_RED_TEAM_TARGET_CA_FILE:"/proof-credentials/cert.pem", ZASP_RED_TEAM_RUN_LEASE:lease},
      stdio:"ignore",
    });
    const timeout = setTimeout(() => child.kill("SIGKILL"), 60_000);
    const [code, signal] = await once(child, "exit");
    clearTimeout(timeout);
    assert.equal(code, 0, `${verdict}: production runner failed (${signal ?? code})`);
    const output = JSON.parse(await readFile(`${directory}/output.json`, "utf8"));
    assert.equal(output.engine, "promptfoo");
    assert.equal(output.engine_version, "0.121.19");
    assert.equal(output.run_id, input.run_id);
    assert.equal(output.input_digest, input.input_digest);
    assert.equal(output.verdict, verdict);
    assert.ok(!JSON.stringify(output).includes(lease),"lease entered normalized evidence");
    assert.deepEqual([...new Set(requests)].sort(), [...input.categories].sort());
    assert.doesNotMatch(JSON.stringify(output), /isolated-image-proof-token|ZASP_RED_TEAM_|Protected boundary|credential_reference/);
    process.stdout.write(`actual pinned Promptfoo: ${verdict} verified\n`);
  }
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
