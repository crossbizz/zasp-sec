import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { installBoundedSignalCleanup } from "../../scripts/bounded-signal-cleanup.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const image = "ghcr.io/promptfoo/promptfoo:0.121.19@sha256:50d3a796710e4db7a5ede90bf27dc28146ef022a7ebb83914c5105608396fd96";

test("actual pinned Promptfoo image distinguishes pass, security failure, and engine failure", {skip:process.env.ZASP_PROMPTFOO_IMAGE_TEST !== "true", timeout:230_000}, async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "zasp-red-team-image-"));
  const owner = process.env.ZASP_RED_TEAM_IMAGE_PROOF_OWNER ?? randomUUID();
  assert.match(owner,/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  const name = `zasp-red-team-image-${owner}`;
  let creating = Promise.resolve();
  let cleaning = false;
  const command = async (executable, args, timeout = 10_000) => {
    const child = spawn(executable, args, {stdio:["ignore","pipe","pipe"]});
    let output = "";
    child.stdout.on("data", (value) => {output += value;});
    child.stderr.on("data", (value) => {output += value;});
    const deadline = setTimeout(() => child.kill("SIGKILL"), timeout);
    try {const [code,signal] = await once(child,"exit");return {code,signal,output};} finally {clearTimeout(deadline);}
  };
  const cleanup = installBoundedSignalCleanup(async () => {
    cleaning = true;
    try {
      await creating.catch(() => undefined);
      const inspected = await command("docker",["inspect","--format",'{{index .Config.Labels "io.zasp.red-team-image-proof"}}',name],3_000);
      if(inspected.code===0){assert.equal(inspected.output.trim(),owner);const removed=await command("docker",["rm","-f",name],3_000);assert.equal(removed.code,0,"owned proof container cleanup failed");}
      else assert.match(inspected.output,/No such (object|container)/,"owned container cleanup could not verify absence");
    } finally {
      await rm(temporary,{recursive:true,force:true});
    }
  }, {timeout:20_000});
  try {
    const dockerfile = await readFile(path.join(root,"deploy/production/redteam-worker.Dockerfile"),"utf8");
    assert.ok(dockerfile.includes(`FROM ${image}`));
    const production = await readFile(path.join(root,"services/platform/agentsec-worker/red_team_production.go"),"utf8");
    const promptfooPath = /PromptfooPath: "([^"]+)"/.exec(production)?.[1];
    assert.ok(promptfooPath, "production executable pin missing");
    const certificate = await command("openssl", ["req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=agentsec-red-team-adapter.zasp.svc.cluster.local","-addext","subjectAltName=DNS:agentsec-red-team-adapter.zasp.svc.cluster.local","-keyout",path.join(temporary,"key.pem"),"-out",path.join(temporary,"cert.pem")]);
    assert.equal(certificate.code,0,"test certificate creation failed");
    // These are disposable test-only TLS keys, mounted read-only in an offline container.
    await chmod(temporary,0o755);await chmod(path.join(temporary,"key.pem"),0o444);await chmod(path.join(temporary,"cert.pem"),0o444);
    if(cleaning) throw new Error("proof cancelled");
    creating = command("docker", ["create","--name",name,"--label",`io.zasp.red-team-image-proof=${owner}`,"--user","1000:1000","--network","none","--read-only","--cap-drop","ALL","--security-opt","no-new-privileges","--pids-limit","128","--memory","1g","--cpus","2","--tmpfs","/tmp:rw,nosuid,nodev,size=256m,mode=1777","--add-host","agentsec-red-team-adapter.zasp.svc.cluster.local:127.0.0.1","--mount",`type=bind,src=${path.join(root,"workers/redteam-node")},dst=/proof,readonly`,"--mount",`type=bind,src=${temporary},dst=/proof-credentials,readonly`,"--env","ZASP_RED_TEAM_IMAGE_PROOF=true","--env",`ZASP_IMAGE_PROMPTFOO_PATH=${promptfooPath}`,"--entrypoint","/usr/local/bin/node",image,"/proof/image-proof.mjs"]);
    const created = await creating;
    assert.equal(created.code,0,created.output);
    assert.match(created.output.trim(),/^[a-f0-9]{64}$/);
    if(cleaning) throw new Error("proof cancelled");
    const result = await command("docker",["start","--attach",name],200_000);
    assert.equal(result.code,0,result.output);
    for(const verdict of ["pass","fail","engine_error"]) assert.ok(result.output.includes(`actual pinned Promptfoo: ${verdict} verified`));
    assert.ok(result.output.includes("actual pinned Promptfoo: cancellation reaped engine with no completed output"));
    process.stdout.write(result.output);
  } finally {
    try {await cleanup.run();} finally {cleanup.dispose();}
  }
});
