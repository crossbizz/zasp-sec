import assert from "node:assert/strict";
import net from "node:net";
import { once, EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";
import { spawn } from "node:child_process";
import { createIsolatedPostgresBridge } from "./isolated-postgres-bridge.mjs";

test("bridge stop rejects numeric failure and signals it did not issue", async (t) => {
  for (const [name, code, signal] of [["exit7", 7, null], ["unissued-term", null, "SIGTERM"], ["unissued-kill", null, "SIGKILL"]]) await t.test(name, async () => {
    let accepted;
    const connection = new Promise(resolve => { accepted = resolve; });
    const bridge = createIsolatedPostgresBridge({containerID: "d".repeat(64), port: 0, spawnProcess: () => {
      const child = new EventEmitter();
      child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => true;
      // stop() destroys this stream before either escalation timer can fire.
      child.stdout.once("close", () => queueMicrotask(() => child.emit("close", code, signal)));
      accepted();
      return child;
    }});
    await bridge.start();
    const socket = net.connect(bridge.port, "127.0.0.1");
    try {
      await Promise.all([once(socket, "connect"), connection]);
      await assert.rejects(bridge.stop(), error => error instanceof AggregateError && error.errors.some(cause => cause.message.includes(`owned relay exited ${code}/${signal}`)));
      assert.equal(bridge.connections, 0);
    } finally {
      socket.destroy();
      await bridge.stop().catch(() => {});
    }
  });
});

test("bridge accepts SIGPIPE only after its own peer-close path", async (t) => {
  for (const outcome of ["owned-pipe", "owned-nonzero", "spontaneous-pipe", "spontaneous-nonzero"]) await t.test(outcome, async () => {
    let child;
    let accepted;
    const connection = new Promise(resolve => { accepted = resolve; });
    const bridge = createIsolatedPostgresBridge({containerID: "c".repeat(64), port: 0, spawnProcess: () => {
      child = new EventEmitter();
      child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => {};
      if (outcome.startsWith("owned-")) child.stdout.once("close", () => queueMicrotask(() => child.emit("close", outcome === "owned-nonzero" ? 7 : null, outcome === "owned-pipe" ? "SIGPIPE" : null)));
      accepted();
      return child;
    }});
    await bridge.start();
    const socket = net.connect(bridge.port, "127.0.0.1");
    try {
      await Promise.all([once(socket, "connect"), connection]);
      // A controlled process exit is the slow/external boundary; the actual
      // bridge owns the socket and decides whether it initiated pipe closure.
      const closed = once(socket, "close");
      const joined = once(child, "close");
      if (outcome.startsWith("owned-")) socket.destroy();
      else child.emit("close", outcome === "spontaneous-nonzero" ? 7 : null, outcome === "spontaneous-pipe" ? "SIGPIPE" : null);
      await Promise.all([closed, joined]);
      await new Promise(resolve => setImmediate(resolve));
      if (outcome === "owned-pipe") await bridge.stop();
      else await assert.rejects(bridge.stop(), /bridge failed/);
      assert.equal(bridge.connections, 0);
    } finally {
      socket.destroy();
      await bridge.stop().catch(() => {});
    }
  });
});

test("bridge forwards raw bytes only through its owned container and joins on stop", async () => {
  const id = "a".repeat(64), calls = [];
  const spawnProcess = (executable, args, options) => {
    calls.push({ executable, args, options });
    const child = new EventEmitter();
    child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
    child.stdin.pipe(child.stdout);
    child.stdin.on("close", () => child.emit("close", 0, null));
    return child;
  };
  const bridge = createIsolatedPostgresBridge({ containerID: id, port: 0, spawnProcess });
  await bridge.start();
  const socket = net.connect(bridge.port, "127.0.0.1");
  await once(socket, "connect");
  const reply = once(socket, "data"); socket.write(Buffer.from([0, 1, 255, 9]));
  assert.deepEqual((await reply)[0], Buffer.from([0, 1, 255, 9]));
  assert.deepEqual(calls[0].args, ["exec", "-i", id, "/zasp-postgres-relay"]);
  assert.equal(calls[0].executable, "docker");
  const closed = once(socket, "close");
  await bridge.stop(); await closed;
  assert.equal(bridge.connections, 0);
  await bridge.stop();
  await assert.rejects(bridge.start(), /stopped/);
});

test("bridge rejects foreign container identity and invalid bounds before listening", () => {
  for (const containerID of ["", "foreign", "a".repeat(63), "A".repeat(64)]) assert.throws(() => createIsolatedPostgresBridge({containerID, port: 54321}), /identity/);
  for (const port of [-1, 65536, "5432"]) assert.throws(() => createIsolatedPostgresBridge({containerID: "a".repeat(64), port}), /port/);
});

test("bridge joins only its own SIGTERM and SIGKILL escalation", async (t) => {
  for (const signal of ["SIGTERM", "SIGKILL"]) await t.test(signal, async () => {
    let child;
    const bridge = createIsolatedPostgresBridge({containerID: "b".repeat(64), port: 0, spawnProcess: () => {
      const handler = signal === "SIGKILL" ? "process.on('SIGTERM',()=>{});" : "";
      child = spawn(process.execPath, ["-e", handler + "process.stdin.resume();process.stdin.on('end',()=>{});setInterval(()=>{},1000);process.stdout.write('ready');"], {stdio:["pipe","pipe","pipe"]});
      return child;
    }});
    await bridge.start();
    const socket = net.connect(bridge.port, "127.0.0.1");
    try {
      await once(socket, "data");
      await bridge.stop();
      assert.equal(child.signalCode, signal);
      assert.equal(bridge.connections, 0);
      assert.throws(() => process.kill(child.pid, 0), {code:"ESRCH"});
    } finally {
      socket.destroy();
      if (child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); await once(child, "close"); }
    }
  });
});
