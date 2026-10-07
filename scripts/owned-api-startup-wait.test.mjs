import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { performance } from 'node:perf_hooks';
import { waitForOwnedAPIStartup as wait } from './owned-api-startup-wait.mjs';
import http from 'node:http';
import { spawn } from 'node:child_process';

// These two case bodies are byte-identical in the causal old-helper RED file.
test('already exited owned child cannot authorize a 200', async t => {
  const f = await fixture(t, (_req, res) => res.end('ready'));
  f.child.kill('SIGTERM'); await f.joined;
  await assert.rejects(wait({ ...f, ...options }), /child-exited/);
});
test('non-readyz endpoint is refused before network dispatch', async t => {
  let requests = 0;
  const f = await fixture(t, (_req, res) => { requests++; res.end('ready'); });
  await assert.rejects(wait({ ...f, target: f.target.replace('/readyz', '/other'), ...options }), /inputs/);
  assert.equal(requests, 0);
});
test('real transient 503 retries then accepts exactly 200 and closes sockets/listeners', async t => {
  let requests = 0;
  const f = await fixture(t, (_req, res) => { res.statusCode = ++requests === 1 ? 503 : 200; res.end('ready'); });
  const counts = ['exit', 'close', 'error'].map(name => f.child.listenerCount(name));
  assert.deepEqual(await wait({ ...f, ...options }), { status: 200 });
  assert.equal(requests, 2);
  assert.deepEqual(['exit', 'close', 'error'].map(name => f.child.listenerCount(name)), counts);
  await f.joinSockets();
  assert.equal(f.sockets.size, 0);
});
test('stalled body and request are aborted then joined at absolute deadline', async t => {
  for (const headers of [false, true]) {
    let seen = 0;
    const f = await fixture(t, (_req, res) => { seen++; if (headers) { res.writeHead(200); res.write('partial'); } });
    const began = performance.now();
    await assert.rejects(wait({ ...f, timeoutMS: 140, requestMS: 30, retryMS: 5 }), /deadline/);
    assert.ok(seen >= 1);
    assert.ok(performance.now() - began < 1000, 'absolute deadline extended by stalled requests');
    await f.joinSockets();
    assert.equal(f.sockets.size, 0);
  }
});
test('never-ready status has one bounded absolute allowance', async t => {
  let seen = 0;
  const f = await fixture(t, (_req, res) => { seen++; res.statusCode = 503; res.end('not ready'); });
  const began = performance.now();
  await assert.rejects(wait({ ...f, timeoutMS: 120, requestMS: 25, retryMS: 5 }), /deadline/);
  assert.ok(seen > 1); assert.ok(performance.now() - began < 1000);
});
test('real child exit during 503 polling refuses promptly and closes probe', async t => {
  const f = await fixture(t, (_req, res) => { res.statusCode = 503; res.end('not ready'); f.child.kill('SIGTERM'); });
  const began = performance.now();
  await assert.rejects(wait({ ...f, timeoutMS: 1000, requestMS: 100, retryMS: 5 }), /child-exited/);
  assert.ok(performance.now() - began < 750); await f.joined;
  await f.joinSockets(); assert.equal(f.sockets.size, 0);
});
test('200 response arriving after real child exit is not readiness', async t => {
  const f = await fixture(t, async (_req, res) => {
    f.child.kill('SIGTERM'); await f.joined;
    if (!res.destroyed) res.end('ready');
  });
  await assert.rejects(wait({ ...f, ...options }), /child-exited/);
  await f.joinSockets(); assert.equal(f.sockets.size, 0);
});
test('external cleanup cancellation joins a stalled request without raw error disclosure', async t => {
  const controller = new AbortController();
  const f = await fixture(t, () => controller.abort());
  await assert.rejects(wait({ ...f, ...options, signal: controller.signal }), error => error.message === 'owned API startup refused: canceled');
  await f.joinSockets(); assert.equal(f.sockets.size, 0);
});
test('invalid URL and cap inputs never dispatch and oversized body is refused', async t => {
  let requests = 0;
  const f = await fixture(t, (_req, res) => { requests++; res.end('x'.repeat(2049)); });
  for (const target of ['https://127.0.0.1:12345/readyz', 'http://localhost:12345/readyz', 'http://user:password@127.0.0.1:12345/readyz', f.target+'?token=private', f.target+'#secret', 'http://127.0.0.1:99999/readyz', 'http://127.0.0.1:00081/readyz']) {
    await assert.rejects(wait({ ...f, target, ...options }), error => error.message === 'owned API startup refused: inputs');
  }
  for (const caps of [{ timeoutMS: 60001 }, { requestMS: 1001 }, { retryMS: 51 }, { timeoutMS: 0 }, { requestMS: NaN }]) {
    await assert.rejects(wait({ ...f, ...options, ...caps }), /inputs/);
  }
  assert.equal(requests, 0);
  await assert.rejects(wait({ ...f, ...options }), /body-limit/);
});

async function fixture(t, handler) {
  const sockets = new Set();
  const socketCloses = [];
  const server = http.createServer(handler);
  server.on('connection', socket => { sockets.add(socket); socketCloses.push(new Promise(resolve => socket.once('close', resolve))); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const child = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' });
  await once(child, 'spawn');
  const joined = once(child, 'close');
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    await joined;
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  });
  return { server, child, sockets, joinSockets: () => Promise.all(socketCloses), target: `http://127.0.0.1:${server.address().port}/readyz`, joined };
}
const options = { timeoutMS: 250, requestMS: 40, retryMS: 5 };
