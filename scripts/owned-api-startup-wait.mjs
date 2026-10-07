import http from 'node:http';
import { performance } from 'node:perf_hooks';

export class OwnedAPIStartupError extends Error {
  constructor(reason) { super(`owned API startup refused: ${reason}`); this.name = 'OwnedAPIStartupError'; }
}
const refused = reason => new OwnedAPIStartupError(reason);
const alive = child => child.exitCode === null && child.signalCode === null;
const bounded = (value, maximum) => Number.isSafeInteger(value) && value > 0 && value <= maximum;

// This is a harness boot allowance, not a provider, SQL or request budget.
// Only a canonical owned loopback HTTP /readyz may be probed. No response body
// or network error is returned/logged. Every attempted request is closed first.
export async function waitForOwnedAPIStartup({ target, child, timeoutMS = 60_000, requestMS = 1_000, retryMS = 50, signal } = {}) {
  if (typeof target !== 'string' || !/^http:\/\/(?:127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}\/readyz$/.test(target) ||
      !child || !Number.isSafeInteger(child.pid) || child.pid <= 0 || typeof child.on !== 'function' || typeof child.removeListener !== 'function' ||
      !bounded(timeoutMS, 60_000) || !bounded(requestMS, 1_000) || !bounded(retryMS, 50) ||
      (signal !== undefined && !(signal instanceof AbortSignal))) throw refused('inputs');
  let url;
  try { url = new URL(target); } catch { throw refused('inputs'); }
  if (url.href !== target || !url.port || Number(url.port) > 65535) throw refused('inputs');
  const deadline = performance.now() + timeoutMS;
  const abort = new AbortController();
  let failure;
  const stop = reason => { failure ??= reason; abort.abort(); };
  const childStopped = () => stop('child-exited');
  const canceled = () => stop('canceled');
  child.on('exit', childStopped); child.on('close', childStopped); child.on('error', childStopped);
  signal?.addEventListener('abort', canceled, { once: true });
  const timer = setTimeout(() => stop('deadline'), timeoutMS);
  const check = () => {
    if (!alive(child)) stop('child-exited');
    if (signal?.aborted) stop('canceled');
    if (performance.now() >= deadline) stop('deadline');
    if (failure) throw refused(failure);
  };
  try {
    check();
    while (true) {
      const status = await probe(url, Math.min(requestMS, deadline - performance.now()), abort.signal);
      check(); // A 200 observed after child death/deadline is never accepted.
      if (status === 200) return { status: 200 };
      if (status === -1) throw refused('body-limit');
      await pause(Math.min(retryMS, deadline - performance.now()), abort.signal);
      check();
    }
  } finally {
    clearTimeout(timer);
    abort.abort();
    child.removeListener('exit', childStopped); child.removeListener('close', childStopped); child.removeListener('error', childStopped);
    signal?.removeEventListener('abort', canceled);
  }
}

function probe(url, milliseconds, signal) {
  return new Promise(resolve => {
    let status = 0, bytes = 0, response;
    const request = http.get(url, { agent: false }, incoming => {
      response = incoming;
      incoming.on('error', () => { if (status !== -1) status = 0; request.destroy(); });
      incoming.on('aborted', () => { if (status !== -1) status = 0; request.destroy(); });
      incoming.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 2048) { status = -1; incoming.destroy(); request.destroy(); }
      });
      incoming.on('end', () => { if (status !== -1) status = incoming.statusCode ?? 0; request.destroy(); });
    });
    const stop = () => { response?.destroy(); request.destroy(); };
    const timer = setTimeout(stop, Math.max(1, Math.ceil(milliseconds)));
    signal.addEventListener('abort', stop, { once: true });
    request.on('error', () => { if (status !== -1) status = 0; });
    request.once('close', () => {
      clearTimeout(timer); signal.removeEventListener('abort', stop);
      response?.destroy(); resolve(status);
    });
    if (signal.aborted) stop();
  });
}

function pause(milliseconds, signal) {
  return new Promise(resolve => {
    const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve(); };
    const timer = setTimeout(finish, Math.max(1, Math.ceil(milliseconds)));
    signal.addEventListener('abort', finish, { once: true });
    if (signal.aborted) finish();
  });
}
