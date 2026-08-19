const SIGNAL_EXIT_CODES = new Map([["SIGINT", 130], ["SIGTERM", 143]]);

export function installBoundedSignalCleanup(cleanup, options = {}) {
  if (typeof cleanup !== "function") throw new TypeError("cleanup must be a function");
  const timeout = options.timeout ?? 45_000;
  const exit = options.exit ?? ((code) => process.exit(code));
  if (!Number.isSafeInteger(timeout) || timeout < 1 || typeof exit !== "function") throw new TypeError("invalid cleanup options");
  let pending;
  const run = () => {
    if (!pending) pending = bounded(Promise.resolve().then(cleanup), timeout);
    return pending;
  };
  const handlers = new Map();
  for (const [signal, code] of SIGNAL_EXIT_CODES) {
    const handler = () => { void run().catch(() => undefined).finally(() => exit(code)); };
    handlers.set(signal, handler);
    process.once(signal, handler);
  }
  return {
    run,
    dispose() {
      for (const [signal, handler] of handlers) process.removeListener(signal, handler);
    },
  };
}

function bounded(operation, timeout) {
  let deadline;
  const expired = new Promise((_, reject) => {
    deadline = setTimeout(() => reject(new Error("owned cleanup exceeded its deadline")), timeout);
    deadline.unref?.();
  });
  return Promise.race([operation, expired]).finally(() => clearTimeout(deadline));
}
