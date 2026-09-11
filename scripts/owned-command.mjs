import { spawn } from "node:child_process";

// Commands may start compilers or other children. Their completion includes the
// inherited output pipes, not just the exit of the command's immediate parent.
export function spawnOwnedCommand(executable, args, options = {}) {
  const graceMs = options.graceMs ?? 5000;
  const killMs = options.killMs ?? 2000;
  if (![graceMs, killMs].every((value) => Number.isSafeInteger(value) && value >= 1 && value <= 5000)) {
    throw new TypeError("invalid owned command shutdown bounds");
  }
  const grouped = process.platform !== "win32";
  const child = spawn(executable, args, {
    cwd: options.cwd, env: options.env, detached: grouped, stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "", stderr = "", closed = false, failure;
  child.stdout.on("data", (value) => { stdout += value; });
  child.stderr.on("data", (value) => { stderr += value; });
  child.stdin.on("error", (error) => { failure ??= error; });
  const completed = new Promise((resolve, reject) => {
    child.once("error", (error) => { failure = error; });
    child.once("close", (status, signal) => {
      closed = true;
      if (failure) reject(failure); else resolve({ status, signal, stdout, stderr });
    });
  });
  // The owner awaits completion later, including during signal cleanup.
  void completed.catch(() => {});
  if (options.input) child.stdin.end(options.input); else child.stdin.end();
  const signal = (name) => {
    // Never signal historical completed commands, an ambient process group, or
    // a guessed PID. A detached POSIX child owns its group from creation.
    if (closed || !Number.isSafeInteger(child.pid) || child.pid <= 1) return;
    try {
      if (grouped) process.kill(-child.pid, name);
      else child.kill(name);
    } catch (error) {
      if (error.code !== "ESRCH") throw error;
    }
  };
  const settles = async (milliseconds) => {
    let timer;
    try {
      return await Promise.race([
        completed.then(() => true, () => true),
        new Promise((resolve) => { timer = setTimeout(() => resolve(false), milliseconds); }),
      ]);
    } finally { clearTimeout(timer); }
  };
  let stopping;
  const stop = () => stopping ??= (async () => {
    if (!closed) {
      signal("SIGTERM");
      if (!await settles(graceMs)) {
        signal("SIGKILL");
        if (!await settles(killMs)) throw new Error("owned command descendants did not settle");
      }
    }
    // Execution errors belong to the caller of completed. Cleanup still joins
    // a failed spawn or stdin write without aborting the owner's other cleanup.
    await completed.catch(() => {});
  })();
  return { child, completed, stop };
}
