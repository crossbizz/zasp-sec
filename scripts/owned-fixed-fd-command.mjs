import { spawn } from "node:child_process";

// Commands may start compilers or other children. Their completion includes the
// inherited output pipes, not just the exit of the command's immediate parent.
export function spawnFixedFDCommand(executableFD, args, options = {}) {
  if (process.platform !== "linux" || !Number.isSafeInteger(executableFD) || executableFD < 3 || Object.hasOwn(options,"stdio")) throw new Error("fixed executable descriptor refused");
  const graceMs = options.graceMs ?? 5000;
  const killMs = options.killMs ?? 2000;
  if (![graceMs, killMs].every((value) => Number.isSafeInteger(value) && value >= 1 && value <= 5000)) {
    throw new TypeError("invalid owned command shutdown bounds");
  }
  const boundedCapture = Object.hasOwn(options, "maxOutputBytes");
  const maxOutputBytes = options.maxOutputBytes;
  if (boundedCapture && (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > 16 * 1024 * 1024)) {
    throw new TypeError("invalid owned command capture limit");
  }
  const grouped = process.platform !== "win32";
  const child = spawn("/proc/self/fd/3", args, {
    cwd: options.cwd, env: options.env, detached: grouped, stdio: ["pipe", "pipe", "pipe", executableFD],
  });
  const spawned = new Promise(resolve => { child.once("spawn",()=>resolve(true)); child.once("error",()=>resolve(false)); });
  let stdout = "", stderr = "", closed = false, failure;
  let capturedOutputBytes = 0, outputLimitExceeded = false;
  const stdoutChunks = [], stderrChunks = [];
  const capture = (value, chunks, isStdout) => {
    if (!boundedCapture) {
      if (isStdout) stdout += value; else stderr += value;
      return;
    }
    const retained = Math.min(value.length, maxOutputBytes - capturedOutputBytes);
    if (retained > 0) {
      // Copy only the permitted slice, not a view retaining a larger backing
      // buffer. After overflow both streams remain drained but are discarded.
      chunks.push(Buffer.from(value.subarray(0, retained)));
      capturedOutputBytes += retained;
    }
    if (retained < value.length && !outputLimitExceeded) {
      outputLimitExceeded = true;
      void stop().catch(error => { failure ??= error; });
    }
  };
  child.stdout.on("data", value => capture(value, stdoutChunks, true));
  child.stderr.on("data", value => capture(value, stderrChunks, false));
  child.stdin.on("error", (error) => { failure ??= error; });
  const completed = new Promise((resolve, reject) => {
    child.once("error", (error) => { failure = error; });
    child.once("close", (status, signal) => {
      closed = true;
      if (failure) reject(failure);
      else if (boundedCapture) resolve({ status, signal, stdout: Buffer.concat(stdoutChunks).toString("utf8"), stderr: Buffer.concat(stderrChunks).toString("utf8"), capturedOutputBytes, outputLimitExceeded });
      else resolve({ status, signal, stdout, stderr });
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
  return { child, spawned, completed, stop };
}
