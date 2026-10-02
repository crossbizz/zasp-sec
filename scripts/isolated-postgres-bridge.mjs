import net from "node:net";
import { spawn } from "node:child_process";

// Raw PostgreSQL wire only. Each local socket owns one bounded docker exec
// stream to a no-options relay in this invocation's network-none container.
export function createIsolatedPostgresBridge({ containerID, port, spawnProcess = spawn } = {}) {
  if (!/^[a-f0-9]{64}$/.test(containerID ?? "")) throw new TypeError("invalid owned container identity");
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) throw new TypeError("invalid bridge port");
  const active = new Set(), errors = [];
  let stopped = false, starting, stopping;
  const server = net.createServer(socket => {
    if (stopped || active.size >= 64) { socket.destroy(); return; }
    const child = spawnProcess("docker", ["exec", "-i", containerID, "/zasp-postgres-relay"], { stdio: ["pipe", "pipe", "pipe"] });
    let resolve, closed = false, closing = false, terminate, kill, stderr = "";
    let terminateSent = false, killSent = false;
    const entry = { socket, child, joined: new Promise(done => { resolve = done; }) };
    active.add(entry);
    const close = () => {
      socket.destroy(); child.stdin.destroy(); child.stdout.destroy();
      if (closed || closing) return;
      closing = true;
      // EOF normally joins the fixed relay. Bound ownership even if the CLI
      // becomes stuck: signals address this child process only, never a group.
      terminate = setTimeout(() => { if (!closed) terminateSent = child.kill("SIGTERM"); }, 250);
      kill = setTimeout(() => { if (!closed) killSent = child.kill("SIGKILL"); }, 1250);
    };
    entry.close = close;
    child.once("error", error => { errors.push(error); close(); });
    child.stderr.on("data", chunk => { stderr = (stderr + chunk.toString()).slice(-4096); });
    child.stdin.on("error", close); child.stdout.on("error", close); socket.on("error", close);
    const deadline = setTimeout(close, 120_000);
    child.once("close", (code, signal) => {
      // Destroying our output pipe during an owned close can signal the CLI.
      // Escalation signals count only after this bridge successfully sent them.
      // Numeric failures remain failures even while stop() is in progress.
      const ownedSignalClose = code === null && closing && (signal === "SIGPIPE" || signal === "SIGTERM" && terminateSent || signal === "SIGKILL" && killSent);
      closed = true; clearTimeout(deadline); clearTimeout(terminate); clearTimeout(kill); close(); active.delete(entry); resolve();
      if (code !== 0 && !ownedSignalClose) errors.push(new Error(`owned relay exited ${code}/${signal}: ${stderr}`));
    });
    socket.once("close", close);
    socket.pipe(child.stdin); child.stdout.pipe(socket);
  });
  server.on("error", error => { if (!starting) errors.push(error); });
  return {
    get port() { return server.address()?.port; },
    get connections() { return active.size; },
    start() {
      if (stopped) return Promise.reject(new Error("owned bridge stopped"));
      starting ??= new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); });
      });
      return starting;
    },
    stop() {
      stopping ??= (async () => {
        stopped = true;
        await starting?.catch(() => {});
        const closedServer = new Promise((resolve, reject) => server.close(error => error && error.code !== "ERR_SERVER_NOT_RUNNING" ? reject(error) : resolve()));
        const entries = [...active];
        for (const entry of entries) entry.close();
        let timer;
        try {
          await Promise.race([Promise.all([closedServer, ...entries.map(e => e.joined)]), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("owned PostgreSQL bridge did not join")), 3000); })]);
        } finally { clearTimeout(timer); }
        if (errors.length) throw new AggregateError(errors, "owned PostgreSQL bridge failed");
      })();
      return stopping;
    },
  };
}
