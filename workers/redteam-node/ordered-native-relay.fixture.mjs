// Test-only TCP relay for the actual pinned engine. TLS stays end-to-end
// between Promptfoo and the owning Go HTTPS adapter; this process has no key.
import {createServer, connect} from "node:net";
import {spawn} from "node:child_process";
import {once} from "node:events";

const [portText,input,output] = process.argv.slice(2);
const port = Number(portText);
if (process.argv.length !== 5 || !Number.isInteger(port) || port < 1024 || port > 65535 ||
    !input?.startsWith("/private/") && !input?.startsWith("/var/") && !input?.startsWith("/tmp/") ||
    !output?.startsWith("/private/") && !output?.startsWith("/var/") && !output?.startsWith("/tmp/") ||
    process.env.ZASP_RED_TEAM_TARGET_ENDPOINT !== "https://agentsec-red-team-adapter.zasp-system.svc.cluster.local/v1/effects/evaluate" ||
    process.env.ZASP_PROMPTFOO_BIN !== "/app/dist/src/entrypoint.js") {
  throw new Error("invalid owned engine relay configuration");
}
const sockets = new Set();
const server = createServer(incoming => {
  const upstream = connect({host:"host.docker.internal",port});
  for (const socket of [incoming,upstream]) {
    sockets.add(socket);
    socket.on("close",()=>sockets.delete(socket));
    socket.on("error",()=>{incoming.destroy();upstream.destroy();});
  }
  incoming.pipe(upstream).pipe(incoming);
});
server.listen(443,"127.0.0.1");
await once(server,"listening");
let child;
const stop = () => child?.kill("SIGTERM");
process.once("SIGTERM",stop);
process.once("SIGINT",stop);
try {
  child = spawn(process.execPath,["/app/redteam-runner.mjs","run",input,output],{
    env:process.env,stdio:"inherit",
  });
  const [code,signal] = await once(child,"exit");
  process.exitCode = signal === null && code === 0 ? 0 : 1;
} finally {
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => server.close(resolve));
  process.removeListener("SIGTERM",stop);
  process.removeListener("SIGINT",stop);
}
