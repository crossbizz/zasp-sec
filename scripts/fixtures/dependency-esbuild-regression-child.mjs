import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

const require = createRequire(import.meta.url);
const fromDrizzle = createRequire(require.resolve("drizzle-kit"));
const fromLoader = createRequire(fromDrizzle.resolve("@esbuild-kit/esm-loader"));
const corePath = fromLoader.resolve("@esbuild-kit/core-utils");
const fromCore = createRequire(corePath);
const parser = fromCore.resolve("esbuild");
const esbuild = fromCore("esbuild");
const owned = await mkdtemp(join(tmpdir(), "zasp-esbuild-regression-"));
let context;

function readLocal(port, origin) {
  return new Promise((resolveResponse, reject) => {
    // Only the owned listener is contacted. The .invalid Origin is a header,
    // never a network destination. Responses are capped before evaluation.
    const req = request({ hostname: "127.0.0.1", port, path: "/entry.js", method: "GET",
      headers: origin ? { Origin: origin } : {}, timeout: 2_000 }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
        if (Buffer.byteLength(body) > 8 * 1024) req.destroy(new Error("fixture response too large"));
      });
      res.on("error", reject);
      res.on("end", () => resolveResponse({ status: res.statusCode, allowOrigin: res.headers["access-control-allow-origin"] ?? null, body }));
    });
    req.on("timeout", () => req.destroy(new Error("owned request timed out")));
    req.on("error", reject);
    req.end();
  });
}

let result;
try {
  if (process.argv[2] === "cors") {
    await writeFile(join(owned, "entry.ts"), "export const fixtureValue: number = 17;\n");
    context = await esbuild.context({ absWorkingDir: owned, entryPoints: ["entry.ts"], outdir: "out",
      bundle: true, format: "esm", write: false, logLevel: "silent" });
    const server = await context.serve({ host: "127.0.0.1", port: 0 });
    const control = await readLocal(server.port);
    const crossOrigin = await readLocal(server.port, "https://unrelated.invalid");
    for (const response of [control, crossOrigin]) {
      const fixtureModule = await import(`data:text/javascript;base64,${Buffer.from(response.body).toString("base64")}`);
      response.value = fixtureModule.fixtureValue;
      delete response.body;
    }
    result = { parser, control, crossOrigin };
  } else if (process.argv[2] === "transform") {
    const core = require(corePath);
    const source = 'type Note = { id: number; title: string; content: string; createdAt: string }; export const note: Note = { id: 7, title: "local-note", content: "", createdAt: "2026-09-15" };';
    const asyncResult = await core.transform(source, join(owned, "note.mts"));
    const asyncModule = await import(`data:text/javascript;base64,${Buffer.from(asyncResult.code).toString("base64")}`);
    const syncResult = core.transformSync(source, join(owned, "note.cts"));
    const syncModule = { exports: {} };
    runInNewContext(syncResult.code, { module: syncModule, exports: syncModule.exports }, { timeout: 1_000 });
    result = { async: asyncModule.note, sync: syncModule.exports.note };
  } else if (process.argv[2] === "drizzle") {
    const root = fileURLToPath(new URL("../../", import.meta.url));
    const cli = resolve(dirname(require.resolve("drizzle-kit")), "bin.cjs");
    const generated = join(owned, "generated");
    const command = spawnSync(process.execPath, [cli, "generate", "--dialect", "sqlite", "--schema",
      join(root, "examples/d1/db/schema.ts"), "--out", generated], {
      cwd: owned, env: { PATH: dirname(process.execPath), TZ: "UTC", ESBK_DISABLE_CACHE: "1" },
      encoding: "utf8", timeout: 10_000, maxBuffer: 16 * 1024, killSignal: "SIGKILL",
    });
    if (command.error || command.status !== 0 || command.signal || command.stderr) {
      throw new Error(`drizzle generation failed: ${JSON.stringify({ status: command.status, signal: command.signal, error: command.error?.message, stdout: command.stdout, stderr: command.stderr })}`);
    }
    const snapshot = JSON.parse(await readFile(join(generated, "meta/0000_snapshot.json"), "utf8"));
    const sqlFiles = (await readdir(generated)).filter(name => name.endsWith(".sql"));
    if (sqlFiles.length !== 1) throw new Error("expected one generated migration");
    result = { tables: Object.keys(snapshot.tables), columns: snapshot.tables.notes.columns,
      sql: await readFile(join(generated, sqlFiles[0]), "utf8") };
  } else throw new Error("unknown esbuild regression mode");
} finally {
  if (context) await context.dispose();
  // Old esbuild has no exported stop(); its service exits with the child.
  // The parent checks that the entire process group has exited in both cases.
  if (typeof esbuild.stop === "function") await esbuild.stop();
  // Only this invocation's mkdtemp directory is removed, never project data.
  await rm(owned, { recursive: true, force: true });
}
process.stdout.write(JSON.stringify(result));
