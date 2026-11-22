// Load the real package into an isolated, temporary Chromium profile over a
// local debugger pipe. No extension policies are installed on the host.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const extension = fileURLToPath(new URL("../extension", import.meta.url));
const profile = await mkdtemp(join(tmpdir(), "zasp-browser-test-"));
const fixtureUI = process.argv.includes("--fixture-ui");
const args = [
  "--headless=new", "--remote-debugging-pipe", "--disable-dev-shm-usage", "--disable-sync",
  "--disable-background-networking", "--disable-component-update", "--no-first-run", "--no-default-browser-check",
  "--host-resolver-rules=MAP * ~NOTFOUND", "--user-data-dir=" + profile,
  "about:blank",
];
if (!fixtureUI) args.unshift("--enable-unsafe-extension-debugging");
if (process.env.BROWSER_GUARD_TEST_NO_SANDBOX === "1") args.unshift("--no-sandbox");
const browser = spawn(process.env.CHROMIUM_BIN || "chromium", args, { stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"] });
const closed = once(browser, "close").catch(() => {});
let stderr = "";
browser.stderr.on("data", (data) => { stderr = (stderr + data).slice(-1500); });
let next = 0;
const callbacks = new Map();
let input = "";
browser.stdio[4].setEncoding("utf8");
browser.stdio[4].on("data", (chunk) => {
  input += chunk;
  for (let end; (end = input.indexOf("\0")) >= 0;) {
    const message = JSON.parse(input.slice(0, end));
    input = input.slice(end + 1);
    callbacks.get(message.id)?.(message);
  }
});
function send(method, params = {}, sessionId) {
  if (browser.exitCode !== null || browser.signalCode) throw Error("Chromium exited before " + method + "\n" + stderr);
  return new Promise((resolve, reject) => {
    const id = ++next;
    const timer = setTimeout(() => { callbacks.delete(id); reject(Error(method + " timed out\n" + stderr)); }, 4000);
    callbacks.set(id, (message) => {
      clearTimeout(timer);
      callbacks.delete(id);
      if (message.error) reject(Error(method + ": " + message.error.message));
      else resolve(message.result);
    });
    browser.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + "\0");
  });
}
async function until(check) {
  for (let attempt = 0; attempt < 60; attempt++) {
    const value = await check();
    if (value) return value;
    await delay(100);
  }
  throw Error("Chromium did not reach the required popup state");
}
try {
  const version = await send("Browser.getVersion");
  const target = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId: target.targetId, flatten: true });
  async function evaluate(expression) {
    const result = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }, sessionId);
    assert.equal(result.exceptionDetails, undefined);
    return result.result.value;
  }
  if (fixtureUI) {
    // Exercise the popup DOM and script with synthetic local data. No
    // attempt is made to install an extension or change browser management.
    const data = {policy:{status:"enabled",retentionDays:7,origins:["https://claude.ai"]},observations:[{day:"2026-01-01",origin:"https://claude.ai"}]};
    const page = (await readFile(join(extension, "status.html"), "utf8"))
      .replace('<script src="status.js"></script>', "").replace('<link rel="stylesheet" href="status.css">', "");
    const script = await readFile(join(extension,"status.js"),"utf8");
    const {frameTree} = await send("Page.getFrameTree", {}, sessionId);
    await send("Page.setDocumentContent", {frameId:frameTree.frame.id, html:page}, sessionId);
    await evaluate("globalThis.chrome ??= {}; chrome.runtime = {sendMessage:async () => (" +
      JSON.stringify(data) + ")};\n" + script);
    try {
      await until(async () => await evaluate('document.querySelector("#status")?.textContent') === "Local app usage collection enabled.");
    } catch (error) {
      const state = await evaluate('[document.title, document.querySelector("#status")?.textContent, typeof globalThis.chrome?.runtime].join(" | ")');
      throw Error("Local popup fixture failed: " + state, { cause: error });
    }
    assert.equal(await evaluate('document.querySelector("#observations").innerText'), "2026-01-01 · https://claude.ai");
    console.log(version.product + ": real Chromium popup rendering with fixture data; extension APIs and enrollment outside this test");
  } else {
    const loaded = await send("Extensions.loadUnpacked", { path: extension });
    await send("Page.navigate", {url:"chrome-extension://" + loaded.id + "/status.html"}, sessionId);
    const status = await until(async () =>
      (await evaluate('document.querySelector("#status")?.textContent')) === "Managed policy required. Collection is off.");
    assert.ok(status);
    const blank = await evaluate('chrome.storage.local.get(null)');
    assert.deepEqual(blank, {});
    assert.deepEqual(await evaluate('chrome.scripting.getRegisteredContentScripts()'), []);
    // Exercise the real browser registration, storage and cleanup APIs with an
    // explicitly synthetic policy adapter. This does not test enterprise rollout.
    const registrations = await evaluate(`(async () => {
      const {createGuard} = await import(chrome.runtime.getURL("guard.mjs"));
      let config = {Enabled: true, AllowedOrigins: ["https://claude.ai"]};
      const guard = createGuard({runtime: chrome.runtime, scripting: chrome.scripting,
        storage: {local: chrome.storage.local, managed: {get: async () => config}}});
      await guard.refresh();
      const rules = await chrome.scripting.getRegisteredContentScripts();
      config = {Enabled: false}; await guard.refresh();
      return {rules, cleaned: await chrome.scripting.getRegisteredContentScripts()};
    })()`);
    assert.deepEqual(registrations.rules.map((rule) => rule.matches), [["https://claude.ai/*"]]);
    assert.deepEqual(registrations.cleaned, []);
    console.log(version.product + ": loaded real extension, policy-off popup, empty storage, fixture-rule registration and removal");
  }
} finally {
  try { await send("Browser.close"); } catch {}
  if (browser.exitCode === null && !browser.signalCode) {
    await Promise.race([closed, delay(500)]);
    if (browser.exitCode === null && !browser.signalCode) browser.kill("SIGKILL");
  }
  await closed;
  await rm(profile, { recursive: true, force: true, maxRetries: 3 });
}
