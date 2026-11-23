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
const managedProfile = process.argv.includes("--managed-profile");
const managedID = process.env.BROWSER_GUARD_MANAGED_ID;
const expected = process.env.BROWSER_GUARD_UPLOAD_STATE;
if (managedProfile && (fixtureUI || !/^[a-p]{32}$/.test(managedID ?? "") || !["active","disabled"].includes(expected))) {
  throw Error("Managed profile verification requires an installed extension ID and expected upload state.");
}
const args = [
  "--headless=new", "--remote-debugging-pipe", "--disable-dev-shm-usage", "--disable-sync",
  "--disable-background-networking", "--disable-component-update", "--no-first-run", "--no-default-browser-check",
  "--host-resolver-rules=MAP * ~NOTFOUND", "--user-data-dir=" + profile,
  "about:blank",
];
if (!fixtureUI && !managedProfile) args.unshift("--enable-unsafe-extension-debugging");
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
    const data = {policy:{status:"enabled",retentionDays:7,origins:["https://claude.ai"]},uploads:{status:"active",count:1},observations:[{day:"2026-01-01",origin:"https://claude.ai"}]};
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
    assert.match(await evaluate('document.querySelector("#uploads").innerText'), /^1 exact upload/);
    console.log(version.product + ": real Chromium popup rendering with fixture data; extension APIs and enrollment outside this test");
  } else if (managedProfile) {
    // The normal enterprise store installs the signed build. This mode only
    // reads the profile's actual managed storage, registered rules and popup.
    const url = "chrome-extension://" + managedID + "/status.html";
    await until(async () => {
      await send("Page.navigate", {url}, sessionId);
      await delay(180);
      return evaluate('Boolean(document.querySelector("#uploads"))');
    });
    const proof = await evaluate(`(async () => {
      const raw = await chrome.storage.managed.get(["Enabled","AllowedOrigins","UploadBlockingEnabled","UploadBlockingRoutes"]);
      const local = await chrome.runtime.sendMessage({kind:"local-status"});
      const applied = (await chrome.declarativeNetRequest.getSessionRules()).filter(r=>r.id>=8100 && r.id<8108);
      const valid = raw.Enabled === true && raw.UploadBlockingEnabled === true && Array.isArray(raw.UploadBlockingRoutes) &&
        raw.UploadBlockingRoutes.length > 0 && raw.UploadBlockingRoutes.length === applied.length &&
        raw.UploadBlockingRoutes.every(url=>applied.some(r=>r.action.type==="block" && r.condition.urlFilter==="|"+url+"|" &&
          r.condition.requestMethods.join(",")==="post" && r.condition.resourceTypes.join(",")==="xmlhttprequest"));
      return {managed:raw.Enabled===true, status:local.uploads?.status, count:applied.length, valid};
    })()`);
    assert.equal(proof.managed,true);
    assert.equal(proof.status,expected);
    if (expected === "active") assert.equal(proof.valid,true);
    else assert.equal(proof.count,0);
    console.log(version.product+": signed managed profile acknowledged "+proof.count+" exact upload rules.");
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
      const route = "https://chatgpt.com/backend-api/files";
      let config = {Enabled: true, AllowedOrigins: ["https://claude.ai", "https://chatgpt.com"]};
      const guard = createGuard({runtime: chrome.runtime, scripting: chrome.scripting, declarativeNetRequest: chrome.declarativeNetRequest,
        storage: {local: chrome.storage.local, managed: {get: async () => config}}});
      const matching = async (url, method = "post", initiator = "https://chatgpt.com") =>
        (await chrome.declarativeNetRequest.testMatchOutcome({url, method, initiator, type: "xmlhttprequest"})).matchedRules.map(r => r.ruleId);
      await guard.refresh();
      const before = await matching(route);
      config = {...config, UploadBlockingEnabled: true, UploadBlockingRoutes: [route]};
      const active = (await guard.refresh()).uploads;
      const during = await matching(route);
      const unrelated = await Promise.all([matching(route, "get"), matching(route+"/"), matching(route+"?q=x"), matching(route, "post", "https://unrelated.example")]);
      const rules = await chrome.scripting.getRegisteredContentScripts();
      config = {Enabled: false}; await guard.refresh();
      return {rules, before, active, during, unrelated, after:await matching(route), cleaned: await chrome.scripting.getRegisteredContentScripts()};
    })()`);
    assert.deepEqual(registrations.rules.flatMap(rule => rule.matches).sort(), ["https://chatgpt.com/*","https://claude.ai/*"]);
    assert.deepEqual(registrations.before, []);
    assert.deepEqual(registrations.active, {status:"active",count:1});
    assert.deepEqual(registrations.during, [8100]);
    assert.deepEqual(registrations.unrelated, [[],[],[],[]]);
    assert.deepEqual(registrations.after, []);
    assert.deepEqual(registrations.cleaned, []);
    console.log(version.product + ": loaded real extension, policy-off popup, empty storage, fixture-rule registration and removal");
  }
} finally {
  try {
    await send("Browser.close");
  } catch {
    // Chromium can close the debugging socket before acknowledging shutdown.
  }
  if (browser.exitCode === null && !browser.signalCode) {
    await Promise.race([closed, delay(500)]);
    if (browser.exitCode === null && !browser.signalCode) browser.kill("SIGKILL");
  }
  await closed;
  await rm(profile, { recursive: true, force: true, maxRetries: 3 });
}
