// Invoked by the installed PostgreSQL release test, using a disposable profile.
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { createReporting } from "../extension/reporting.mjs";

const origin = process.env.BROWSER_TEST_ORIGIN;
const policy = { remoteEnabled: true, retentionDays: 7, origins: ["https://claude.ai"] };
let entry;
const store = {
  async load() { return structuredClone(entry); },
  async save(x) { entry = structuredClone(x); },
  async clear() { entry = undefined; },
};
const reporter = createReporting({ origin, cryptoApi: webcrypto, store });
const created = await reporter.status(policy);
assert.equal(created.state, "awaiting_registration");
const admin = await fetch(origin + "/fixture/approve-public-key", { method: "POST", body: JSON.stringify({ key: created.publicKey }) });
assert.equal(admin.status, 200);
const enrolled = await reporter.enroll(policy, process.env.BROWSER_TEST_ID, process.env.BROWSER_TEST_ENV, process.env.BROWSER_TEST_TOKEN);
assert.equal(enrolled.state, "reporting");
await reporter.observe(policy, { day: new Date().toISOString().slice(0, 10), origin: "https://claude.ai" });
assert.equal((await reporter.sync(policy)).state, "reporting");
