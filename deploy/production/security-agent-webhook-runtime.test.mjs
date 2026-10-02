import assert from "node:assert/strict";
import test from "node:test";
import { validateWebhookTestEvents } from "./security-agent-webhook-runtime.mjs";

const name = "TestSecurityAgentWebhookAuthorityPostgres";
const events = values => values.map(Action => JSON.stringify({ Test: name, Action })).join("\n");
test("proof requires the selected test to run and pass without any skip", () => {
  assert.equal(validateWebhookTestEvents(events(["run", "pass"]), [name]).length, 2);
  for (const value of ["", events(["run", "skip"]), events(["run", "fail"]), events(["pass"]), events(["run", "run", "pass"]), events(["run", "pass", "skip"])]) {
    assert.throws(() => validateWebhookTestEvents(value, [name]));
  }
});
