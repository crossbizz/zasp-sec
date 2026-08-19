import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("combined production E2E owns every local boundary and fixed assertion", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const value of [
    "initdb", "postgres", "agentsec-migrate", "agentsec-api", "vinext", "Google Chrome",
    "/api/v1/session/start", "/auth/callback", "__Host-zasp_session", "Support agent",
    "not_found", "SIGTERM", "pg_ctl", "FIXED_NODE_VERSION",
  ]) assert.match(source, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(source, /(?:^|[/])\.env(?:$|[/ ])|docker|kubectl|localhost:\d{2,5}/i);
});
