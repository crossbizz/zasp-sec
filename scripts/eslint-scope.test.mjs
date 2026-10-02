import assert from "node:assert/strict";
import test from "node:test";
import { ESLint } from "eslint";

test("lint excludes local agent evidence without excluding product code or durable tests", { timeout: 10000 }, async () => {
  const eslint = new ESLint();
  assert.equal(await eslint.isPathIgnored(".superpowers/sdd/example/standalone-smoke.mjs"), true);
  assert.equal(await eslint.isPathIgnored("superpowers/sdd/example/source-snapshot.mjs"), true);
  assert.equal(await eslint.isPathIgnored("docs/internal/archive/root-checkpoint-2026-10-01/scripts/launch-batch.mjs"), true);
  assert.equal(await eslint.isPathIgnored("services/platform/migrations/tools/ordered-current-private-historical-v1/tools/ordered-current-catalog.mjs"), true);
  assert.equal(await eslint.isPathIgnored("services/platform/migrations/tools/ordered-current-catalog.mjs"), false);
  assert.equal(await eslint.isPathIgnored("app/features/securityagents/SecurityAgentsView.tsx"), false);
  assert.equal(await eslint.isPathIgnored("scripts/dependency-esbuild-regression.test.mjs"), false);
  assert.equal(await eslint.isPathIgnored("scripts/eslint-scope.test.mjs"), false);
});

test("recovery confirmation component satisfies active UI lint rules", { timeout: 10000 }, async () => {
  const [result] = await new ESLint().lintFiles("app/features/securityagents/SingleTestRecoveryPanel.tsx");
  assert.equal(result.errorCount, 0, JSON.stringify(result.messages));
});

test("ordinary product scripts still reject accidental control-byte regexes", { timeout: 10000 }, async () => {
  const [result] = await new ESLint().lintText("const expression = /\\x00/; console.log(expression);", { filePath: "scripts/ordinary-validation.mjs" });
  assert.ok(result.messages.some(message => message.ruleId === "no-control-regex"));
});
