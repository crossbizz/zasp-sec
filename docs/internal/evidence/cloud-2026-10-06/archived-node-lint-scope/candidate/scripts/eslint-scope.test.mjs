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


const archivedNodeFiles = [
  "docs/internal/evidence/cloud-2026-10-06/native379-v2-safe-diagnostics/evidence/ordered-current-native379-packet-v2.mjs",
  "docs/internal/evidence/cloud-2026-10-06/native379-v2-safe-diagnostics/evidence/ordered-current-native379-packet-v2.test.mjs",
];
const nextModuleRule = "@next/next/no-assign-module-variable";

test("the two archived Node evidence files retain lint coverage without the Next-only module rule", { timeout: 10000 }, async () => {
  const eslint = new ESLint();
  for (const file of archivedNodeFiles) {
    assert.equal(await eslint.isPathIgnored(file), false);
    const [result] = await eslint.lintFiles(file);
    assert.equal(result.errorCount, 0, JSON.stringify(result.messages));
    const config = await eslint.calculateConfigForFile(file);
    assert.equal(config.rules[nextModuleRule][0], 0);
  }
});

test("ordinary web modules retain the module-name and raw-fetch security rules", { timeout: 10000 }, async () => {
  const [result] = await new ESLint().lintText("const module = {}; console.log(module); await fetch('/api/unsafe');", { filePath: "app/ordinary-web-module.mjs" });
  assert.ok(result.messages.some(message => message.ruleId === nextModuleRule));
  assert.ok(result.messages.some(message => message.ruleId === "zasp/no-raw-fetch"));
});

test("unreviewed evidence neighbors and later dates retain the Next-only module rule", { timeout: 10000 }, async () => {
  const eslint = new ESLint();
  for (const file of [
    "docs/internal/evidence/cloud-2026-10-06/native379-v2-safe-diagnostics/evidence/unreviewed-node-tool.mjs",
    "docs/internal/evidence/cloud-2026-10-07/native379-v2-safe-diagnostics/evidence/ordered-current-native379-packet-v2.mjs",
  ]) {
    assert.equal(await eslint.isPathIgnored(file), false);
    const [result] = await eslint.lintText("const module = {}; console.log(module);", { filePath: file });
    assert.ok(result.messages.some(message => message.ruleId === nextModuleRule));
  }
});

test("both archived Node paths still reject control-byte regexes", { timeout: 10000 }, async () => {
  const eslint = new ESLint();
  for (const file of archivedNodeFiles) {
    const [result] = await eslint.lintText("const module = {}; console.log(module); const expression = /\\x00/; console.log(expression);", { filePath: file });
    assert.ok(result.messages.some(message => message.ruleId === "no-control-regex"));
    assert.equal(result.messages.some(message => message.ruleId === nextModuleRule), false);
  }
});
