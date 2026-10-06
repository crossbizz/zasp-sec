import assert from "node:assert/strict";
import fs from "node:fs";
import { ESLint } from "eslint";
const before = new ESLint({overrideConfigFile: "baseline-eslint.config.mjs"});
const after = new ESLint();
const rule = "@next/next/no-assign-module-variable";
const archived = [
 "docs/internal/evidence/cloud-2026-10-06/native379-v2-safe-diagnostics/evidence/ordered-current-native379-packet-v2.mjs",
 "docs/internal/evidence/cloud-2026-10-06/native379-v2-safe-diagnostics/evidence/ordered-current-native379-packet-v2.test.mjs",
];
const paths = [...archived, "app/ordinary-web-module.mjs", "apps/web/ordinary-web-module.mjs", "scripts/ordinary-validation.mjs", "services/platform/migrations/tools/ordinary-tool.mjs", "docs/internal/evidence/cloud-2026-10-06/native379-v2-safe-diagnostics/evidence/unreviewed-node-tool.mjs", "docs/internal/evidence/cloud-2026-10-07/native379-v2-safe-diagnostics/evidence/ordered-current-native379-packet-v2.mjs"];
const results = [];
for (const path of paths) {
 const a = await before.calculateConfigForFile(path), b = await after.calculateConfigForFile(path);
 const changed = [...new Set([...Object.keys(a.rules), ...Object.keys(b.rules)])].filter(key => JSON.stringify(a.rules[key]) !== JSON.stringify(b.rules[key]));
 assert.deepEqual(changed, archived.includes(path) ? [rule] : []);
 if (archived.includes(path)) { assert.equal(a.rules[rule][0], 2); assert.equal(b.rules[rule][0], 0); }
 assert.deepEqual(a.languageOptions, b.languageOptions);
 assert.deepEqual(a.settings, b.settings);
 assert.deepEqual(Object.keys(a.plugins), Object.keys(b.plugins));
 results.push({path, active_rule_count: Object.keys(b.rules).length, changed_rule_keys: changed, ignored: await after.isPathIgnored(path)});
}
fs.writeFileSync("../evidence/config-rule-scope-comparison.json", JSON.stringify({assessment:"PASS", results}, null, 2)+"\n");
