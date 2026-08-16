import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";

import { ESLint, Linter } from "eslint";

import noRawFetchRule from "./no-raw-fetch.mjs";

const repositoryRoot = resolve(import.meta.dirname, "..");
const ruleID = "zasp/no-raw-fetch";
const ruleConfig = [
  {
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
    },
    plugins: {
      zasp: {
        rules: {
          "no-raw-fetch": noRawFetchRule,
        },
      },
    },
    rules: {
      [ruleID]: "error",
    },
  },
];

function lintRule(source) {
  const linter = new Linter({ configType: "flat" });
  return linter.verify(source, ruleConfig);
}

test("seeded raw API Fetch calls fail with the generated-client diagnostic", () => {
  const violations = [
    'fetch("/api/v1/home/summary");',
    "globalThis.fetch(path);",
    'window["fetch"]?.(new Request(path));',
    "self.fetch.call(null, path);",
    "fetch.apply(null, [path]);",
    "fetch.bind(null, path);",
  ];

  for (const source of violations) {
    const messages = lintRule(source);
    assert.equal(messages.length, 1, source);
    assert.equal(messages[0]?.ruleId, ruleID, source);
    assert.equal(messages[0]?.messageId, "useGeneratedClient", source);
    assert.equal(
      messages[0]?.message,
      "Use the generated API client from apps/web/api/client.ts instead of raw Fetch.",
      source,
    );
  }
});

test("generated-client calls and inert public API strings remain valid", () => {
  for (const source of [
    'client.GET("/api/v1/home/summary");',
    'const documentation = "/api/v1/home/summary";',
    'const fetcher = { fetch() {} }; fetcher.fetch("/api/v1/home/summary");',
  ]) {
    assert.deepEqual(lintRule(source), [], source);
  }
});

test("flat config rejects normal frontend files and exempts only the client boundary", async () => {
  const eslint = new ESLint({ cwd: repositoryRoot });
  const cases = [
    ["app/seeded-raw-fetch.ts", 1],
    ["apps/web/page.tsx", 1],
    ["apps/web/api/other.ts", 1],
    ["apps/web/api/client.ts", 0],
    ["apps/web/api/generated.ts", 0],
    ["proofs/seeded-raw-fetch.mjs", 0],
  ];

  for (const [relativePath, want] of cases) {
    const [result] = await eslint.lintText('fetch("/api/v1/home/summary");', {
      filePath: resolve(repositoryRoot, relativePath),
      warnIgnored: false,
    });
    assert.ok(result, relativePath);
    const messages = result.messages.filter(({ ruleId }) => ruleId === ruleID);
    assert.equal(messages.length, want, relativePath);
  }
});
