import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { checkCompiledBuild, checkSourceGraph } from "./check-production-imports.mjs";

async function fixture(files) {
  const root = await mkdtemp(join(tmpdir(), "zasp-production-imports-"));
  await Promise.all(Object.entries(files).map(async ([name, value]) => {
    const path = join(root, name);
    await mkdir(join(path, ".."), { recursive: true });
    await writeFile(path, value);
  }));
  return root;
}

test("source graph accepts an API-only production entry", async () => {
  const root = await fixture({
    "app/page.tsx": 'export { App } from "./App";',
    "app/[...path]/page.tsx": 'export { App } from "../App";',
    "app/App.tsx": 'import { get } from "../apps/web/api/client"; export const App = get;',
    "apps/web/api/client.ts": "export const get = 1;",
  });
  const result = await checkSourceGraph({ root });
  assert.equal(result.files.length, 4);
});

test("source graph rejects transitive demo, fixture, and browser storage imports", async () => {
  const cases = [
    ["demo module", 'import "./components/ZaspDemoApp";', "app/components/ZaspDemoApp.tsx", "export const Demo = 1;"],
    ["fixture module", 'import "./data/fixtures";', "app/data/fixtures.ts", "export const fixture = 1;"],
    ["browser storage", 'import "./Product";', "app/Product.tsx", 'window.localStorage.setItem("state", "bad");'],
  ];
  for (const [name, source, target, targetSource] of cases) {
    const root = await fixture({
      "app/page.tsx": source,
      "app/[...path]/page.tsx": "export {};",
      [target]: targetSource,
    });
    await assert.rejects(() => checkSourceGraph({ root }), new RegExp(name));
  }
});

test("compiled closure accepts clean client and server chunks", async () => {
  const root = await fixture({
    "dist/client/.vite/manifest.json": JSON.stringify({
      "virtual:vinext-app-browser-entry": { file: "entry.js", isEntry: true, dynamicImports: ["app/components/ZaspProductionApp.tsx"] },
      "app/components/ZaspProductionApp.tsx": { file: "production.js", src: "app/components/ZaspProductionApp.tsx" },
    }),
    "dist/client/entry.js": "import('./production.js')",
    "dist/client/production.js": "const title = 'Findings';",
    "dist/server/.vite/manifest.json": JSON.stringify({
      "app/page.tsx": { file: "page.js", src: "app/page.tsx", isDynamicEntry: true, imports: ["_production.js"] },
      "app/[...path]/page.tsx": { file: "catch.js", src: "app/[...path]/page.tsx", isDynamicEntry: true, imports: ["_production.js"] },
      "_production.js": { file: "production.js", imports: [] },
    }),
    "dist/server/page.js": "export const page = true;",
    "dist/server/catch.js": "export const page = true;",
    "dist/server/production.js": "const title = 'Attack Paths';",
  });
  const result = await checkCompiledBuild({ root });
  assert.deepEqual(result, { clientChunks: 2, serverChunks: 3 });
});

test("compiled closure rejects forbidden sources and bundled demo sentinels", async () => {
  const forbiddenSource = await fixture({
    "dist/client/.vite/manifest.json": JSON.stringify({
      "virtual:vinext-app-browser-entry": { file: "entry.js", isEntry: true, imports: ["app/domain/store.tsx"] },
      "app/domain/store.tsx": { file: "store.js", src: "app/domain/store.tsx" },
    }),
    "dist/client/entry.js": "production",
    "dist/client/store.js": "state",
    "dist/server/.vite/manifest.json": JSON.stringify({
      "app/page.tsx": { file: "page.js", src: "app/page.tsx", isDynamicEntry: true },
      "app/[...path]/page.tsx": { file: "catch.js", src: "app/[...path]/page.tsx", isDynamicEntry: true },
    }),
    "dist/server/page.js": "page",
    "dist/server/catch.js": "page",
  });
  await assert.rejects(() => checkCompiledBuild({ root: forbiddenSource }), /forbidden source/);

  const forbiddenSentinel = await fixture({
    "dist/client/.vite/manifest.json": JSON.stringify({
      "virtual:vinext-app-browser-entry": { file: "entry.js", isEntry: true },
    }),
    "dist/client/entry.js": 'const storageKey = "zasp-demo-state";',
    "dist/server/.vite/manifest.json": JSON.stringify({
      "app/page.tsx": { file: "page.js", src: "app/page.tsx", isDynamicEntry: true },
      "app/[...path]/page.tsx": { file: "catch.js", src: "app/[...path]/page.tsx", isDynamicEntry: true },
    }),
    "dist/server/page.js": "page",
    "dist/server/catch.js": "page",
  });
  await assert.rejects(() => checkCompiledBuild({ root: forbiddenSentinel }), /forbidden sentinel/);
});
