import assert from "node:assert/strict";
import test from "node:test";

import { reloadBrowserPage } from "./browser-e2e-helpers.mjs";

test("browser reload preserves the current top-level browsing context", async () => {
  const calls = [];
  const cdp = {
    async send(method, params) {
      calls.push({ method, params });
      return {};
    },
    async replaceTarget() {
      throw new Error("reload replaced the top-level browsing context");
    },
  };

  await reloadBrowserPage(cdp);

  assert.deepEqual(calls, [{ method: "Page.reload", params: { ignoreCache: true } }]);
});
