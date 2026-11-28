import "./owned-api-startup-wait.test.mjs";
import assert from "node:assert/strict";
import test from "node:test";

import { JSDOM } from "jsdom";
import { readComplianceSourceDetail, reloadBrowserPage, revealComplianceExport } from "./browser-e2e-helpers.mjs";

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

test("source detail binds freshness and exact time to the mounted evidence card", () => {
  const {document} = new JSDOM(`<time datetime="2040-01-01"></time><span class="badge">fresh</span>
    <section class="evidence-source"><header class="card__header"><span class="badge">stale</span></header>
    <dl><dt>Source ID</dt><dd><code>policy-fixture</code></dd><dt>Version</dt><dd>7</dd><dt>Recorded</dt>
    <dd><time datetime="2020-01-01T00:00:00+00:00">1 Jan 2020, 00:00 UTC</time></dd></dl></section>`).window;
  const detail = readComplianceSourceDetail(document);
  assert.deepEqual(detail, {id: "policy-fixture", version: "7", recorded: "2020-01-01T00:00:00+00:00", freshness: "stale"});
  assert.equal(Date.parse(detail.recorded), Date.UTC(2020, 0, 1));
  document.querySelector("section").remove();
  assert.equal(readComplianceSourceDetail(document), null);
});

test("screenshot reveal scrolls to the exact export button and still checks its viewport bounds", () => {
  const {document} = new JSDOM("<button>Evidence exports</button><button>Create evidence export</button>").window;
  const button = document.querySelectorAll("button")[1];
  let top = 1100;
  button.scrollIntoView = ({block}) => { assert.equal(block, "center"); top = 420; };
  button.getBoundingClientRect = () => ({top, bottom: top + 36, height: 36, width: 140});
  assert.equal(revealComplianceExport(document, 900), true);
  assert.equal(revealComplianceExport(document, 400), false);
  button.remove();
  assert.equal(revealComplianceExport(document, 900), false);
});
