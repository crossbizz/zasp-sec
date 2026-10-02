import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export async function forwardAuditPage(stream, response, query, trace, fault = {}) {
  const started = fault.startedAt ?? performance.now();
  let body = await boundedResponse(stream, 1048576, "bounded audit response exceeded");
  let status = stream.statusCode;
  let headers = stream.headers;
  if (fault.fail) {
    assert.equal(status, 200, "Next fault did not reach a genuine successful upstream response");
    status = 503;
    headers = { "content-type": "application/json", "cache-control": "no-store" };
    body = JSON.stringify({ code: "dependency_unavailable", message: "Owned audit Next response failure", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true });
  }
  let released = false;
  const release = () => {
    assert.equal(released, false, "delayed audit response already released"); released = true;
    const page = status === 200 ? JSON.parse(body) : null;
    if (page) {
      const filters = new URLSearchParams(query);
      for (const item of page.items) {
        for (const key of ["actor_id", "action", "outcome"]) if (filters.has(key)) assert.equal(item[key], filters.get(key), `actual audit ${key} predicate mismatch`);
        if (filters.has("from")) assert.ok(item.occurred_at >= filters.get("from"), "actual audit inclusive from predicate mismatch");
        if (filters.has("to")) assert.ok(item.occurred_at < filters.get("to"), "actual audit exclusive to predicate mismatch");
      }
    }
    if (page && fault.verifyWitness) fault.verifyWitness(page);
    trace.record({ query, status, ids: page?.items.map(item => item.id) ?? [], page_info: page?.page_info ?? null, elapsed_ms: performance.now() - started });
    response.writeHead(status, headers); response.end(body); body = "";
  };
  if (fault.delay) { assert.equal(status, 200, "delay did not reach genuine successful upstream response"); fault.onDelayed(release); }
  else release();
}

export function assertAuditPublicWitnessProjection(page, expectedEvents) {
  for (const { source } of expectedEvents) {
    const item = page.items.find(item => item.id === source.id);
    if (!item) continue;
    for (const key of ["action", "actor_id", "target_id", "outcome", "workspace_id", "environment_id", "occurred_at"]) assert.equal(item[key], source[key], `public source witness ${key} mismatch`);
    assert.deepEqual(item.metadata, source.metadata, "public source provenance mismatch");
  }
}

function boundedResponse(stream, bound, label) {
  return new Promise((resolve, reject) => {
    let bytes = 0; let chunks = [];
    stream.on("data", chunk => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > bound) { chunks = []; reject(new Error(label)); return; }
      chunks.push(Buffer.from(chunk));
    });
    stream.once("error", () => reject(new Error(label)));
    stream.once("aborted", () => reject(new Error(label)));
    stream.once("end", () => { if (bytes <= bound) resolve(Buffer.concat(chunks).toString("utf8")); });
  });
}
export function createAuditMutationCollector() {
  const records = [];
  return {
    async observe(request, stream) {
      if (stream.statusCode < 200 || stream.statusCode >= 300) return;
      let family, action;
      if (request.method === "POST" && request.path === "/api/v1/policies") [family, action] = ["policy", "policy.create"];
      else if (request.method === "POST" && request.path === "/api/v1/admin/sso-connections") [family, action] = ["sso", "identity_provider.createSSOConnection"];
      else if (request.method === "POST" && /^\/api\/v1\/admin\/sso-connections\/[^/]+\/test$/.test(request.path)) [family, action] = ["sso", "identity_provider.testSSOConnection"];
      else if (request.method === "PATCH" && request.path === "/api/v1/settings/data-controls") [family, action] = ["configuration", "data_controls.update"];
      else if (request.method === "POST" && /^\/api\/v1\/tests\/pid_[0-9a-f-]+\/runs$/.test(request.path)) [family, action] = ["test", "test.run.queued"];
      else if (request.method === "POST" && /^\/api\/v1\/test-runs\/pid_[0-9a-f-]+\/cancel$/.test(request.path)) [family, action] = ["test", "test.run.cancel_requested"];
      else return;
      let id, target = request.target, receipt;
      if (family === "policy" || family === "test") {
        id = stream.headers["x-audit-id"]; receipt = stream.headers["x-mutation-receipt-id"];
        assert.ok(productID.test(receipt), "actual mutation receipt header required");
      } else {
        const body = JSON.parse(await boundedResponse(stream, 4096, "bounded mutation response exceeded"));
        id = body.audit_correlation_id;
        target = family === "configuration" ? body.environment_id : body.id ?? decodeURIComponent(request.path.split("/").at(-2));
      }
      assert.ok(productID.test(id), "actual mutation audit ID required");
      assert.ok(typeof target === "string" && target.length > 0 && target.length <= 128, "actual mutation target required");
      assert.ok(typeof request.scope === "string" && request.scope.split("/").length === 3 && request.scope.split("/").every(id => productID.test(id)), "actual mutation scope required");
      const entry = { family, id, action, target_id: target, scope: request.scope, status: stream.statusCode, ...(receipt ? { receipt_id: receipt } : {}) };
      const previous = records.find(value => value.id === id);
      if (previous) assert.deepEqual(entry, previous, "replayed mutation witness changed");
      else { assert.ok(records.length < 8, "bounded mutation witness count exceeded"); records.push(entry); }
    },
    read: () => structuredClone(records),
  };
}
export async function captureAuditPageResponse(stream, query, trace) {
  const started = performance.now();
  const body = await boundedResponse(stream, 1048576, "bounded audit response exceeded");
  let ids = [], page_info = null;
  if (stream.statusCode === 200) {
    const page = JSON.parse(body);
    assert.ok(Array.isArray(page.items) && page.items.length <= 100, "bounded audit page required");
    ids = page.items.map(item => item.id); page_info = page.page_info;
  }
  trace.record({ query, status: stream.statusCode, ids, page_info, elapsed_ms: performance.now() - started });
}
export async function runAuditLogBrowserProof(configuration) {
  const { expectedEvents, principalID, publicOrigin, browser, readAuditRequests, fixtures } = configuration;
  assertAuditMutationWitnesses(expectedEvents, principalID);
  const deadline = performance.now() + 240_000;
  const labels = { actor_id: "Actor ID (exact)", action: "Action (exact)", from: "From (UTC, inclusive)", to: "To (UTC, exclusive)" };
  const checkTime = () => assert.ok(performance.now() < deadline, "audit browser proof exceeded four-minute budget");
  const rendered = async (record) => {
    await browser.waitForRows(record.ids);
    const snapshot = await browser.snapshot();
    assert.deepEqual(snapshot.rows.map(row => row.id), record.ids, "rendered audit IDs differ from actual response");
    assert.ok(snapshot.rows.length <= 50, "browser retained more than one audit page (not a heap claim)");
    assert.match(snapshot.text, /Audit exports unavailable/);
    assert.equal(snapshot.interactiveExport, false, "uninstalled export became interactive");
    return snapshot;
  };
  const read = async (action, filters = {}, cursor, status = 200) => {
    checkTime();
    const sequence = readAuditRequests().at(-1)?.sequence ?? 0;
    await action();
    const record = await browser.waitForRead(sequence);
    if (status === 200) { assertAuditPage(record, filters, cursor); await rendered(record); }
    else {
      assert.equal(record.status, status, "expected reached audit response boundary");
      assert.deepEqual(Object.fromEntries(new URLSearchParams(record.query)), { limit: "50", ...filters, ...(cursor ? { cursor } : {}) }, "failed audit request query changed");
    }
    return record;
  };
  const draft = async filters => {
    for (const [key, label] of Object.entries(labels)) await browser.fillLabel(label, filters[key] ?? "");
    await browser.selectOption("Outcome", { succeeded: "Succeeded", denied: "Denied", failed: "Failed" }[filters.outcome] ?? "Any outcome");
  };
  const apply = async filters => { await draft(filters); return read(() => browser.clickText("Apply filters"), filters); };
  const find = async (filters, event) => {
    let record = await apply(filters);
    for (let n = 0; !record.ids.includes(event.id); n++) {
      assert.ok(n < 199 && record.page_info.has_more, "actual mutation witness absent from bounded filtered traversal");
      record = await read(() => browser.clickText("Next"), filters, record.page_info.next_cursor);
    }
    const row = (await browser.snapshot()).rows.find(row => row.id === event.id);
    for (const value of [event.action, event.actor_id, event.target_id, event.outcome, event.occurred_at]) assert.ok(row.text.includes(value), "rendered mutation witness fields differ from committed source");
    return record;
  };
  await read(() => browser.navigate(`${publicOrigin}/administration/audit-log`));
  for (const { source: event } of expectedEvents) {
    for (const filters of [{ actor_id: event.actor_id }, { action: event.action }, { outcome: event.outcome }, { from: event.occurred_at }, { to: event.after }, { actor_id: event.actor_id, action: event.action, outcome: event.outcome, from: event.occurred_at, to: event.after }]) await find(filters, event);
    const filters = { action: event.action, from: event.before, to: event.occurred_at };
    const excluded = await apply(filters);
    assert.equal(excluded.ids.includes(event.id), false, "exclusive source-microsecond upper bound included witness");
  }
  const sso = expectedEvents.find(event => event.family === "sso").source;
  for (const filters of [{ actor_id: "pid_7bffffff-ffff-4fff-8fff-ffffffffffff" }, { action: sso.action.toLowerCase() }, { outcome: "failed" }]) {
    const empty = await apply(filters);
    assert.deepEqual(empty.ids, [], "unknown actor/action case/failed outcome was relabeled");
    assert.equal(empty.page_info.has_more, false);
  }
  await find({ action: sso.action }, sso);
  const applied = await browser.snapshot();
  await browser.fillLabel("Action (exact)", "audit.unapplied");
  const unsubmitted = await browser.snapshot();
  assert.deepEqual(unsubmitted.rows, applied.rows, "draft changed displayed rows");
  assert.equal(unsubmitted.applied, applied.applied, "draft relabeled applied identity");
  await read(() => browser.clickText("Clear filters"));

  const fixture = await fixtures.seedPagingRows();
  assert.ok(fixture.count > 2000 && fixture.count <= 5000, "separate bounded paging fixture required");
  assert.ok(expectedEvents.every(event => !event.response.id.startsWith(fixture.idPrefix)), "paging fixture overlaps actual mutations");
  const filters = { action: "audit.browser.paging" };
  let record = await apply(filters);
  let count = 0, pages = 0;
  const digest = createHash("sha256");
  while (true) {
    checkTime(); pages++;
    for (const id of record.ids) {
      assert.equal(id, fixtures.pagingID(fixture.count - count), "stable paging skipped, duplicated or reordered fixture ID");
      digest.update(id + "\n"); count++;
    }
    if (!record.page_info.has_more) break;
    assert.ok(pages < 100, "paging fixture did not terminate");
    const decoded = Buffer.from(record.page_info.next_cursor, "base64url");
    const position = JSON.parse(decoded.subarray(0, -32).toString("utf8"));
    assert.equal(position.i, record.ids.at(-1), "cursor did not bind last returned row");
    record = await read(() => browser.clickText("Next"), filters, record.page_info.next_cursor);
  }
  assert.ok(pages > 20, "browser did not cross twenty pages");
  assert.equal(count, fixture.count);
  assert.equal(digest.digest("hex"), fixture.sha256, "rolling stable-source digest mismatch");
  record = await read(() => browser.clickText("First"), filters);
  assert.equal(record.ids[0], fixtures.pagingID(fixture.count));
  await fixtures.changeOwnedPagingRow();
  await read(() => browser.clickText("Refresh"), filters);
  assert.ok((await browser.snapshot()).rows[0].text.includes("owned-refresh-change"), "Refresh missed committed live-source change");

  const beforeFailure = await browser.snapshot();
  const nextCursor = readAuditRequests().at(-1).page_info.next_cursor;
  fixtures.failNext();
  const failed = await read(() => browser.clickText("Next"), filters, nextCursor, 503);
  await browser.waitForText(/last successful page is still shown/);
  assert.deepEqual((await browser.snapshot()).rows, beforeFailure.rows, "Next failure discarded the last good page");
  const retry = await read(() => browser.clickText("Retry next page"), filters, nextCursor);
  assert.equal(retry.query, failed.query, "retry changed exact failed query/cursor bytes");

  await apply({ action: "audit.browser.crossscope" });
  assert.ok((await browser.snapshot()).rows.some(row => row.id === fixture.crossScopeID), "same-org other-scope row hidden");
  await read(() => browser.selectOption("Authorized scope", "Staging"));
  await apply({ action: "audit.browser.crossscope" });
  assert.ok((await browser.snapshot()).rows.some(row => row.id === fixture.crossScopeID), "selected scope narrowed organization audit source");
  const foreign = await apply({ action: "audit.browser.foreign" });
  assert.deepEqual(foreign.ids, [], "foreign organization audit exposed");
  await read(() => browser.selectOption("Authorized scope", "Production"));
  await apply(filters);
  const delayedPageIDs = (await browser.snapshot()).rows.map(row => row.id);
  fixtures.delayNext();
  await browser.clickText("Next");
  await fixtures.waitDelayed();
  await read(() => browser.selectOption("Authorized scope", "Staging"));
  await apply({ actor_id: "pid_7bffffff-ffff-4fff-8fff-ffffffffffff" });
  await fixtures.releaseDelayed();
  await browser.waitForRows([]);
  assert.deepEqual((await browser.snapshot()).rows, [], "delayed old-scope results painted new filter/identity");
  assert.ok(delayedPageIDs.length > 0);
  await browser.preparePrincipalReplacement();
  await read(() => browser.navigate(`${publicOrigin}/administration/audit-log`));
  await apply(filters);
  assert.equal((await browser.authenticatedPrincipal()).id, principalID, "old request principal was not authenticated");
  const principalCursor = readAuditRequests().at(-1).page_info.next_cursor;
  fixtures.delayNext();
  await browser.clickText("Next");
  await fixtures.waitDelayed();
  try {
    await browser.replacePrincipal();
    const replacement = await browser.authenticatedPrincipal();
    assert.equal(replacement.id, fixtures.replacementPrincipalID, "replacement principal was not authenticated");
    assert.notEqual(replacement.id, principalID, "replacement principal did not change");
    assert.equal(replacement.role, "read_only_viewer");
    assert.equal(replacement.auditRead, false, "replacement principal unexpectedly has audit access");
    await browser.waitForRows([]);
    await fixtures.releaseDelayed();
    assertAuditPage(readAuditRequests().at(-1), filters, principalCursor, [fixtures.pagingID(fixture.count - 50)]);
    await browser.waitForRows([]);
    assert.deepEqual((await browser.snapshot()).rows, [], "delayed old-principal results repainted the read-only session");
    assert.equal((await browser.authenticatedPrincipal()).id, replacement.id, "replacement principal changed during release");
  } finally {
    await browser.restorePrincipal();
  }
  await read(() => browser.navigate(`${publicOrigin}/administration/audit-log`));
  record = await apply(filters);
  try {
    await fixtures.revokeAuditAccess();
    await read(() => browser.clickText("Next"), filters, record.page_info.next_cursor, 403);
    // This must clear on current authorization loss; a general retry panel is
    // not evidence that a now-forbidden page has been invalidated.
    await browser.waitForRows([]);
    assert.deepEqual((await browser.snapshot()).rows, [], "authorization downgrade retained stale audit rows");
  } finally {
    await fixtures.restoreAuditAccess();
  }
  return { mutationWitnesses: expectedEvents.length, pagingRows: count, pages, exportSaving: "NOT RUN", liveIdP: "NOT RUN", externalTestExecution: "NOT RUN" };
}

export function validateAuditBrowserMode(environment) {
  if (!Object.hasOwn(environment, "ZASP_COMBINED_E2E_AUDIT_BROWSE")) return false;
  assert.equal(environment.ZASP_COMBINED_E2E_AUDIT_BROWSE, "true", "audit browser mode requires exact true or absent opt-in");
  for (const key of ["RUNTIME_PIPELINE_ONLY", "RUNTIME_SANDBOX_SEARCH", "RUNTIME_PRECISION", "RUNTIME_PRECISION_BROWSER"]) {
    assert.notEqual(environment[`ZASP_COMBINED_E2E_${key}`], "true", "audit browser mode incompatible with runtime-only/sandbox/precision");
  }
  return true;
}

export function auditBrowserEnvironment(environment) {
  return Object.fromEntries(Object.entries(environment).filter(([key]) => !key.startsWith("ZASP_AUDIT_EXPORT_")));
}

const policy = Object.freeze({ schema: "audit-export-policy-v1", policy_id: "pid_7b000001-0000-4000-8000-000000000001", bucket: "owned-audit-browser-fixture", expected_bucket_owner: "123456789012", kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/7b000002-0000-4000-8000-000000000002", maximum_export_bytes: 1073741824, maximum_retained_bytes: 10737418240, maximum_inflight: 2, capture_timeout_seconds: 120 });
export function auditBrowserAPISettings() {
  return {
    ZASP_AUDIT_EXPORT_POLICIES_JSON: JSON.stringify([policy]),
    ZASP_AUDIT_EXPORT_READER_ROLE_ARN: "arn:aws:iam::123456789012:role/zasp-owned-audit-browser-reader",
    ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY: Buffer.alloc(32, 71).toString("base64url"),
  };
}
export function auditBrowserSetupEnvironment(environment, dsn, port) {
  assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535, "owned setup port required");
  assert.equal(dsn, `postgres://zasp_e2e@127.0.0.1:${port}/postgres?sslmode=disable`, "owned setup DSN required");
  return {
    ...Object.fromEntries(Object.entries(environment).filter(([key]) => !key.startsWith("PG") && !key.startsWith("ZASP_"))),
    ZASP_AUDIT_BROWSER_SETUP: "true", ZASP_AUDIT_BROWSER_SETUP_PORT: String(port), ZASP_AUDIT_BROWSER_SETUP_DSN: dsn,
  };
}
export function auditBrowserPolicyEnvironment() {
  return Object.fromEntries(Object.entries(policy).filter(([key]) => key !== "schema").map(([key, value]) => [`ZASP_AUDIT_EXPORT_${key.toUpperCase()}`, String(value)]));
}
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function assertPageShape(record) {
  assert.ok(Array.isArray(record.ids) && record.ids.length <= 100 && record.ids.every(id => productID.test(id)), "bounded trace IDs required");
  assert.equal(new Set(record.ids).size, record.ids.length, "duplicate page IDs");
  const info = record.page_info;
  assert.ok(info && typeof info.has_more === "boolean", "page info required");
  if (info.has_more) assert.ok(record.ids.length > 0 && typeof info.next_cursor === "string" && info.next_cursor.length > 0 && info.next_cursor.length <= 512, "empty-more or missing cursor");
  else assert.equal(info.next_cursor, null, "terminal cursor must be null");
}
export function assertAuditPage(record, filters, cursor, expected = []) {
  assert.equal(record.status, 200, "audit page did not succeed");
  const query = new URLSearchParams(record.query);
  const entries = [...query];
  assert.equal(new Set(entries.map(([key]) => key)).size, entries.length, "duplicate query keys");
  assert.deepEqual(Object.fromEntries(query), { limit: "50", ...filters, ...(cursor ? { cursor } : {}) }, "audit query omitted or changed a filter/cursor");
  assertPageShape(record);
  for (const id of expected) assert.ok(record.ids.includes(id), "actual mutation witness ID missing from filtered response");
}
export function createAuditRequestTrace() {
  const records = [];
  let sequence = 0;
  return {
    record: entry => {
      assert.deepEqual(Object.keys(entry).sort(), ["elapsed_ms", "ids", "page_info", "query", "status"], "trace accepts only a closed projection");
      assert.ok(typeof entry.query === "string" && Buffer.byteLength(entry.query) <= 2048 && Number.isFinite(entry.elapsed_ms) && entry.elapsed_ms >= 0 && Number.isInteger(entry.status), "bounded trace query/status required");
      if (entry.status === 200) assertPageShape(entry);
      else assert.ok(entry.ids.length === 0 && entry.page_info === null, "error trace retained page data");
      records.push(Object.freeze({ ...structuredClone(entry), sequence: ++sequence }));
      if (records.length > 2) records.shift();
    },
    read: () => structuredClone(records),
  };
}

export function assertAuditMutationWitnesses(events, principalID) {
  assert.ok(Array.isArray(events) && events.length <= 8, "bounded witness set required");
  const families = new Set();
  for (const event of events) {
    assert.ok(event && event.response && event.source, "actual response and committed source witness required");
    const { response, source } = event;
    assert.ok(productID.test(response.id) && response.status >= 200 && response.status < 300, "successful response witness required");
    for (const key of ["id", "action", "target_id"]) assert.equal(source[key], response[key], `source/response witness ${key} mismatch`);
    assert.equal([source.organization_id, source.workspace_id, source.environment_id].join("/"), response.scope, "source/response witness scope mismatch");
    assert.equal(source.actor_id, principalID, "witness actor mismatch");
    assert.equal(source.outcome, "succeeded", "successful witness source outcome required");
    assert.equal(source.source_valid, true, "valid witness source required");
    assert.equal(source.committed, true, "committed witness source required");
    assert.match(source.occurred_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/, "source witness must preserve microseconds");
    assert.ok(source.before < source.occurred_at && source.after > source.occurred_at, "source witness half-open endpoints required");
    const familySource = { sso: "administration", configuration: "administration", policy: "workflow_policy", test: "red_team_mutation" };
    assert.equal(source.source_kind, familySource[event.family], "witness source family mismatch");
    if (event.family === "policy" || event.family === "test") {
      assert.ok(productID.test(response.receipt_id), "response receipt witness required");
      assert.equal(source.receipt_id, response.receipt_id, "source receipt mismatch");
      assert.ok(productID.test(source.correlation_id), "source correlation witness required");
    }
    families.add(event.family);
  }
  assert.deepEqual([...families].sort(), ["configuration", "policy", "sso", "test"], "four mutation families required");
  assert.deepEqual([...new Set(events.map(event => event.source.action))].sort(), ["data_controls.update", "identity_provider.createSSOConnection", "identity_provider.testSSOConnection", "policy.create", "test.run.cancel_requested", "test.run.queued"], "six actual mutation actions required, including SSO test and test cancellation");
  return events;
}
