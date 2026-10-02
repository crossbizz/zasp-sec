import assert from "node:assert/strict";
import test from "node:test";
import { Readable } from "node:stream";
import { createHash } from "node:crypto";
import { createAuditMutationCollector, captureAuditPageResponse, runAuditLogBrowserProof, forwardAuditPage, assertAuditPublicWitnessProjection } from "./audit-log-browser-proof.mjs";
import { auditBrowserEnvironment, auditBrowserAPISettings, auditBrowserPolicyEnvironment, auditBrowserSetupEnvironment, assertAuditMutationWitnesses, assertAuditPage, createAuditRequestTrace, validateAuditBrowserMode } from "./audit-log-browser-proof.mjs";

test("audit acceptance refuses empty/unknown opt-ins and incompatible modes before setup", () => {
  assert.equal(validateAuditBrowserMode({}), false);
  assert.equal(validateAuditBrowserMode({ ZASP_COMBINED_E2E_AUDIT_BROWSE: "true" }), true);
  for (const value of ["", "false", "TRUE", "1"]) {
    assert.throws(() => validateAuditBrowserMode({ ZASP_COMBINED_E2E_AUDIT_BROWSE: value }), /audit browser mode/);
  }
  for (const key of ["RUNTIME_PIPELINE_ONLY", "RUNTIME_SANDBOX_SEARCH", "RUNTIME_PRECISION", "RUNTIME_PRECISION_BROWSER"]) {
    assert.throws(() => validateAuditBrowserMode({ ZASP_COMBINED_E2E_AUDIT_BROWSE: "true", [`ZASP_COMBINED_E2E_${key}`]: "true" }), /incompatible/);
  }
});

test("selected API receives four exact reader settings matching the configured policy", () => {
  const settings = auditBrowserAPISettings();
  assert.deepEqual(Object.keys(settings).sort(), ["ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY", "ZASP_AUDIT_EXPORT_POLICIES_JSON", "ZASP_AUDIT_EXPORT_READER_ROLE_ARN", "ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE"]);
  const policy = JSON.parse(settings.ZASP_AUDIT_EXPORT_POLICIES_JSON)[0];
  assert.equal(policy.schema, "audit-export-policy-v1");
  assert.equal(policy.policy_id, auditBrowserPolicyEnvironment().ZASP_AUDIT_EXPORT_POLICY_ID);
  assert.equal(policy.bucket, auditBrowserPolicyEnvironment().ZASP_AUDIT_EXPORT_BUCKET);
  assert.equal(settings.ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE, "/var/run/secrets/eks.amazonaws.com/serviceaccount/token");
  assert.notEqual(settings.ZASP_AUDIT_EXPORT_READER_ROLE_ARN, "arn:aws:iam::000000000000:role/zasp-production-e2e-api-connectors");
});

test("setup child gets only the fixed owned connection and opt-in, without ambient PG or ZASP state", () => {
  assert.deepEqual(auditBrowserSetupEnvironment({ PATH: "/owned", PGOPTIONS: "secret", ZASP_POSTGRES_DSN: "ambient", ZASP_OTHER: "" }, "postgres://zasp_e2e@127.0.0.1:54321/postgres?sslmode=disable", 54321), {
    PATH: "/owned", ZASP_AUDIT_BROWSER_SETUP: "true", ZASP_AUDIT_BROWSER_SETUP_PORT: "54321", ZASP_AUDIT_BROWSER_SETUP_DSN: "postgres://zasp_e2e@127.0.0.1:54321/postgres?sslmode=disable",
  });
});

const eventID = "pid_11111111-1111-4111-8111-111111111111";
const actor = "pid_22222222-2222-4222-8222-222222222222";
const record = { query: "?limit=50&actor_id="+actor, status: 200, ids: [eventID], page_info: { has_more: false, next_cursor: null }, elapsed_ms: 1 };
test("audit page assertion refuses omitted filters, wrong query, status and missing actual ID", () => {
  assert.doesNotThrow(() => assertAuditPage(record, { actor_id: actor }, undefined, [eventID]));
  for (const bad of [{ ...record, query: "?limit=50" }, { ...record, query: record.query+"&action=policy.create" }, { ...record, status: 503 }, { ...record, ids: [] }, { ...record, page_info: { has_more: true, next_cursor: null } }]) {
    assert.throws(() => assertAuditPage(bad, { actor_id: actor }, undefined, [eventID]));
  }
  for (const key of ["actor_id", "action", "outcome", "from", "to"]) {
    assert.throws(() => assertAuditPage({ ...record, query: "?limit=50" }, { [key]: "required" }, undefined, []));
  }
});

test("trace retains two bounded projections across thousands of pages and refuses arbitrary bodies", () => {
  const trace = createAuditRequestTrace();
  for (let n=0;n<2100;n++) trace.record(record);
  assert.equal(trace.read().length, 2);
  assert.throws(() => trace.record({ ...record, body: "secret" }), /trace/);
  assert.throws(() => trace.record({ ...record, ids: Array(101).fill(eventID) }), /trace/);
  assert.throws(() => trace.record({ ...record, query: "x".repeat(2049) }), /trace/);
});

test("default child removes audit setting presence without mutating the parent", () => {
  const parent = { PATH: "/owned/bin", ZASP_AUDIT_EXPORT_POLICIES_JSON: "ambient", ZASP_AUDIT_EXPORT_FUTURE: "", ZASP_POSTGRES_DSN: "kept" };
  assert.deepEqual(auditBrowserEnvironment(parent), { PATH: "/owned/bin", ZASP_POSTGRES_DSN: "kept" });
  assert.equal(parent.ZASP_AUDIT_EXPORT_POLICIES_JSON, "ambient");
});

test("labels cannot substitute for actual four-family response identities", () => {
  assert.throws(() => assertAuditMutationWitnesses([]), /four mutation families/);
  assert.throws(() => assertAuditMutationWitnesses([{ action: "policy.create" }]), /witness/);
});

function witnesses() {
  return [["sso", "identity_provider.createSSOConnection", "administration"], ["configuration", "data_controls.update", "administration"], ["policy", "policy.create", "workflow_policy"], ["test", "test.run.queued", "red_team_mutation"], ["sso", "identity_provider.testSSOConnection", "administration"], ["test", "test.run.cancel_requested", "red_team_mutation"]].map(([family, action, source_kind], index) => {
    const id = `pid_11111111-1111-4111-8111-11111111111${index}`;
    const target = family === "policy" ? "policy-production" : actor;
    return { family, response: { id, status: 201, action, target_id: target, scope: [actor, actor, actor].join("/"), receipt_id: actor }, source: { id, action, target_id: target, actor_id: actor, organization_id: actor, workspace_id: actor, environment_id: actor, occurred_at: "2026-09-12T00:00:00.123456Z", before: "2026-09-12T00:00:00.123455Z", after: "2026-09-12T00:00:00.123457Z", outcome: "succeeded", source_kind, source_valid: true, committed: true, receipt_id: actor, correlation_id: actor, metadata: {} } };
  });
}
test("witness validation binds actual response ID/action/target/scope and receipt to committed source", () => {
  assert.doesNotThrow(() => assertAuditMutationWitnesses(witnesses(), actor));
  for (const [key, value] of [["id", actor], ["action", "policy.delete"], ["target_id", eventID], ["workspace_id", eventID], ["outcome", "denied"], ["committed", false], ["source_valid", false], ["receipt_id", eventID], ["occurred_at", "2026-09-12T00:00:00.123Z"]]) {
    const events = witnesses(); events[2].source[key] = value;
    assert.throws(() => assertAuditMutationWitnesses(events, actor), /witness|source|response|receipt/);
  }
  assert.throws(() => assertAuditMutationWitnesses(witnesses(), eventID), /actor/);
});

test("four families cannot hide a missing actual SSO test or test cancellation witness", () => {
  for (const action of ["identity_provider.testSSOConnection", "test.run.cancel_requested"]) assert.throws(() => assertAuditMutationWitnesses(witnesses().filter(event => event.response.action !== action), actor), /six actual mutation/);
});

test("actual mutation collector captures bounded headers before policy loss and SSO/config response IDs", async () => {
  const collector = createAuditMutationCollector();
  for (const [method, path, body, headers, target] of [
    ["POST", "/api/v1/policies", "ignored", { "x-audit-id": eventID, "x-mutation-receipt-id": actor }, "policy-production"],
    ["POST", "/api/v1/admin/sso-connections", JSON.stringify({ id: "saml-actual", audit_correlation_id: actor }), {}, undefined],
  ]) {
    const stream = Readable.from([body]); stream.statusCode = 201; stream.headers = headers;
    await collector.observe({ method, path, scope: `${actor}/${actor}/${actor}`, target }, stream);
  }
  assert.deepEqual(collector.read().map(x => [x.family, x.id, x.target_id]), [["policy", eventID, "policy-production"], ["sso", actor, "saml-actual"]]);
  const tooBig = Readable.from(["x".repeat(4097)]); tooBig.statusCode = 200; tooBig.headers = {};
  await assert.rejects(collector.observe({ method: "PATCH", path: "/api/v1/settings/data-controls", scope: `${actor}/${actor}/${actor}` }, tooBig), /bounded mutation/);
});

test("page capture drops metadata/body and rejects response byte overflow", async () => {
  const trace = createAuditRequestTrace();
  const stream = Readable.from([JSON.stringify({ items: [{ id: eventID, metadata: { secret: "not retained" } }], page_info: { next_cursor: null, has_more: false } })]);
  stream.statusCode = 200;
  await captureAuditPageResponse(stream, "?limit=50", trace);
  assert.equal(trace.read().length, 1, "actual page projection was not captured");
  assert.equal(trace.read()[0].ids[0], eventID);
  assert.equal(JSON.stringify(trace.read()).includes("secret"), false);
  const huge = Readable.from([Buffer.alloc(1048577)]); huge.statusCode = 200;
  await assert.rejects(captureAuditPageResponse(huge, "?limit=50", trace), /bounded audit response/);
});

test("browser proof refuses missing real witnesses before any browser operation", async () => {
  await assert.rejects(runAuditLogBrowserProof({ expectedEvents: [], principalID: actor }), /four mutation families/);
});

test("browser proof catches a UI which omits an applied actor filter", async () => {
  let sequence = 0;
  const browser = {
    navigate: async () => {}, fillLabel: async () => {}, selectOption: async () => {}, clickText: async () => {},
    waitForRead: async () => ({ query: "?limit=50", status: 200, ids: [], page_info: { has_more: false, next_cursor: null }, elapsed_ms: 1, sequence: ++sequence }),
    waitForRows: async () => {},
    snapshot: async () => ({ rows: [], applied: "All retained organization audit records", text: "Audit exports unavailable", interactiveExport: false }),
  };
  await assert.rejects(runAuditLogBrowserProof({ expectedEvents: witnesses(), principalID: actor, publicOrigin: "https://owned.invalid", browser, readAuditRequests: () => [], fixtures: {} }), /audit query omitted/);
});

test("one-shot Next fault records the real reached upstream then returns503; delayed result releases once", async () => {
  const trace = createAuditRequestTrace();
  const body = JSON.stringify({ items: [{ id: eventID }], page_info: { has_more: false, next_cursor: null } });
  const stream = () => { const value = Readable.from([body]); value.statusCode = 200; value.headers = { "content-type": "application/json" }; return value; };
  let status, output, delayed;
  const response = { writeHead: value => { status = value; }, end: value => { output = value; } };
  await forwardAuditPage(stream(), response, "?limit=50&cursor=actual", trace, { fail: true });
  assert.equal(status, 503);
  assert.equal(trace.read()[0].status, 503);
  assert.deepEqual(trace.read()[0].ids, []);
  status = undefined; output = undefined;
  await forwardAuditPage(stream(), response, "?limit=50&cursor=actual", trace, { delay: true, onDelayed: value => { delayed = value; } });
  assert.equal(status, undefined);
  assert.equal(typeof delayed, "function", "real response delay was not reached");
  delayed();
  assert.equal(status, 200); assert.equal(output, body);
  assert.throws(() => delayed(), /released/);
  assert.equal(trace.read().length, 2);
});

function browserBoundary(omitQueryKey, retainDenied = false, principalFault) {
  const events = witnesses(); const trace = createAuditRequestTrace();
  let rows = events.map(event => event.source), visible = [], draft = {}, applied = {}, cursor, more = null, statusText = "";
  let fail = false, delay = false, release, denied = false, changed = false;
  let currentPrincipal = actor, principalReleases = 0, restored = 0;
  const observedFilters = new Set();
  const pagingID = n => `pid_7b100001-0000-4000-8000-${String(n).padStart(12, "0")}`;
  const crossScopeID = "pid_7b200001-0000-4000-8000-000000000001";
  const labelKeys = { "Actor ID (exact)": "actor_id", "Action (exact)": "action", "From (UTC, inclusive)": "from", "To (UTC, exclusive)": "to" };
  const makeRead = (filters, nextCursor) => {
    const offset = nextCursor ? JSON.parse(Buffer.from(nextCursor, "base64url").subarray(0,-32)).offset : 0;
    const matches = rows.filter(row => (!filters.actor_id || row.actor_id === filters.actor_id) && (!filters.action || row.action === filters.action) && (!filters.outcome || row.outcome === filters.outcome) && (!filters.from || row.occurred_at >= filters.from) && (!filters.to || row.occurred_at < filters.to)).sort((a,b) => b.occurred_at.localeCompare(a.occurred_at) || b.id.localeCompare(a.id));
    const page = matches.slice(offset,offset+50);
    const next = offset+50 < matches.length ? Buffer.concat([Buffer.from(JSON.stringify({ i: page.at(-1).id, offset: offset+50 })),Buffer.alloc(32)]).toString("base64url") : null;
    const query = new URLSearchParams({ limit: "50", ...filters, ...(nextCursor ? { cursor: nextCursor } : {}) });
    if (omitQueryKey) query.delete(omitQueryKey);
    const status = denied ? 403 : fail ? 503 : 200;
    fail = false;
    const record = { query: "?"+query, status, ids: status === 200 ? page.map(row => row.id) : [], page_info: status === 200 ? { has_more: next !== null, next_cursor: next } : null, elapsed_ms: 1 };
    const publish = (paint = true) => {
      trace.record(record);
      if (paint) {
        if (status === 200) { visible = page; more = next; statusText = ""; }
        else { if (status === 403 && !retainDenied) visible = []; statusText = "last successful page is still shown"; }
      }
    };
    if (delay) {
      const requestPrincipal = currentPrincipal;
      delay = false; release = () => {
        if (principalFault === "unreleased" && requestPrincipal !== currentPrincipal) { release = undefined; return; }
        if (requestPrincipal !== currentPrincipal) principalReleases++;
        publish(principalFault === "stale" && requestPrincipal !== currentPrincipal); release = undefined;
      };
    }
    else publish();
  };
  const browser = {
    preparePrincipalReplacement: async () => {},
    authenticatedPrincipal: async () => ({ id: currentPrincipal, role: currentPrincipal === actor ? "security_admin" : "read_only_viewer", auditRead: currentPrincipal === actor }),
    replacePrincipal: async () => { if (principalFault !== "omitted") currentPrincipal = eventID; visible = []; },
    restorePrincipal: async () => { currentPrincipal = actor; restored++; },
    navigate: async () => { applied = {}; makeRead(applied); },
    fillLabel: async (label,value) => { const key = labelKeys[label]; assert.ok(key); if (value) draft[key] = value; else delete draft[key]; },
    selectOption: async (label,value) => {
      if (label === "Authorized scope") { applied = {}; draft = {}; cursor = undefined; makeRead(applied); return; }
      assert.equal(label,"Outcome");
      const outcome = { Succeeded: "succeeded", Denied: "denied", Failed: "failed" }[value];
      if (outcome) draft.outcome = outcome; else delete draft.outcome;
    },
    clickText: async label => {
      if (label === "Apply filters") { applied = { ...draft }; cursor = undefined; for (const key of Object.keys(applied)) observedFilters.add(key); }
      else if (label === "Clear filters") { applied = {}; draft = {}; cursor = undefined; }
      else if (label === "First" || label === "Refresh") cursor = undefined;
      else if (label === "Next") { assert.ok(more); cursor = more; }
      else assert.equal(label,"Retry next page");
      makeRead(applied,cursor);
    },
    waitForRead: async sequence => { const record = trace.read().at(-1); assert.ok(record.sequence > sequence); return record; },
    waitForRows: async ids => assert.deepEqual(visible.map(row=>row.id),ids),
    waitForText: async expression => assert.match(statusText,expression),
    snapshot: async () => ({ rows: visible.map(row=>({id:row.id,text:[row.action,row.actor_id,row.target_id,row.outcome,row.occurred_at].join(" ")})), applied: JSON.stringify(applied), text: "Audit exports unavailable", interactiveExport: false }),
  };
  const fixtures = {
    pagingID,
    replacementPrincipalID: eventID,
    seedPagingRows: async () => {
      const hash = createHash("sha256");
      for (let n=2101;n>0;n--) { const id = pagingID(n); hash.update(id+"\n"); rows.push({ ...events[0].source, id, action: "audit.browser.paging", target_id: "owned-paging-fixture" }); }
      rows.push({ ...events[0].source, id:crossScopeID,action:"audit.browser.crossscope" });
      return {count:2101,idPrefix:"pid_7b100001-",sha256:hash.digest("hex"),crossScopeID};
    },
    changeOwnedPagingRow: async () => { rows.find(row=>row.id===pagingID(2101)).target_id = "owned-refresh-change"; changed = true; },
    failNext: () => { fail = true; }, delayNext: () => { delay = true; }, waitDelayed: async () => assert.equal(typeof release,"function"), releaseDelayed: async () => release(),
    revokeAuditAccess: async () => { denied = true; }, restoreAuditAccess: async () => { denied = false; },
  };
  return { configuration:{expectedEvents:events,principalID:actor,publicOrigin:"https://owned.invalid",browser,readAuditRequests:trace.read,fixtures}, observedFilters, changed:()=>changed, principalProof:()=>({principalReleases,restored}) };
}

test("six-scenario driver traverses43pages with all five controls and exact retry/invalidation boundaries", async () => {
  const boundary = browserBoundary();
  const result = await runAuditLogBrowserProof(boundary.configuration);
  assert.equal(result.pages,43); assert.equal(result.pagingRows,2101); assert.equal(result.mutationWitnesses,6);
  assert.deepEqual([...boundary.observedFilters].sort(),["action","actor_id","from","outcome","to"]);
  assert.equal(boundary.changed(),true);
  assert.equal(result.exportSaving,"NOT RUN");
});

test("principal replacement establishes a distinct authenticated reader before releasing old success", async () => {
  const boundary = browserBoundary();
  await runAuditLogBrowserProof(boundary.configuration);
  assert.deepEqual(boundary.principalProof(), { principalReleases: 1, restored: 1 });
});

test("principal replacement refuses an omitted login even when old rows are cleared", async () => {
  await assert.rejects(runAuditLogBrowserProof(browserBoundary(undefined,false,"omitted").configuration), /replacement principal/);
});

test("principal replacement refuses stale success repaint and still restores the original session", async () => {
  const boundary = browserBoundary(undefined,false,"stale");
  await assert.rejects(runAuditLogBrowserProof(boundary.configuration), /Expected values/);
  assert.equal(boundary.principalProof().restored, 1);
});

test("principal replacement refuses a held response that was never released", async () => {
  await assert.rejects(runAuditLogBrowserProof(browserBoundary(undefined,false,"unreleased").configuration), /audit query/);
});

test("six-scenario driver refuses each omitted UI control and stale rows after authoritative denial", async () => {
  for (const key of ["action","actor_id","from","outcome","to"]) await assert.rejects(runAuditLogBrowserProof(browserBoundary(key).configuration), /audit query omitted/);
  await assert.rejects(runAuditLogBrowserProof(browserBoundary(undefined,true).configuration), /Expected values/);
});

test("public mutation witness metadata and fields must match committed provenance", async () => {
  const events = witnesses();
  assertAuditPublicWitnessProjection({ items: [events[2].source] }, events);
  for (const changes of [{ metadata: { receipt_id: "wrong" } }, { action: "policy.delete" }, { occurred_at: "2026-09-12T00:00:00.123000Z" }]) {
    assert.throws(() => assertAuditPublicWitnessProjection({ items: [{ ...events[2].source, ...changes }] }, events), /public source/);
  }
  const stream = Readable.from([JSON.stringify({ items: [{ ...events[2].source, metadata: { wrong: "receipt" } }], page_info: { next_cursor: null, has_more: false } })]);
  stream.statusCode = 200; stream.headers = {};
  await assert.rejects(forwardAuditPage(stream, { writeHead() {}, end() {} }, "?limit=50", createAuditRequestTrace(), { verifyWitness: page => assertAuditPublicWitnessProjection(page, events) }), /provenance/);
});

test("actual forwarded page refuses a row violating any individual filter predicate", async () => {
  for (const [key,value] of [["actor_id",eventID],["action","policy.delete"],["outcome","failed"],["from","2026-09-12T00:00:00.123457Z"],["to","2026-09-12T00:00:00.123456Z"]]) {
    const stream = Readable.from([JSON.stringify({items:[witnesses()[2].source],page_info:{next_cursor:null,has_more:false}})]);
    stream.statusCode = 200; stream.headers = {};
    await assert.rejects(forwardAuditPage(stream,{writeHead(){},end(){}} ,"?"+new URLSearchParams({limit:"50",[key]:value}),createAuditRequestTrace()), /predicate/);
  }
});
