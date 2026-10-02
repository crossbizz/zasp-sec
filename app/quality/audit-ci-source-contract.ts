import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";

export type AuditSources = Record<string, string>;
export type AuditLane = { id: string; pattern: string; mode?: string; repeat?: boolean; localstackImage?: string; localstackRequired?: string };

export async function readAuditSources(root: string): Promise<AuditSources> {
  const entries = await Promise.all(["apiserver", "agentsec-worker"].map(async (pkg) => {
    const directory = resolve(root, "services/platform", pkg);
    return Promise.all((await readdir(directory)).filter(name => name.endsWith("_test.go")).sort().map(async name =>
      [`${pkg}/${name}`, await readFile(resolve(directory, name), "utf8")] as const));
  }));
  return Object.fromEntries(entries.flat());
}

function requireEvidence(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

// Mask Go comments/literals before counting braces or finding calls. Keep offsets
// stable so checks on a function cannot borrow evidence from the next function.
function mask(source: string, literals = true): string {
  return source.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\/|"(?:\\.|[^"\\])*"|`[^`]*`|'(?:\\.|[^'\\])*'/g,
    value => value.startsWith("/") || literals ? value.replace(/[^\n]/g, " ") : value);
}

type GoFunction = { name: string; file: string; body: string; code: string };
function functions(sources: AuditSources): GoFunction[] {
  return Object.entries(sources).flatMap(([file, source]) => {
    const code = mask(source);
    return [...code.matchAll(/^func (?:\([^\n]*?\) )?(\w+)\([^\n]*\)[^{\n]*\{/gm)].map(match => {
      const start = match.index! + match[0].length;
      let end = start, depth = 1;
      while (end < code.length && depth) {
        if (code[end] === "{") depth++;
        if (code[end] === "}") depth--;
        end++;
      }
      requireEvidence(depth === 0, `unclosed Go function ${file}:${match[1]}`);
      return { name: match[1], file, body: mask(source.slice(start, end - 1), false), code: code.slice(start, end - 1) };
    });
  });
}

export function assertAuditSourceCoverage(sources: AuditSources, lanes: AuditLane[]) {
  const all = functions(sources);
  const api = all.filter(fn => fn.file.startsWith("apiserver/"));
  const worker = all.filter(fn => fn.file.startsWith("agentsec-worker/"));
  // The narrow function parser may refuse a signature, but it must never hide
  // a worker test before the parent-owned child checks below can inspect it.
  const rawWorkerDeclarations = Object.entries(sources).filter(([file]) => file.startsWith("agentsec-worker/"))
    .flatMap(([file, source]) => [...mask(source).matchAll(/^[ \t]*func\s+(TestAudit\w*)\s*\(/gm)].map(match => `${file}:${match[1]}`)).sort();
  const parsedWorkerDeclarations = worker.filter(fn => /^TestAudit/.test(fn.name)).map(fn => `${fn.file}:${fn.name}`).sort();
  requireEvidence(rawWorkerDeclarations.length === parsedWorkerDeclarations.length && rawWorkerDeclarations.every((name, index) => name === parsedWorkerDeclarations[index]),
    "unsupported or missing worker audit declaration syntax");
  const declarations = api.filter(fn => /^(TestAuditExport|TestAuditHTTP|TestDisposablePostgresCleanup)/.test(fn.name));
  const rawDeclarations = Object.entries(sources).filter(([file]) => file.startsWith("apiserver/"))
    .flatMap(([, source]) => [...mask(source).matchAll(/^func\s+(Test(?:AuditExport|AuditHTTP|DisposablePostgresCleanup)\w*)\s*\(/gm)]);
  requireEvidence(declarations.length === rawDeclarations.length && declarations.length > 200, "unsupported or missing audit declaration syntax");
  requireEvidence(new Set(declarations.map(fn => fn.name)).size === declarations.length, "duplicate audit declaration");
  const get = (name: string, file?: string) => {
    const matches = api.filter(fn => fn.name === name && (!file || fn.file.endsWith(file)));
    requireEvidence(matches.length === 1, `missing or ambiguous parent function ${name}`);
    return matches[0];
  };
  const body = (name: string) => get(name).body;
  const calls = (from: string, to: string, file?: string) => {
    requireEvidence(new RegExp(`\\b${to}\\s*\\(`).test(get(from, file).code), `missing child ownership edge ${from} -> ${to}`);
  };
  const contains = (name: string, pattern: RegExp) => requireEvidence(pattern.test(body(name)), `missing full-size/mode evidence in ${name}: ${pattern}`);
  const selected = new Map<string, string>();
  for (const declaration of declarations) {
    const base = lanes.filter(lane => !lane.repeat && new RegExp(lane.pattern).test(declaration.name));
    const child = declaration.name === "TestAuditHTTPSizeAPIProcess";
    requireEvidence(base.length === (child ? 0 : 1), `${declaration.name}: expected ${child ? 0 : 1} base assignment, found ${base.map(lane => lane.id)}`);
    if (!child) selected.set(declaration.name, base[0].id);
  }
  for (const lane of lanes) {
    requireEvidence(!lane.pattern.includes("/"), `subcase filtering is forbidden: ${lane.id}`);
    requireEvidence(declarations.some(fn => new RegExp(lane.pattern).test(fn.name)), `empty audit lane ${lane.id}`);
  }
  const numeric = "TestAuditExportHTTPSizeProcessPostgres";
  const orderly = "TestAuditExportHTTPOrderlyRestartPostgres";
  for (const parent of [numeric, orderly]) {
    const modes = lanes.filter(lane => new RegExp(lane.pattern).test(parent));
    requireEvidence(modes.length === 2 && modes.filter(lane => lane.mode === "").length === 1 && modes.filter(lane => lane.mode === "race" && lane.repeat).length === 1,
      `missing explicit numeric/race child modes for ${parent}`);
  }
  requireEvidence(lanes.filter(lane => lane.repeat).length === 2, "undocumented repeated audit mode");
  const control = "TestAuditExportHTTPSizeMemorySensitivityPostgres";
  requireEvidence(lanes.find(lane => new RegExp(lane.pattern).test(control))?.mode === "", "controls need explicit non-race children");
  contains(control, /range \[\]string\{"api-retain", "worker-retain"\}/);
  contains(control, /auditHTTPSizePair\(t, binaries, root, retain, control, false, true\)/);
  contains(numeric, /range \[\]string\{"N1-off", "N2-off", "N3-on"\}/);
  contains(numeric, /t\.Run\("functional-race"/);
  contains(numeric, /auditHTTPSizePair\(t, binaries, root, retain, "", false, false\)/);
  contains(numeric, /pairs\[i\] = auditHTTPSizePair\(t, binaries, root, retain, "", i == 2, true\)/);
  contains(numeric, /off, on := pairs\[1\]\[i\], pairs\[2\]\[i\]/);
  contains("auditHTTPSizePair", /range \[\]string\{"small", "full"\}/);
  contains("auditHTTPSizePair", /rows := 1000\s+if i == 1 \{\s+rows = 100001/);
  contains("auditHTTPSizePair", /Rows: rows, Control: control, Diagnostics: diagnostics/);
  contains(orderly, /Rows: 100001, OrderlyRestart: true/);
  for (const parent of [numeric, orderly]) {
    contains(parent, /mode := os\.Getenv\("ZASP_AUDIT_HTTP_SIZE_BUILD"\)/);
    contains(parent, /auditHTTPSizeBuildChildren\(t, mode\)/);
  }
  const composition = "TestAuditHTTPSizeProcessCompositionPostgres";
  contains(composition, /auditHTTPSizeBuildChildren\(t, "race"\)/);
  contains(composition, /range \[\]bool\{false, true\}/);
  contains(composition, /"controlled-zero-source"/);
  contains(composition, /Rows: 1000, Empty: empty/);
  contains("auditHTTPSizeCompositionCase", /range \[\]string\{"audit-export-outbox", "audit-export"\}/);
  const recovery = "TestAuditExportWorkerPostgresRecoveryProcessBatch";
  contains(recovery, /range \[\]string\{"capture", "receipt", "stale", "manifest", "finish"\}/);
  contains(recovery, /t\.Run\(phase,/);
  const provider = "TestAuditExportWorkerPostgresLocalStackCompletionRestart";
  const providerLane = lanes.find(lane => !lane.repeat && new RegExp(lane.pattern).test(provider));
  requireEvidence(providerLane?.localstackRequired === "true", "actual provider must be required, never opt-in skipped");
  const providerPin = mask(sources["apiserver/audit_export_localstack_owner_test.go"], false).match(/const auditLocalstackImage = "([^"]+)"/)?.[1];
  requireEvidence(providerPin && providerLane.localstackImage === providerPin && /^localstack\/localstack:4\.7\.0@sha256:[a-f0-9]{64}$/.test(providerPin), "workflow pull must match source-owned immutable provider image");
  contains(provider, /os\.Getenv\("ZASP_AUDIT_EXPORT_LOCALSTACK_REQUIRED"\)/);
  for (const parent of [control, numeric, orderly, composition, recovery]) {
    requireEvidence(!/\bt\.Parallel\s*\(/.test(get(parent).code), `serial acceptance changed: ${parent}`);
  }

  // Explicit parent -> launcher paths. Reaching a skipped child from an
  // unfiltered worker package alone never supplies execution credit.
  const ownership: Array<{ child: string; parent: string; chain: string[]; launcherFile?: string }> = [
    { child: "TestAuditExportAuthorityPostgres", parent: "TestAuditExportWorkerPostgresClaimHeartbeatRoundTrip", chain: [] },
    ...[
      ["TestAuditExportAuthorityCapturePostgres", "TestAuditExportWorkerPostgresCaptureFrozenPagesResume"],
      ["TestAuditExportAuthorityChunksPostgres", "TestAuditExportWorkerPostgresChunkReceiptsResume"],
      ["TestAuditExportCompletedWorkerPostgres", "TestAuditExportWorkerPostgresCompletedSDK"],
    ].map(([child, parent]) => ({ child, parent, chain: ["auditExportWorkerCaptureAndResume", "auditExportCaptureWorkerChild"] })),
    { child: "TestAuditExportProcessWorkerPostgres", parent: "TestAuditExportWorkerPostgresDurableOutboxSDK", chain: ["run", "runOutcome"], launcherFile: "audit_export_process_postgres_test.go" },
    { child: "TestAuditExportProcessWorkerPostgres", parent: "TestAuditExportWorkerPostgresOutboxResponseLossSDK", chain: ["runOutcome"], launcherFile: "audit_export_process_postgres_test.go" },
    ...["TestAuditExportWorkerPostgresOutboxSaturatedSDKRetries", "TestAuditExportWorkerPostgresOutboxSaturationRejectsAbortedSend"].map(parent => ({ child: "TestAuditExportOutboxSaturationProcessWorkerPostgres", parent, chain: ["auditExportSaturationAcceptance", "runSaturation"] })),
    { child: "TestAuditExportExecutorRetryProcessWorkerPostgres", parent: "TestAuditExportWorkerPostgresRetrySDKFaultAgreement", chain: ["runExecutorRetry"] },
    { child: "TestAuditExportLocalStackProcessWorkerPostgres", parent: "TestAuditExportWorkerPostgresLocalStackCompletionRestart", chain: ["exerciseAuditExportLocalStackRestart", "launch"], launcherFile: "audit_export_localstack_postgres_test.go" },
    { child: "TestAuditExportRecoveryProcessWorkerPostgres", parent: recovery, chain: ["startRecovery"] },
    ...[composition, numeric, control, orderly].flatMap(parent => [
      { child: "TestAuditHTTPSizeAPIProcess", parent, chain: [...([numeric, control].includes(parent) ? ["auditHTTPSizePair"] : []), "auditHTTPSizeCompositionCase", "startAuditHTTPSizeAPI", "startAuditHTTPSizeAPIWithRunner"] },
      { child: "TestAuditHTTPSizeWorkerProcess", parent, chain: [...([numeric, control].includes(parent) ? ["auditHTTPSizePair"] : []), "auditHTTPSizeCompositionCase", "runAuditHTTPSizeWorker"] },
    ]),
  ];
  for (const owner of ownership) {
    requireEvidence(selected.has(owner.parent), `unselected child parent ${owner.parent}`);
    const path = [owner.parent, ...owner.chain];
    for (let i = 0; i < path.length - 1; i++) calls(path[i], path[i + 1], owner.launcherFile);
    const launcher = get(path.at(-1)!, owner.launcherFile);
    requireEvidence(launcher.body.includes(owner.child), `missing child launch ${owner.parent} -> ${owner.child}`);
    const target = owner.child === "TestAuditHTTPSizeAPIProcess" ? api : worker;
    requireEvidence(target.filter(fn => fn.name === owner.child).length === 1, `missing/ambiguous child declaration ${owner.child}`);
  }
  const children = new Set(ownership.map(owner => owner.child));
  const childReferences = api.flatMap(fn => [...fn.body.matchAll(/"(?:-test\.run=)?\^?(TestAudit\w+)(?:\$)?"/g)].map(match => match[1]));
  for (const child of childReferences) requireEvidence(children.has(child), `unmapped child entrypoint ${child}`);
  for (const fn of worker.filter(fn => /^TestAudit/.test(fn.name) && /\bt\.Skip\w*\s*\(/.test(fn.code))) {
    requireEvidence(children.has(fn.name), `unmapped skipping worker entrypoint ${fn.name}`);
  }
  return { declarations: declarations.map(fn => fn.name).sort(), assignments: Object.fromEntries(selected), ownership };
}
