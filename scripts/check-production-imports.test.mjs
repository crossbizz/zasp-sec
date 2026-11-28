import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { checkCompiledBuild, checkSourceGraph } from "./check-production-imports.mjs";

async function fixture(files) {
  const root = await mkdtemp(join(tmpdir(), "zasp-production-imports-"));
  const entries = { "app/deployment-admin/page.tsx": "export {};", ...files };
  await Promise.all(Object.entries(entries).map(async ([name, value]) => {
    const path = join(root, name);
    await mkdir(join(path, ".."), { recursive: true });
    await writeFile(path, value);
  }));
  return root;
}

test("production add-on downloads admit the exact release pin and check transitive imports", async () => {
  const panel = "app/features/tools/CLIReleaseDownloads.tsx";
  const pin = "app/features/tools/cli-release-pin.json";
  const root = await fixture({
    "app/page.tsx": 'export { Downloads } from "./features/tools/CLIReleaseDownloads";',
    "app/[...path]/page.tsx": "export {};",
    [panel]: 'import pin from "./cli-release-pin.json"; export const Downloads = pin;',
    [pin]: '{"version":"","commit":"","manifest_sha256":"","assets":[]}',
    "app/features/tools/unapproved.json": "{}",
    "app/features/tools/ToolViews.tsx": "export const Demo = 1;",
  });
  assert.ok((await checkSourceGraph({ root })).files.includes(pin));

  await writeFile(join(root, panel), 'export { default as Downloads } from "./unapproved.json";');
  await assert.rejects(() => checkSourceGraph({ root }), /unresolved production import.*unapproved\.json/);
  await writeFile(join(root, panel), 'export { Demo } from "./ToolViews";');
  await assert.rejects(() => checkSourceGraph({ root }), /demo module.*ToolViews\.tsx/);
});

test("the coverage screen admits only the reviewed public surface labels", async () => {
  const panel = "app/features/sessions/FrameworkSurfaceReview.tsx";
  const surfaces = "services/platform/compliancemap/surfaces.json";
  const root = await fixture({
    "app/page.tsx": 'export { surfaces } from "./features/sessions/FrameworkSurfaceReview";',
    "app/[...path]/page.tsx": "export {};",
    [panel]: 'export { default as surfaces } from "../../../services/platform/compliancemap/surfaces.json";',
    [surfaces]: '[{"id":"managed_endpoint","label":"Managed endpoint"}]',
    "services/platform/compliancemap/unreviewed.json": "[]",
  });
  assert.ok((await checkSourceGraph({ root })).files.includes(surfaces));
  await writeFile(join(root, panel), 'export { default as surfaces } from "../../../services/platform/compliancemap/unreviewed.json";');
  await assert.rejects(() => checkSourceGraph({ root }), /unresolved production import.*unreviewed\.json/);
});

test("source graph accepts an API-only production entry", async () => {
  const root = await fixture({
    "app/page.tsx": 'export { App } from "./App";',
    "app/[...path]/page.tsx": 'export { App } from "../App";',
    "app/App.tsx": 'import { get } from "../apps/web/api/client"; export const App = get;',
    "apps/web/api/client.ts": "export const get = 1;",
  });
  const result = await checkSourceGraph({ root });
  assert.equal(result.files.length, 5);
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

test("source graph permits only the exact scoped retry-recovery storage boundaries", async () => {
  const approved = await fixture({
    "app/page.tsx": 'export { Risk } from "./features/risk/ProductionRiskView";',
    "app/[...path]/page.tsx": "export {};",
    "app/features/risk/ProductionRiskView.tsx": 'export const Risk = window.sessionStorage.getItem("zasp:finding-ticket:v1");',
  });
  await assert.rejects(() => checkSourceGraph({ root: approved }), /browser storage/);

  const recovery = await fixture({
    "app/page.tsx": 'export { RecoveryOperationsView } from "./features/recovery/RecoveryOperationsView";',
    "app/[...path]/page.tsx": "export {};",
    "app/features/recovery/RecoveryOperationsView.tsx": 'export const RecoveryOperationsView = window.sessionStorage.getItem("zasp:recovery:v1:scope");',
  });
  await assert.rejects(() => checkSourceGraph({ root: recovery }), /browser storage/);

  const redTeam = await fixture({
    "app/page.tsx": 'export { ProductionRedTeamView } from "./features/redteam/ProductionRedTeamView";',
    "app/[...path]/page.tsx": "export {};",
    "app/features/redteam/ProductionRedTeamView.tsx": 'export const ProductionRedTeamView = window.sessionStorage.getItem("zasp:red-team:request:v1:principal/scope"); export { recover } from "./redTeamMutationRecovery";',
    "app/features/redteam/redTeamMutationRecovery.ts": 'export const recover = 1;',
  });
  await assert.rejects(() => checkSourceGraph({ root: redTeam }), /browser storage/);

  const auditExport = await fixture({
    "app/page.tsx": 'export { AuditExportPanel } from "./features/administration/AuditExportPanel";',
    "app/[...path]/page.tsx": "export {};",
    "app/features/administration/AuditExportPanel.tsx": 'export const AuditExportPanel = window.sessionStorage.getItem("zasp.audit-export.resume.v1");',
  });
  await assert.rejects(() => checkSourceGraph({ root: auditExport }), /browser storage/);

  const complianceExport = await fixture({
    "app/page.tsx": 'export { ComplianceEvidenceView } from "./features/sessions/ComplianceEvidenceView";',
    "app/[...path]/page.tsx": "export {};",
    "app/features/sessions/ComplianceEvidenceView.tsx": 'export const ComplianceEvidenceView = window.sessionStorage.getItem("zasp.compliance.export/principal/organization/workspace/environment");',
  });
  await assert.rejects(() => checkSourceGraph({ root: complianceExport }), /browser storage/);

  for (const [entry, source] of [
    ["app/features/risk/OtherRiskView.tsx", 'export const View = window.sessionStorage.getItem("state");'],
    ["app/features/recovery/OtherRecoveryView.tsx", 'export const View = window.sessionStorage.getItem("state");'],
    ["app/features/workflows/ProductionWorkflowViews.tsx", 'export const View = window.sessionStorage.getItem("sign-in");'],
    ["app/features/administration/OtherAuditExportPanel.tsx", 'export const View = window.sessionStorage.getItem("state");'],
    ["app/features/sessions/OtherComplianceEvidenceView.tsx", 'export const View = window.sessionStorage.getItem("state");'],
  ]) {
    const unapproved = await fixture({
      "app/page.tsx": `export { View } from "./${entry.slice(4, -4)}";`,
      "app/[...path]/page.tsx": "export {};",
      [entry]: source,
    });
    await assert.rejects(() => checkSourceGraph({ root: unapproved }), /browser storage/);
  }
});

test("source graph accepts the production sensor surface but rejects its demo sibling", async () => {
  const production = await fixture({
    "app/page.tsx": 'export { ProductionSensorView } from "./features/sensors/ProductionSensorView";',
    "app/[...path]/page.tsx": "export {};",
    "app/features/sensors/ProductionSensorView.tsx": 'export { getSensors } from "./api";',
    "app/features/sensors/api.ts": "export const getSensors = 1;",
  });
  const result = await checkSourceGraph({ root: production });
  assert.ok(result.files.includes("app/features/sensors/ProductionSensorView.tsx"));
  assert.ok(result.files.includes("app/features/sensors/api.ts"));

  for (const [target, symbol] of [
    ["SensorView.tsx", "SensorView"],
    ["api.test.ts", "fixtureAPI"],
    ["future-sibling.ts", "futureSibling"],
  ]) {
    const demo = await fixture({
      "app/page.tsx": `export { ${symbol} } from "./features/sensors/${target}";`,
      "app/[...path]/page.tsx": "export {};",
      [`app/features/sensors/${target}`]: `export const ${symbol} = 1;`,
    });
    await assert.rejects(() => checkSourceGraph({ root: demo }), /demo module/);
  }
});

test("source graph accepts only the exact production red-team surface", async () => {
  const production = await fixture({
    "app/page.tsx": 'export { ProductionRedTeamView } from "./features/redteam/ProductionRedTeamView"; export { ProductionAttackLabView } from "./features/redteam/ProductionAttackLabView";',
    "app/[...path]/page.tsx": "export {};",
    "app/features/redteam/ProductionRedTeamView.tsx": 'export { getRuns as ProductionRedTeamView } from "./api";',
		"app/features/redteam/ProductionAttackLabView.tsx": 'export { getRuns as ProductionAttackLabView } from "./api";',
    "app/features/redteam/api.ts": 'export { getRuns } from "./recommendations";',
    "app/features/redteam/recommendations.ts": 'export { getRuns } from "./outcomes";',
    "app/features/redteam/outcomes.ts": "export const getRuns = 1;",
  });
  const result = await checkSourceGraph({ root: production });
  assert.ok(result.files.includes("app/features/redteam/ProductionRedTeamView.tsx"));
	assert.ok(result.files.includes("app/features/redteam/ProductionAttackLabView.tsx"));
  assert.ok(result.files.includes("app/features/redteam/api.ts"));
  assert.ok(result.files.includes("app/features/redteam/recommendations.ts"));
  assert.ok(result.files.includes("app/features/redteam/outcomes.ts"));

  for (const target of ["AttackLabView.tsx", "RedTeamViews.tsx", "fixture-api.ts", "outcomes.test.ts", "outcomes-demo.ts"]) {
    const unapproved = await fixture({
      "app/page.tsx": `export { View } from "./features/redteam/${target.replace(/\.[^.]+$/, "")}";`,
      "app/[...path]/page.tsx": "export {};",
      [`app/features/redteam/${target}`]: "export const View = 1;",
    });
    await assert.rejects(() => checkSourceGraph({ root: unapproved }), /demo module/);
  }
});

test("compiled closure accepts clean client and server chunks", async () => {
  const root = await fixture({
    "dist/client/.vite/manifest.json": JSON.stringify({
      "virtual:vinext-app-browser-entry": { file: "entry.js", isEntry: true, dynamicImports: ["app/features/sensors/ProductionSensorView.tsx", "app/features/redteam/ProductionAttackLabView.tsx"] },
      "app/features/sensors/ProductionSensorView.tsx": { file: "production.js", src: "app/features/sensors/ProductionSensorView.tsx", imports: ["app/features/sensors/api.ts"] },
      "app/features/sensors/api.ts": { file: "sensor-api.js", src: "app/features/sensors/api.ts" },
		"app/features/redteam/ProductionAttackLabView.tsx": { file: "attack-lab.js", src: "app/features/redteam/ProductionAttackLabView.tsx", imports: ["app/features/redteam/api.ts"] },
		"app/features/redteam/api.ts": { file: "red-team-api.js", src: "app/features/redteam/api.ts" },
    }),
    "dist/client/entry.js": "import('./production.js')",
    "dist/client/production.js": "const title = 'Red Team'; const destination = '/test/attack-lab';",
    "dist/client/sensor-api.js": "export const listSensors = true;",
		"dist/client/attack-lab.js": "export const AttackLab = true;",
		"dist/client/red-team-api.js": "export const listAttackLabRuns = true;",
    "dist/server/.vite/manifest.json": JSON.stringify({
      "app/page.tsx": { file: "page.js", src: "app/page.tsx", isDynamicEntry: true, imports: ["_production.js"] },
      "app/[...path]/page.tsx": { file: "catch.js", src: "app/[...path]/page.tsx", isDynamicEntry: true, imports: ["_production.js"] },
      "app/deployment-admin/page.tsx": { file: "operator.js", src: "app/deployment-admin/page.tsx", isDynamicEntry: true },
      "_production.js": { file: "production.js", imports: [] },
    }),
    "dist/server/page.js": "export const page = true;",
    "dist/server/catch.js": "export const page = true;",
    "dist/server/operator.js": "operator",
    "dist/server/production.js": "const title = 'Attack Paths';",
  });
  const result = await checkCompiledBuild({ root });
  assert.deepEqual(result, { clientChunks: 5, serverChunks: 4 });
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
      "app/deployment-admin/page.tsx": { file: "operator.js", src: "app/deployment-admin/page.tsx", isDynamicEntry: true },
    }),
    "dist/server/page.js": "page",
    "dist/server/catch.js": "page",
    "dist/server/operator.js": "operator",
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
      "app/deployment-admin/page.tsx": { file: "operator.js", src: "app/deployment-admin/page.tsx", isDynamicEntry: true },
    }),
    "dist/server/page.js": "page",
    "dist/server/catch.js": "page",
    "dist/server/operator.js": "operator",
  });
  await assert.rejects(() => checkCompiledBuild({ root: forbiddenSentinel }), /forbidden sentinel/);

  for (const sensorSource of ["app/features/sensors/SensorView.tsx", "app/features/sensors/api.test.ts"]) {
    const forbiddenSensor = await fixture({
      "dist/client/.vite/manifest.json": JSON.stringify({
        "virtual:vinext-app-browser-entry": { file: "entry.js", isEntry: true, imports: [sensorSource] },
        [sensorSource]: { file: "sensor.js", src: sensorSource },
      }),
      "dist/client/entry.js": "production",
      "dist/client/sensor.js": "sensor",
      "dist/server/.vite/manifest.json": JSON.stringify({
        "app/page.tsx": { file: "page.js", src: "app/page.tsx", isDynamicEntry: true },
        "app/[...path]/page.tsx": { file: "catch.js", src: "app/[...path]/page.tsx", isDynamicEntry: true },
        "app/deployment-admin/page.tsx": { file: "operator.js", src: "app/deployment-admin/page.tsx", isDynamicEntry: true },
      }),
      "dist/server/page.js": "page",
      "dist/server/catch.js": "page",
      "dist/server/operator.js": "operator",
    });
    await assert.rejects(() => checkCompiledBuild({ root: forbiddenSensor }), /forbidden source/);
  }

	for (const redTeamSource of ["app/features/redteam/AttackLabView.tsx", "app/features/redteam/api.test.ts"]) {
		const forbiddenRedTeam = await fixture({
			"dist/client/.vite/manifest.json": JSON.stringify({
				"virtual:vinext-app-browser-entry": { file: "entry.js", isEntry: true, imports: [redTeamSource] },
				[redTeamSource]: { file: "red-team.js", src: redTeamSource },
			}),
			"dist/client/entry.js": "production",
			"dist/client/red-team.js": "red-team",
			"dist/server/.vite/manifest.json": JSON.stringify({
				"app/page.tsx": { file: "page.js", src: "app/page.tsx", isDynamicEntry: true },
				"app/[...path]/page.tsx": { file: "catch.js", src: "app/[...path]/page.tsx", isDynamicEntry: true },
				"app/deployment-admin/page.tsx": { file: "operator.js", src: "app/deployment-admin/page.tsx", isDynamicEntry: true },
			}),
			"dist/server/page.js": "page",
			"dist/server/catch.js": "page",
			"dist/server/operator.js": "operator",
		});
		await assert.rejects(() => checkCompiledBuild({ root: forbiddenRedTeam }), /forbidden source/);
	}
});
