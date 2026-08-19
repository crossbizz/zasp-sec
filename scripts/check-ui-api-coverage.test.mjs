import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  MAP_MAX_BYTES,
  OPENAPI_MAX_BYTES,
  parseMapSource,
  parseOpenAPISource,
  readBoundedRegularFile,
  runMain,
  validateCoverage,
} from "./check-ui-api-coverage.mjs";

const repositoryRoot = resolve(import.meta.dirname, "..");
const mapPath = resolve(repositoryRoot, "docs/product/ui-api-map.yaml");
const openapiPath = resolve(repositoryRoot, "openapi/openapi.yaml");

async function currentSources() {
  const [map, openapi] = await Promise.all([
    readFile(mapPath, "utf8"),
    readFile(openapiPath, "utf8"),
  ]);
  return { map, openapi };
}

function availableMap(source) {
  return source.replaceAll("availability: planned", "availability: available");
}

function futureOpenAPI(operationIDs, { internal = [] } = {}) {
  const rows = [];
  for (const [index, operationID] of operationIDs.entries()) {
    rows.push(`  /api/v1/fixture-${index}:\n    get:\n      operationId: ${operationID}`);
  }
  for (const [index, operationID] of internal.entries()) {
    rows.push(`  /internal/v1/fixture-${index}:\n    post:\n      operationId: ${operationID}`);
  }
  return `openapi: 3.1.0\npaths:\n${rows.join("\n")}\n`;
}

function captureStream() {
  let value = "";
  return {
    stream: { write(chunk) { value += String(chunk); } },
    value: () => value,
  };
}

test("current API and planned map passes honestly", async () => {
  const { map, openapi } = await currentSources();
  assert.deepEqual(validateCoverage(parseMapSource(map), parseOpenAPISource(openapi)), {
    planned: 0,
    apiAvailable: 84,
    available: 41,
    public: 125,
    internal: 0,
  });
});

test("all current public operations resolve and deliberate removal fails", async () => {
  const { map } = await currentSources();
  const document = parseMapSource(availableMap(map));
  const operationIDs = document.screens.flatMap((screen) => screen.actions.map((action) => action.operation_id));
  const complete = parseOpenAPISource(futureOpenAPI(operationIDs));
  assert.deepEqual(validateCoverage(document, complete), {
    planned: 0,
    apiAvailable: 84,
    available: 41,
    public: 125,
    internal: 0,
  });

  assert.throws(() => validateCoverage(document, parseOpenAPISource(futureOpenAPI(operationIDs.slice(1)))));
});

test("unmapped public operations fail while unmapped internal operations pass", async () => {
  const { map } = await currentSources();
  const planned = parseMapSource(map);
  const apiOperations = planned.screens.flatMap((screen) => screen.actions)
    .filter((action) => action.availability !== "planned")
    .map((action) => action.operation_id);
  assert.throws(() => validateCoverage(planned, parseOpenAPISource(futureOpenAPI([...apiOperations, "unmappedPublic"]))));
  assert.deepEqual(validateCoverage(planned, parseOpenAPISource(futureOpenAPI(apiOperations, { internal: ["ingestEvents"] }))), {
    planned: 0,
    apiAvailable: 84,
    available: 41,
    public: 125,
    internal: 1,
  });
});

test("planned, available, and internal lifecycle mismatches fail", async () => {
  const { map } = await currentSources();
  const planned = parseMapSource(map.replace("availability: api_available", "availability: planned"));
  const apiOperations = planned.screens.flatMap((screen) => screen.actions)
    .filter((action) => action.availability !== "planned")
    .map((action) => action.operation_id);
  const firstOperation = planned.screens.flatMap((screen) => screen.actions)
    .find((action) => action.availability === "planned").operation_id;
  assert.throws(() => validateCoverage(planned, parseOpenAPISource(futureOpenAPI([...apiOperations, firstOperation]))));

  const oneAvailable = parseMapSource(map.replace("availability: planned", "availability: available"));
  assert.throws(() => validateCoverage(oneAvailable, parseOpenAPISource(futureOpenAPI(apiOperations))));
  assert.throws(() => validateCoverage(oneAvailable, parseOpenAPISource(futureOpenAPI(apiOperations, { internal: [firstOperation] }))));
});

test("API-available operations require OpenAPI but do not claim a wired UI", async () => {
  const { map } = await currentSources();
  const apiMap = parseMapSource(map);
  const apiOperations = apiMap.screens.flatMap((screen) => screen.actions)
    .filter((action) => action.availability !== "planned")
    .map((action) => action.operation_id);
  const result = validateCoverage(apiMap, parseOpenAPISource(futureOpenAPI(apiOperations)));
  assert.deepEqual(result, { planned: 0, apiAvailable: 84, available: 41, public: 125, internal: 0 });
  assert.throws(() => validateCoverage(apiMap, parseOpenAPISource(futureOpenAPI(apiOperations.slice(1)))));
});

test("OpenAPI operation extraction rejects missing, duplicate, and unclassified operations", () => {
  assert.throws(() => parseOpenAPISource("openapi: 3.1.0\npaths:\n  /api/v1/a:\n    get: {}\n"));
  assert.throws(() => parseOpenAPISource([
    "openapi: 3.1.0",
    "paths:",
    "  /api/v1/a:",
    "    get:",
    "      operationId: duplicatedOperation",
    "  /api/v1/b:",
    "    post:",
    "      operationId: duplicatedOperation",
    "",
  ].join("\n")));
  assert.throws(() => parseOpenAPISource("openapi: 3.1.0\npaths:\n  /health:\n    get:\n      operationId: getHealth\n"));
});

test("strict YAML parsing rejects representation and map-schema ambiguity", async () => {
  const { map, openapi } = await currentSources();
  for (const hostile of [
    `${map}\nschema_version: 1\n`,
    "schema_version: &version 1\ncopy: *version\n",
    "schema_version: 1\nscreens:\n  - <<: {id: home}\n",
    `${map}\n---\n{}`,
    map.replace("schema_version: 1", "schema_version: 1\nunknown: true"),
    map.replace("availability: api_available", "availability: active"),
  ]) {
    assert.throws(() => parseMapSource(hostile));
  }
  assert.throws(() => parseOpenAPISource(`${openapi}\npaths: {}\n`));
});

test("fixed file boundary accepts regular UTF-8 and rejects symlink, oversize, and invalid UTF-8", async () => {
  const root = await mkdtemp(join(tmpdir(), "zasp-ui-api-coverage-"));
  try {
    const regular = join(root, "regular.yaml");
    const link = join(root, "link.yaml");
    const oversized = join(root, "oversized.yaml");
    const invalid = join(root, "invalid.yaml");
    await writeFile(regular, "paths: {}\n", { mode: 0o600 });
    await symlink(regular, link);
    await writeFile(oversized, Buffer.alloc(MAP_MAX_BYTES + 1, 0x61), { mode: 0o600 });
    await writeFile(invalid, Buffer.from([0xff]), { mode: 0o600 });

    assert.equal(await readBoundedRegularFile(regular, OPENAPI_MAX_BYTES), "paths: {}\n");
    await assert.rejects(readBoundedRegularFile(link, OPENAPI_MAX_BYTES));
    await assert.rejects(readBoundedRegularFile(oversized, MAP_MAX_BYTES));
    await assert.rejects(readBoundedRegularFile(invalid, OPENAPI_MAX_BYTES));
  } finally {
    await rm(root, { recursive: true, force: false });
  }
});

test("CLI emits only fixed success or rejection lines", async () => {
  const successOut = captureStream();
  const successErr = captureStream();
  assert.equal(await runMain({ stdout: successOut.stream, stderr: successErr.stream }), 0);
  assert.equal(successOut.value(), "UI/API coverage passed: planned=0 api_available=84 available=41 public=125 internal=0.\n");
  assert.equal(successErr.value(), "");

  const failureOut = captureStream();
  const failureErr = captureStream();
  assert.equal(await runMain({
    stdout: failureOut.stream,
    stderr: failureErr.stream,
    readSource: async () => { throw new Error("sensitive parser detail"); },
  }), 1);
  assert.equal(failureOut.value(), "");
  assert.equal(failureErr.value(), "UI/API coverage rejected.\n");
  assert.doesNotMatch(failureErr.value(), /sensitive|parser|detail/);
});

test("package command is wired into root verification", async () => {
  const packageDocument = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8"));
  assert.equal(packageDocument.scripts["ui-api:test"], "node --test scripts/check-ui-api-coverage.test.mjs");
  assert.equal(packageDocument.scripts["ui-api:check"], "node scripts/check-ui-api-coverage.mjs");
  assert.match(packageDocument.scripts.verify, /npm run ui-api:test/);
  assert.match(packageDocument.scripts.verify, /npm run ui-api:check/);
});
