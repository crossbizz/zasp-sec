import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { JSON_SCHEMA, load } from "js-yaml";

export const MAP_MAX_BYTES = 16 * 1024;
export const OPENAPI_MAX_BYTES = 2 * 1024 * 1024;

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultMapPath = resolve(repositoryRoot, "docs/product/ui-api-map.yaml");
const defaultOpenAPIPath = resolve(repositoryRoot, "openapi/openapi.yaml");
const operationMethods = new Set(["get", "put", "post", "delete", "options", "head", "patch", "trace"]);
const pathMetadata = new Set(["$ref", "summary", "description", "servers", "parameters"]);
const identifierPattern = /^[a-z][A-Za-z0-9]*$/;
const snakePattern = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;

function invariant(condition) {
  if (!condition) {
    throw new Error("invalid coverage input");
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireExactKeys(value, expected) {
  invariant(isRecord(value));
  invariant(Object.keys(value).sort().join("\0") === [...expected].sort().join("\0"));
}

function parseStrictYAML(source, maxBytes) {
  invariant(typeof source === "string");
  invariant(Buffer.byteLength(source, "utf8") <= maxBytes);
  invariant(!source.includes("\0"));
  invariant(!/(?:^|[\s,[{])&[A-Za-z0-9_-]+(?:\s|$)/m.test(source));
  invariant(!/(?:^|[\s,[{])\*[A-Za-z0-9_-]+(?:\s|$)/m.test(source));
  invariant(!/^\s*<<\s*:/m.test(source));
  return load(source, { schema: JSON_SCHEMA, json: false });
}

export function parseMapSource(source) {
  const document = parseStrictYAML(source, MAP_MAX_BYTES);
  requireExactKeys(document, ["schema_version", "screens"]);
  invariant(document.schema_version === 1);
  invariant(Array.isArray(document.screens) && document.screens.length > 0);

  const screenIDs = new Set();
  const labels = new Set();
  const actionIDs = new Set();
  const operationIDs = new Set();
  for (const screen of document.screens) {
    requireExactKeys(screen, ["id", "label", "actions"]);
    invariant(typeof screen.id === "string" && snakePattern.test(screen.id));
    invariant(typeof screen.label === "string" && /^[A-Za-z][A-Za-z0-9 &/-]{0,79}$/.test(screen.label));
    invariant(!screenIDs.has(screen.id) && !labels.has(screen.label));
    invariant(Array.isArray(screen.actions) && screen.actions.length > 0);
    screenIDs.add(screen.id);
    labels.add(screen.label);

    for (const action of screen.actions) {
      requireExactKeys(action, ["id", "operation_id", "availability"]);
      invariant(typeof action.id === "string" && snakePattern.test(action.id));
      invariant(typeof action.operation_id === "string" && identifierPattern.test(action.operation_id));
      invariant(action.availability === "planned" || action.availability === "available");
      invariant(!actionIDs.has(action.id) && !operationIDs.has(action.operation_id));
      actionIDs.add(action.id);
      operationIDs.add(action.operation_id);
    }
  }

  return document;
}

export function parseOpenAPISource(source) {
  const document = parseStrictYAML(source, OPENAPI_MAX_BYTES);
  invariant(isRecord(document));
  invariant(document.openapi === "3.1.0");
  invariant(isRecord(document.paths));

  const allOperations = new Map();
  const publicOperations = new Set();
  const internalOperations = new Set();
  for (const [path, pathItem] of Object.entries(document.paths)) {
    invariant(typeof path === "string" && path.startsWith("/") && isRecord(pathItem));
    for (const [key, operation] of Object.entries(pathItem)) {
      invariant(operationMethods.has(key) || pathMetadata.has(key));
      if (!operationMethods.has(key)) {
        continue;
      }
      invariant(isRecord(operation));
      invariant(typeof operation.operationId === "string" && identifierPattern.test(operation.operationId));
      invariant(!allOperations.has(operation.operationId));

      let visibility;
      if (path === "/api/v1" || path.startsWith("/api/v1/")) {
        visibility = "public";
        publicOperations.add(operation.operationId);
      } else if (path === "/internal/v1" || path.startsWith("/internal/v1/")) {
        visibility = "internal";
        internalOperations.add(operation.operationId);
      } else {
        throw new Error("invalid coverage input");
      }
      allOperations.set(operation.operationId, { path, method: key, visibility });
    }
  }

  return { allOperations, publicOperations, internalOperations };
}

export function validateCoverage(mapDocument, openAPIDocument) {
  invariant(isRecord(mapDocument) && Array.isArray(mapDocument.screens));
  invariant(isRecord(openAPIDocument));
  invariant(openAPIDocument.allOperations instanceof Map);
  invariant(openAPIDocument.publicOperations instanceof Set);
  invariant(openAPIDocument.internalOperations instanceof Set);

  let planned = 0;
  let available = 0;
  const availableMappings = new Set();
  for (const screen of mapDocument.screens) {
    for (const action of screen.actions) {
      const operation = openAPIDocument.allOperations.get(action.operation_id);
      if (action.availability === "planned") {
        planned += 1;
        invariant(operation === undefined);
      } else {
        available += 1;
        invariant(operation?.visibility === "public");
        availableMappings.add(action.operation_id);
      }
      invariant(!openAPIDocument.internalOperations.has(action.operation_id));
    }
  }

  invariant(availableMappings.size === openAPIDocument.publicOperations.size);
  for (const operationID of openAPIDocument.publicOperations) {
    invariant(availableMappings.has(operationID));
  }

  return {
    planned,
    available,
    public: openAPIDocument.publicOperations.size,
    internal: openAPIDocument.internalOperations.size,
  };
}

export async function readBoundedRegularFile(path, maxBytes) {
  invariant(typeof path === "string" && path.length > 0);
  invariant(Number.isSafeInteger(maxBytes) && maxBytes > 0);
  const flags = constants.O_RDONLY | constants.O_NONBLOCK | (constants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags);
  try {
    const before = await handle.stat({ bigint: true });
    invariant(before.isFile() && before.size <= BigInt(maxBytes));

    const buffer = Buffer.alloc(maxBytes + 1);
    let offset = 0;
    while (offset <= maxBytes) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
      if (bytesRead === 0) {
        break;
      }
      offset += bytesRead;
    }
    invariant(offset <= maxBytes);

    const after = await handle.stat({ bigint: true });
    invariant(after.isFile());
    invariant(before.dev === after.dev && before.ino === after.ino);
    invariant(before.size === after.size && after.size === BigInt(offset));
    invariant(before.mtimeNs === after.mtimeNs);
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, offset));
  } finally {
    await handle.close();
  }
}

export async function runMain({
  stdout = process.stdout,
  stderr = process.stderr,
  mapPath = defaultMapPath,
  openapiPath = defaultOpenAPIPath,
  readSource = readBoundedRegularFile,
} = {}) {
  try {
    const [mapSource, openAPISource] = await Promise.all([
      readSource(mapPath, MAP_MAX_BYTES),
      readSource(openapiPath, OPENAPI_MAX_BYTES),
    ]);
    const result = validateCoverage(parseMapSource(mapSource), parseOpenAPISource(openAPISource));
    stdout.write(`UI/API coverage passed: planned=${result.planned} available=${result.available} public=${result.public} internal=${result.internal}.\n`);
    return 0;
  } catch {
    stderr.write("UI/API coverage rejected.\n");
    return 1;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  process.exitCode = await runMain();
}
