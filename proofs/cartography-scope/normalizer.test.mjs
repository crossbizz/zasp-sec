import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  mergeNormalizedGraphs,
  normalizeGraph,
  parseRawGraph,
  validateOrganizationId,
} from "./normalizer.mjs";

const fixtureA = JSON.parse(
  await readFile(new URL("./fixtures/org-a.json", import.meta.url), "utf8"),
);
const fixtureB = JSON.parse(
  await readFile(new URL("./fixtures/org-b.json", import.meta.url), "utf8"),
);

const organizationA = "org_aaaaaaaaaaaaaaaa";
const organizationB = "org_bbbbbbbbbbbbbbbb";
const forbiddenCustomerTerms = /cartography|neo4j|aws|github/i;

function clone(value) {
  return structuredClone(value);
}

function validNormalizedGraph() {
  return normalizeGraph(organizationA, parseRawGraph(clone(fixtureA)));
}

function assertRejected(operation) {
  assert.throws(operation, { name: "TypeError" });
}

function relationshipId(organizationId, kind, sourceId, targetId) {
  const digest = createHash("sha256")
    .update(JSON.stringify([organizationId, kind, sourceId, targetId]))
    .digest("hex");
  return `${organizationId}:relationship:${kind}:${digest}`;
}

function nodeId(organizationId, provider, kind, sourceId) {
  const digest = createHash("sha256")
    .update(JSON.stringify([organizationId, provider, kind, sourceId]))
    .digest("hex");
  return `${organizationId}:${provider}:${kind}:${digest}`;
}

function resignNodeSource(graph, kind, sourceId) {
  const node = graph.nodes.find((candidate) => candidate.kind === kind);
  assert.ok(node);
  const oldId = node.id;
  node.source_id = sourceId;
  node.id = nodeId(node.organization_id, node.provider, node.kind, node.source_id);

  for (const relationship of graph.relationships) {
    if (relationship.source_id === oldId) relationship.source_id = node.id;
    if (relationship.target_id === oldId) relationship.target_id = node.id;
    relationship.id = relationshipId(
      relationship.organization_id,
      relationship.kind,
      relationship.source_id,
      relationship.target_id,
    );
  }
}

test("normalizes each Organization to four nodes and two relationships", () => {
  const normalized = validNormalizedGraph();

  assert.equal(normalized.organization_id, organizationA);
  assert.equal(normalized.nodes.length, 4);
  assert.equal(normalized.relationships.length, 2);
  assert.deepEqual(
    normalized.nodes.map(({ provider, kind, source_id }) => ({ provider, kind, source_id })),
    [
      { provider: "aws", kind: "cloud_account", source_id: "000000000000" },
      {
        provider: "aws",
        kind: "identity_role",
        source_id: "arn:aws:iam::000000000000:role/shared-fixture-role",
      },
      {
        provider: "github",
        kind: "code_organization",
        source_id: "https://api.github.test/orgs/shared-fixture",
      },
      { provider: "github", kind: "code_repository", source_id: "424242" },
    ],
  );
  assert.deepEqual(
    normalized.relationships.map(({ kind }) => kind),
    ["contains_identity", "owns_repository"],
  );
});

test("scopes deliberately overlapping raw identities to distinct canonical IDs", () => {
  const merged = mergeNormalizedGraphs([
    normalizeGraph(organizationA, parseRawGraph(clone(fixtureA))),
    normalizeGraph(organizationB, parseRawGraph(clone(fixtureB))),
  ]);

  assert.equal(merged.organization_id, "multiple");
  assert.equal(new Set(merged.nodes.map((node) => node.id)).size, 8);
  assert.equal(merged.relationships.length, 4);
  for (const node of merged.nodes) {
    assert.match(node.id, /^org_[a-z0-9]{16}:(aws|github):[a-z_]+:[a-f0-9]{64}$/);
  }
  for (const rawId of [
    "000000000000",
    "arn:aws:iam::000000000000:role/shared-fixture-role",
    "https://api.github.test/orgs/shared-fixture",
    "424242",
  ]) {
    assert.equal(merged.nodes.filter((node) => node.source_id === rawId).length, 2);
  }
});

test("canonical IDs use the fixed Organization-scoped SHA-256 grammar", () => {
  const normalized = validNormalizedGraph();

  assert.equal(
    normalized.nodes[0].id,
    "org_aaaaaaaaaaaaaaaa:aws:cloud_account:4d769aea32fd04eee6db097041f0f2f5503ec4c61185af5e95f215bf0446c4be",
  );
});

test("normalization and merging have deterministic ordering", () => {
  const graphA = normalizeGraph(organizationA, parseRawGraph(clone(fixtureA)));
  const graphB = normalizeGraph(organizationA, parseRawGraph(clone(fixtureB)));

  assert.deepEqual(graphA, graphB);
  assert.deepEqual(
    mergeNormalizedGraphs([graphA, normalizeGraph(organizationB, parseRawGraph(clone(fixtureA)))]),
    mergeNormalizedGraphs([normalizeGraph(organizationB, parseRawGraph(clone(fixtureB))), graphB]),
  );
});

test("customer-visible kinds do not expose implementation or provider names", () => {
  const normalized = validNormalizedGraph();

  for (const value of [
    ...normalized.nodes.map((node) => node.kind),
    ...normalized.relationships.map((relationship) => relationship.kind),
  ]) {
    assert.doesNotMatch(value, forbiddenCustomerTerms);
  }
});

test("accepts only the fixed Organization ID grammar", () => {
  assert.equal(validateOrganizationId(organizationA), organizationA);

  for (const invalid of [
    undefined,
    null,
    "",
    "org_aaaaaaaaaaaaaaa",
    "org_aaaaaaaaaaaaaaaaa",
    "ORG_aaaaaaaaaaaaaaaa",
    "org_Aaaaaaaaaaaaaaaa",
    "tenant_aaaaaaaaaaaaaaaa",
    1,
    [],
    {},
  ]) {
    assertRejected(() => validateOrganizationId(invalid));
  }
});

test("raw graph rejects missing, null, unknown, and case-aliased keys", () => {
  const cases = [];
  for (const key of ["schema_version", "nodes", "relationships"]) {
    const value = clone(fixtureA);
    delete value[key];
    cases.push(value);
  }
  for (const key of ["schema_version", "nodes", "relationships"]) {
    const value = clone(fixtureA);
    value[key] = null;
    cases.push(value);
  }
  cases.push({ ...clone(fixtureA), surprise: true });
  cases.push({ ...clone(fixtureA), Nodes: clone(fixtureA.nodes) });

  for (const value of cases) assertRejected(() => parseRawGraph(value));
});

test("raw graph rejects unknown, extra, case-aliased, and duplicate labels", () => {
  for (const labels of [
    ["Unknown"],
    ["awsaccount"],
    ["AWSAccount", "Extra"],
    ["AWSAccount", "AWSAccount"],
    [],
    [1],
  ]) {
    const value = clone(fixtureA);
    value.nodes[0].labels = labels;
    assertRejected(() => parseRawGraph(value));
  }
});

test("raw graph rejects missing, extra, case-aliased, and non-string properties", () => {
  const cases = [];
  const missing = clone(fixtureA);
  delete missing.nodes[0].properties.id;
  cases.push(missing);
  const extra = clone(fixtureA);
  extra.nodes[0].properties.name = "fixture";
  cases.push(extra);
  const alias = clone(fixtureA);
  alias.nodes[0].properties.ID = alias.nodes[0].properties.id;
  cases.push(alias);
  for (const invalid of [null, 0, true, [], {}]) {
    const value = clone(fixtureA);
    value.nodes[0].properties.id = invalid;
    cases.push(value);
  }

  for (const value of cases) assertRejected(() => parseRawGraph(value));
});

test("raw graph rejects malformed source IDs", () => {
  const cases = [
    [0, "id", "123"],
    [1, "arn", "arn:aws:iam::111111111111:role/shared-fixture-role"],
    [1, "arn", "arn:aws:s3:::fixture"],
    [2, "url", "https://github.com/orgs/shared-fixture"],
    [2, "url", "https://api.github.test/users/shared-fixture"],
    [3, "id", "repo-424242"],
  ];

  for (const [index, key, invalid] of cases) {
    const value = clone(fixtureA);
    value.nodes[index].properties[key] = invalid;
    assertRejected(() => parseRawGraph(value));
  }
});

test("raw graph rejects duplicate semantic node identities", () => {
  const value = clone(fixtureA);
  value.nodes.push(clone(value.nodes[0]));

  assertRejected(() => parseRawGraph(value));
});

test("raw graph rejects duplicate relationships", () => {
  const value = clone(fixtureA);
  value.relationships.push(clone(value.relationships[0]));

  assertRejected(() => parseRawGraph(value));
});

test("raw graph rejects an empty Organization graph", () => {
  assertRejected(() => parseRawGraph({ schema_version: 1, nodes: [], relationships: [] }));
});

test("raw graph rejects a partial Organization graph", () => {
  const value = clone(fixtureA);
  value.nodes = value.nodes.slice(0, 2);
  value.relationships = value.relationships.slice(0, 1);

  assertRejected(() => parseRawGraph(value));
});

test("raw graph rejects an extra instance of a mapped kind", () => {
  const value = clone(fixtureA);
  value.nodes.push({ labels: ["AWSAccount"], properties: { id: "111111111111" } });

  assertRejected(() => parseRawGraph(value));
});

test("raw graph rejects a missing required edge", () => {
  const value = clone(fixtureA);
  value.relationships.pop();

  assertRejected(() => parseRawGraph(value));
});

test("raw graph rejects dangling endpoints and reversed edges", () => {
  const dangling = clone(fixtureA);
  dangling.relationships[0].target.id =
    "arn:aws:iam::000000000000:role/missing-fixture-role";
  assertRejected(() => parseRawGraph(dangling));

  const reversed = clone(fixtureA);
  [reversed.relationships[0].source, reversed.relationships[0].target] = [
    reversed.relationships[0].target,
    reversed.relationships[0].source,
  ];
  assertRejected(() => parseRawGraph(reversed));
});

test("raw graph rejects malformed relationship values and keys", () => {
  const cases = [];
  const unknownType = clone(fixtureA);
  unknownType.relationships[0].type = "resource";
  cases.push(unknownType);
  const extra = clone(fixtureA);
  extra.relationships[0].extra = true;
  cases.push(extra);
  const missing = clone(fixtureA);
  delete missing.relationships[0].source.label;
  cases.push(missing);
  const caseAlias = clone(fixtureA);
  caseAlias.relationships[0].source.Label = caseAlias.relationships[0].source.label;
  cases.push(caseAlias);
  for (const invalid of [null, 0, true, [], {}]) {
    const value = clone(fixtureA);
    value.relationships[0].type = invalid;
    cases.push(value);
  }

  for (const value of cases) assertRejected(() => parseRawGraph(value));
});

test("raw graph rejects arrays beyond eight entries and non-finite numeric values", () => {
  const tooManyNodes = clone(fixtureA);
  tooManyNodes.nodes = Array.from({ length: 9 }, () => clone(fixtureA.nodes[0]));
  assertRejected(() => parseRawGraph(tooManyNodes));

  const tooManyRelationships = clone(fixtureA);
  tooManyRelationships.relationships = Array.from(
    { length: 9 },
    () => clone(fixtureA.relationships[0]),
  );
  assertRejected(() => parseRawGraph(tooManyRelationships));

  const nonFiniteVersion = clone(fixtureA);
  nonFiniteVersion.schema_version = Number.POSITIVE_INFINITY;
  assertRejected(() => parseRawGraph(nonFiniteVersion));
});

test("raw graph rejects cycles, accessors, symbols, and non-plain objects", () => {
  const cyclic = clone(fixtureA);
  cyclic.self = cyclic;
  assertRejected(() => parseRawGraph(cyclic));

  const accessor = clone(fixtureA);
  Object.defineProperty(accessor.nodes[0].properties, "id", {
    enumerable: true,
    get() {
      return "000000000000";
    },
  });
  assertRejected(() => parseRawGraph(accessor));

  const symbolic = clone(fixtureA);
  symbolic[Symbol("hidden")] = true;
  assertRejected(() => parseRawGraph(symbolic));

  const nonPlain = clone(fixtureA);
  Object.setPrototypeOf(nonPlain.nodes[0], { inherited: true });
  assertRejected(() => parseRawGraph(nonPlain));
});

test("normalizer rejects duplicate canonical IDs", () => {
  const value = clone(fixtureA);
  value.nodes[1] = clone(value.nodes[0]);

  assertRejected(() => normalizeGraph(organizationA, value));
});

test("merge rejects duplicate canonical IDs and duplicate relationships", () => {
  const duplicateNode = validNormalizedGraph();
  duplicateNode.nodes.push(clone(duplicateNode.nodes[0]));
  assertRejected(() => mergeNormalizedGraphs([duplicateNode]));

  const duplicateRelationship = validNormalizedGraph();
  duplicateRelationship.relationships.push(clone(duplicateRelationship.relationships[0]));
  assertRejected(() => mergeNormalizedGraphs([duplicateRelationship]));
});

test("merge rejects cross-Organization endpoints", () => {
  const normalized = validNormalizedGraph();
  normalized.relationships[0].source_id = normalizeGraph(
    organizationB,
    parseRawGraph(clone(fixtureB)),
  ).relationships[0].source_id;

  assertRejected(() => mergeNormalizedGraphs([normalized]));
});

test("merge rejects a canonically signed reversed relationship", () => {
  const normalized = validNormalizedGraph();
  const relationship = normalized.relationships[0];
  [relationship.source_id, relationship.target_id] = [
    relationship.target_id,
    relationship.source_id,
  ];
  relationship.id = relationshipId(
    organizationA,
    relationship.kind,
    relationship.source_id,
    relationship.target_id,
  );

  assertRejected(() => mergeNormalizedGraphs([normalized]));
});

for (const [kind, malformedSourceId] of [
  ["cloud_account", "not-an-account"],
  ["identity_role", "role-not-an-arn"],
  ["code_organization", "organization-not-a-url"],
  ["code_repository", "repo-not-numeric"],
]) {
  test(`merge rejects a canonically re-signed malformed ${kind} source ID`, () => {
    const normalized = validNormalizedGraph();
    resignNodeSource(normalized, kind, malformedSourceId);

    assertRejected(() => mergeNormalizedGraphs([normalized]));
  });
}

test("merge rejects dangling endpoints and customer-visible forbidden kinds", () => {
  const dangling = validNormalizedGraph();
  dangling.relationships[0].target_id = `${organizationA}:aws:identity_role:${"0".repeat(64)}`;
  dangling.relationships[0].id = relationshipId(
    organizationA,
    dangling.relationships[0].kind,
    dangling.relationships[0].source_id,
    dangling.relationships[0].target_id,
  );
  assertRejected(() => mergeNormalizedGraphs([dangling]));

  const forbiddenNode = validNormalizedGraph();
  forbiddenNode.nodes[0].kind = "aws_account";
  assertRejected(() => mergeNormalizedGraphs([forbiddenNode]));

  const forbiddenRelationship = validNormalizedGraph();
  forbiddenRelationship.relationships[0].kind = "cartography_edge";
  assertRejected(() => mergeNormalizedGraphs([forbiddenRelationship]));
});
