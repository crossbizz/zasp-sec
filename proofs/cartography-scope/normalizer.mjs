import { createHash } from "node:crypto";

import {
  canonicalScopedSourceId,
  validateOrganizationId,
} from "../prowler-evidence/scoped_id.mjs";

export { validateOrganizationId } from "../prowler-evidence/scoped_id.mjs";

const nodeKinds = new Map([
  ["AWSAccount", ["aws", "cloud_account"]],
  ["AWSRole", ["aws", "identity_role"]],
  ["GitHubOrganization", ["github", "code_organization"]],
  ["GitHubRepository", ["github", "code_repository"]],
]);

const relationshipKinds = new Map([
  ["AWSAccount|RESOURCE|AWSRole", "contains_identity"],
  ["GitHubRepository|OWNER|GitHubOrganization", "owns_repository"],
]);

const propertyByLabel = new Map([
  ["AWSAccount", "id"],
  ["AWSRole", "arn"],
  ["GitHubOrganization", "url"],
  ["GitHubRepository", "id"],
]);

const labelByNormalizedKind = new Map([
  ["cloud_account", "AWSAccount"],
  ["identity_role", "AWSRole"],
  ["code_organization", "GitHubOrganization"],
  ["code_repository", "GitHubRepository"],
]);

const accountIdPattern = /^\d{12}$/;
const roleArnPattern = /^arn:aws:iam::(\d{12}):role\/[A-Za-z0-9+=,.@_/-]{1,512}$/;
const repositoryIdPattern = /^[1-9]\d*$/;
const digestPattern = /^[a-f0-9]{64}$/;
const forbiddenKindPattern = /cartography|neo4j|aws|github/i;

export function parseRawGraph(value) {
  const rawGraph = copyData(value, new Set());
  expectKeys(rawGraph, ["schema_version", "nodes", "relationships"], "raw graph");
  if (rawGraph.schema_version !== 1) throw new TypeError("schema_version must be 1");
  expectArray(rawGraph.nodes, "nodes");
  expectArray(rawGraph.relationships, "relationships");

  const identities = new Map();
  for (const [index, node] of rawGraph.nodes.entries()) {
    parseNode(node, index, identities);
  }

  const relationships = new Set();
  for (const [index, relationship] of rawGraph.relationships.entries()) {
    parseRelationship(relationship, index, identities, relationships);
  }

  validateRequiredShape(rawGraph);

  return rawGraph;
}

export function normalizeGraph(organizationId, rawGraph) {
  const scope = validateOrganizationId(organizationId);
  const parsed = parseRawGraph(rawGraph);
  const canonicalByIdentity = new Map();
  const nodes = parsed.nodes.map((node) => {
    const label = node.labels[0];
    const [provider, kind] = nodeKinds.get(label);
    assertCustomerKind(kind);
    const sourceId = sourceIdForNode(node);
    const id = canonicalNodeId(scope, provider, kind, sourceId);
    const identity = identityKey(label, sourceId);
    if (canonicalByIdentity.has(identity)) throw new TypeError("duplicate canonical node identity");
    canonicalByIdentity.set(identity, id);
    return {
      id,
      organization_id: scope,
      provider,
      kind,
      source_id: sourceId,
    };
  });

  const canonicalIds = new Set();
  for (const node of nodes) {
    if (canonicalIds.has(node.id)) throw new TypeError("duplicate canonical node ID");
    canonicalIds.add(node.id);
  }

  const relationshipIds = new Set();
  const relationships = parsed.relationships.map((relationship) => {
    const sourceIdentity = identityKey(relationship.source.label, relationship.source.id);
    const targetIdentity = identityKey(relationship.target.label, relationship.target.id);
    const sourceId = canonicalByIdentity.get(sourceIdentity);
    const targetId = canonicalByIdentity.get(targetIdentity);
    const key = `${relationship.source.label}|${relationship.type}|${relationship.target.label}`;
    const kind = relationshipKinds.get(key);
    assertCustomerKind(kind);
    const id = canonicalRelationshipId(scope, kind, sourceId, targetId);
    if (relationshipIds.has(id)) throw new TypeError("duplicate normalized relationship");
    relationshipIds.add(id);
    return {
      id,
      organization_id: scope,
      kind,
      source_id: sourceId,
      target_id: targetId,
    };
  });

  nodes.sort(compareNodes);
  relationships.sort(compareRelationships);
  return { organization_id: scope, nodes, relationships };
}

export function mergeNormalizedGraphs(graphs) {
  const cleanGraphs = copyData(graphs, new Set());
  expectArray(cleanGraphs, "graphs");
  const nodes = [];
  const relationships = [];
  const organizations = new Set();

  for (const [index, graph] of cleanGraphs.entries()) {
    validateNormalizedGraph(graph, index);
    organizations.add(graph.organization_id);
    nodes.push(...graph.nodes);
    relationships.push(...graph.relationships);
  }

  const nodeIds = new Set();
  for (const node of nodes) {
    if (nodeIds.has(node.id)) throw new TypeError("duplicate canonical node ID");
    nodeIds.add(node.id);
  }

  const relationshipIds = new Set();
  for (const relationship of relationships) {
    if (relationshipIds.has(relationship.id)) {
      throw new TypeError("duplicate normalized relationship");
    }
    relationshipIds.add(relationship.id);
    if (!nodeIds.has(relationship.source_id) || !nodeIds.has(relationship.target_id)) {
      throw new TypeError("relationship endpoint is dangling or cross-Organization");
    }
  }

  nodes.sort(compareNodes);
  relationships.sort(compareRelationships);
  const organizationId = organizations.size === 1 ? organizations.values().next().value : "multiple";
  return { organization_id: organizationId, nodes, relationships };
}

function copyData(value, ancestors) {
  if (value === null || typeof value !== "object") return value;
  if (ancestors.has(value)) throw new TypeError("cyclic input is not allowed");

  const isArray = Array.isArray(value);
  if (!isArray) {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("only plain objects are allowed");
    }
  }

  ancestors.add(value);
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) {
      throw new TypeError("symbol keys are not allowed");
    }
    if (new Set(keys).size !== keys.length) throw new TypeError("duplicate keys are not allowed");

    if (isArray) return copyArray(value, keys, ancestors);

    const output = {};
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("object properties must be enumerable data properties");
      }
      Object.defineProperty(output, key, {
        value: copyData(descriptor.value, ancestors),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return output;
  } finally {
    ancestors.delete(value);
  }
}

function copyArray(value, keys, ancestors) {
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    !lengthDescriptor ||
    !("value" in lengthDescriptor) ||
    !Number.isFinite(lengthDescriptor.value) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > 8
  ) {
    throw new TypeError("array size is invalid");
  }
  const expectedKeys = Array.from({ length: lengthDescriptor.value }, (_, index) => String(index));
  const actualKeys = keys.filter((key) => key !== "length");
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new TypeError("arrays must be dense and contain no extra keys");
  }
  return expectedKeys.map((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("array entries must be enumerable data properties");
    }
    return copyData(descriptor.value, ancestors);
  });
}

function parseNode(node, index, identities) {
  expectKeys(node, ["labels", "properties"], `nodes[${index}]`);
  expectArray(node.labels, `nodes[${index}].labels`);
  if (node.labels.length !== 1 || typeof node.labels[0] !== "string") {
    throw new TypeError(`nodes[${index}].labels must contain exactly one string`);
  }
  const label = node.labels[0];
  if (!nodeKinds.has(label)) throw new TypeError(`nodes[${index}] has an unknown label`);

  const property = propertyByLabel.get(label);
  expectKeys(node.properties, [property], `nodes[${index}].properties`);
  const sourceId = node.properties[property];
  validateSourceId(label, sourceId);
  const identity = identityKey(label, sourceId);
  if (identities.has(identity)) throw new TypeError("duplicate semantic node identity");
  identities.set(identity, node);
}

function parseRelationship(relationship, index, identities, relationships) {
  expectKeys(relationship, ["type", "source", "target"], `relationships[${index}]`);
  if (typeof relationship.type !== "string") {
    throw new TypeError(`relationships[${index}].type must be a string`);
  }
  parseEndpoint(relationship.source, `relationships[${index}].source`);
  parseEndpoint(relationship.target, `relationships[${index}].target`);

  const relationshipKey =
    `${relationship.source.label}|${relationship.type}|${relationship.target.label}`;
  if (!relationshipKinds.has(relationshipKey)) {
    throw new TypeError(`relationships[${index}] has an unknown or reversed edge`);
  }
  const source = identityKey(relationship.source.label, relationship.source.id);
  const target = identityKey(relationship.target.label, relationship.target.id);
  if (!identities.has(source) || !identities.has(target)) {
    throw new TypeError(`relationships[${index}] has a dangling endpoint`);
  }
  const semanticIdentity = JSON.stringify([relationship.type, source, target]);
  if (relationships.has(semanticIdentity)) throw new TypeError("duplicate relationship");
  relationships.add(semanticIdentity);

  if (relationship.type === "RESOURCE") {
    const account = relationship.source.id;
    const match = roleArnPattern.exec(relationship.target.id);
    if (!match || match[1] !== account) {
      throw new TypeError("identity relationship crosses cloud accounts");
    }
  }
}

function parseEndpoint(endpoint, context) {
  expectKeys(endpoint, ["label", "id"], context);
  if (typeof endpoint.label !== "string" || !nodeKinds.has(endpoint.label)) {
    throw new TypeError(`${context}.label is invalid`);
  }
  validateSourceId(endpoint.label, endpoint.id);
}

function validateRequiredShape(rawGraph) {
  if (rawGraph.nodes.length !== nodeKinds.size) {
    throw new TypeError("raw graph must contain exactly four nodes");
  }
  if (rawGraph.relationships.length !== relationshipKinds.size) {
    throw new TypeError("raw graph must contain exactly two relationships");
  }

  const labels = new Set(rawGraph.nodes.map((node) => node.labels[0]));
  if (labels.size !== nodeKinds.size || [...nodeKinds.keys()].some((label) => !labels.has(label))) {
    throw new TypeError("raw graph must contain exactly one node of each mapped kind");
  }

  const edges = new Set(
    rawGraph.relationships.map(
      (relationship) =>
        `${relationship.source.label}|${relationship.type}|${relationship.target.label}`,
    ),
  );
  if (
    edges.size !== relationshipKinds.size ||
    [...relationshipKinds.keys()].some((edge) => !edges.has(edge))
  ) {
    throw new TypeError("raw graph must contain exactly one of each mapped relationship");
  }
}

function validateSourceId(label, value) {
  if (typeof value !== "string") throw new TypeError(`${label} source ID must be a string`);
  if (label === "AWSAccount" && !accountIdPattern.test(value)) {
    throw new TypeError("cloud account source ID is invalid");
  }
  if (label === "AWSRole" && !roleArnPattern.test(value)) {
    throw new TypeError("identity role source ID is invalid");
  }
  if (label === "GitHubRepository" && !repositoryIdPattern.test(value)) {
    throw new TypeError("code repository source ID is invalid");
  }
  if (label === "GitHubOrganization" && !isOrganizationUrl(value)) {
    throw new TypeError("code organization source ID is invalid");
  }
}

function isOrganizationUrl(value) {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      (url.hostname === "api.github.com" || url.hostname === "api.github.test") &&
      url.port === "" &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      /^\/orgs\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(url.pathname)
    );
  } catch {
    return false;
  }
}

function validateNormalizedGraph(graph, graphIndex) {
  expectKeys(graph, ["organization_id", "nodes", "relationships"], `graphs[${graphIndex}]`);
  const scope = validateOrganizationId(graph.organization_id);
  expectArray(graph.nodes, `graphs[${graphIndex}].nodes`);
  expectArray(graph.relationships, `graphs[${graphIndex}].relationships`);

  const localNodes = new Map();
  for (const [nodeIndex, node] of graph.nodes.entries()) {
    expectKeys(
      node,
      ["id", "organization_id", "provider", "kind", "source_id"],
      `graphs[${graphIndex}].nodes[${nodeIndex}]`,
    );
    if (node.organization_id !== scope) throw new TypeError("node crosses Organization scope");
    if (node.provider !== "aws" && node.provider !== "github") {
      throw new TypeError("normalized provider is invalid");
    }
    const allowedKinds = node.provider === "aws"
      ? new Set(["cloud_account", "identity_role"])
      : new Set(["code_organization", "code_repository"]);
    if (typeof node.kind !== "string" || !allowedKinds.has(node.kind)) {
      throw new TypeError("normalized node kind is invalid");
    }
    assertCustomerKind(node.kind);
    validateSourceId(labelByNormalizedKind.get(node.kind), node.source_id);
    const expectedId = canonicalNodeId(scope, node.provider, node.kind, node.source_id);
    if (node.id !== expectedId) throw new TypeError("canonical node ID is invalid");
    if (localNodes.has(node.id)) throw new TypeError("duplicate canonical node ID");
    localNodes.set(node.id, node);
  }

  const localRelationships = new Set();
  for (const [relationshipIndex, relationship] of graph.relationships.entries()) {
    expectKeys(
      relationship,
      ["id", "organization_id", "kind", "source_id", "target_id"],
      `graphs[${graphIndex}].relationships[${relationshipIndex}]`,
    );
    if (relationship.organization_id !== scope) {
      throw new TypeError("relationship crosses Organization scope");
    }
    if (
      relationship.kind !== "contains_identity" &&
      relationship.kind !== "owns_repository"
    ) {
      throw new TypeError("normalized relationship kind is invalid");
    }
    assertCustomerKind(relationship.kind);
    if (!isScopedNodeId(relationship.source_id, scope) || !isScopedNodeId(relationship.target_id, scope)) {
      throw new TypeError("relationship endpoint crosses Organization scope");
    }
    const sourceNode = localNodes.get(relationship.source_id);
    const targetNode = localNodes.get(relationship.target_id);
    if (!sourceNode || !targetNode) throw new TypeError("relationship endpoint is dangling");
    if (!hasExpectedDirection(relationship.kind, sourceNode, targetNode)) {
      throw new TypeError("normalized relationship is reversed");
    }
    const expectedId = canonicalRelationshipId(
      scope,
      relationship.kind,
      relationship.source_id,
      relationship.target_id,
    );
    if (relationship.id !== expectedId) throw new TypeError("canonical relationship ID is invalid");
    if (localRelationships.has(relationship.id)) {
      throw new TypeError("duplicate normalized relationship");
    }
    localRelationships.add(relationship.id);
  }
}

function expectKeys(value, expected, context) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${context} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${context} has invalid keys`);
  }
}

function expectArray(value, context) {
  if (!Array.isArray(value)) throw new TypeError(`${context} must be an array`);
  if (!Number.isFinite(value.length) || !Number.isSafeInteger(value.length) || value.length > 8) {
    throw new TypeError(`${context} has an invalid size`);
  }
}

function sourceIdForNode(node) {
  return node.properties[propertyByLabel.get(node.labels[0])];
}

function identityKey(label, sourceId) {
  return JSON.stringify([label, sourceId]);
}

function hash(parts) {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

function canonicalNodeId(organizationId, provider, kind, sourceId) {
  return canonicalScopedSourceId(organizationId, provider, kind, sourceId);
}

function canonicalRelationshipId(organizationId, kind, sourceId, targetId) {
  return `${organizationId}:relationship:${kind}:${hash([
    organizationId,
    kind,
    sourceId,
    targetId,
  ])}`;
}

function assertCustomerKind(kind) {
  if (typeof kind !== "string" || forbiddenKindPattern.test(kind)) {
    throw new TypeError("customer-visible kind exposes a forbidden name");
  }
}

function isScopedNodeId(value, organizationId) {
  if (typeof value !== "string") return false;
  const parts = value.split(":");
  return (
    parts.length === 4 &&
    parts[0] === organizationId &&
    (parts[1] === "aws" || parts[1] === "github") &&
    /^[a-z_]+$/.test(parts[2]) &&
    digestPattern.test(parts[3])
  );
}

function hasExpectedDirection(kind, sourceNode, targetNode) {
  if (kind === "contains_identity") {
    return (
      sourceNode.provider === "aws" &&
      sourceNode.kind === "cloud_account" &&
      targetNode.provider === "aws" &&
      targetNode.kind === "identity_role"
    );
  }
  return (
    sourceNode.provider === "github" &&
    sourceNode.kind === "code_repository" &&
    targetNode.provider === "github" &&
    targetNode.kind === "code_organization"
  );
}

function compareNodes(left, right) {
  return (
    compareStrings(left.provider, right.provider) ||
    compareStrings(left.kind, right.kind) ||
    compareStrings(left.source_id, right.source_id) ||
    compareStrings(left.id, right.id)
  );
}

function compareRelationships(left, right) {
  return (
    compareStrings(left.kind, right.kind) ||
    compareStrings(left.source_id, right.source_id) ||
    compareStrings(left.target_id, right.target_id) ||
    compareStrings(left.id, right.id)
  );
}

function compareStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}
