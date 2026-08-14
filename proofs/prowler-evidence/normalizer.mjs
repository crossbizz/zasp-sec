import { createHash } from "node:crypto";

import {
  canonicalScopedSourceId,
  validateOrganizationId,
} from "./scoped_id.mjs";

const maximumArtifactBytes = 65_536;
const maximumDepth = 16;
const maximumStringLength = 16_384;
const maximumCollectionSize = 32;
const checkId = "iam_role_cross_service_confused_deputy_prevention";
const accountIdPattern = /^\d{12}$/;
const roleArnPattern = /^arn:aws:iam::(\d{12}):role\/([A-Za-z0-9+=,.@_/-]{1,512})$/;
const observationPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/;
const utcInstantPattern =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const forbiddenLabelPattern = /prowler|ocsf|docker|localstack|aws/i;

const rootKeys = [
  "message",
  "metadata",
  "severity_id",
  "severity",
  "status",
  "status_code",
  "status_detail",
  "status_id",
  "unmapped",
  "activity_name",
  "activity_id",
  "finding_info",
  "resources",
  "category_name",
  "category_uid",
  "class_name",
  "class_uid",
  "cloud",
  "time",
  "time_dt",
  "remediation",
  "risk_details",
  "type_uid",
  "type_name",
];

export function parseProwlerOcsfArtifact(artifact) {
  if (!(artifact instanceof Uint8Array)) throw new TypeError("artifact must be bytes");
  if (artifact.byteLength === 0 || artifact.byteLength > maximumArtifactBytes) {
    throw new TypeError("artifact size is invalid");
  }

  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(
      new Uint8Array(artifact.buffer, artifact.byteOffset, artifact.byteLength),
    );
  } catch {
    throw new TypeError("artifact is not valid UTF-8");
  }

  let parsed;
  try {
    parsed = parseUniqueJson(source);
  } catch {
    throw new TypeError("artifact is not strict JSON");
  }
  validateOcsfDocument(parsed);
  return parsed;
}

export function normalizeProwlerEvidence(organizationId, artifact, observedAt) {
  const scope = validateOrganizationId(organizationId);
  validateObservationInstant(observedAt);
  const [finding] = parseProwlerOcsfArtifact(artifact);
  const resource = finding.resources[0];
  const arn = resource.uid;
  const canonicalResourceId = canonicalScopedSourceId(scope, "aws", "identity_role", arn);
  const ruleCode = "cloud_identity_role_confused_deputy";
  const evidenceKind = "cloud_posture_check";
  const evidenceDigest = hash([
    scope,
    canonicalResourceId,
    ruleCode,
    "fail",
    observedAt,
  ]);

  const normalized = {
    organization_id: scope,
    resources: [
      {
        id: canonicalResourceId,
        organization_id: scope,
        provider: "aws",
        kind: "identity_role",
        source_id: arn,
      },
    ],
    findings: [
      {
        organization_id: scope,
        category: "privileged_identity",
        rule_code: ruleCode,
        severity: "high",
        status: "open",
        resource_id: canonicalResourceId,
      },
    ],
    evidence: [
      {
        id: `${scope}:evidence:${evidenceKind}:${evidenceDigest}`,
        organization_id: scope,
        resource_id: canonicalResourceId,
        kind: evidenceKind,
        confidence: "exact",
        observed_at: observedAt,
        facts: {
          account_id: finding.cloud.account.uid,
          region: finding.cloud.region,
          service_principal:
            resource.data.metadata.assume_role_policy.Statement[0].Principal.Service,
          source_scope_present: false,
        },
      },
    ],
  };

  validateNormalizedProwlerEvidence(normalized);
  return normalized;
}

export function validateNormalizedProwlerEvidence(value) {
  expectKeys(value, ["organization_id", "resources", "findings", "evidence"], "normalized");
  const scope = validateOrganizationId(value.organization_id);
  expectExactArrayLength(value.resources, 1, "normalized.resources");
  expectExactArrayLength(value.findings, 1, "normalized.findings");
  expectExactArrayLength(value.evidence, 1, "normalized.evidence");

  const resource = value.resources[0];
  expectKeys(
    resource,
    ["id", "organization_id", "provider", "kind", "source_id"],
    "normalized resource",
  );
  if (
    resource.organization_id !== scope ||
    resource.provider !== "aws" ||
    resource.kind !== "identity_role" ||
    !roleArnPattern.test(resource.source_id)
  ) {
    throw new TypeError("normalized resource is invalid");
  }
  const expectedResourceId = canonicalScopedSourceId(
    scope,
    resource.provider,
    resource.kind,
    resource.source_id,
  );
  if (resource.id !== expectedResourceId) throw new TypeError("normalized resource ID is invalid");

  const finding = value.findings[0];
  expectKeys(
    finding,
    ["organization_id", "category", "rule_code", "severity", "status", "resource_id"],
    "normalized finding",
  );
  if (
    finding.organization_id !== scope ||
    finding.category !== "privileged_identity" ||
    finding.rule_code !== "cloud_identity_role_confused_deputy" ||
    finding.severity !== "high" ||
    finding.status !== "open" ||
    finding.resource_id !== resource.id
  ) {
    throw new TypeError("normalized finding is invalid");
  }

  const evidence = value.evidence[0];
  expectKeys(
    evidence,
    [
      "id",
      "organization_id",
      "resource_id",
      "kind",
      "confidence",
      "observed_at",
      "facts",
    ],
    "normalized evidence",
  );
  expectKeys(
    evidence.facts,
    ["account_id", "region", "service_principal", "source_scope_present"],
    "normalized evidence facts",
  );
  const match = roleArnPattern.exec(resource.source_id);
  if (
    evidence.organization_id !== scope ||
    evidence.resource_id !== resource.id ||
    evidence.kind !== "cloud_posture_check" ||
    evidence.confidence !== "exact" ||
    evidence.facts.account_id !== match?.[1] ||
    evidence.facts.region !== "us-east-1" ||
    evidence.facts.service_principal !== "lambda.amazonaws.com" ||
    evidence.facts.source_scope_present !== false
  ) {
    throw new TypeError("normalized evidence is invalid");
  }
  validateObservationInstant(evidence.observed_at);
  const expectedEvidenceId = `${scope}:evidence:${evidence.kind}:${hash([
    scope,
    resource.id,
    finding.rule_code,
    "fail",
    evidence.observed_at,
  ])}`;
  if (evidence.id !== expectedEvidenceId) throw new TypeError("normalized evidence ID is invalid");

  for (const label of [
    resource.kind,
    finding.category,
    finding.rule_code,
    finding.severity,
    finding.status,
    evidence.kind,
    evidence.confidence,
    ...Object.keys(evidence.facts),
  ]) {
    if (typeof label !== "string" || forbiddenLabelPattern.test(label)) {
      throw new TypeError("customer-visible label is invalid");
    }
  }
  return value;
}

function validateOcsfDocument(document) {
  expectExactArrayLength(document, 1, "OCSF document");
  const finding = document[0];
  expectKeys(finding, rootKeys, "OCSF finding");
  for (const key of [
    "message",
    "status_detail",
    "risk_details",
    "time_dt",
    "type_name",
    "class_name",
    "category_name",
    "activity_name",
    "severity",
    "status",
    "status_code",
  ]) {
    expectString(finding[key], `OCSF finding.${key}`);
  }

  expectKeys(finding.metadata, ["event_code", "product", "version", "profiles", "tenant_uid"], "metadata");
  expectKeys(finding.metadata.product, ["name", "uid", "vendor_name", "version"], "metadata.product");
  if (
    finding.metadata.event_code !== checkId ||
    finding.metadata.version !== "1.5.0" ||
    finding.metadata.tenant_uid !== "" ||
    finding.metadata.product.name !== "Prowler" ||
    finding.metadata.product.uid !== "prowler" ||
    finding.metadata.product.vendor_name !== "Prowler" ||
    finding.metadata.product.version !== "5.39.0" ||
    !sameArray(finding.metadata.profiles, ["cloud", "datetime"])
  ) {
    throw new TypeError("OCSF metadata is invalid");
  }

  if (
    finding.severity_id !== 4 ||
    finding.severity !== "High" ||
    finding.status !== "New" ||
    finding.status_code !== "FAIL" ||
    finding.status_id !== 1 ||
    finding.activity_name !== "Create" ||
    finding.activity_id !== 1 ||
    finding.category_name !== "Findings" ||
    finding.category_uid !== 2 ||
    finding.class_name !== "Detection Finding" ||
    finding.class_uid !== 2004 ||
    finding.type_uid !== 200401 ||
    finding.type_name !== "Detection Finding: Create"
  ) {
    throw new TypeError("OCSF finding classification is invalid");
  }

  expectKeys(
    finding.unmapped,
    [
      "related_url",
      "categories",
      "depends_on",
      "related_to",
      "additional_urls",
      "notes",
      "compliance",
      "scan_id",
      "provider_uid",
      "provider",
    ],
    "unmapped",
  );
  for (const key of ["related_url", "notes", "scan_id", "provider_uid", "provider"]) {
    expectString(finding.unmapped[key], `unmapped.${key}`);
  }
  for (const key of ["categories", "depends_on", "related_to", "additional_urls"]) {
    expectStringArray(finding.unmapped[key], `unmapped.${key}`);
  }
  expectObject(finding.unmapped.compliance, "unmapped.compliance");
  if (!uuidPattern.test(finding.unmapped.scan_id) || finding.unmapped.provider !== "aws") {
    throw new TypeError("unmapped provider identity is invalid");
  }

  expectKeys(
    finding.finding_info,
    ["analytic", "created_time", "created_time_dt", "desc", "title", "uid", "types"],
    "finding_info",
  );
  expectKeys(
    finding.finding_info.analytic,
    ["name", "uid", "type_id", "type", "category"],
    "finding_info.analytic",
  );
  for (const key of ["name", "uid", "type", "category"]) {
    expectString(finding.finding_info.analytic[key], `finding_info.analytic.${key}`);
  }
  for (const key of ["created_time_dt", "desc", "title", "uid"]) {
    expectString(finding.finding_info[key], `finding_info.${key}`);
  }
  validateTimestampPair(
    finding.finding_info.created_time,
    finding.finding_info.created_time_dt,
    "finding_info.created_time",
  );
  if (
    finding.finding_info.analytic.uid !== checkId ||
    finding.finding_info.analytic.type_id !== 1 ||
    finding.finding_info.analytic.type !== "Rule" ||
    finding.finding_info.analytic.category !== "iam" ||
    !sameArray(finding.finding_info.types, [
      "Software and Configuration Checks/AWS Security Best Practices",
      "TTPs/Privilege Escalation",
    ])
  ) {
    throw new TypeError("OCSF analytic is invalid");
  }

  expectExactArrayLength(finding.resources, 1, "resources");
  validateResource(finding.resources[0], finding);
  validateCloud(finding.cloud, finding.resources[0], finding.unmapped);

  validateTimestampPair(finding.time, finding.time_dt, "time");
  expectKeys(finding.remediation, ["desc", "references"], "remediation");
  expectString(finding.remediation.desc, "remediation.desc");
  expectStringArray(finding.remediation.references, "remediation.references");
}

function validateResource(resource, finding) {
  expectKeys(
    resource,
    ["cloud_partition", "region", "data", "group", "labels", "name", "type", "uid"],
    "resource",
  );
  expectKeys(resource.data, ["details", "metadata"], "resource.data");
  expectKeys(resource.group, ["name"], "resource.group");
  expectString(resource.data.details, "resource.data.details");
  expectExactArrayLength(resource.labels, 0, "resource.labels");
  const metadata = resource.data.metadata;
  expectKeys(
    metadata,
    [
      "name",
      "arn",
      "assume_role_policy",
      "is_service_role",
      "attached_policies",
      "inline_policies",
      "permissions_boundary",
      "tags",
    ],
    "resource.data.metadata",
  );
  expectExactArrayLength(metadata.attached_policies, 0, "attached_policies");
  expectExactArrayLength(metadata.inline_policies, 0, "inline_policies");
  expectExactArrayLength(metadata.tags, 0, "tags");
  if (metadata.permissions_boundary !== null || metadata.is_service_role !== true) {
    throw new TypeError("IAM role metadata is invalid");
  }

  const arnMatch = roleArnPattern.exec(resource.uid);
  if (
    resource.cloud_partition !== "aws" ||
    resource.region !== "us-east-1" ||
    resource.group.name !== "iam" ||
    resource.type !== "AwsIamRole" ||
    !arnMatch ||
    resource.name !== arnMatch[2] ||
    metadata.name !== resource.name ||
    metadata.arn !== resource.uid ||
    finding.unmapped.provider_uid !== arnMatch[1]
  ) {
    throw new TypeError("IAM role resource is invalid");
  }

  expectKeys(metadata.assume_role_policy, ["Version", "Statement"], "assume role policy");
  expectExactArrayLength(metadata.assume_role_policy.Statement, 1, "assume role statements");
  const statement = metadata.assume_role_policy.Statement[0];
  expectKeys(statement, ["Effect", "Principal", "Action"], "assume role statement");
  expectKeys(statement.Principal, ["Service"], "assume role principal");
  if (
    metadata.assume_role_policy.Version !== "2012-10-17" ||
    statement.Effect !== "Allow" ||
    statement.Principal.Service !== "lambda.amazonaws.com" ||
    statement.Action !== "sts:AssumeRole"
  ) {
    throw new TypeError("IAM role trust policy is invalid");
  }
}

function validateCloud(cloud, resource, unmapped) {
  expectKeys(cloud, ["account", "org", "provider", "region"], "cloud");
  expectKeys(cloud.account, ["name", "type", "type_id", "uid", "labels"], "cloud.account");
  expectKeys(cloud.org, ["name", "uid"], "cloud.org");
  expectExactArrayLength(cloud.account.labels, 0, "cloud.account.labels");
  const match = roleArnPattern.exec(resource.uid);
  if (
    cloud.provider !== "aws" ||
    cloud.region !== "us-east-1" ||
    cloud.account.name !== "" ||
    cloud.account.type !== "AWS Account" ||
    cloud.account.type_id !== 10 ||
    !accountIdPattern.test(cloud.account.uid) ||
    cloud.account.uid !== match?.[1] ||
    unmapped.provider_uid !== cloud.account.uid ||
    cloud.org.name !== "" ||
    cloud.org.uid !== ""
  ) {
    throw new TypeError("OCSF cloud scope is invalid");
  }
}

function parseUniqueJson(source) {
  if (typeof source !== "string") throw new SyntaxError("invalid JSON");
  let index = 0;

  const whitespace = () => {
    while (index < source.length && /[\t\n\r ]/.test(source[index])) index += 1;
  };

  const parseString = () => {
    if (source[index] !== '"') throw new SyntaxError("invalid JSON string");
    const start = index;
    index += 1;
    while (index < source.length) {
      const character = source[index];
      if (character === '"') {
        index += 1;
        const parsed = JSON.parse(source.slice(start, index));
        if (parsed.length > maximumStringLength || hasUnpairedSurrogate(parsed)) {
          throw new SyntaxError("JSON string is invalid");
        }
        return parsed;
      }
      if (character.charCodeAt(0) <= 0x1f) throw new SyntaxError("invalid JSON string");
      if (character !== "\\") {
        index += 1;
        continue;
      }
      index += 1;
      const escape = source[index];
      if ('"\\/bfnrt'.includes(escape ?? "")) {
        index += 1;
      } else if (escape === "u" && /^[a-fA-F0-9]{4}$/.test(source.slice(index + 1, index + 5))) {
        index += 5;
      } else {
        throw new SyntaxError("invalid JSON escape");
      }
    }
    throw new SyntaxError("unterminated JSON string");
  };

  const parseValue = (depth) => {
    if (depth > maximumDepth) throw new SyntaxError("JSON depth is invalid");
    whitespace();
    if (source[index] === "{") {
      index += 1;
      whitespace();
      const output = Object.create(null);
      const keys = new Set();
      if (source[index] === "}") {
        index += 1;
        return output;
      }
      while (true) {
        const key = parseString();
        if (keys.has(key)) throw new SyntaxError("duplicate JSON key");
        keys.add(key);
        if (keys.size > maximumCollectionSize) throw new SyntaxError("JSON object is too large");
        whitespace();
        if (source[index] !== ":") throw new SyntaxError("invalid JSON object");
        index += 1;
        output[key] = parseValue(depth + 1);
        whitespace();
        if (source[index] === "}") {
          index += 1;
          return output;
        }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON object");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === "[") {
      index += 1;
      whitespace();
      const output = [];
      if (source[index] === "]") {
        index += 1;
        return output;
      }
      while (true) {
        output.push(parseValue(depth + 1));
        if (output.length > maximumCollectionSize) throw new SyntaxError("JSON array is too large");
        whitespace();
        if (source[index] === "]") {
          index += 1;
          return output;
        }
        if (source[index] !== ",") throw new SyntaxError("invalid JSON array");
        index += 1;
        whitespace();
      }
    }
    if (source[index] === '"') return parseString();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) {
        index += literal.length;
        return value;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
    if (number === null) throw new SyntaxError("invalid JSON value");
    index += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isFinite(parsed)) throw new SyntaxError("invalid JSON number");
    return parsed;
  };

  const output = parseValue(0);
  whitespace();
  if (index !== source.length) throw new SyntaxError("invalid trailing JSON");
  return output;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function validateObservationInstant(value) {
  if (
    typeof value !== "string" ||
    !observationPattern.test(value) ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new TypeError("observation instant is invalid");
  }
}

function expectKeys(value, expected, context) {
  expectObject(value, context);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${context} has invalid keys`);
  }
}

function expectObject(value, context) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${context} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${context} must be a plain object`);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") throw new TypeError(`${context} has a symbol key`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError(`${context} must contain enumerable data properties`);
    }
  }
}

function expectExactArrayLength(value, length, context) {
  if (!Array.isArray(value) || value.length !== length) {
    throw new TypeError(`${context} has invalid length`);
  }
  const expectedKeys = Array.from({ length }, (_, index) => String(index));
  const actualKeys = Reflect.ownKeys(value).filter((key) => key !== "length");
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new TypeError(`${context} must be dense and contain no side properties`);
  }
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError(`${context} must contain enumerable data entries`);
    }
  }
}

function expectString(value, context) {
  if (typeof value !== "string" || value.length > maximumStringLength) {
    throw new TypeError(`${context} must be a bounded string`);
  }
}

function expectStringArray(value, context) {
  if (!Array.isArray(value) || value.length > maximumCollectionSize) {
    throw new TypeError(`${context} must be a bounded array`);
  }
  for (const entry of value) expectString(entry, `${context} entry`);
}

function validateTimestampPair(seconds, instant, context) {
  if (
    !Number.isSafeInteger(seconds) ||
    seconds < 0 ||
    typeof instant !== "string" ||
    !utcInstantPattern.test(instant)
  ) {
    throw new TypeError(`${context} must be a UTC timestamp pair`);
  }
  const milliseconds = Date.parse(instant);
  if (!Number.isFinite(milliseconds) || Math.floor(milliseconds / 1_000) !== seconds) {
    throw new TypeError(`${context} timestamp values do not match`);
  }
}

function sameArray(actual, expected) {
  return (
    Array.isArray(actual) &&
    actual.length === expected.length &&
    actual.every((entry, index) => entry === expected[index])
  );
}

function hash(parts) {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}
