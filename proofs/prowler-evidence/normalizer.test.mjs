import assert from "node:assert/strict";
import test from "node:test";

const normalizerApi = await import("./normalizer.mjs").catch(() => undefined);
const scopedIdApi = await import("./scoped_id.mjs").catch(() => undefined);

const organizationA = "org_aaaaaaaaaaaaaaaa";
const organizationB = "org_bbbbbbbbbbbbbbbb";
const observedAt = "2026-08-14T00:00:00.000Z";
const accountId = "000000000000";
const region = "us-east-1";
const roleName = "shared-fixture-role";
const roleArn = `arn:aws:iam::${accountId}:role/${roleName}`;
const resourceId =
  "org_aaaaaaaaaaaaaaaa:aws:identity_role:81eeba69c5c0887f4083a0e195a431b852d750fd3ee41ad276c1142285d1b77b";
const evidenceId =
  "org_aaaaaaaaaaaaaaaa:evidence:cloud_posture_check:ceee7fb6289f6bca038c500f9c4f9f97d6f94c144a282d61f0a2e8fc2c75f403";
const checkId = "iam_role_cross_service_confused_deputy_prevention";
const findingId =
  "org_aaaaaaaaaaaaaaaa:finding:cloud_identity_role_confused_deputy:b636729a9428ccdaf01accba0f8399a37bd6fd6855a0199d85b01d8dbf34f6c2";

function clone(value) {
  return structuredClone(value);
}

function exactOcsfFinding() {
  return [
    {
      message: "IAM Service Role shared-fixture-role lacks source scoping.",
      metadata: {
        event_code: checkId,
        product: {
          name: "Prowler",
          uid: "prowler",
          vendor_name: "Prowler",
          version: "5.39.0",
        },
        version: "1.5.0",
        profiles: ["cloud", "datetime"],
        tenant_uid: "",
      },
      severity_id: 4,
      severity: "High",
      status: "New",
      status_code: "FAIL",
      status_detail: "IAM Service Role shared-fixture-role lacks source scoping.",
      status_id: 1,
      unmapped: {
        related_url: "https://example.invalid/upstream-related",
        categories: ["identity-access", "trust-boundaries"],
        depends_on: [],
        related_to: [],
        additional_urls: ["https://example.invalid/upstream-reference"],
        notes: "upstream note that must not cross the product boundary",
        compliance: { upstream: ["arbitrary-control"] },
        scan_id: "0198a2c3-4d5e-7abc-8def-0123456789ab",
        provider_uid: accountId,
        provider: "aws",
      },
      activity_name: "Create",
      activity_id: 1,
      finding_info: {
        analytic: {
          name: "IAM service role prevents cross-service confused deputy attack",
          uid: checkId,
          type_id: 1,
          type: "Rule",
          category: "iam",
        },
        created_time: 1_786_665_600,
        created_time_dt: "2026-08-14T00:00:00+00:00",
        desc: "upstream check description",
        title: "upstream check title",
        uid: "upstream-finding-uuid",
        types: [
          "Software and Configuration Checks/AWS Security Best Practices",
          "TTPs/Privilege Escalation",
        ],
      },
      resources: [
        {
          cloud_partition: "aws",
          region,
          data: {
            details: "",
            metadata: {
              name: roleName,
              arn: roleArn,
              assume_role_policy: {
                Version: "2012-10-17",
                Statement: [
                  {
                    Effect: "Allow",
                    Principal: { Service: "lambda.amazonaws.com" },
                    Action: "sts:AssumeRole",
                  },
                ],
              },
              is_service_role: true,
              attached_policies: [],
              inline_policies: [],
              permissions_boundary: null,
              tags: [],
            },
          },
          group: { name: "iam" },
          labels: [],
          name: roleName,
          type: "AwsIamRole",
          uid: roleArn,
        },
      ],
      category_name: "Findings",
      category_uid: 2,
      class_name: "Detection Finding",
      class_uid: 2004,
      cloud: {
        account: {
          name: "",
          type: "AWS Account",
          type_id: 10,
          uid: accountId,
          labels: [],
        },
        org: { name: "", uid: "" },
        provider: "aws",
        region,
      },
      time: 1_786_665_600,
      time_dt: "2026-08-14T00:00:00+00:00",
      remediation: {
        desc: "upstream remediation that must not cross the product boundary",
        references: ["https://example.invalid/upstream-remediation"],
      },
      risk_details: "upstream risk prose that must not cross the product boundary",
      type_uid: 200401,
      type_name: "Detection Finding: Create",
    },
  ];
}

function artifact(value = exactOcsfFinding()) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function requireFunction(api, name) {
  assert.equal(typeof api?.[name], "function", `${name} production API is absent`);
  return api[name];
}

function normalize(organizationId = organizationA, value = exactOcsfFinding()) {
  const operation = requireFunction(normalizerApi, "normalizeProwlerEvidence");
  return operation(organizationId, artifact(value), observedAt);
}

function assertArtifactRejected(value) {
  assert.throws(
    () => normalizeProwlerEvidenceRaw(organizationA, value, observedAt),
    (error) => error instanceof TypeError,
  );
}

function normalizeProwlerEvidenceRaw(organizationId, bytes, instant) {
  return requireFunction(normalizerApi, "normalizeProwlerEvidence")(
    organizationId,
    bytes,
    instant,
  );
}

function expectedNormalized() {
  return {
    organization_id: organizationA,
    resources: [
      {
        id: resourceId,
        organization_id: organizationA,
        provider: "aws",
        kind: "identity_role",
        source_id: roleArn,
      },
    ],
    findings: [
      {
        id: findingId,
        organization_id: organizationA,
        category: "privileged_identity",
        rule_code: "cloud_identity_role_confused_deputy",
        severity: "high",
        status: "open",
        resource_id: resourceId,
      },
    ],
    evidence: [
      {
        id: evidenceId,
        organization_id: organizationA,
        resource_id: resourceId,
        kind: "cloud_posture_check",
        confidence: "exact",
        observed_at: observedAt,
        facts: {
          account_id: accountId,
          region,
          service_principal: "lambda.amazonaws.com",
          source_scope_present: false,
        },
      },
    ],
  };
}

function getAtPath(value, path) {
  return path.reduce((current, key) => current[key], value);
}

function parentAtPath(value, path) {
  return getAtPath(value, path.slice(0, -1));
}

test("normalizes the exact Prowler 5.39.0 OCSF finding into one product record", () => {
  assert.deepEqual(normalize(), expectedNormalized());
});

test("scopes the same provider resource and evidence independently for Organizations A and B", () => {
  const firstA = normalize(organizationA);
  const secondA = normalize(organizationA);
  const resultB = normalize(organizationB);

  assert.deepEqual(firstA, secondA);
  assert.notEqual(firstA.resources[0].id, resultB.resources[0].id);
  assert.notEqual(firstA.findings[0].id, resultB.findings[0].id);
  assert.notEqual(firstA.evidence[0].id, resultB.evidence[0].id);
  assert.equal(resultB.organization_id, organizationB);
  assert.equal(resultB.resources[0].organization_id, organizationB);
  assert.equal(resultB.findings[0].organization_id, organizationB);
  assert.equal(resultB.evidence[0].organization_id, organizationB);
});

test("uses the shared M0-10 scoped-source-ID grammar for the IAM role", () => {
  const canonicalScopedSourceId = requireFunction(scopedIdApi, "canonicalScopedSourceId");

  assert.equal(
    canonicalScopedSourceId(organizationA, "aws", "identity_role", roleArn),
    resourceId,
  );
  assert.equal(normalize().resources[0].id, resourceId);
});

test("rejects missing, null, extra, and case-aliased keys at every accepted object boundary", () => {
  const objectPaths = [
    [0],
    [0, "metadata"],
    [0, "metadata", "product"],
    [0, "unmapped"],
    [0, "finding_info"],
    [0, "finding_info", "analytic"],
    [0, "resources", 0],
    [0, "resources", 0, "data"],
    [0, "resources", 0, "data", "metadata"],
    [0, "resources", 0, "data", "metadata", "assume_role_policy"],
    [0, "resources", 0, "data", "metadata", "assume_role_policy", "Statement", 0],
    [0, "resources", 0, "data", "metadata", "assume_role_policy", "Statement", 0, "Principal"],
    [0, "resources", 0, "group"],
    [0, "cloud"],
    [0, "cloud", "account"],
    [0, "cloud", "org"],
    [0, "remediation"],
  ];

  for (const path of objectPaths) {
    const original = exactOcsfFinding();
    const object = getAtPath(original, path);
    const key = Object.keys(object)[0];

    const missing = clone(original);
    delete getAtPath(missing, path)[key];
    assertArtifactRejected(artifact(missing));

    const nullValue = clone(original);
    getAtPath(nullValue, path)[key] = null;
    assertArtifactRejected(artifact(nullValue));

    const extra = clone(original);
    getAtPath(extra, path).unexpected = true;
    assertArtifactRejected(artifact(extra));

    const alias = clone(original);
    const aliasObject = getAtPath(alias, path);
    const aliasInitial = key[0] === key[0].toUpperCase()
      ? key[0].toLowerCase()
      : key[0].toUpperCase();
    aliasObject[`${aliasInitial}${key.slice(1)}`] = clone(aliasObject[key]);
    assertArtifactRejected(artifact(alias));
  }
});

test("rejects duplicate JSON keys before ordinary JSON parsing can collapse them", () => {
  const source = JSON.stringify(exactOcsfFinding()).replace(
    `"event_code":"${checkId}"`,
    `"event_code":"duplicate","event_code":"${checkId}"`,
  );

  assertArtifactRejected(Buffer.from(source, "utf8"));
});

test("rejects malformed UTF-8, trailing JSON, excessive depth, oversized strings, and oversized artifacts", () => {
  assertArtifactRejected(Buffer.from([0xff, 0xfe, 0xfd]));
  assertArtifactRejected(Buffer.concat([artifact(), Buffer.from(" true")]));

  const deep = exactOcsfFinding();
  let nested = deep[0].unmapped.compliance;
  for (let index = 0; index < 20; index += 1) {
    nested.child = {};
    nested = nested.child;
  }
  assertArtifactRejected(artifact(deep));

  const longString = exactOcsfFinding();
  longString[0].message = "x".repeat(16_385);
  assertArtifactRejected(artifact(longString));

  assertArtifactRejected(Buffer.concat([artifact(), Buffer.alloc(65_537, 0x20)]));
});

test("rejects schema, class, type, activity, and product drift", () => {
  const cases = [
    [[0, "metadata", "version"], "1.4.0"],
    [[0, "metadata", "product", "version"], "5.38.0"],
    [[0, "metadata", "product", "name"], "Other"],
    [[0, "metadata", "product", "uid"], "other"],
    [[0, "metadata", "product", "vendor_name"], "Other"],
    [[0, "metadata", "profiles"], ["datetime", "cloud"]],
    [[0, "category_name"], "Other"],
    [[0, "category_uid"], 3],
    [[0, "class_name"], "Compliance Finding"],
    [[0, "class_uid"], 2005],
    [[0, "type_name"], "Detection Finding: Update"],
    [[0, "type_uid"], 200402],
    [[0, "activity_name"], "Update"],
    [[0, "activity_id"], 2],
    [[0, "finding_info", "created_time_dt"], "not-an-instant"],
    [[0, "finding_info", "created_time"], 1],
    [[0, "time_dt"], "not-an-instant"],
    [[0, "time"], 1],
    [[0, "unmapped", "scan_id"], "123e4567-e89b-42d3-a456-426614174000"],
  ];

  for (const [path, invalid] of cases) {
    const value = exactOcsfFinding();
    parentAtPath(value, path)[path.at(-1)] = invalid;
    assertArtifactRejected(artifact(value));
  }
});

test("rejects unknown check identity, status, and severity combinations", () => {
  const cases = [
    [[0, "metadata", "event_code"], "iam_other_check"],
    [[0, "finding_info", "analytic", "uid"], "iam_other_check"],
    [[0, "finding_info", "analytic", "type_id"], 2],
    [[0, "finding_info", "analytic", "type"], "Behavioral"],
    [[0, "finding_info", "analytic", "category"], "sts"],
    [[0, "status"], "Suppressed"],
    [[0, "status_id"], 5],
    [[0, "status_code"], "PASS"],
    [[0, "severity"], "Medium"],
    [[0, "severity_id"], 3],
  ];

  for (const [path, invalid] of cases) {
    const value = exactOcsfFinding();
    parentAtPath(value, path)[path.at(-1)] = invalid;
    assertArtifactRejected(artifact(value));
  }
});

test("rejects resource, provider, region, and account drift", () => {
  const cases = [
    [[0, "resources"], []],
    [[0, "resources", 0, "cloud_partition"], "aws-cn"],
    [[0, "resources", 0, "region"], "us-west-2"],
    [[0, "resources", 0, "group", "name"], "sts"],
    [[0, "resources", 0, "labels"], ["provider-native-label"]],
    [[0, "resources", 0, "name"], "other-role"],
    [[0, "resources", 0, "type"], "Other"],
    [[0, "resources", 0, "uid"], "arn:aws:iam::000000000000:role/other-role"],
    [[0, "cloud", "provider"], "azure"],
    [[0, "cloud", "region"], "us-west-2"],
    [[0, "cloud", "account", "type"], "Other"],
    [[0, "cloud", "account", "type_id"], 99],
    [[0, "cloud", "account", "uid"], "111111111111"],
    [[0, "cloud", "account", "labels"], ["provider-native-label"]],
    [[0, "unmapped", "provider"], "azure"],
    [[0, "unmapped", "provider_uid"], "111111111111"],
  ];

  for (const [path, invalid] of cases) {
    const value = exactOcsfFinding();
    parentAtPath(value, path)[path.at(-1)] = invalid;
    assertArtifactRejected(artifact(value));
  }

  const multiple = exactOcsfFinding();
  multiple[0].resources.push(clone(multiple[0].resources[0]));
  assertArtifactRejected(artifact(multiple));
});

test("rejects ARN/account mismatches and any trust policy other than one unscoped service statement", () => {
  const cases = [
    [[0, "resources", 0, "data", "metadata", "arn"], "arn:aws:iam::111111111111:role/shared-fixture-role"],
    [[0, "resources", 0, "data", "metadata", "name"], "other-role"],
    [[0, "resources", 0, "data", "metadata", "is_service_role"], false],
    [[0, "resources", 0, "data", "metadata", "attached_policies"], [{}]],
    [[0, "resources", 0, "data", "metadata", "inline_policies"], ["policy"]],
    [[0, "resources", 0, "data", "metadata", "permissions_boundary"], {}],
    [[0, "resources", 0, "data", "metadata", "tags"], [{ Key: "scope", Value: "foreign" }]],
    [[0, "resources", 0, "data", "metadata", "assume_role_policy", "Version"], "2008-10-17"],
    [[0, "resources", 0, "data", "metadata", "assume_role_policy", "Statement", 0, "Effect"], "Deny"],
    [[0, "resources", 0, "data", "metadata", "assume_role_policy", "Statement", 0, "Principal", "Service"], "ec2.amazonaws.com"],
    [[0, "resources", 0, "data", "metadata", "assume_role_policy", "Statement", 0, "Action"], "sts:*"],
  ];

  for (const [path, invalid] of cases) {
    const value = exactOcsfFinding();
    parentAtPath(value, path)[path.at(-1)] = invalid;
    assertArtifactRejected(artifact(value));
  }

  const secondStatement = exactOcsfFinding();
  secondStatement[0].resources[0].data.metadata.assume_role_policy.Statement.push(
    clone(secondStatement[0].resources[0].data.metadata.assume_role_policy.Statement[0]),
  );
  assertArtifactRejected(artifact(secondStatement));

  const sourceScoped = exactOcsfFinding();
  sourceScoped[0].resources[0].data.metadata.assume_role_policy.Statement[0].Condition = {
    StringEquals: { "aws:SourceAccount": accountId },
  };
  assertArtifactRejected(artifact(sourceScoped));
});

test("rejects coherent alternate accounts, role ARNs, and role names", () => {
  const alternateAccount = exactOcsfFinding();
  const alternateAccountId = "111111111111";
  const alternateAccountArn =
    `arn:aws:iam::${alternateAccountId}:role/${roleName}`;
  alternateAccount[0].resources[0].uid = alternateAccountArn;
  alternateAccount[0].resources[0].data.metadata.arn = alternateAccountArn;
  alternateAccount[0].cloud.account.uid = alternateAccountId;
  alternateAccount[0].unmapped.provider_uid = alternateAccountId;
  assertArtifactRejected(artifact(alternateAccount));

  const alternateRole = exactOcsfFinding();
  const alternateRoleName = "other-fixture-role";
  const alternateRoleArn = `arn:aws:iam::${accountId}:role/${alternateRoleName}`;
  alternateRole[0].resources[0].name = alternateRoleName;
  alternateRole[0].resources[0].uid = alternateRoleArn;
  alternateRole[0].resources[0].data.metadata.name = alternateRoleName;
  alternateRole[0].resources[0].data.metadata.arn = alternateRoleArn;
  assertArtifactRejected(artifact(alternateRole));
});

test("excludes arbitrary upstream prose, timestamps, UUIDs, tags, remediation, and native labels", () => {
  const changed = exactOcsfFinding();
  changed[0].message = "different upstream message";
  changed[0].status_detail = "different upstream status prose";
  changed[0].finding_info.name = undefined;
  delete changed[0].finding_info.name;
  changed[0].finding_info.desc = "different upstream description";
  changed[0].finding_info.title = "different upstream title";
  changed[0].finding_info.analytic.name = "different upstream analytic title";
  changed[0].finding_info.uid = "different-upstream-uuid";
  changed[0].finding_info.created_time = 1;
  changed[0].finding_info.created_time_dt = "1970-01-01T00:00:01+00:00";
  changed[0].time = 2;
  changed[0].time_dt = "1970-01-01T00:00:02+00:00";
  changed[0].unmapped.related_url = "arbitrary prose";
  changed[0].unmapped.categories = ["provider-native-category"];
  changed[0].unmapped.depends_on = ["provider-native-dependency"];
  changed[0].unmapped.related_to = ["provider-native-related"];
  changed[0].unmapped.additional_urls = ["arbitrary prose"];
  changed[0].unmapped.notes = "arbitrary prose";
  changed[0].unmapped.compliance = { arbitrary: { nested: "provider-native-control" } };
  changed[0].unmapped.scan_id = "0198a2c3-4d5e-7fff-8fff-ffffffffffff";
  changed[0].remediation.desc = "different upstream remediation";
  changed[0].remediation.references = ["arbitrary prose"];
  changed[0].risk_details = "different upstream risk";

  assert.deepEqual(normalize(organizationA, changed), expectedNormalized());
});

test("rejects upstream tenant scope claims instead of trusting them", () => {
  for (const path of [
    [0, "metadata", "tenant_uid"],
    [0, "cloud", "org", "uid"],
    [0, "cloud", "org", "name"],
  ]) {
    const value = exactOcsfFinding();
    parentAtPath(value, path)[path.at(-1)] = organizationB;
    assertArtifactRejected(artifact(value));
  }
});

test("normalized validation rejects Organization and resource-link mismatches", () => {
  const validate = requireFunction(normalizerApi, "validateNormalizedProwlerEvidence");
  assert.doesNotThrow(() => validate(expectedNormalized()));

  for (const mutate of [
    (value) => { value.resources[0].organization_id = organizationB; },
    (value) => { value.findings[0].organization_id = organizationB; },
    (value) => { value.evidence[0].organization_id = organizationB; },
    (value) => { value.findings[0].resource_id = `${organizationA}:aws:identity_role:${"0".repeat(64)}`; },
    (value) => { value.findings[0].rule_code = "other_rule"; },
    (value) => { value.findings[0].id = `${organizationA}:finding:cloud_identity_role_confused_deputy:${"0".repeat(64)}`; },
    (value) => { value.evidence[0].resource_id = `${organizationA}:aws:identity_role:${"0".repeat(64)}`; },
    (value) => { value.resources[0].id = `${organizationA}:aws:identity_role:${"0".repeat(64)}`; },
    (value) => { value.evidence[0].id = `${organizationA}:evidence:cloud_posture_check:${"0".repeat(64)}`; },
  ]) {
    const value = expectedNormalized();
    mutate(value);
    assert.throws(() => validate(value), { name: "TypeError" });
  }
});

test("rejects impossible OCSF calendar instants and accepts both canonical UTC forms", () => {
  for (const instant of [
    "2026-02-31T00:00:00Z",
    "2026-02-31T00:00:00+00:00",
  ]) {
    for (const pair of [
      ["created_time", "created_time_dt"],
      ["time", "time_dt"],
    ]) {
      const value = exactOcsfFinding();
      const target = pair[0] === "time" ? value[0] : value[0].finding_info;
      target[pair[0]] = 1_772_496_000;
      target[pair[1]] = instant;
      assertArtifactRejected(artifact(value));
    }
  }

  const zulu = exactOcsfFinding();
  zulu[0].finding_info.created_time_dt = "2026-08-14T00:00:00Z";
  zulu[0].time_dt = "2026-08-14T00:00:00Z";
  assert.deepEqual(normalize(organizationA, zulu), expectedNormalized());
});

test("normalized validation rejects hostile source IDs without invoking coercion hooks", () => {
  const validate = requireFunction(normalizerApi, "validateNormalizedProwlerEvidence");

  for (const hostile of [
    {
      toString() {
        throw new Error("toString must not run");
      },
    },
    {
      toString() {
        return {};
      },
      valueOf() {
        throw new Error("valueOf must not run");
      },
    },
  ]) {
    const value = expectedNormalized();
    value.resources[0].source_id = hostile;
    assert.throws(() => validate(value), { name: "TypeError" });
  }
});

test("normalized validation rejects accessors, symbols, and array side properties", () => {
  const validate = requireFunction(normalizerApi, "validateNormalizedProwlerEvidence");

  const accessor = expectedNormalized();
  Object.defineProperty(accessor.resources[0], "organization_id", {
    enumerable: true,
    get() {
      return organizationA;
    },
  });
  assert.throws(() => validate(accessor), { name: "TypeError" });

  const symbolic = expectedNormalized();
  symbolic[Symbol("hidden")] = true;
  assert.throws(() => validate(symbolic), { name: "TypeError" });

  const arrayProperty = expectedNormalized();
  arrayProperty.resources.hidden = true;
  assert.throws(() => validate(arrayProperty), { name: "TypeError" });
});

test("product-visible labels remain implementation- and provider-neutral", () => {
  const normalized = normalize();
  const labels = [
    normalized.resources[0].kind,
    normalized.findings[0].category,
    normalized.findings[0].rule_code,
    normalized.findings[0].severity,
    normalized.findings[0].status,
    normalized.evidence[0].kind,
    normalized.evidence[0].confidence,
    ...Object.keys(normalized.evidence[0].facts),
  ];

  for (const label of labels) {
    assert.doesNotMatch(label, /prowler|ocsf|docker|localstack|aws/i);
  }
});

test("rejects invalid Organization and observation inputs", () => {
  assert.throws(
    () => normalizeProwlerEvidenceRaw("tenant_aaaaaaaaaaaaaaaa", artifact(), observedAt),
    { name: "TypeError" },
  );
  for (const invalid of [undefined, null, "", "2026-08-14", "2026-08-14T00:00:00Z", 1]) {
    assert.throws(
      () => normalizeProwlerEvidenceRaw(organizationA, artifact(), invalid),
      { name: "TypeError" },
    );
  }
  assert.throws(
    () => normalizeProwlerEvidenceRaw(organizationA, exactOcsfFinding(), observedAt),
    { name: "TypeError" },
  );
});
