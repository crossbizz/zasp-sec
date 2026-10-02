import assert from "node:assert/strict";
import test from "node:test";
import { normalizeTestReconciler } from "./test-reconciler-rollout.mjs";
import { testReconcilerReleaseFixture } from "./test-reconciler-release-fixture.mjs";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";

const normalize = (input, schema = 55, phase = "precision-intake", account = "123456789012") => normalizeTestReconciler(input, account, schema, phase);

test("full release reconciler opt-in pins workload authority and rejects tampering", async () => {
  const config = testReconcilerReleaseFixture();
  const rows = await renderRelease(productionReleaseFixture, { schemaVersion: 55, sessionSearchPhase: "precision-intake", testReconciler: config });
  const one = (rs, kind, name = "zasp-test-reconciler") => rs.find(r => r.kind === kind && r.metadata.name === name);
  const pod = rs => one(rs, "Deployment").spec.template.spec;
  const check = rs => validateRenderedRelease(rs, "123456789012", 55, "precision-intake", undefined, config);
  assert.doesNotThrow(() => check(rows));
  assert.equal(pod(rows).containers[0].env.find(e => e.name === "ZASP_WORKER_MODE").value, "security-agent-test-reconciler");
  assert.equal(pod(rows).serviceAccountName, "zasp-test-reconciler");
  assert.throws(() => validateRenderedRelease(rows, "123456789012", 55, "precision-intake"), /release rejected/);
  for (const mutate of [
    r => pod(r).hostNetwork = true,
    r => pod(r).initContainers = [{ name: "extra", image: "busybox" }],
    r => pod(r).automountServiceAccountToken = true,
    r => pod(r).containers[0].securityContext.privileged = true,
    r => pod(r).containers[0].image = `registry.example/unreviewed@sha256:${"f".repeat(64)}`,
    r => pod(r).containers[0].env.push({ name: "ZASP_PLANNER_TOKEN", value: "unexpected" }),
    r => pod(r).containers[0].args = ["exec /app/other"],
    r => pod(r).containers[0].volumeMounts[0].readOnly = false,
    r => pod(r).volumes[1].projected.sources[0].serviceAccountToken.audience = "other",
    r => pod(r).terminationGracePeriodSeconds = 20,
    r => pod(r).containers[0].readinessProbe.httpGet.path = "/healthz",
    r => pod(r).containers[0].resources.requests.cpu = "0",
    r => one(r, "Deployment").spec.strategy.type = "Recreate",
    r => one(r, "Deployment").spec.template.metadata.annotations["sidecar.istio.io/inject"] = "true",
    r => one(r, "ServiceAccount").metadata.annotations["eks.amazonaws.com/role-arn"] = "arn:aws:iam::123456789012:role/other",
    r => one(r, "SecretProviderClass", "zasp-test-reconciler-secrets").spec.parameters.objects += "\n- objectName: extra-secret\n  objectType: secretsmanager",
    r => one(r, "HorizontalPodAutoscaler").spec.maxReplicas = 1000,
    r => one(r, "PodDisruptionBudget").spec.minAvailable = 0,
    r => r.push(structuredClone(one(r, "Deployment"))),
    r => r.splice(r.indexOf(one(r, "ServiceAccount")), 1),
    r => r.push({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", metadata: { name: "extra-authority" }, subjects: [{ kind: "ServiceAccount", name: "zasp-test-reconciler" }], roleRef: { kind: "Role", name: "admin" } }),
    r => r.push({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "extra-access" }, spec: { podSelector: {}, policyTypes: ["Egress"], egress: [{}] } }),
  ]) {
    const changed = structuredClone(rows); mutate(changed);
    assert.throws(() => check(changed), /release rejected/);
  }
});

test("reconciler refuses indirect RBAC grants through authenticated service-account groups", async () => {
  const config = testReconcilerReleaseFixture();
  const rows = await renderRelease(productionReleaseFixture, { schemaVersion: 55, sessionSearchPhase: "precision-intake", testReconciler: config });
  const check = rs => validateRenderedRelease(rs, "123456789012", 55, "precision-intake", undefined, config);
  for (const kind of ["RoleBinding", "ClusterRoleBinding"]) {
    for (const group of ["system:serviceaccounts:agentsec", "system:serviceaccounts", "system:authenticated"]) {
      const binding = { apiVersion: "rbac.authorization.k8s.io/v1", kind, metadata: { name: "indirect-authority", ...(kind === "RoleBinding" ? { namespace: "another-namespace" } : {}) },
        subjects: [{ kind: "Group", apiGroup: "rbac.authorization.k8s.io", name: group }],
        roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: "admin" } };
      assert.throws(() => check([...rows, binding]), /release rejected/, `${kind} ${group}`);
      binding.subjects[0].name = "system:serviceaccounts:another-namespace";
      assert.doesNotThrow(() => check([...rows, binding]));
    }
  }
});

test("reconciler composes with audit exports in both precision phases", async () => {
  for (const phase of ["precision-consumers", "precision-intake"]) {
    const testReconciler = testReconcilerReleaseFixture(), auditExports = auditExportReleaseFixture();
    const rows = await renderRelease(productionReleaseFixture, { schemaVersion: 55, sessionSearchPhase: phase, auditExports, testReconciler });
    assert.doesNotThrow(() => validateRenderedRelease(rows, "123456789012", 55, phase, auditExports, testReconciler));
  }
});

test("reconciler metrics remain private and retain unready targets for alerting", async () => {
  const config = testReconcilerReleaseFixture();
  const rows = await renderRelease(productionReleaseFixture, { schemaVersion: 55, sessionSearchPhase: "precision-intake", testReconciler: config });
  const one = (rs, kind, name = "zasp-test-reconciler") => rs.find(r => r.kind === kind && r.metadata.name === name);
  const service = one(rows, "Service"), monitor = one(rows, "ServiceMonitor"), rules = one(rows, "PrometheusRule", "zasp-test-reconciler-availability");
  assert.ok(service && monitor && rules, "reconciler monitoring resources missing");
  assert.equal(service.spec.type, "ClusterIP");
  assert.equal(service.spec.publishNotReadyAddresses, true);
  assert.equal(monitor.spec.endpoints[0].path, "/metrics");
  const check = rs => validateRenderedRelease(rs, "123456789012", 55, "precision-intake", undefined, config);
  for (const mutate of [
    r => one(r, "Service").spec.type = "LoadBalancer",
    r => one(r, "Service").spec.publishNotReadyAddresses = false,
    r => one(r, "Service").spec.selector = {},
    r => one(r, "Service").spec.ports[0].targetPort = 8080,
    r => one(r, "ServiceMonitor").spec.namespaceSelector = { any: true },
    r => one(r, "ServiceMonitor").spec.endpoints[0].honorLabels = true,
    r => one(r, "ServiceMonitor").spec.endpoints[0].path = "/readyz",
    r => one(r, "NetworkPolicy", "zasp-test-reconciler-dependencies").spec.ingress[0].from = [{}],
    r => one(r, "NetworkPolicy", "zasp-test-reconciler-dependencies").spec.ingress[0].ports[0].port = 8080,
    r => one(r, "PrometheusRule", "zasp-test-reconciler-availability").spec.groups[0].rules[0].expr = "vector(0)",
    r => r.splice(r.indexOf(one(r, "ServiceMonitor")), 1),
    r => r.push(structuredClone(one(r, "Service"))),
  ]) { const changed = structuredClone(rows); mutate(changed); assert.throws(() => check(changed), /release rejected/); }
});

test("reconciler rejects terminal newlines in authority strings", () => {
  for (const field of ["roleArn", "databaseSecretArn", "evidenceBucket", "evidenceKMSKeyArn"]) {
    const value = testReconcilerReleaseFixture();
    value[field] += "\n";
    assert.throws(() => normalize(value), /release rejected/, field);
  }
});

test("reconciler configuration is explicit and snapshots all authority inputs", () => {
  assert.equal(normalize(undefined), undefined);
  for (const phase of ["precision-consumers", "precision-intake"]) {
    const input = testReconcilerReleaseFixture(), result = normalize(input, 55, phase);
    assert.deepEqual(result, input);
    input.roleArn = "changed";
    input.databaseCIDRs[0] = "0.0.0.0/0";
    input.stsCIDRs.push("10.90.0.0/24");
    assert.equal(result.roleArn, "arn:aws:iam::123456789012:role/zasp-production-test-reconciler");
    assert.deepEqual(result.databaseCIDRs, ["10.30.0.0/24"]);
    assert.deepEqual(result.stsCIDRs, ["10.31.0.0/28"]);
  }
});

test("reconciler rejects ambiguous and cross-account authority", () => {
  for (const change of [
    () => null, () => [], v => ({ ...v, enabled: false }), v => ({ ...v, enabled: "true" }),
    v => ({ ...v, queueURL: "unexpected" }), v => { delete v.roleArn; return v; },
    v => ({ ...v, roleArn: v.roleArn.replace("123456789012", "999999999999") }),
    v => ({ ...v, evidenceOwner: "999999999999" }),
    v => ({ ...v, evidenceKMSKeyArn: v.evidenceKMSKeyArn.replace("us-west-2", "us-east-1") }),
    v => ({ ...v, databaseSecretArn: v.databaseSecretArn.replace("us-west-2", "us-east-1") }),
    v => ({ ...v, awsRegion: "us-west-2 " }), v => ({ ...v, evidenceBucket: "" }),
    v => ({ ...v, evidenceKMSKeyArn: "alias/test" }),
    v => { v[Symbol("secret")] = true; return v; },
    v => { Object.setPrototypeOf(v, { extra: true }); return v; },
  ]) assert.throws(() => normalize(change(testReconcilerReleaseFixture())), /release rejected/);
  for (const [schema, phase] of [[54, "precision-intake"], [57, "precision-intake"], [55, "query"], [55, "compatibility"], [55, undefined]]) {
    assert.throws(() => normalizeTestReconciler(testReconcilerReleaseFixture(), "123456789012", schema, phase), /release rejected/);
  }
  assert.throws(() => normalize(testReconcilerReleaseFixture(), 55, "precision-intake", "000000000000"), /release rejected/);
});

test("reconciler rejects unsafe endpoint snapshots and never invokes input accessors", () => {
  for (const field of ["databaseCIDRs", "stsCIDRs", "s3CIDRs", "kmsCIDRs"]) {
    for (const value of [[], ["0.0.0.0/0"], ["127.0.0.0/24"], ["169.254.0.0/16"], ["224.0.0.0/24"], ["10.0.0.1/24"], ["10.01.0.0/16"], ["10.0.0.0/24", "10.0.0.0/28"], Array(65).fill("10.0.0.0/24"), ["::1/128"]]) {
      assert.throws(() => normalize({ ...testReconcilerReleaseFixture(), [field]: value }), /release rejected/);
    }
  }
  let calls = 0;
  const input = testReconcilerReleaseFixture();
  Object.defineProperty(input, "roleArn", { enumerable: true, get() { calls++; return "secret"; } });
  assert.throws(() => normalize(input), /release rejected/);
  const arrayInput = testReconcilerReleaseFixture();
  Object.defineProperty(arrayInput.databaseCIDRs, "0", { enumerable: true, get() { calls++; return "10.30.0.0/24"; } });
  assert.throws(() => normalize(arrayInput), /release rejected/);
  assert.equal(calls, 0);
});
