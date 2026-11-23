import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadAll } from "js-yaml";

const chart = fileURLToPath(new URL(".", import.meta.url));
const values = {
  enabled: true, region: "eu-central-1", model: "Horizon-Labs/prompt-injection-guard-base",
  inferenceImage: "registry.internal/engine@sha256:" + "b".repeat(64),
  tlsProxyImage: "registry.internal/nginx@sha256:" + "a".repeat(64),
  tlsSecret: "model-tls", weightsClaim: "model-weights", clientNamespace: "control",
};
function render(overrides) {
  return loadAll(execFileSync("helm", ["template", "test", chart, "--values", "-"], {
    input: JSON.stringify(overrides), encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 15_000,
  })).filter(Boolean);
}
test("private models are off by default", () => { assert.equal(render({}).length, 0); });
test("both engines use offline weights behind private TLS and permit only inference clients", () => {
  for (const kind of ["onnx", "vllm"]) {
    const model = kind === "onnx" ? values.model : "mistralai/Shieldstral-1.0-3B";
    const resources = render({ ...values, kind, model });
    const get = k => resources.find(r => r.kind === k);
    const spec = get("Deployment").spec.template.spec;
    assert.equal(spec.nodeSelector["topology.kubernetes.io/region"], values.region);
    assert.equal(spec.automountServiceAccountToken, false);
    assert.ok(spec.volumes.find(v => v.name === "weights").persistentVolumeClaim.readOnly);
    const engine = spec.containers.find(c => c.name === "inference");
    assert.equal(engine.image, values.inferenceImage);
    assert.ok(engine.securityContext.readOnlyRootFilesystem && !engine.securityContext.allowPrivilegeEscalation);
    assert.equal(engine.resources.limits["nvidia.com/gpu"], kind === "vllm" ? "1" : undefined);
    assert.ok(engine.args.includes("127.0.0.1"));
    const proxy = get("ConfigMap").data["nginx.conf"];
    assert.ok(proxy.includes(kind === "onnx" ? "location = /predict" : "location = /v1/chat/completions"));
    assert.ok(proxy.includes("listen 8443 ssl;") && proxy.includes("access_log off;"));
    assert.equal(get("Service").spec.type, "ClusterIP");
    const policy = get("NetworkPolicy").spec;
    assert.deepEqual(policy.egress, []);
    assert.deepEqual(policy.ingress[0].ports, [{ protocol: "TCP", port: 8443 }]);
    assert.equal(policy.ingress[0].from[0].namespaceSelector.matchLabels["kubernetes.io/metadata.name"], values.clientNamespace);
    assert.ok(policy.ingress[0].from[0].podSelector.matchExpressions[0].values.includes("agentsec-api"));
  }
});
test("wrong region, model or mutable images cannot render an enabled service", () => {
  for (const change of [{ region: "ap-south-1" }, { model: "unknown" }, { tlsProxyImage: "nginx:latest" }, { weightsClaim: "" }]) {
    assert.throws(() => render({ ...values, ...change }));
  }
});
