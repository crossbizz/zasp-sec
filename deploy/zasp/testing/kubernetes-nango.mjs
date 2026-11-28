import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadAll } from "js-yaml";

const chart = fileURLToPath(new URL("../../kubernetes/zasp", import.meta.url));
export const release = "team";
export const namespace = "evaluation";
export const origin = "https://zasp.example.test:8443";
export const clientURL = `http://${release}-nango.${namespace}.svc.cluster.local:3003`;

export function helm(command, nango, options = {}) {
  const values = {
    publicOrigin: origin,
    images: { api: "example/zasp-api:ui", worker: "example/zasp-worker:ui", web: "example/zasp-web:ui" },
    secrets: { existingSecret: "product-credentials", ...options.secrets },
    product: { enabled: options.product ?? true },
    persistence: { enabled: options.persistence ?? true },
    nango,
  };
  const args = command === "lint" ? ["lint", chart] : ["template", release, chart, "--namespace", namespace];
  return spawnSync(process.env.ZASP_TEST_HELM || "helm", [...args, "--kube-version", "1.29.0", "--values", "-"], {
    encoding: "utf8",
    input: JSON.stringify(values),
    maxBuffer: 4 * 1024 * 1024,
  });
}

export function rendered(nango, options) {
  const result = helm("template", nango, options);
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return loadAll(result.stdout).filter(Boolean);
}
