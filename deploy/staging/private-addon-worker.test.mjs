import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { load, loadAll } from "js-yaml";

const source = name => readFile(new URL("./product/" + name, import.meta.url), "utf8");

test("private upload grants and the ingress allow exactly the configured worker origin", async t => {
  const chart = await mkdtemp(join(tmpdir(), "zasp-private-worker-ingress-"));
  t.after(() => rm(chart, { recursive: true, force: true }));
  await mkdir(join(chart, "templates"));
  await writeFile(join(chart, "Chart.yaml"), await source("Chart.yaml"));
  for (const file of ["_private-addon-worker.tpl", "ingress.yaml"]) await writeFile(join(chart, "templates", file), await source("templates/" + file));
  const base = load(await source("values.yaml"));
  Object.assign(base.ingress, { host: "ui.test.invalid", tlsSecretName: "ui-cert" });
  base.global.publicOrigin = "https://ui.test.invalid";
  const valuesFile = join(chart, "values.json");
  async function render(worker) {
    await writeFile(valuesFile, JSON.stringify({ ...base, privateAddonWorker: worker }));
    const { stdout } = await promisify(execFile)("helm", ["template", "private-pilot", chart, "-f", valuesFile]);
    const ingress = loadAll(stdout).find(item => item?.metadata?.name === "zasp-product");
    return ingress.metadata.annotations["nginx.ingress.kubernetes.io/configuration-snippet"];
  }
  assert.match(await render(base.privateAddonWorker), /connect-src 'self';/);
  const id = "pid_11111111-2222-4333-8444-555555555555";
  const scope = [id,id,id].join("/");
  const cfg = {scope, origin: "https://worker.test.invalid:8443", resultCredentialID: id};
  assert.match(await render(cfg), /connect-src 'self' https:\/\/worker\.test\.invalid:8443;/);
  for (const invalid of [{origin:"https://*.test.invalid"}, {origin:"https://worker.test.invalid/path"}, {origin:"https://worker.test.invalid:65536"}, {scope:""}, {resultCredentialID:"invalid"}, {retained:"false"}]) {
    await assert.rejects(render({...cfg,...invalid}), /privateAddonWorker/);
  }
  const workload = await source("templates/workloads.yaml");
  assert.match(workload,/with include "zasp\.privateAddonWorker\.origin" \$root[\s\S]*?ZASP_PRIVATE_ADDON_WORKER_ORIGIN[\s\S]*?ZASP_PRIVATE_ADDON_WORKER_SCOPE/);
});
