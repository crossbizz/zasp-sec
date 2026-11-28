import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { helm, rendered, release, clientURL } from "./testing/kubernetes-nango.mjs";
import { nangoImage } from "../production/nango-image-proof.mjs";

const byName = (values, name) => values.find(value => value.name === name);
const podOf = docs => docs.find(doc => doc.kind === "StatefulSet").spec.template.spec;

test("Kubernetes installs the Nango database, migration and server, and binds the product clients to its private service", () => {
  const nango = { enabled: true, existingSecret: "provider-service-credentials" };
  const lint = helm("lint", nango);
  assert.ifError(lint.error);
  assert.equal(lint.status, 0, lint.stdout + lint.stderr);

  const docs = rendered(nango);
  const pod = podOf(docs);
  const ordered = pod.initContainers.map(container => container.name);
  assert.ok(ordered.indexOf("database-init") >= 0 && ordered.indexOf("database-init") < ordered.indexOf("nango-migrate"));
  assert.ok(ordered.indexOf("nango") > ordered.indexOf("nango-migrate"));
  const initDB = byName(pod.initContainers, "database-init");
  assert.match(initDB.args.join("\n"), /CREATE DATABASE nango OWNER nango/);
  const migrate = byName(pod.initContainers, "nango-migrate");
  const server = byName(pod.initContainers, "nango");
  assert.deepEqual(migrate.command, ["node", "packages/server/dist/migrate.js"]);
  assert.deepEqual(server.command, ["node", "packages/server/dist/server.js"]);
  assert.equal(server.restartPolicy, "Always");
  assert.equal(server.startupProbe.httpGet.path, "/ready");
  assert.equal(server.readinessProbe.httpGet.port, "nango");
  assert.equal(server.livenessProbe.httpGet.path, "/health");

  for (const container of [migrate, server]) {
    assert.equal(container.image, nangoImage);
    assert.equal(container.securityContext.runAsNonRoot, true);
    const db = new URL(byName(container.env, "NANGO_DATABASE_URL").value);
    assert.equal(db.hostname, "127.0.0.1");
    assert.equal(db.username, "nango");
    assert.equal(db.pathname, "/nango");
    assert.deepEqual(byName(container.env, "NANGO_ENCRYPTION_KEY").valueFrom.secretKeyRef, { name: nango.existingSecret, key: "encryption-key" });
  }
  assert.deepEqual(byName(server.env, "NANGO_SECRET_KEY_PROD").valueFrom.secretKeyRef, { name: nango.existingSecret, key: "service-key" });
  assert.deepEqual(byName(server.env, "NANGO_ADMIN_KEY").valueFrom.secretKeyRef, { name: nango.existingSecret, key: "admin-key" });
  assert.equal(byName(server.env, "NANGO_PUBLIC_SERVER_URL").value, "http://127.0.0.1:3003");
  assert.equal(byName(server.env, "NANGO_SERVER_URL").value, "http://127.0.0.1:3003");
  assert.equal(byName(server.env, "NANGO_PUBLIC_CONNECT_URL").value, clientURL + "/connect");
  assert.equal(docs.some(doc => doc.kind === "Secret" && doc.metadata.name === nango.existingSecret), false);

  const service = docs.find(doc => doc.kind === "Service" && doc.metadata.name === release + "-nango");
  assert.equal(service.spec.type, "ClusterIP");
  assert.equal(service.spec.publishNotReadyAddresses, true);
  assert.deepEqual(service.spec.ports, [{ name: "nango", port: 3003, targetPort: "nango" }]);
  const policy = docs.find(doc => doc.kind === "NetworkPolicy");
  const trafficToNango = policy.spec.ingress.filter(rule => rule.ports.some(port => port.port === 3003));
  assert.deepEqual(trafficToNango.map(rule => rule.from), [[{ podSelector: { matchLabels: service.spec.selector } }]]);
  const clientVolume = byName(pod.volumes, "nango-client");
  assert.equal(clientVolume.secret.secretName, nango.existingSecret);
  assert.deepEqual(clientVolume.secret.items, [{ key: "service-key", path: "service-key" }]);
  const clients = pod.containers.filter(container => byName(container.volumeMounts ?? [], clientVolume.name));
  assert.deepEqual(clients.map(container => container.name).sort(), ["api", "worker-discovery"]);
  for (const client of clients) {
    assert.equal(byName(client.volumeMounts, clientVolume.name).mountPath, "/var/run/secrets/zasp-nango");
    assert.equal(byName(client.env, "ZASP_NANGO_BASE_URL").value, clientURL);
    assert.equal(byName(client.env, "ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION").value, "collector_v1");
  }
});

test("Kubernetes renders and validates Nango secrets independently of the existing product secret", () => {
  const serviceKey = randomBytes(32).toString("hex");
  const encryptionKey = randomBytes(32).toString("base64");
  const adminKey = randomBytes(32).toString("hex");
  const nango = { enabled: true };
  const secrets = { nangoServiceKey: serviceKey, nangoEncryptionKey: encryptionKey, nangoAdminKey: adminKey };
  const docs = rendered(nango, { secrets });
  const secret = docs.find(doc => doc.kind === "Secret" && doc.metadata.name === release + "-nango");
  assert.equal(Buffer.from(secret.data["service-key"], "base64").toString(), serviceKey);
  assert.equal(Buffer.from(secret.data["encryption-key"], "base64").toString(), encryptionKey);
  assert.equal(Buffer.from(secret.data["admin-key"], "base64").toString(), adminKey);
  const pod = podOf(docs);
  assert.equal(JSON.stringify(pod).includes(adminKey), false);
  assert.equal(JSON.stringify(pod).includes(serviceKey), false);
  assert.equal(JSON.stringify(pod).includes(encryptionKey), false);
  for (const [key, value] of [["nangoServiceKey", ""], ["nangoEncryptionKey", "bad"], ["nangoAdminKey", ""], ["nangoAdminKey", serviceKey]]) {
    const result = helm("template", nango, { secrets: { ...secrets, [key]: value } });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.ok(result.stderr.includes(key));
  }
});

test("the disabled and maintenance Kubernetes profiles leave Nango offline", () => {
  for (const [nango, options] of [[{ enabled: false }, {}], [{ enabled: true, existingSecret: "provider-service-credentials" }, { product: false }]]) {
    const docs = rendered(nango, options);
    const pod = podOf(docs);
    assert.equal(pod.initContainers.some(container => container.name.startsWith("nango")), false);
    assert.equal(pod.volumes.some(volume => volume.name === "nango-client"), false);
    assert.equal(docs.some(doc => doc.kind === "Service" && doc.metadata.name === release + "-nango"), false);
    assert.equal(pod.containers.some(container => container.env?.some(entry => entry.name === "ZASP_NANGO_BASE_URL")), false);
  }
});
