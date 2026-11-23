import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { once } from "node:events";
import test from "node:test";

import { classifyGoLicense, electedNpmLicense, loadReleasePolicy, runReadOnlySynthetic, validateGoSpdxDocument, verifyReleaseSources } from "./release-gates.mjs";

test("json-schema elects the reviewed BSD grant for the exact dual-licensed tarball", () => {
  const entry = {
    name: "json-schema", versionInfo: "0.4.0", licenseDeclared: "(AFL-2.1 OR BSD-3-Clause)",
    checksums: [{ algorithm: "SHA512", checksumValue: "7acf783379d321fb043e2b1169f6a4f870cb7c75e7281855def5397aa3dc4b77e5216a9cc495a05c75e27b2dd8ae968db1a9d8e5e8b55686046cece28eeabd04" }],
  };
  assert.equal(electedNpmLicense(entry), "BSD-3-Clause");
  for (const change of [{ name: "other" }, { versionInfo: "0.4.1" }, { checksums: [] }]) {
    assert.equal(electedNpmLicense({ ...entry, ...change }), entry.licenseDeclared);
  }
  assert.equal(electedNpmLicense({ ...entry, licenseConcluded: "AFL-2.1" }), "AFL-2.1");
  assert.equal(electedNpmLicense({ ...entry, licenseDeclared: "MIT-0" }), "MIT-0");
});

test("the published MIT notice accompanies each image linking segmentio/asm", async () => {
  const notice = await readFile(new URL("../../services/platform/licenses/segmentio-asm-MIT.txt", import.meta.url));
  assert.equal(createHash("sha256").update(notice).digest("hex"), "e2a78de21d6d8ded2dff0f3189cd32e011630d785da127ebfbc8949012c0947b");
  assert.equal(classifyGoLicense(notice.toString()), "MIT");
  assert.equal(classifyGoLicense("MIT No Attribution\nPermission is hereby granted, free of charge"), "MIT-0");
  assert.equal(classifyGoLicense("SPDX-License-Identifier: MIT-0"), "MIT-0");
  assert.equal(classifyGoLicense("Permission is hereby granted, free of charge"), "NOASSERTION");
  for (const image of ["api", "worker", "redteam-worker", "attack-lab-runner"]) {
    const definition = await readFile(new URL(`./${image}.Dockerfile`, import.meta.url), "utf8");
    assert.match(definition, /^COPY services\/platform\/licenses\/segmentio-asm-MIT\.txt \/usr\/share\/licenses\/zasp\/segmentio-asm-MIT\.txt$/m);
  }
});

test("release policy binds performance, resilience, supply-chain, and owned proof gates", async () => {
  const policy = await loadReleasePolicy();
  assert.deepEqual(policy.performance, { webP95Milliseconds: 2000, apiReadP95Milliseconds: 500, apiMutationP95Milliseconds: 1000, errorRatePercent: 1 });
  assert.deepEqual(policy.resilience, ["replica_restart", "provider_timeout", "queue_redrive", "stale_read_revalidation"]);
  assert.deepEqual(policy.supplyChain, ["npm_spdx_sbom", "go_spdx_sbom", "license_allowlist", "offline_dependency_audit", "digest_pinned_container_definition", "full_tracked_gitleaks", "required_ci_gate"]);
  assert.equal(policy.proof.ownedPrefix, "zasp-production-e2e-");
  assert.equal(policy.proof.ambientMutation, false);
});

test("read-only synthetic proves web and authenticated API correlation without leaking token", async () => {
  let observedToken = "";
  const server = createServer((request, response) => {
    if (request.url === "/sign-in") {
      response.writeHead(200, securityHeaders({ "content-type": "text/html" }));
      response.end("Zasp sign in");
      return;
    }
    if (request.url === "/api/v1/home/summary") {
      observedToken = String(request.headers.authorization ?? "");
      response.writeHead(200, securityHeaders({ "content-type": "application/json", "x-correlation-id": "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", traceparent: "00-11111111111111111111111111111111-2222222222222222-01" }));
      response.end("{}");
      return;
    }
    response.writeHead(404); response.end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const origin = `http://${server.address().address}:${server.address().port}`;
    const evidence = await runReadOnlySynthetic({ origin, token: "synthetic-secret-token-with-32-bytes", allowHTTPLoopback: true });
    assert.deepEqual(Object.keys(evidence), ["apiMilliseconds", "correlationID", "traceID", "webMilliseconds"]);
    assert.equal(observedToken, "Bearer synthetic-secret-token-with-32-bytes");
    assert.doesNotMatch(JSON.stringify(evidence), /synthetic-secret/);
  } finally {
    server.close(); await once(server, "close");
  }
});

test("read-only synthetic refuses invalid trace and span identifiers", async (t) => {
  let header;
  const server = createServer((request, response) => {
    const headers = securityHeaders({ "content-type": "application/json" });
    if (request.url === "/api/v1/home/summary") {
      headers["x-correlation-id"] = "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
      headers.traceparent = header;
    }
    response.writeHead(200, headers);
    response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    for (const [name, value, accepted] of [
      ["valid sampled", "00-11111111111111111111111111111111-2222222222222222-01", true],
      ["valid unsampled", "00-11111111111111111111111111111111-2222222222222222-00", true],
      ["zero span", "00-11111111111111111111111111111111-0000000000000000-01", false],
      ["zero trace", "00-00000000000000000000000000000000-2222222222222222-01", false],
      ["malformed", "00-11111111111111111111111111111111-222222222222222-01", false],
    ]) {
      await t.test(name, async () => {
        header = value;
        const probe = runReadOnlySynthetic({ origin, token: "synthetic-secret-token-with-32-bytes", allowHTTPLoopback: true });
        if (accepted) {
          const evidence = await probe;
          assert.equal(evidence.traceID, "11111111111111111111111111111111");
          assert.doesNotMatch(JSON.stringify(evidence), /synthetic-secret/);
        } else {
          await assert.rejects(probe, { message: "synthetic rejected" });
        }
      });
    }
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("release sources contain truthful runbooks, canary, SBOM/license/image/secret gates", async () => {
  const result = await verifyReleaseSources();
  assert.deepEqual(result.renderedRollouts, [
    { schemaVersion: 48, phase: "compatibility", schemaJob: "agentsec-schema-v48" },
    { schemaVersion: 49, phase: "compatibility", schemaJob: "agentsec-schema-v49" },
    { schemaVersion: 50, phase: "backfill", schemaJob: "agentsec-schema-v50" },
    { schemaVersion: 50, phase: "query", schemaJob: "agentsec-schema-v50" },
    { schemaVersion: 51, phase: "precision-consumers", schemaJob: "agentsec-schema-v51" },
    { schemaVersion: 51, phase: "precision-intake", schemaJob: "agentsec-schema-v51" },
    { schemaVersion: 52, phase: "precision-consumers", schemaJob: "agentsec-schema-v52" },
    { schemaVersion: 52, phase: "precision-intake", schemaJob: "agentsec-schema-v52" },
    { schemaVersion: 53, phase: "precision-consumers", schemaJob: "agentsec-schema-v53" },
    { schemaVersion: 53, phase: "precision-intake", schemaJob: "agentsec-schema-v53" },
    { schemaVersion: 54, phase: "precision-consumers", schemaJob: "agentsec-schema-v54" },
    { schemaVersion: 54, phase: "precision-intake", schemaJob: "agentsec-schema-v54" },
  ]);
  assert.equal(result.canary, true);
  assert.equal(result.documentation, true);
  assert.equal(result.imageDefinitions, 9);
  assert.equal(result.licensePolicy, true);
  assert.equal(result.trackedSecretScan, true);
  assert.ok(result.npmSpdxPackages > 20);
  assert.ok(result.goSpdxPackages > 20);
  const asm = result.goSpdx.packages.find(entry => entry.name === "github.com/segmentio/asm");
  assert.equal(asm?.versionInfo, "v1.2.1-0.20231018155815-7fd3678d1b7f");
  assert.equal(asm.licenseConcluded, "MIT");
  assert.ok(result.goSpdx, "Go SPDX document is included in release evidence");
  assert.equal(result.goSpdx.spdxVersion, "SPDX-2.3");
  assert.equal(result.goSpdx.dataLicense, "CC0-1.0");
  assert.equal(result.goSpdx.SPDXID, "SPDXRef-DOCUMENT");
  assert.match(result.goSpdx.documentNamespace, /^https:\/\/zasp\.example\/spdx\/go-source\/[a-f0-9]{64}$/);
  assert.ok(result.goSpdx.creationInfo.creators.includes("Tool: zasp-production-release-gate"));
  const packageIDs = new Set(result.goSpdx.packages.map(({ SPDXID }) => SPDXID));
  assert.equal(packageIDs.size, result.goSpdx.packages.length);
  assert.ok([...packageIDs].every((id) => /^SPDXRef-Package-[A-Za-z0-9.-]+$/.test(id)));
  assert.equal(result.goSpdx.relationships.length, result.goSpdx.packages.length);
  for (const relationship of result.goSpdx.relationships) {
    assert.equal(relationship.spdxElementId, "SPDXRef-DOCUMENT");
    assert.equal(relationship.relationshipType, "DESCRIBES");
    assert.ok(packageIDs.has(relationship.relatedSpdxElement));
  }
  assert.equal(validateGoSpdxDocument(result.goSpdx), true);
  assert.throws(() => validateGoSpdxDocument({ ...result.goSpdx, relationships: [] }), /Go SBOM gate rejected/);
  const secondResult = await verifyReleaseSources();
  assert.deepEqual({
    firstTimestampWholeSecond: /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(result.goSpdx.creationInfo.created),
    secondTimestampWholeSecond: /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(secondResult.goSpdx.creationInfo.created),
    distinctTimestamps: result.goSpdx.creationInfo.created !== secondResult.goSpdx.creationInfo.created,
    distinctNamespaces: result.goSpdx.documentNamespace !== secondResult.goSpdx.documentNamespace,
  }, {
    firstTimestampWholeSecond: true,
    secondTimestampWholeSecond: true,
    distinctTimestamps: true,
    distinctNamespaces: true,
  });
  assert.throws(() => validateGoSpdxDocument({ ...result.goSpdx, creationInfo: { ...result.goSpdx.creationInfo, created: "2026-08-19T12:34:56.123Z" } }), /Go SBOM gate rejected/);
  assert.equal(result.requiredCI, true);
  assert.equal(result.task4Deployment, true);
  assert.equal(result.task6Deployment, true);
  assert.equal(result.recoveryDeployment, true);
  assert.equal(result.attackLabDeployment, true);
  assert.equal(result.privateDependencies, true);
});

function securityHeaders(extra) {
  return {
    ...extra,
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
  };
}
