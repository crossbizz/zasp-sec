import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PROMPTFOO_PINS,
  PROMPTFOO_PROOF_LABEL,
  buildPromptfooConfiguration,
  buildPromptfooRuntimeSpec,
} from "./manifest.mjs";

const marker = "0123456789abcdef";
const root = `/private/tmp/zasp-m0-16-${marker}-ABC123`;
const input = Object.freeze({
  marker,
  platform: "linux/arm64",
  workspaceRoot: root,
  dockerConfigPath: `${root}/docker-config`,
  configurationPath: `${root}/promptfooconfig.yaml`,
  outputPath: `${root}/output`,
  fakeAgentPath: "/workspace/proofs/promptfoo-redteam/fake_agent.mjs",
});

test("pins the exact official current Promptfoo source, package, image, and license", () => {
  assert.deepEqual(PROMPTFOO_PINS, {
    version: "0.121.19",
    sourceCommit: "1ede17aaed940e6dff04f71d24e4ecc011809dae",
    sourceTree: "8c8043c046e3ad5d09f456dcf0db9ae4344521be",
    npmIntegrity: "sha512-5YebsCED/bmR9JktH9YNU62Tr1m3ncFMlM2tKrguI8vFFUfvqxhNzUBa3Z6huG7OvDKbi69UpamU4CLtYLDezQ==",
    license: "MIT",
    licenseSha256: "bf813686553f451e1b833fbd827488aee49b60b189626915bf3108d10b754e44",
    image: "ghcr.io/promptfoo/promptfoo:0.121.19@sha256:50d3a796710e4db7a5ede90bf27dc28146ef022a7ebb83914c5105608396fd96",
  });
  assert.equal(PROMPTFOO_PROOF_LABEL, "m0-16");
});

test("builds the exact one-case HTTP-provider configuration", () => {
  const yaml = buildPromptfooConfiguration(marker);
  assert.match(yaml, /zasp-m0-16-0123456789abcdef-agent:3001\/v1\/agent/);
  assert.match(yaml, /pluginId: hijacking/);
  assert.match(yaml, /strategyId: prompt-injection/);
  assert.match(yaml, /type: not-contains/);
  assert.equal((yaml.match(/ZASP_M016_INJECTION_ACCEPTED/g) ?? []).length, 2);
  assert.doesNotMatch(yaml, /apiKey|credential|openai|anthropic|promptfoo\.app|https:\/\//i);
});

test("builds one internal network and exact non-root agent and runner roles", () => {
  const spec = buildPromptfooRuntimeSpec(input);
  assert.equal(spec.prefix, `zasp-m0-16-${marker}`);
  assert.deepEqual(spec.roles, ["agent", "runner"]);
  assert.deepEqual(spec.network, {
    name: `${spec.prefix}-network`,
    internal: true,
    labels: {
      "zasp.dev/proof": "m0-16",
      "zasp.dev/run": marker,
      "zasp.dev/role": "network",
    },
  });
  for (const role of spec.roles) {
    assert.equal(spec[role].image, PROMPTFOO_PINS.image);
    assert.equal(spec[role].platform, input.platform);
    assert.equal(spec[role].network, spec.network.name);
    assert.equal(spec[role].readOnlyRootfs, true);
    assert.deepEqual(spec[role].publishedPorts, {});
    assert.deepEqual(spec[role].capDrop, ["ALL"]);
    assert.deepEqual(spec[role].securityOpt, ["no-new-privileges"]);
    assert.deepEqual(spec[role].labels, {
      "zasp.dev/proof": "m0-16",
      "zasp.dev/run": marker,
      "zasp.dev/role": role,
    });
  }
  assert.equal(Object.isFrozen(spec), true);
});

test("binds exact commands, environment allowlists, mounts, tmpfs, and output", () => {
  const spec = buildPromptfooRuntimeSpec(input);
  assert.deepEqual(spec.agent.entrypoint, ["node"]);
  assert.deepEqual(spec.agent.command, ["/proof/fake_agent.mjs"]);
  assert.deepEqual(spec.agent.environment, { M016_AGENT_HOST: `${spec.prefix}-agent:3001` });
  assert.deepEqual(spec.agent.mounts, [{ source: input.fakeAgentPath, target: "/proof/fake_agent.mjs", readOnly: true }]);
  assert.deepEqual(spec.runner.entrypoint, ["promptfoo"]);
  assert.deepEqual(spec.runner.command, [
    "eval", "-c", "/proof/promptfooconfig.yaml", "--no-cache", "--no-table", "--no-write", "-o", "/proof/output/promptfoo.json",
  ]);
  assert.deepEqual(spec.runner.environment, {
    HOME: "/tmp",
    PROMPTFOO_CACHE_ENABLED: "false",
    PROMPTFOO_CONFIG_DIR: "/state",
    PROMPTFOO_DISABLE_ERROR_LOG: "1",
    PROMPTFOO_DISABLE_REMOTE_GENERATION: "1",
    PROMPTFOO_DISABLE_TELEMETRY: "1",
    PROMPTFOO_DISABLE_UPDATE: "1",
  });
  assert.deepEqual(spec.runner.mounts, [
    { source: input.configurationPath, target: "/proof/promptfooconfig.yaml", readOnly: true },
    { source: input.outputPath, target: "/proof/output", readOnly: false },
  ]);
});

test("rejects path, platform, marker, and extra-field drift", () => {
  for (const mutation of [
    { ...input, marker: "short" },
    { ...input, platform: "linux/386" },
    { ...input, workspaceRoot: "/tmp/other" },
    { ...input, dockerConfigPath: `${root}/other` },
    { ...input, configurationPath: `${root}/other.yaml` },
    { ...input, outputPath: `${root}/other-output` },
    { ...input, fakeAgentPath: "relative" },
    { ...input, extra: true },
  ]) assert.throws(() => buildPromptfooRuntimeSpec(mutation), TypeError);
});

test("returns isolated deeply immutable specifications", () => {
  const first = buildPromptfooRuntimeSpec(input);
  const second = buildPromptfooRuntimeSpec(input);
  assert.deepEqual(first, second);
  assert.notEqual(first, second);
  assert.throws(() => { first.runner.environment.HOME = "/home"; });
  assert.throws(() => { first.agent.mounts[0].source = "/other"; });
});
