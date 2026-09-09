import assert from "node:assert/strict";
import test from "node:test";
import { cleanupOwned, createOwned, validateReceipt } from "./run.mjs";

const receipt = { proxy_allowed: true, infra_allowed: true, direct_denied: true, wrong_port_denied: true, uid: 65532, capabilities: 0, kernel_dropped_packets: "4", proof_boundary: "owned Linux network namespace; not live AWS security-group attachment" };
test("kernel denial requires independent controls before and after the restricted probe", () => {
  assert.equal(validateReceipt({ reachable: true }, receipt, { reachable: true }), true);
  for (const key of ["proxy_allowed", "infra_allowed", "direct_denied", "wrong_port_denied"]) assert.throws(() => validateReceipt({ reachable: true }, { ...receipt, [key]: false }, { reachable: true }));
  for (const patch of [{ uid: 0 }, { capabilities: 1 }, { kernel_dropped_packets: "0" }, { kernel_dropped_packets: "garbage" }]) assert.throws(() => validateReceipt({ reachable: true }, { ...receipt, ...patch }, { reachable: true }));
  assert.throws(() => validateReceipt({ reachable: false }, receipt, { reachable: true }));
  assert.throws(() => validateReceipt({ reachable: true }, receipt, { reachable: false }));
});

test("uncertain creates reconcile pre-registered exact names and ownership before cleanup", async () => {
  const owner = "zasp-m521-" + "a".repeat(32);
  const network = { kind: "network", name: `${owner}-network` };
  const container = { kind: "container", name: `${owner}-container-0` };
  const id = "b".repeat(64);
  const commands = [];
  const run = async (args) => {
    commands.push(args);
    if (args.includes("inspect")) return JSON.stringify([{ Id: id, Name: args[0] === "network" ? network.name : `/${container.name}`, Labels: { "zasp.fixture.owner": owner }, Config: { Labels: { "zasp.fixture.owner": owner } } }]);
    return "";
  };
  await cleanupOwned([network, container], owner, run);
  assert.deepEqual(commands, [["inspect", container.name], ["rm", "--force", id], ["network", "inspect", network.name], ["network", "rm", id]]);
  await assert.rejects(cleanupOwned([container], owner, async () => JSON.stringify([{ Id: id, Name: `/${container.name}`, Config: { Labels: { "zasp.fixture.owner": "different" } } }])), /cleanup/);
  await assert.rejects(cleanupOwned([container], owner, async () => { throw new Error("daemon unavailable"); }), /cleanup/);
});

test("network and container intents survive loss of the create response", async () => {
  const owner = "zasp-m521-" + "c".repeat(32);
  for (const kind of ["network", "container"]) {
    const intents = [];
    let daemonCreated;
    await assert.rejects(createOwned(intents, owner, kind, async (name) => {
      assert.deepEqual(intents, [{ kind, name }]);
      daemonCreated = name;
      throw new Error("response lost after daemon creation");
    }), /response lost/);
    let removed = false;
    await cleanupOwned(intents, owner, async (args) => {
      if (args.includes("inspect")) return JSON.stringify([{ Id: "d".repeat(64), Name: kind === "network" ? daemonCreated : "/" + daemonCreated, Labels: { "zasp.fixture.owner": owner }, Config: { Labels: { "zasp.fixture.owner": owner } } }]);
      removed = true;
      return "";
    });
    assert.equal(removed, true);
  }
});
