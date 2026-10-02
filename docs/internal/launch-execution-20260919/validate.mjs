// Read-only validation of this execution-plan snapshot and its source graph.
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(directory, "../../..");
const read = relative => fs.readFileSync(path.join(root, relative), "utf8");
const plan = JSON.parse(fs.readFileSync(path.join(directory, "tasks.json"), "utf8"));
const markdown = fs.readFileSync(path.join(directory, "tasks.md"), "utf8");
for (const source of plan.source_hashes) {
  assert.equal(createHash("sha256").update(read(source.path)).digest("hex"), source.sha256, `Reconcile changed source: ${source.path}`);
}
const rows = read(plan.authoritative_status_source).trim().split("\n").slice(1).map(line => line.split("\t"));
const pending = rows.filter(row => row[3] !== "production-available");
assert.equal(rows.length, 728);
assert.equal(pending.length, 202);
assert.deepEqual(plan.tasks.map(t => t.id).sort(), pending.map(r => r[1]).sort());
const original = read(plan.source_hashes[0].path);
const headers = [...original.matchAll(/^\*\*(M(?:0|1A|7A|[1-8])-[0-9]+[a-z0-9]*) - (.+)\*\*/gm)];
const sourceTasks = new Map(headers.map((match, i) => {
  const block = original.slice(match.index, headers[i + 1]?.index ?? original.length);
  return [match[1], {
    title: match[2],
    deps: block.match(/^Depends on: (.+)$/m)?.[1].match(/M(?:0|1A|7A|[1-8])-\d+[a-z0-9]*/g) ?? [],
    deliverable: block.match(/^Deliverable: (.+)$/m)?.[1].trim(),
    verify: block.match(/^Verify: (.+)$/m)?.[1].trim(),
  }];
}));
const originalGraph = new Map(plan.original_dependency_graph.map(t => [t.id, t.depends_on]));
assert.equal(originalGraph.size, 728);
for (const [id, deps] of originalGraph) assert.deepEqual(deps, sourceTasks.get(id).deps);
function checkGraph(graph) {
  const marked = new Map();
  function visit(id) {
    assert(graph.has(id), `Missing dependency: ${id}`);
    assert.notEqual(marked.get(id), 1, `Dependency cycle: ${id}`);
    if (marked.get(id) === 2) return;
    marked.set(id, 1);
    for (const dep of graph.get(id)) visit(dep);
    marked.set(id, 2);
  }
  for (const id of graph.keys()) visit(id);
}
checkGraph(originalGraph);
const pendingIDs = new Set(pending.map(row => row[1]));
function nearest(id, seen = new Set()) {
  const result = new Set();
  for (const dep of originalGraph.get(id)) {
    if (seen.has(dep)) continue;
    seen.add(dep);
    if (pendingIDs.has(dep)) result.add(dep);
    else for (const upstream of nearest(dep, seen)) result.add(upstream);
  }
  return [...result];
}
const execution = new Map(originalGraph);
execution.set("SHIP-GATE", []);
execution.set("DISPATCH-GATE", []);
for (const id of Object.keys(plan.owners)) execution.set(id, []);
const stepIDs = new Set();
for (const task of plan.tasks) {
  const source = sourceTasks.get(task.id);
  const row = pending.find(r => r[1] === task.id);
  assert.equal(task.classification, row[3]);
  assert.equal(task.owner, row[4]);
  assert.equal(task.title, source.title);
  assert.equal(task.original_deliverable, source.deliverable);
  assert.equal(task.original_verification, source.verify);
  assert.deepEqual(task.original_dependencies, source.deps);
  assert.deepEqual(task.nearest_pending_prerequisites, nearest(task.id));
  assert.equal(task.subtasks.length, 4);
  assert(markdown.includes(`## ${task.id}: ${task.title}`));
  for (const step of task.subtasks) {
    assert(!stepIDs.has(step.id), `Duplicate step: ${step.id}`);
    stepIDs.add(step.id);
    execution.set(step.id, step.depends_on);
    assert(markdown.includes(`**${step.id}**`));
    assert(markdown.includes(step.action), `Markdown action drift: ${step.id}`);
    const dependencies = step.depends_on.join(", ") || "none; preparation only";
    assert(markdown.includes(`**${step.id}** (depends on: ${dependencies}).`), `Markdown dependency drift: ${step.id}`);
  }
  assert(task.subtasks[1].depends_on.includes("DISPATCH-GATE"));
  if (task.external_gate) assert(task.subtasks[1].depends_on.includes(task.external_gate));
  assert.deepEqual(task.subtasks[2].depends_on, [`${task.id}.deliver`]);
  for (const dep of new Set([...source.deps, ...nearest(task.id)])) assert(task.subtasks[3].depends_on.includes(dep));
  execution.set(task.id, [`${task.id}.release`]);
}
for (const packet of plan.connected_launch_packets) {
  for (const ref of packet.references) assert(sourceTasks.has(ref));
  execution.set(packet.id, [...packet.depends_on, ...(packet.live_acceptance_gates ?? [])]);
}
checkGraph(execution);
assert.equal(stepIDs.size, 808);
assert.equal((markdown.match(/^## M/gm) ?? []).length, 202);
console.log(JSON.stringify({ result: "PASS", originalTasks: 728, pendingTasks: 202, componentOnly: pending.filter(r => r[3] === "component-only").length, external: pending.filter(r => r[3] === "blocked/external").length, coordinationSteps: stepIDs.size, connectedPackets: plan.connected_launch_packets.length, dependencyCycles: 0, missingReferences: 0, localVerifyStepsWithoutPublicationDependencies: plan.tasks.length }));
