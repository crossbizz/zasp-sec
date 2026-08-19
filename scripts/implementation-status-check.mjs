import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requiredColumns = [
  "milestone",
  "id",
  "ledger_status",
  "production_class",
  "owning_production_task",
  "current_evidence",
];
const allowedLedgerStatuses = new Set(["Complete", "Blocked"]);
const allowedProductionClasses = new Set([
  "production-available",
  "component-only",
  "blocked/external",
  "missing",
]);
const expectedClassCounts = new Map([
  ["production-available", 229],
  ["component-only", 425],
  ["blocked/external", 61],
  ["missing", 13],
]);
const productionOwnerTaskIDs = new Set([
  "T02-discovery-authority",
  "T03-launch-connectors",
  "T04-discovery-worker",
  "T05-inventory-cutover",
  "T06-runtime-data-plane",
  "T07-security-agent-authority",
  "T08-supervised-agent",
  "T09-agent-actions",
  "T10-product-ui",
  "T11-identity-admin",
  "T12-red-team",
  "T13-attack-lab",
  "T14-data-workflows",
  "T15-deployment",
  "T16-recovery-ops",
]);
const externalGateIDs = new Set([
  "EXT-cloud-deploy",
  "EXT-human-observation",
  "EXT-image-attestation",
  "EXT-live-aws",
  "EXT-live-fargate",
  "EXT-live-stytch",
]);

function sourcePlanTasks(sourcePlan) {
  const tasks = [];
  const taskPattern = /^\*\*(M(?:0|1A|7A|[1-8])-[0-9]+[a-z0-9]*) - /gmu;

  for (const match of sourcePlan.matchAll(taskPattern)) {
    const id = match[1];
    tasks.push({ id, milestone: id.split("-")[0] });
  }

  return tasks;
}

function parseLedger(ledger) {
  const lines = ledger.replace(/^\uFEFF/u, "").trimEnd().split("\n");
  const errors = [];
  const header = lines.shift()?.split("\t") ?? [];

  if (header.join("\t") !== requiredColumns.join("\t")) {
    errors.push(`header must be ${requiredColumns.join(", ")}`);
    return { errors, rows: [] };
  }

  const rows = [];
  for (const [index, line] of lines.entries()) {
    if (!line) {
      errors.push(`row ${index + 2} is blank`);
      continue;
    }

    const columns = line.split("\t");
    if (columns.length !== requiredColumns.length) {
      errors.push(`row ${index + 2} has ${columns.length} columns; expected ${requiredColumns.length}`);
      continue;
    }

    const [milestone, id, ledgerStatus, productionClass, owner, evidence] = columns;
    rows.push({ evidence, id, ledgerStatus, milestone, owner, productionClass });

    if (!allowedLedgerStatuses.has(ledgerStatus)) {
      errors.push(`invalid ledger status "${ledgerStatus}" for ${id}`);
    }
    if (!allowedProductionClasses.has(productionClass)) {
      errors.push(`invalid production class "${productionClass}" for ${id}`);
    }
    if (productionClass === "production-available" && ledgerStatus !== "Complete") {
      errors.push(`production-available requires Complete historical status for ${id}`);
    }
    if (productionClass === "blocked/external" && ledgerStatus !== "Blocked") {
      errors.push(`blocked/external requires Blocked historical status for ${id}`);
    }
    if (
      (productionClass === "component-only" || productionClass === "missing") &&
      ledgerStatus !== "Complete"
    ) {
      errors.push(`${productionClass} requires Complete historical status for ${id}`);
    }
    if (
      (productionClass === "component-only" || productionClass === "missing") &&
      !productionOwnerTaskIDs.has(owner)
    ) {
      errors.push(`${productionClass} requires one concrete owner task ID for ${id}`);
    }
    if (productionClass === "blocked/external" && !externalGateIDs.has(owner)) {
      errors.push(`blocked/external requires an approved typed gate ID for ${id}`);
    }
    if (!owner) {
      errors.push(`owner is required for ${id}`);
    }
    if (!evidence) {
      errors.push(`evidence is required for ${id}`);
    }
  }

  return { errors, rows };
}

export async function validateLedger({
  ledgerPath = path.join(repositoryRoot, "docs/internal/implementation_production_availability_v1.5.tsv"),
  sourcePlanPath = path.join(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
} = {}) {
  const [ledger, sourcePlan] = await Promise.all([
    readFile(ledgerPath, "utf8"),
    readFile(sourcePlanPath, "utf8"),
  ]);
  const sourceTasks = sourcePlanTasks(sourcePlan);
  const sourceTaskIDs = new Set(sourceTasks.map(({ id }) => id));
  const sourceMilestones = new Map(sourceTasks.map(({ id, milestone }) => [id, milestone]));
  const { errors, rows } = parseLedger(ledger);
  const counts = new Map([...expectedClassCounts].map(([productionClass]) => [productionClass, 0]));
  const seen = new Set();
  const duplicateIDs = new Set();
  const unknownIDs = new Set();

  for (const row of rows) {
    if (seen.has(row.id)) {
      duplicateIDs.add(row.id);
    }
    seen.add(row.id);

    if (!sourceTaskIDs.has(row.id)) {
      unknownIDs.add(row.id);
    } else if (sourceMilestones.get(row.id) !== row.milestone) {
      errors.push(`milestone ${row.milestone} does not match ${row.id}`);
    }

    if (counts.has(row.productionClass)) {
      counts.set(row.productionClass, counts.get(row.productionClass) + 1);
    }
  }

  if (sourceTasks.length !== 728) {
    errors.push(`source plan contains ${sourceTasks.length} task IDs; expected 728`);
  }
  if (rows.length !== 728) {
    errors.push(`ledger has ${rows.length} rows; expected 728`);
  }
  if (duplicateIDs.size) {
    errors.push(`duplicate IDs: ${[...duplicateIDs].sort().join(", ")}`);
  }
  if (unknownIDs.size) {
    errors.push(`unknown IDs: ${[...unknownIDs].sort().join(", ")}`);
  }

  const missingIDs = [...sourceTaskIDs].filter((id) => !seen.has(id)).sort();
  if (missingIDs.length) {
    errors.push(`missing source-plan IDs: ${missingIDs.join(", ")}`);
  }

  for (const [productionClass, expected] of expectedClassCounts) {
    const actual = counts.get(productionClass);
    if (actual !== expected) {
      errors.push(`${productionClass} count is ${actual}; expected ${expected}`);
    }
  }

  if (errors.length) {
    throw new Error(`Implementation status ledger is invalid: ${errors.join("; ")}`);
  }

  return {
    classifications: Object.fromEntries(counts),
    rows: rows.length,
    sourceTasks: sourceTasks.length,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const summary = await validateLedger();
    console.log(
      `Implementation status ledger valid: ${summary.rows} rows; ` +
        `${summary.classifications["production-available"]} production-available, ` +
        `${summary.classifications["component-only"]} component-only, ` +
        `${summary.classifications["blocked/external"]} blocked/external, ` +
        `${summary.classifications.missing} missing.`,
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
