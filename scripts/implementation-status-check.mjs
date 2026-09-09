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
const requiredOwnerMapColumns = ["id", "owning_production_task"];
const allowedLedgerStatuses = new Set(["Complete", "Blocked"]);
const allowedProductionClasses = new Set([
  "production-available",
  "component-only",
  "blocked/external",
  "missing",
]);
const expectedClassCounts = new Map([
  ["production-available", 518],
  ["component-only", 149],
  ["blocked/external", 61],
  ["missing", 0],
]);
const expectedMilestoneClassCounts = new Map([
  ["M0", new Map([["production-available", 7], ["component-only", 17], ["blocked/external", 3], ["missing", 0]])],
  ["M1", new Map([["production-available", 58], ["component-only", 10], ["blocked/external", 0], ["missing", 0]])],
  ["M1A", new Map([["production-available", 0], ["component-only", 6], ["blocked/external", 4], ["missing", 0]])],
  ["M2", new Map([["production-available", 69], ["component-only", 3], ["blocked/external", 0], ["missing", 0]])],
  ["M3", new Map([["production-available", 73], ["component-only", 0], ["blocked/external", 2], ["missing", 0]])],
  ["M4", new Map([["production-available", 82], ["component-only", 0], ["blocked/external", 0], ["missing", 0]])],
  ["M5", new Map([["production-available", 23], ["component-only", 19], ["blocked/external", 0], ["missing", 0]])],
  ["M6", new Map([["production-available", 36], ["component-only", 0], ["blocked/external", 0], ["missing", 0]])],
  ["M7", new Map([["production-available", 37], ["component-only", 25], ["blocked/external", 0], ["missing", 0]])],
  ["M7A", new Map([["production-available", 98], ["component-only", 15], ["blocked/external", 0], ["missing", 0]])],
  ["M8", new Map([["production-available", 35], ["component-only", 54], ["blocked/external", 52], ["missing", 0]])],
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
const auditedProductionClassOwners = new Set([
  "T04-discovery-worker",
  "T05-inventory-cutover",
  "T06-runtime-data-plane",
  "T13-attack-lab",
  "T15-deployment",
  "T16-recovery-ops",
]);
const auditedProductionAvailableIDs = new Set([
  "M5-01", "M5-03", "M5-04",
  "M3-48h", "M3-52d",
  "M0-12", "M0-13", "M0-17",
  "M1-01a", "M1-01e", "M1-01f", "M1-12", "M1-13", "M1-14", "M1-15", "M1-16", "M1-22", "M1-28c", "M1-28d", "M1-32", "M1-33",
  "M2-20", "M2-21", "M2-22", "M2-23", "M2-24", "M2-25", "M2-26", "M2-27", "M2-28", "M2-29", "M2-30", "M2-31", "M2-32", "M2-33", "M2-43c", "M2-43d", "M2-43e", "M2-47a", "M2-47b",
  "M3-09", "M3-10", "M3-11", "M3-12", "M3-13", "M3-15", "M3-16", "M3-17", "M3-18", "M3-19", "M3-20", "M3-21", "M3-22a", "M3-22b", "M3-22c", "M3-22", "M3-23", "M3-24", "M3-25", "M3-26", "M3-27", "M3-28", "M3-29", "M3-30", "M3-31", "M3-32", "M3-33", "M3-34", "M3-35", "M3-36", "M3-37", "M3-38", "M3-39", "M3-40", "M3-41", "M3-42", "M3-43a", "M3-43b", "M3-43c", "M3-43d", "M3-43", "M3-44", "M3-45", "M3-46", "M3-47", "M3-48c2", "M3-48c3", "M3-48d", "M3-48e", "M3-48f", "M3-48g", "M3-49", "M3-50", "M3-51", "M3-52a", "M3-52b", "M3-52c", "M3-52e",
  "M4-01a", "M4-01b", "M4-01c", "M4-01d", "M4-01e", "M4-01f", "M4-01", "M4-02", "M4-05", "M4-16", "M4-17", "M4-18", "M4-19", "M4-20", "M4-21", "M4-22", "M4-23", "M4-24", "M4-25", "M4-26", "M4-27", "M4-28", "M4-29", "M4-30", "M4-31", "M4-32", "M4-33", "M4-38", "M4-39", "M4-40", "M4-41", "M4-42", "M4-59a", "M4-59b", "M4-59c", "M4-59d", "M4-59e", "M4-59",
  "M5-23a", "M5-23b", "M5-23c", "M5-23d", "M5-23", "M5-24", "M5-25", "M5-26", "M5-27", "M5-28", "M5-29", "M5-30", "M5-31", "M5-32", "M5-33a", "M5-33b", "M5-33c", "M5-33", "M5-34", "M5-35",
  "M6-03", "M6-04", "M6-05", "M6-06", "M6-07", "M6-13", "M6-16", "M6-17", "M6-19", "M6-20", "M6-21", "M6-22", "M6-23", "M6-24", "M6-25", "M6-26", "M6-30", "M6-31a", "M6-31b", "M6-31c", "M6-31d", "M6-31e", "M6-31",
  "M7A-02", "M7A-03", "M7A-04", "M7A-05", "M7A-06", "M7A-07", "M7A-08", "M7A-09", "M7A-10", "M7A-11", "M7A-12", "M7A-13", "M7A-14", "M7A-35", "M7A-36", "M7A-37", "M7A-38", "M7A-38a", "M7A-38b", "M7A-38c", "M7A-38d", "M7A-39", "M7A-42", "M7A-43", "M7A-44", "M7A-45", "M7A-46", "M7A-47", "M7A-48", "M7A-49", "M7A-62", "M7A-68", "M7A-69", "M7A-70", "M7A-71", "M7A-72", "M7A-73", "M7A-74", "M7A-75", "M7A-76",
  "M7A-15", "M7A-16", "M7A-17", "M7A-18", "M7A-18a", "M7A-18b", "M7A-18c", "M7A-18d", "M7A-19", "M7A-20", "M7A-25", "M7A-26", "M7A-27", "M7A-28",
  "M7A-50", "M7A-52", "M7A-53", "M7A-54", "M7A-55", "M7A-56", "M7A-57", "M7A-58", "M7A-59", "M7A-60", "M7A-90a", "M7A-90b", "M7A-90c", "M7A-90d", "M7A-92", "M7A-93", "M7A-97", "M7A-98", "M7A-99",
  "M8-09a", "M8-09b", "M8-09c", "M8-09", "M8-10", "M8-11", "M8-12", "M8-13", "M8-14",
  "M8-20a", "M8-20b", "M8-20c", "M8-20", "M8-21a", "M8-21b", "M8-21c", "M8-21d", "M8-21e", "M8-21", "M8-43", "M8-44",
  "M8-57a", "M8-57b", "M8-57c", "M8-57",
]);
const auditedMissingIDs = new Set();
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

function parseOwnerMap(ownerMap) {
  const lines = ownerMap.replace(/^\uFEFF/u, "").trimEnd().split("\n");
  const errors = [];
  const header = lines.shift()?.split("\t") ?? [];

  if (header.join("\t") !== requiredOwnerMapColumns.join("\t")) {
    errors.push(`owner map header must be ${requiredOwnerMapColumns.join(", ")}`);
    return { errors, owners: new Map() };
  }

  const owners = new Map();
  for (const [index, line] of lines.entries()) {
    const [id, owner, ...extraColumns] = line.split("\t");
    if (!id || !owner || extraColumns.length) {
      errors.push(`owner map row ${index + 2} must contain exactly two non-empty columns`);
      continue;
    }
    if (owners.has(id)) {
      errors.push(`owner map duplicate ID: ${id}`);
      continue;
    }
    owners.set(id, owner);
  }

  return { errors, owners };
}

function renderAvailabilityMatrix() {
  const lines = [
    "| Milestone | Total | Production-available | Component-only | Blocked/external | Missing |",
    "| --- | ---: | ---: | ---: | ---: | ---: |",
  ];
  let total = 0;
  const totals = new Map([...expectedClassCounts].map(([productionClass]) => [productionClass, 0]));

  for (const [milestone, counts] of expectedMilestoneClassCounts) {
    const milestoneTotal = [...counts.values()].reduce((sum, count) => sum + count, 0);
    total += milestoneTotal;
    for (const [productionClass, count] of counts) {
      totals.set(productionClass, totals.get(productionClass) + count);
    }
    lines.push(
      `| ${milestone} | ${milestoneTotal} | ${counts.get("production-available")} | ` +
        `${counts.get("component-only")} | ${counts.get("blocked/external")} | ${counts.get("missing")} |`,
    );
  }

  lines.push(
    `| **Total** | **${total}** | **${totals.get("production-available")}** | ` +
      `**${totals.get("component-only")}** | **${totals.get("blocked/external")}** | **${totals.get("missing")}** |`,
  );
  return lines.join("\n");
}

function renderAvailabilitySummary() {
  return [
    "| Production class | Count |",
    "| --- | ---: |",
    `| Production-available | ${expectedClassCounts.get("production-available")} |`,
    `| Component-only | ${expectedClassCounts.get("component-only")} |`,
    `| Blocked/external | ${expectedClassCounts.get("blocked/external")} |`,
    `| Missing | ${expectedClassCounts.get("missing")} |`,
  ].join("\n");
}

export async function validateLedger({
  ledgerPath = path.join(repositoryRoot, "docs/internal/implementation_production_availability_v1.5.tsv"),
  ownerMapPath = path.join(repositoryRoot, "docs/internal/implementation_production_availability_owners_v1.5.tsv"),
  sourcePlanPath = path.join(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
  statusPath = path.join(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
} = {}) {
  const [ledger, ownerMap, sourcePlan, status] = await Promise.all([
    readFile(ledgerPath, "utf8"),
    readFile(ownerMapPath, "utf8"),
    readFile(sourcePlanPath, "utf8"),
    readFile(statusPath, "utf8"),
  ]);
  const sourceTasks = sourcePlanTasks(sourcePlan);
  const sourceTaskIDs = new Set(sourceTasks.map(({ id }) => id));
  const sourceMilestones = new Map(sourceTasks.map(({ id, milestone }) => [id, milestone]));
  const { errors, rows } = parseLedger(ledger);
  const { errors: ownerMapErrors, owners: expectedOwners } = parseOwnerMap(ownerMap);
  errors.push(...ownerMapErrors);
  const counts = new Map([...expectedClassCounts].map(([productionClass]) => [productionClass, 0]));
  const milestoneCounts = new Map(
    [...expectedMilestoneClassCounts].map(([milestone, expectedCounts]) => [
      milestone,
      new Map([...expectedCounts].map(([productionClass]) => [productionClass, 0])),
    ]),
  );
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

    const expectedOwner = expectedOwners.get(row.id);
    if (expectedOwner && row.owner !== expectedOwner) {
      errors.push(`owner ${row.owner} does not match expected owner ${expectedOwner} for ${row.id}`);
    }
    if (auditedProductionClassOwners.has(row.owner) || auditedProductionAvailableIDs.has(row.id) || auditedMissingIDs.has(row.id)) {
      const expectedProductionClass = auditedProductionAvailableIDs.has(row.id)
        ? "production-available"
        : auditedMissingIDs.has(row.id) ? "missing" : "component-only";
      if (row.productionClass !== expectedProductionClass) {
        errors.push(`production class ${row.productionClass} does not match audited ${expectedProductionClass} for ${row.id}`);
      }
    }

    if (counts.has(row.productionClass)) {
      counts.set(row.productionClass, counts.get(row.productionClass) + 1);
    }
    if (milestoneCounts.has(row.milestone) && milestoneCounts.get(row.milestone).has(row.productionClass)) {
      const milestoneCount = milestoneCounts.get(row.milestone);
      milestoneCount.set(row.productionClass, milestoneCount.get(row.productionClass) + 1);
    }
  }

  if (sourceTasks.length !== 728) {
    errors.push(`source plan contains ${sourceTasks.length} task IDs; expected 728`);
  }
  if (rows.length !== 728) {
    errors.push(`ledger has ${rows.length} rows; expected 728`);
  }
  if (expectedOwners.size !== 728) {
    errors.push(`owner map has ${expectedOwners.size} rows; expected 728`);
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

  const missingOwnerIDs = [...sourceTaskIDs].filter((id) => !expectedOwners.has(id)).sort();
  if (missingOwnerIDs.length) {
    errors.push(`owner map missing source-plan IDs: ${missingOwnerIDs.join(", ")}`);
  }
  const unknownOwnerIDs = [...expectedOwners.keys()].filter((id) => !sourceTaskIDs.has(id)).sort();
  if (unknownOwnerIDs.length) {
    errors.push(`owner map unknown IDs: ${unknownOwnerIDs.join(", ")}`);
  }

  for (const [productionClass, expected] of expectedClassCounts) {
    const actual = counts.get(productionClass);
    if (actual !== expected) {
      errors.push(`${productionClass} count is ${actual}; expected ${expected}`);
    }
  }

  for (const [milestone, expectedCounts] of expectedMilestoneClassCounts) {
    const actualCounts = milestoneCounts.get(milestone);
    for (const [productionClass, expected] of expectedCounts) {
      const actual = actualCounts.get(productionClass);
      if (actual !== expected) {
        errors.push(`${milestone} ${productionClass} count is ${actual}; expected ${expected}`);
      }
    }
  }

  if (!status.includes(`## Production availability by milestone\n\n${renderAvailabilityMatrix()}`)) {
    errors.push("documentation matrix does not match audited milestone counts");
  }
  if (!status.includes(`## Production availability summary\n\n${renderAvailabilitySummary()}`)) {
    errors.push("documentation summary does not match audited class counts");
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
