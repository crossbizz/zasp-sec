import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { validateLedger } from "./implementation-status-check.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const sourcePlanPath = path.join(
  repositoryRoot,
  "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md",
);
const canonicalLedgerPath = path.join(
  repositoryRoot,
  "docs/internal/implementation_production_availability_v1.5.tsv",
);

async function withLedger(mutator, assertion) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "zasp-ledger-"));
  const ledgerPath = path.join(directory, "ledger.tsv");

  try {
    const canonicalLedger = await readFile(canonicalLedgerPath, "utf8");
    await writeFile(ledgerPath, mutator(canonicalLedger), "utf8");
    await assertion(ledgerPath);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

function rows(ledger) {
  return ledger.trimEnd().split("\n");
}

test("rejects a ledger missing a source-plan task", async () => {
  await withLedger(
    (ledger) => rows(ledger).filter((_, index) => index !== 1).join("\n") + "\n",
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /missing source-plan IDs: M0-01/,
      );
    },
  );
});

test("rejects a duplicated source-plan task", async () => {
  await withLedger(
    (ledger) => {
      const ledgerRows = rows(ledger);
      return `${ledgerRows.join("\n")}\n${ledgerRows[1]}\n`;
    },
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /duplicate IDs: M0-01/,
      );
    },
  );
});

test("rejects an unknown source-plan task", async () => {
  await withLedger(
    (ledger) => ledger.replace("\tM0-01\t", "\tM0-999\t"),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /unknown IDs: M0-999/,
      );
    },
  );
});

test("rejects an invalid production class", async () => {
  await withLedger(
    (ledger) => ledger.replace("\tcomponent-only\t", "\tready\t"),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /invalid production class "ready"/,
      );
    },
  );
});

test("rejects a production class paired with the wrong historical state", async () => {
  await withLedger(
    (ledger) => ledger.replace("M1\tM1-01d\tComplete\tproduction-available", "M1\tM1-01d\tBlocked\tproduction-available"),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /production-available requires Complete historical status for M1-01d/,
      );
    },
  );
});

test("rejects a grouped production owner for component-only work", async () => {
  await withLedger(
    (ledger) => ledger.replace("T02-discovery-authority", "Tasks 2-9 production promotion"),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /component-only requires one concrete owner task ID for M0-01/,
      );
    },
  );
});

test("rejects an external row without an approved typed gate ID", async () => {
  await withLedger(
    (ledger) => ledger.replace("EXT-live-aws", "EXT-live-aws-other"),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /blocked\/external requires an approved typed gate ID for M0-09/,
      );
    },
  );
});

test("rejects audited production-class count drift", async () => {
  await withLedger(
    (ledger) => ledger.replace("\tproduction-available\t", "\tcomponent-only\t"),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /production-available count is 228; expected 229/,
      );
    },
  );
});
