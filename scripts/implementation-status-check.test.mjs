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
const canonicalStatusPath = path.join(
  repositoryRoot,
  "docs/internal/implementation_status_v1.5.md",
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

async function withLedgerAndStatus(ledgerMutator, statusMutator, assertion) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "zasp-ledger-"));
  const ledgerPath = path.join(directory, "ledger.tsv");
  const statusPath = path.join(directory, "status.md");

  try {
    const [canonicalLedger, canonicalStatus] = await Promise.all([
      readFile(canonicalLedgerPath, "utf8"),
      readFile(canonicalStatusPath, "utf8"),
    ]);
    await Promise.all([
      writeFile(ledgerPath, ledgerMutator(canonicalLedger), "utf8"),
      writeFile(statusPath, statusMutator(canonicalStatus), "utf8"),
    ]);
    await assertion({ ledgerPath, statusPath });
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
    (ledger) => ledger.replace(
      "M1\tM1-01c\tComplete\tcomponent-only\tT10-product-ui",
      "M1\tM1-01c\tComplete\tcomponent-only\tTasks 2-9 production promotion",
    ),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /component-only requires one concrete owner task ID for M1-01c/,
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

test("rejects an approved but wrong production owner for a source ID", async () => {
  await withLedger(
    (ledger) => ledger.replace("M2\tM2-20\tComplete\tcomponent-only\tT11-identity-admin", "M2\tM2-20\tComplete\tcomponent-only\tT02-discovery-authority"),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /owner T02-discovery-authority does not match expected owner T11-identity-admin for M2-20/,
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
        /production-available count is 313; expected 314/,
      );
    },
  );
});

test("rejects a cross-milestone class swap that preserves global totals", async () => {
  await withLedger(
    (ledger) => ledger
      .replace(
        "M1\tM1-01c\tComplete\tcomponent-only\tT10-product-ui",
        "M1\tM1-01c\tComplete\tproduction-available\tT10-product-ui",
      )
      .replace(
        "M2\tM2-01\tComplete\tproduction-available\tPROD-current-composition",
        "M2\tM2-01\tComplete\tcomponent-only\tT11-identity-admin",
      ),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /M1 production-available count is 58; expected 57/,
      );
    },
  );
});

test("rejects a same-owner same-milestone audited class swap", async () => {
  await withLedger(
    (ledger) => ledger
      .replace(
        "M3\tM3-41\tComplete\tproduction-available\tT06-runtime-data-plane",
        "M3\tM3-41\tComplete\tcomponent-only\tT06-runtime-data-plane",
      )
      .replace(
        "M3\tM3-42\tComplete\tcomponent-only\tT06-runtime-data-plane",
        "M3\tM3-42\tComplete\tproduction-available\tT06-runtime-data-plane",
      ),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /production class component-only does not match audited production-available for M3-41/,
      );
    },
  );
});

test("rejects demotion of audited shipped deployment tasks", async () => {
  for (const id of [
    "M8-09a", "M8-09b", "M8-09c", "M8-09", "M8-10", "M8-11", "M8-14",
    "M8-12", "M8-13", "M8-57a", "M8-57b", "M8-57c", "M8-57",
  ]) {
    await withLedger(
      (ledger) => ledger.replace(
        new RegExp(`(M8\\t${id}\\tComplete\\t)production-available`),
        "$1missing",
      ),
      async (ledgerPath) => {
        await assert.rejects(
          () => validateLedger({ ledgerPath, sourcePlanPath }),
          new RegExp(`production class missing does not match audited production-available for ${id}`),
        );
      },
    );
  }
});

test("rejects demotion of audited durable gateway tasks", async () => {
  for (const [milestone, id] of [["M1", "M1-01a"], ["M6", "M6-31e"]]) {
    await withLedger(
      (ledger) => ledger.replace(
        new RegExp(`(${milestone}\\t${id}\\tComplete\\t)production-available`),
        "$1component-only",
      ),
      async (ledgerPath) => {
        await assert.rejects(
          () => validateLedger({ ledgerPath, sourcePlanPath }),
          new RegExp(`production class component-only does not match audited production-available for ${id}`),
        );
      },
    );
  }
});

test("rejects a published milestone matrix that drifts from the audited map", async () => {
  await withLedgerAndStatus(
    (ledger) => ledger,
    (status) => status.replace("| M1 | 68 | 57 | 11 | 0 | 0 |", "| M1 | 68 | 58 | 10 | 0 | 0 |"),
    async ({ ledgerPath, statusPath }) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath, statusPath }),
        /documentation matrix does not match audited milestone counts/,
      );
    },
  );
});
