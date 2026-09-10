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

test("canonical ledger, owner map and documentation satisfy every audited count", async () => {
  await validateLedger({ ledgerPath: canonicalLedgerPath, sourcePlanPath, statusPath: canonicalStatusPath });
});

test("runtime session tasks cannot inherit console-login or fixture-only production credit", async () => {
  const ledger = await readFile(canonicalLedgerPath, "utf8");
  for (const id of ["M7-07b", "M7-07c", "M7-07"]) {
    assert.ok(ledger.includes(`M7\t${id}\tComplete\tcomponent-only\tT14-data-workflows\t`), `${id} must await original runtime-session acceptance`);
  }
});

test("shipped runtime session acceptance cannot silently lose production credit", async () => {
  for (const id of ["M7-01", "M7-02", "M7-03", "M7-04", "M7-05", "M7-06", "M7-07a"]) {
    await withLedger((ledger) => {
      const expected = `M7\t${id}\tComplete\tproduction-available\t`;
      assert.ok(ledger.includes(expected), `${id} acceptance was not recorded`);
      return ledger.replace(expected, `M7\t${id}\tComplete\tcomponent-only\t`);
    }, async (ledgerPath) => {
      await assert.rejects(() => validateLedger({ ledgerPath, sourcePlanPath }), /audited production-available/);
    });
  }
});

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
    (ledger) => ledger.replace("M2\tM2-20\tComplete\tproduction-available\tT11-identity-admin", "M2\tM2-20\tComplete\tproduction-available\tT02-discovery-authority"),
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
        /production-available count is 534; expected 535/,
      );
    },
  );
});

test("artifact, outcome and Fargate-create acceptance cannot silently lose production credit", async () => {
  for (const id of ["M5-02", "M5-14", "M5-18", "M5-16", "M5-17", "M5-19", "M5-20", "M5-21", "M5-22"]) {
    await withLedger((ledger) => {
      const expected = `M5\t${id}\tComplete\tproduction-available\t`;
      assert.ok(ledger.includes(expected), `${id} acceptance was not recorded`);
      return ledger.replace(expected, `M5\t${id}\tComplete\tcomponent-only\t`);
    }, async (ledgerPath) => {
      await assert.rejects(() => validateLedger({ ledgerPath, sourcePlanPath }), new RegExp(`production-available.*${id}|${id}.*production-available`));
    });
  }
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
        /M1 production-available count is 59; expected 58/,
      );
    },
  );
});

test("rejects a same-owner same-milestone audited class swap", async () => {
  await withLedger(
    (ledger) => ledger
      .replace(
        "M1\tM1-01e\tComplete\tproduction-available\tT04-discovery-worker",
        "M1\tM1-01e\tComplete\tcomponent-only\tT04-discovery-worker",
      )
      .replace(
        "M1\tM1-01b\tComplete\tcomponent-only\tT04-discovery-worker",
        "M1\tM1-01b\tComplete\tproduction-available\tT04-discovery-worker",
      ),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /production class component-only does not match audited production-available for M1-01e/,
      );
    },
  );
});

test("rejects demotion of the shipped finding ticket and final M4 gate", async () => {
  for (const id of ["M4-38", "M4-39", "M4-59"]) {
    await withLedger(
      (ledger) => ledger.replace(
        new RegExp(`(M4\\t${id}\\tComplete\\t)production-available`),
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

test("rejects demotion of audited shipped identity administration tasks", async () => {
  for (const id of [
    "M2-20", "M2-21", "M2-22", "M2-23", "M2-24",
    "M2-25", "M2-26", "M2-27", "M2-28", "M2-29", "M2-30",
    "M2-31", "M2-32", "M2-33", "M2-43c", "M2-43d", "M2-43e",
    "M2-47a", "M2-47b",
  ]) {
    await withLedger(
      (ledger) => ledger.replace(
        new RegExp(`(M2\\t${id}\\tComplete\\t)production-available`),
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

test("rejects demotion of audited shipped recovery tasks", async () => {
  for (const id of [
    "M8-20a", "M8-20b", "M8-20c", "M8-20",
    "M8-21a", "M8-21b", "M8-21c", "M8-21d", "M8-21e", "M8-21",
  ]) {
    await withLedger(
      (ledger) => ledger.replace(
        new RegExp(`(M8\\t${id}\\tComplete\\t)production-available`),
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

test("rejects demotion of production-composed policy history operations", async () => {
  for (const id of ["M6-13", "M6-16", "M6-17"]) {
    await withLedger(
      (ledger) => ledger.replace(
        new RegExp(`(M6\\t${id}\\tComplete\\t)production-available`),
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

test("rejects demotion of the production signed webhook setup task", async () => {
  await withLedger(
    (ledger) => ledger.replace("M3\tM3-48h\tComplete\tproduction-available", "M3\tM3-48h\tComplete\tcomponent-only"),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /production class component-only does not match audited production-available for M3-48h/,
      );
    },
  );
});

test("rejects demotion of the verified runtime queue/archive/index task", async () => {
  await withLedger(
    (ledger) => ledger.replace("M3\tM3-52d\tComplete\tproduction-available", "M3\tM3-52d\tComplete\tcomponent-only"),
    async (ledgerPath) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath }),
        /production class component-only does not match audited production-available for M3-52d/,
      );
    },
  );
});

test("rejects demotion of individually accepted Red Team domain, APIs, worker and UI",async()=>{
  for(const id of ["M5-01","M5-03","M5-04","M5-05","M5-06","M5-07","M5-08","M5-09","M5-10","M5-11","M5-12","M5-13","M5-15"]){
    await withLedger(ledger=>ledger.replace(`M5\t${id}\tComplete\tproduction-available`,`M5\t${id}\tComplete\tcomponent-only`),async ledgerPath=>{
      await assert.rejects(()=>validateLedger({ledgerPath,sourcePlanPath}),new RegExp(`production class component-only does not match audited production-available for ${id}`));
    });
  }
});

test("rejects a published milestone matrix that drifts from the audited map", async () => {
  await withLedgerAndStatus(
    (ledger) => ledger,
    (status) => status.replace("| M1 | 68 | 58 | 10 | 0 | 0 |", "| M1 | 68 | 57 | 11 | 0 | 0 |"),
    async ({ ledgerPath, statusPath }) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath, statusPath }),
        /documentation matrix does not match audited milestone counts/,
      );
    },
  );
});

test("rejects a published availability summary that drifts from the audited ledger", async () => {
  await withLedgerAndStatus(
    (ledger) => ledger,
    (status) => status.replace(
      "| Production-available | 535 |",
      "| Production-available | 496 |",
    ),
    async ({ ledgerPath, statusPath }) => {
      await assert.rejects(
        () => validateLedger({ ledgerPath, sourcePlanPath, statusPath }),
        /documentation summary does not match audited class counts/,
      );
    },
  );
});
