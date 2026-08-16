import { readFile } from "node:fs/promises";

const inventoryUrl = new URL("./licenses.json", import.meta.url);
const expected = Object.freeze({
  driver: Object.freeze({
    name: "github.com/neo4j/neo4j-go-driver/v6",
    version: "v6.2.0",
    source_repository: "https://github.com/neo4j/neo4j-go-driver",
    source_tag: "v6.2.0",
    source_commit: "3a8a87f4507e95fcf70e0148ea455f47a3dfaad3",
    license: "Apache-2.0",
    license_sha256: "c1b9df1275e769f3dbab000d1e457a2d4b0f28eb5da6c77e48dc37eeba202ed7",
    scope: "runtime",
    product_approved: true,
  }),
  server: Object.freeze({
    name: "neo4j-community-server",
    version: "5.26.28",
    source_repository: "https://github.com/neo4j/neo4j",
    source_tag: "5.26.28",
    source_commit: "09de4c547ee24f69400c75df8428685e27a9cffc",
    license: "GPL-3.0-only",
    license_sha256: "8e1bb72dd89711d9612ea2749c906e4b17760245f4ffdfcc237219f4df48e440",
    scope: "proof-only",
    product_approved: false,
    image: "neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357",
  }),
});

function exactObject(value, wanted) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actualKeys = Object.keys(value).sort();
  const wantedKeys = Object.keys(wanted).sort();
  return actualKeys.length === wantedKeys.length
    && actualKeys.every((key, index) => key === wantedKeys[index])
    && wantedKeys.every((key) => value[key] === wanted[key]);
}

export async function auditLicenses(options = {}) {
  const raw = await readFile(options.path ?? inventoryUrl, "utf8");
  if (Buffer.byteLength(raw, "utf8") > 16 * 1024) throw new Error("license audit rejected");
  let inventory;
  try {
    inventory = JSON.parse(raw);
  } catch {
    throw new Error("license audit rejected");
  }
  options.mutate?.(inventory);
  if (inventory === null || typeof inventory !== "object" || Array.isArray(inventory)
      || Object.keys(inventory).sort().join("|") !== "components|schema_version"
      || inventory.schema_version !== 1 || !Array.isArray(inventory.components)
      || inventory.components.length !== 2 || !exactObject(inventory.components[0], expected.driver)
      || !exactObject(inventory.components[1], expected.server)) {
    throw new Error("license audit rejected");
  }
  return { components: 2, approvedRuntime: 1, proofOnly: 1, prohibitedRuntime: 0 };
}

async function cli() {
  try {
    const result = await auditLicenses();
    process.stdout.write(`Neo4j GraphStore license audit passed: components=${result.components} approved_runtime=${result.approvedRuntime} proof_only=${result.proofOnly} prohibited_runtime=${result.prohibitedRuntime}.\n`);
  } catch {
    process.stdout.write("Neo4j GraphStore license audit failed.\n");
    process.exitCode = 1;
  }
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).href === import.meta.url) {
  await cli();
}
