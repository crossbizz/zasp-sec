import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const shardCount = 8;
const packageResult = /^ok\s+github\.com\/zasp-ai\/zasp-sec\/services\/platform\/apiserver\s+(?:[0-9.]+s|\(cached\))$/;
const testName = /^Test[\p{L}\p{Nd}_]*$/u;

export function durableApiserverShard(inventory, shard) {
  if (!Number.isInteger(shard) || shard < 0 || shard >= shardCount) {
    throw new Error("Expected an apiserver shard from 0 through 7");
  }
  const lines = inventory.trimEnd().split(/\r?\n/);
  if (!packageResult.test(lines.pop())) throw new Error("Missing successful apiserver go test -list result");
  if (lines.length < shardCount || lines.some(name => !testName.test(name))) {
    throw new Error("Incomplete or malformed apiserver test list");
  }
  if (new Set(lines).size !== lines.length) throw new Error("Duplicate apiserver test name");

  // Adjacent tests often build the same expensive PostgreSQL fixture. Spread
  // each family across the runners while keeping each test's subtests together.
  lines.sort();
  const selected = lines.filter((_, index) => index % shardCount === shard);
  return { total: lines.length, selected, pattern: `^(${selected.join("|")})$` };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [file, shard] = process.argv.slice(2);
  if (process.argv.length !== 4 || !/^[0-7]$/.test(shard)) {
    throw new Error("Usage: node scripts/durable-apiserver-shard.mjs TEST_LIST SHARD");
  }
  const { total, selected, pattern } = durableApiserverShard(readFileSync(file, "utf8"), Number(shard));
  console.error(`Apiserver shard ${Number(shard) + 1} of ${shardCount}, running ${selected.length} of ${total} tests`);
  console.log(pattern);
}
