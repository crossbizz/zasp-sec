import assert from "node:assert/strict";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import test from "node:test";

import {
  ARTIFACT_NAME,
  buildCollectorConfig,
  readStableArtifact,
  validateOwnedDirectory,
} from "./artifact.mjs";

const expectedConfig = `receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 64
    spike_limit_mib: 16
  batch:
    timeout: 100ms
    send_batch_size: 1
    send_batch_max_size: 1
exporters:
  file:
    path: /proof/output/traces.json
    format: json
    append: false
    flush_interval: 100ms
service:
  telemetry:
    logs:
      level: error
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [file]
`;

async function withTemporaryDirectory(callback) {
  const root = await mkdtemp(join(tmpdir(), "zasp-m0-13-test-"));
  try {
    await callback(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("builds the exact bounded ingest-only Collector configuration", () => {
  const config = buildCollectorConfig();
  assert.equal(config.toString("utf8"), expectedConfig);
  assert.equal(config.equals(buildCollectorConfig()), true);
  assert.equal(config.byteLength < 2_048, true);
  assert.doesNotMatch(config.toString("utf8"), /otlphttp|otlp\/|endpoint: https|authorization|token|proxy|debug/i);
});

test("admits only one canonical direct-child owned directory", async () => {
  await withTemporaryDirectory(async (parent) => {
    const candidate = join(parent, "zasp-m0-13-0123456789abcdef");
    await mkdir(candidate, { mode: 0o700 });
    const identity = await validateOwnedDirectory(candidate, parent, "zasp-m0-13-");
    const stat = await lstat(candidate);

    assert.deepEqual(identity, {
      path: candidate,
      parent: await realpath(parent),
      canonical: await realpath(candidate),
      dev: stat.dev,
      ino: stat.ino,
    });
    assert.equal(Object.isFrozen(identity), true);
    await assert.rejects(validateOwnedDirectory(parent, parent, "zasp-m0-13-"));
    await assert.rejects(validateOwnedDirectory(join(parent, "other"), parent, "zasp-m0-13-"));
    await assert.rejects(validateOwnedDirectory("relative", parent, "zasp-m0-13-"));
  });
});

test("rejects symlink, nested, empty-suffix, and wrong-parent directories", async () => {
  await withTemporaryDirectory(async (parent) => {
    const owned = join(parent, "zasp-m0-13-0123456789abcdef");
    const nested = join(owned, "zasp-m0-13-fedcba9876543210");
    const link = join(parent, "zasp-m0-13-aaaaaaaaaaaaaaaa");
    await mkdir(nested, { recursive: true });
    await symlink(owned, link);

    await assert.rejects(validateOwnedDirectory(link, parent, "zasp-m0-13-"));
    await assert.rejects(validateOwnedDirectory(nested, parent, "zasp-m0-13-"));
    await assert.rejects(validateOwnedDirectory(join(parent, "zasp-m0-13-"), parent, "zasp-m0-13-"));
    await assert.rejects(validateOwnedDirectory(owned, join(parent, "foreign"), "zasp-m0-13-"));
  });
});

test("reads one stable bounded regular artifact through its descriptor", async () => {
  await withTemporaryDirectory(async (parent) => {
    const directory = join(parent, "zasp-m0-13-0123456789abcdef");
    await mkdir(directory);
    const identity = await validateOwnedDirectory(directory, parent, "zasp-m0-13-");
    const artifact = Buffer.from('{"resourceSpans":[]}\n');
    await writeFile(join(directory, ARTIFACT_NAME), artifact, { mode: 0o600 });

    assert.deepEqual(await readStableArtifact(identity), artifact.subarray(0, -1));
  });
});

test("rejects missing, empty, oversized, directory, and symlink artifacts", async () => {
  await withTemporaryDirectory(async (parent) => {
    const directory = join(parent, "zasp-m0-13-0123456789abcdef");
    await mkdir(directory);
    const identity = await validateOwnedDirectory(directory, parent, "zasp-m0-13-");
    const path = join(directory, ARTIFACT_NAME);

    await assert.rejects(readStableArtifact(identity));
    await writeFile(path, Buffer.alloc(0));
    await assert.rejects(readStableArtifact(identity));
    await writeFile(path, Buffer.alloc(65_537, 0x20));
    await assert.rejects(readStableArtifact(identity));
    await rm(path);
    await mkdir(path);
    await assert.rejects(readStableArtifact(identity));
    await rm(path, { recursive: true });
    await writeFile(join(directory, "foreign"), "{}");
    await symlink(join(directory, "foreign"), path);
    await assert.rejects(readStableArtifact(identity));
  });
});

test("rejects directory replacement before artifact access", async () => {
  await withTemporaryDirectory(async (parent) => {
    const directory = join(parent, "zasp-m0-13-0123456789abcdef");
    const replacement = join(parent, "replacement");
    await mkdir(directory);
    await mkdir(replacement);
    const identity = await validateOwnedDirectory(directory, parent, "zasp-m0-13-");
    await rm(directory, { recursive: true });
    await symlink(replacement, directory);

    await assert.rejects(readStableArtifact(identity));
  });
});

test("uses read-only no-follow nonblocking flags and rejects descriptor mutation", async () => {
  await withTemporaryDirectory(async (parent) => {
    const directory = join(parent, "zasp-m0-13-0123456789abcdef");
    await mkdir(directory);
    const identity = await validateOwnedDirectory(directory, parent, "zasp-m0-13-");
    const path = join(directory, ARTIFACT_NAME);
    await writeFile(path, "{}\n");
    let flags;
    const handle = await open(path, constants.O_RDONLY);
    const before = await handle.stat();
    let statCalls = 0;
    const io = {
      lstat,
      realpath,
      async open(value, valueFlags) {
        flags = valueFlags;
        return {
          async stat() {
            statCalls += 1;
            return statCalls === 1 ? before : { ...before, size: before.size + 1 };
          },
          async read(buffer) {
            buffer.set(Buffer.from("{}\n"));
            return { bytesRead: 3, buffer };
          },
          async close() {
            await handle.close();
          },
        };
      },
    };

    await assert.rejects(readStableArtifact(identity, io));
    assert.equal((flags & constants.O_RDONLY) === constants.O_RDONLY, true);
    if (constants.O_NOFOLLOW !== undefined) assert.equal((flags & constants.O_NOFOLLOW) !== 0, true);
    if (constants.O_NONBLOCK !== undefined) assert.equal((flags & constants.O_NONBLOCK) !== 0, true);
  });
});

test("close failure rejects an otherwise valid artifact", async () => {
  await withTemporaryDirectory(async (parent) => {
    const directory = join(parent, "zasp-m0-13-0123456789abcdef");
    await mkdir(directory);
    const identity = await validateOwnedDirectory(directory, parent, "zasp-m0-13-");
    const path = join(directory, ARTIFACT_NAME);
    await writeFile(path, "{}\n");
    const handle = await open(path, constants.O_RDONLY);
    const stat = await handle.stat();
    const io = {
      lstat,
      realpath,
      async open() {
        return {
          async stat() { return stat; },
          async read(buffer) {
            buffer.set(Buffer.from("{}\n"));
            return { bytesRead: 3, buffer };
          },
          async close() {
            await handle.close();
            throw new Error("close rejected");
          },
        };
      },
    };

    await assert.rejects(readStableArtifact(identity, io));
  });
});

test("exports only the fixed artifact filename", () => {
  assert.equal(ARTIFACT_NAME, "traces.json");
  assert.equal(basename(ARTIFACT_NAME), ARTIFACT_NAME);
  assert.equal(dirname(ARTIFACT_NAME), ".");
});
