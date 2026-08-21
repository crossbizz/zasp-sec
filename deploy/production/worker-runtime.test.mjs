import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./worker.Dockerfile", import.meta.url), "utf8");

test("worker image builds exact isolated Cartography and Prowler runtimes", () => {
  assert.match(
    source,
    /^FROM python:3\.13\.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS security-python-build$/m,
  );
  assert.match(source, /\/opt\/zasp\/security\/cartography\/bin\/pip install --require-hashes --no-build-isolation --no-deps -r \/src\/security-python\/cartography\/requirements\.lock/);
  assert.match(source, /\/opt\/zasp\/security\/prowler\/bin\/pip install --require-hashes --no-build-isolation --no-deps -r \/src\/security-python\/prowler\/requirements\.lock/);
  assert.equal((source.match(/pip install --require-hashes --no-deps -r \/src\/security-python\/build-requirements\.lock/g) ?? []).length, 2);
  assert.match(source, /cartography_aws\.load_runtime_api\(\)\.version == '0\.139\.1'/);
  assert.match(source, /all\(name in prowler_aws\._CHECK_MODULES for name in prowler_aws\.CHECKS\)/);
  assert.match(source, /COPY --from=security-python-build --chown=65532:65532 \/opt\/zasp\/security \/opt\/zasp\/security/);
});

test("worker runtime retains a pinned Python base and nonroot health boundary", () => {
  const runtime = source.slice(source.lastIndexOf("\nFROM "));
  assert.match(runtime, /^\nFROM python:3\.13\.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS runtime$/m);
  assert.match(runtime, /^USER 65532:65532$/m);
  assert.match(runtime, /^HEALTHCHECK .*\/app\/zasp-healthcheck.*$/m);
  assert.doesNotMatch(runtime, /\b(?:ARG|ENV)\s+[^\n]*(?:SECRET|TOKEN|PASSWORD|DSN)/i);
});
