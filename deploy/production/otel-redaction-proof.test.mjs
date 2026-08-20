import assert from "node:assert/strict";
import test from "node:test";

import { collectorImage, runOTelRedactionProof } from "./otel-redaction-proof.mjs";

test("rendered pinned Collector strips every hostile trace, metric, log, scope, schema, link, and exemplar value", { timeout: 180_000 }, async () => {
  assert.deepEqual(await runOTelRedactionProof(), { image: collectorImage, readOnlyRoot: true, redacted: true, runtimeUser: "65532:65532", signals: 3 });
});
