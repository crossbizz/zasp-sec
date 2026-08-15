import assert from "node:assert/strict";
import test from "node:test";

import { main, run } from "./health.mjs";

test("writes the exact health result", () => {
  const output = writer();

  assert.equal(run(["health"], output), 0);
  assert.equal(output.value(), "redteam-worker health ok\n");
});

test("rejects invalid arguments without output", () => {
  for (const arguments_ of [[], ["ready"], ["health", "extra"]]) {
    const output = writer();

    assert.equal(run(arguments_, output), 2);
    assert.equal(output.value(), "");
  }
});

test("contains writer failure at the process boundary", () => {
  const output = {
    write() {
      throw new Error("write failed");
    },
  };

  assert.throws(() => run(["health"], output), /write failed/);
  assert.equal(main(["health"], output), 1);
});

function writer() {
  let content = "";
  return {
    write(value) {
      content += value;
    },
    value() {
      return content;
    },
  };
}
