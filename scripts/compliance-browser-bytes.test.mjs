import './browser-command-failure.test.mjs';
import assert from "node:assert/strict";
import test from "node:test";
import { storedComplianceJSON } from "./compliance-browser-bytes.mjs";
test("raw member comparison retains whitespace, escaped strings and record order",()=>{
  const raw=String.raw`[ {"at":"old", "value":"quoted \" [ ]"},2 ]`;
  assert.equal(storedComplianceJSON(Buffer.from(`{"version":1,"json":${raw},"csv":"x"}`)).toString(),raw);
  assert.throws(()=>storedComplianceJSON(Buffer.from('{"json":[')));
});
