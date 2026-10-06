import './compliance-runtime-prerequisites.test.mjs';
import './owned-runtime-startup-diagnostics.test.mjs';
import './hosted-runtime-tool-intake.test.mjs';
import './owned-runtime-services.test.mjs';
import './owned-listener.test.mjs';
import './owned-runtime-lifetime.test.mjs';
import './retained-runtime-lifetime.test.mjs';
import './official-held-tools.test.mjs';
import './held-custody.test.mjs';
import './owned-current80-composition.test.mjs';
import './current80-runner-consumption.test.mjs';
import './browser-command-failure.test.mjs';
import './browser-startup-phase.test.mjs';
import './browser-provisioning-subphase.test.mjs';
import assert from "node:assert/strict";
import test from "node:test";
import { storedComplianceJSON } from "./compliance-browser-bytes.mjs";
test("raw member comparison retains whitespace, escaped strings and record order",()=>{
  const raw=String.raw`[ {"at":"old", "value":"quoted \" [ ]"},2 ]`;
  assert.equal(storedComplianceJSON(Buffer.from(`{"version":1,"json":${raw},"csv":"x"}`)).toString(),raw);
  assert.throws(()=>storedComplianceJSON(Buffer.from('{"json":[')));
});

import './browser-current-profile-command.test.mjs';
import './browser-current-profile-inner-marker.test.mjs';
import './browser-current-profile-inner-command.test.mjs';
