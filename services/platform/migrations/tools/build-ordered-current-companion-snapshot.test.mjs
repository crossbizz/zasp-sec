import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {buildOrderedConsolidatedReference} from './build-ordered-current-consolidated-reference.mjs';

// Break caught: the source replay companion imports the descriptor adapter,
// which must be available in an owned snapshot without the original checkout.
test('owned A snapshot runs the worker source replay companion in isolation',t=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-companion-snapshot-'));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 const built=buildOrderedConsolidatedReference();
 for(const [relative,raw]of Object.entries(built.snapshotFiles)){
  const filename=path.join(directory,relative);
  fs.mkdirSync(path.dirname(filename),{recursive:true});
  fs.writeFileSync(filename,raw);
 }
 const result=spawnSync(process.execPath,['--test','services/platform/migrations/tools/ordered-current-worker-source-replay-v1.test.mjs'],{
  cwd:directory,encoding:'utf8',timeout:60000,
  env:{PATH:process.env.PATH,NODE_OPTIONS:''},
 });
 assert.equal(result.status,0,result.stderr||result.stdout);
 assert.match(result.stdout,/(?:# |ℹ )pass 8\b/);
 assert.match(result.stdout,/(?:# |ℹ )fail 0\b/);
 assert.match(result.stdout,/(?:# |ℹ )skipped 0\b/);
});
