import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {load} from 'js-yaml';
const workflowFile=new URL('../.github/workflows/runnable-ui.yml',import.meta.url);
const packageFile=new URL('../package.json',import.meta.url);
const parsedVerifyRun=()=>load(fs.readFileSync(workflowFile,'utf8')).jobs.verify.steps.find(step=>step.name==='Verify runnable UI').run;
import {verifyFailureAnnotation} from './annotate-verify-failure.mjs';
const generic='::error title=npm verify failed::npm run verify failed; phase unavailable.';
const header=phase=>`> zasp-agent-security-console@0.1.0 ${phase}\n> synthetic command\n`;
test('latest exact failing phase annotation excludes all raw secret bytes',()=>{const raw=Buffer.from(header('dependencies:check')+'CANARY_secret ::error%0Aevil\n'+header('lint')+'credential=CANARY_secret\n');assert.equal(verifyFailureAnnotation(raw),'::error title=npm verify failed::npm run verify failed; latest observed phase: lint.');assert.doesNotMatch(verifyFailureAnnotation(raw),/CANARY|credential|evil/);});
test('missing, unknown, forged package and annotation-injection headers fall back safely',()=>{for(const raw of ['', 'CANARY_secret',header('unknown'),header('lint')+header('unknown'),header('lint')+'> zasp-agent-security-console@0.1.0 '+ 'x'.repeat(5000),'> fake@0.1.0 lint\n','> zasp-agent-security-console@0.1.0 lint%0A::error\n'])assert.equal(verifyFailureAnnotation(Buffer.from(raw)),generic);});
test('bounded read supports actual tail, rejects symlinks and never prints file errors',()=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'verify-phase-'));try{const file=path.join(dir,'log');fs.writeFileSync(file,'x'.repeat(300000)+'\n'+header('build')+'CANARY_secret\n');for(const target of [file,path.join(dir,'missing'),path.join(dir,'link')]){if(target.endsWith('link'))fs.symlinkSync(file,target);const r=spawnSync(process.execPath,[new URL('./annotate-verify-failure.mjs',import.meta.url).pathname,target],{encoding:'utf8',timeout:3000,maxBuffer:4096});assert.equal(r.status,0);assert.equal(r.stderr,'');assert.equal(r.stdout.trim(),target===file?'::error title=npm verify failed::npm run verify failed; latest observed phase: build.':generic);assert.doesNotMatch(r.stdout,/CANARY|ENOENT|verify-phase-/);} }finally{fs.rmSync(dir,{recursive:true,force:true});}});
test('candidate shell keeps actual failing subprocess status and fail-fast chain',()=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'verify-shell-'));try{const npm=path.join(dir,'npm');fs.writeFileSync(npm,"#!/bin/bash\nprintf '> zasp-agent-security-console@0.1.0 dependencies:check\\n'\n/bin/bash -c 'printf \"> zasp-agent-security-console@0.1.0 health:contract:test\\nCANARY_secret\\n\"; exit 37' && printf 'UNREACHED_LATER_PHASE\\n'\n",{mode:0o700});const shell=parsedVerifyRun().replace('node scripts/annotate-verify-failure.mjs',`${JSON.stringify(process.execPath)} ${JSON.stringify(new URL('./annotate-verify-failure.mjs',import.meta.url).pathname)}`);const r=spawnSync('/bin/bash',['--noprofile','--norc','-e','-o','pipefail','-c',shell],{env:{PATH:dir+':/usr/bin:/bin',RUNNER_TEMP:dir},encoding:'utf8',timeout:5000,maxBuffer:4096});assert.equal(r.status,37);assert.doesNotMatch(r.stdout,/UNREACHED_LATER_PHASE/);assert.match(r.stdout,/::error title=npm verify failed::npm run verify failed; latest observed phase: health:contract:test\./);assert.equal((shell.match(/npm run verify/g)||[]).length,1);assert.match(shell,/task_verify_status=\$\{PIPESTATUS\[0\]\}/);assert.equal(r.stderr,'');}finally{fs.rmSync(dir,{recursive:true,force:true});}});

test('diagnostic failure and success cannot replace verifier exit status',()=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'verify-status-'));try{const npm=path.join(dir,'npm');const block=parsedVerifyRun().replace('node scripts/annotate-verify-failure.mjs', 'false');for(const code of [0,29]){fs.writeFileSync(npm,`#!/bin/bash\nprintf '> zasp-agent-security-console@0.1.0 lint\n'\nexit ${code}\n`,{mode:0o700});const r=spawnSync('/bin/bash',['--noprofile','--norc','-e','-o','pipefail','-c',block],{env:{PATH:dir+':/usr/bin:/bin',RUNNER_TEMP:dir},encoding:'utf8',timeout:5000,maxBuffer:4096});assert.equal(r.status,code);if(code===0)assert.doesNotMatch(r.stdout,/::error/);else assert.match(r.stdout,/::error title=npm verify failed::Verification failed; phase unavailable\./);}}finally{fs.rmSync(dir,{recursive:true,force:true});}});


test('portable workflow binds exact original chain and phase roster',()=>{const run=parsedVerifyRun(),pkg=JSON.parse(fs.readFileSync(packageFile,'utf8'));assert.equal(pkg.name,'zasp-agent-security-console');assert.equal(pkg.version,'0.1.0');assert.equal(pkg.scripts.verify,"npm run dependencies:check && npm run health:contract:test && npm run openapi:test && npm run openapi:lint && npm run openapi:check && npm run ui-api:test && npm run ui-api:check && npm run raw-fetch:test && npm run saas:tenancy:test && npm run graph:neo4j:test && npm run db:tenant-rls:test && npm test && npm run typecheck && npm run lint && npm run production:imports:test && npm run production:imports:source && npm run staging:gate:test && npm run production:release:test && npm run build && npm run production:imports:compiled && npm run implementation:status:check");const phases=pkg.scripts.verify.split(' && ').map(command=>command.startsWith('npm run ')?command.slice(8):'test');assert.equal(phases.length,21);const helper=fs.readFileSync(new URL('./annotate-verify-failure.mjs',import.meta.url),'utf8');assert.deepEqual(JSON.parse(helper.match(/Object.freeze\((\[.*\])\)/)[1]),phases);assert.equal((run.match(/npm run verify/g)||[]).length,1);assert.match(run,/set \+e\nnpm run verify 2>&1 \| tee "\$task_verify_log"\ntask_verify_status=\$\{PIPESTATUS\[0\]\}\nset -e/);});

test('actual parsed workflow equals both exact TypeScript contract expectations',()=>{const actual=parsedVerifyRun();for(const name of ['runnable-ui-workflow.test.ts','dependency-lock-contract.test.ts']){const source=fs.readFileSync(new URL('../app/quality/'+name,import.meta.url),'utf8');const match=/const verifyDiagnosticRun = ("[^\n]*");/.exec(source);assert.ok(match);const expected=JSON.parse(match[1]);assert.equal(actual,expected);assert.throws(()=>assert.equal(actual+'\n',expected));}});

const releaseName='API build dependency stage resolves its copied local health module';
const releasePrefix='::error title=npm verify failed::npm run verify failed; latest observed phase: production:release:test.';
test('release diagnostics identify exact TAP and spec failures without raw child detail',()=>{
 for(const row of [`not ok 12 - ${releaseName}`,`✖ ${releaseName} (123.456ms)`]){
 const result=verifyFailureAnnotation(Buffer.from(header('production:release:test')+row+'\nCANARY_SECRET assertion stack\n# tests 285\n# pass 284\n# fail 1\n# cancelled 0\n# skipped 0\n# todo 0\n'));
 assert.equal(result,releasePrefix+` Observed failed tests: ${releaseName}. Observed summary: tests=285, pass=284, fail=1, cancelled=0, skipped=0, todo=0.`);assert.doesNotMatch(result,/CANARY|assertion|stack/);
 }
});
test('release diagnostics reset phase and refuse arbitrary names or counter text',()=>{
 assert.equal(verifyFailureAnnotation(Buffer.from(header('test')+`not ok 1 - ${releaseName}\n`+header('production:release:test'))),releasePrefix+' Observed failed tests: unavailable. Observed summary: unavailable.');
 for(const name of ['CANARY_SECRET',releaseName+'%0A::error',releaseName+' extra'])assert.equal(verifyFailureAnnotation(Buffer.from(header('production:release:test')+'not ok 1 - '+name+'\n# tests 1\n# pass 0\n# fail 1000001\n# cancelled 0\n# skipped 0\n# todo 0\n')),releasePrefix+' Observed failed tests: unavailable. Observed summary: unavailable.');
 assert.equal(verifyFailureAnnotation(Buffer.from(header('production:release:test')+`not ok 1 - ${releaseName}\n`+header('lint'))),'::error title=npm verify failed::npm run verify failed; latest observed phase: lint.');
 for(const count of ['01','-1','1e3','NaN','2 CANARY_SECRET','999999999999999999999'])assert.match(verifyFailureAnnotation(Buffer.from(header('production:release:test')+'# tests '+count+'\n')),/Observed summary: unavailable\.$/);
});
test('release diagnostics bound names, deduplicate, and require complete coherent summary',()=>{
 const src=fs.readFileSync(new URL('./annotate-verify-failure.mjs',import.meta.url),'utf8');const names=JSON.parse(src.match(/const RELEASE_TEST_NAMES = (\[[^\n]*\]);/)[1]);assert.ok(names.length>100);const rows=names.slice(0,8).map((name,i)=>`not ok ${i+1} - ${name}\n`).join('');const result=verifyFailureAnnotation(Buffer.from(header('production:release:test')+rows+rows));assert.ok(Buffer.byteLength(result)<=4096);for(const n of names.slice(0,4))assert.ok(result.includes(n));for(const n of names.slice(4,8))assert.ok(!result.includes(n));
 for(const summary of ['# tests 285\n# pass 284\n# fail 1\n','# tests 2\n# pass 2\n# fail 1\n# cancelled 0\n# skipped 0\n# todo 0\n','# tests 1\n# tests 2\n# pass 0\n# fail 1\n# cancelled 0\n# skipped 0\n# todo 0\n'])assert.match(verifyFailureAnnotation(Buffer.from(header('production:release:test')+summary)),/Observed summary: unavailable\.$/);
});

test('CLI retains closed phases across verbose output and refuses incomplete or hostile streams',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'verify-stream-'));
 const helper=new URL('./annotate-verify-failure.mjs',import.meta.url).pathname;
 const annotate=(file,extra={})=>spawnSync(process.execPath,[helper,file],{encoding:'utf8',timeout:3000,maxBuffer:4096,...extra});
 const phase=label=>`::error title=npm verify failed::npm run verify failed; latest observed phase: ${label}.`;
 try{
  const rows=[
   ['header before verbose tail',header('test')+'x'.repeat(300000)+'\nCANARY_SECRET\n',phase('test')],
   ['real header split across chunks','x'.repeat(65530)+'\n'+header('lint')+'CANARY_SECRET\n',phase('lint')],
   ['oversized line cannot inject a chunk-tail header',header('test')+'x'.repeat(65536)+header('lint'),phase('test')],
   ['oversized header clears earlier phase',header('test')+'> '+'x'.repeat(65536)+header('lint'),generic],
   ['unknown package clears earlier phase',header('test')+'> other-package@1.0.0 install\n',generic],
  ];
  for(const [name,body,want]of rows){const file=path.join(dir,name);fs.writeFileSync(file,body);const r=annotate(file);assert.equal(r.status,0,name);assert.equal(r.stderr,'',name);assert.equal(r.stdout.trim(),want,name);assert.doesNotMatch(r.stdout,/CANARY_SECRET|verify-stream-|x{16}/);}
  const capped=path.join(dir,'oversize');fs.writeFileSync(capped,header('lint'));fs.truncateSync(capped,64*1024*1024+1);const capfd=fs.openSync(capped,'r+');try{const ending=Buffer.from('\n'+header('lint'));fs.writeSync(capfd,ending,0,ending.length,64*1024*1024+1-ending.length);}finally{fs.closeSync(capfd);}const over=annotate(capped);assert.equal(over.status,0);assert.equal(over.stdout.trim(),generic);assert.equal(over.stderr,'');
  const lines=path.join(dir,'too-many-lines');fs.writeFileSync(lines,header('lint')+'\n'.repeat(1000001));const lineResult=annotate(lines);assert.equal(lineResult.status,0);assert.equal(lineResult.stdout.trim(),generic);assert.equal(lineResult.stderr,'');
  const preload=path.join(dir,'mutate.mjs');fs.writeFileSync(preload,`import fs from 'node:fs';const read=fs.readSync,target=fs.statSync(process.env.VERIFY_TARGET);let changed=false;fs.readSync=function(...args){const n=read.apply(this,args),current=fs.fstatSync(args[0]);if(!changed&&current.dev===target.dev&&current.ino===target.ino){changed=true;if(process.env.VERIFY_MUTATION==='truncate')fs.truncateSync(process.env.VERIFY_TARGET,0);else fs.appendFileSync(process.env.VERIFY_TARGET,'CANARY_SECRET appended\\n');}return n;};`);
  for(const mutation of ['append','truncate']){const file=path.join(dir,mutation);fs.writeFileSync(file,header('lint')+'x'.repeat(100000)+'\n');const actual=spawnSync(process.execPath,['--import',preload,helper,file],{env:{...process.env,VERIFY_TARGET:file,VERIFY_MUTATION:mutation},encoding:'utf8',timeout:3000,maxBuffer:4096});assert.equal(actual.status,0,mutation);assert.equal(actual.stdout.trim(),generic,mutation);assert.equal(actual.stderr,'');assert.doesNotMatch(actual.stdout,/CANARY_SECRET|verify-stream-/);}
  const fifo=path.join(dir,'fifo');const made=spawnSync('mkfifo',[fifo],{encoding:'utf8',timeout:3000});assert.equal(made.status,0);const nonregular=annotate(fifo);assert.equal(nonregular.status,0,'FIFO must be rejected before blocking read');assert.equal(nonregular.stdout.trim(),generic);assert.equal(nonregular.stderr,'');
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
