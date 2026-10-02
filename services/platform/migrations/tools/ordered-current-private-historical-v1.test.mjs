import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import test from 'node:test';

const adapter = new URL('./ordered-current-private-historical-v1.mjs', import.meta.url);
const bundle = new URL('./ordered-current-private-historical-v1/', import.meta.url);
const packetRaw = fs.readFileSync(new URL('./ordered-current-capture-intake-v1-artifacts/private-successor-packet.json', import.meta.url));
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const packetSHA = '6a487133102fb497db4e3209842a00ce3a0cec48ffd595c84dc3216a982a9cd0';

function fixture(t) {
  assert.ok(fs.existsSync(adapter), 'fixed historical provider must exist');
  assert.ok(fs.existsSync(bundle), 'closed historical source bundle must exist');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'zasp-private-historical-'));
  t.after(() => fs.rmSync(directory, {recursive:true, force:true}));
  fs.copyFileSync(adapter, path.join(directory, 'ordered-current-private-historical-v1.mjs'));
  fs.cpSync(bundle, path.join(directory, 'ordered-current-private-historical-v1'), {recursive:true});
  return {directory, root:path.join(directory, 'ordered-current-private-historical-v1'), url:pathToFileURL(path.join(directory, 'ordered-current-private-historical-v1.mjs')).href};
}

function child(value, body) {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `import assert from 'node:assert/strict'; import fs from 'node:fs'; import crypto from 'node:crypto'; const url=${JSON.stringify(value.url)}; const root=${JSON.stringify(value.root)}; ${body}`], {encoding:'utf8', timeout:15000});
  assert.equal(result.error, undefined, String(result.error));
  assert.equal(result.status, 0, result.stdout + result.stderr);
}

test('historical provider reproduces the independently pinned packet without archive paths', async t => {
  const value = fixture(t);
  assert.equal(sha(packetRaw), packetSHA);
  const files = fs.readdirSync(path.join(value.root, 'tools'));
  assert.equal(files.length, 26);
  assert.ok(files.every(file => file.endsWith('.mjs')));
  child(value, `const module=await import(url); const packet=module.buildOrderedCurrentPrivateHistoricalPacketV1(); const raw=Buffer.from(JSON.stringify(packet)+'\\n'); assert.equal(crypto.createHash('sha256').update(raw).digest('hex'), '${packetSHA}'); assert.equal(crypto.createHash('sha256').update(JSON.stringify(packet)).digest('hex'), '3a93f396bd3a60ae3f95e9690ff6b937d31507f95ebabeda7fd84133780fdc08'); assert.deepEqual(packet.counts,{rules:11,rows:57,routineRows:22,nonroutineRows:35}); assert.equal(packet.installable,false); assert.equal(packet.expectedRoutineFacts.length,22); assert.throws(()=>module.buildOrderedCurrentPrivateHistoricalPacketV1({root,sha256:'0'.repeat(64)}),/caller/);`);
  const module = await import(adapter);
  assert.deepEqual(Buffer.from(JSON.stringify(module.buildOrderedCurrentPrivateHistoricalPacketV1())+'\n'), packetRaw);
});

test('refuses drift in every historical source file before evaluating it', async t => {
  const value = fixture(t);
  const manifest = JSON.parse(fs.readFileSync(path.join(value.root, 'manifest.json')));
  assert.equal(Object.keys(manifest.files).length, 27);
  for (const file of Object.keys(manifest.files)) await t.test(file, () => {
    const target = path.join(value.root, file), original = fs.readFileSync(target);
    try {
      fs.appendFileSync(target, '\nthrow new Error("POISON_EXECUTED");\n');
      child(value, `await assert.rejects(import(url), error=>/private historical/.test(error.message)&&!error.message.includes('POISON_EXECUTED'));`);
    } finally { fs.writeFileSync(target, original); }
  });
});

for (const mode of ['missing', 'manifest', 'extra-module', 'extra-directory', 'file-symlink', 'directory-symlink', 'root-symlink', 'current-private', 'current-catalog']) {
  test(`refuses ${mode} without caller-selected authority or current-helper fallback`, t => {
    const value = fixture(t), target = path.join(value.root, 'tools/ordered-current-private.mjs');
    if (mode === 'missing') fs.unlinkSync(target);
    if (mode === 'manifest') fs.appendFileSync(path.join(value.root, 'manifest.json'), ' ');
    if (mode === 'extra-module') fs.writeFileSync(path.join(value.root, 'tools/extra.mjs'), 'throw Error("POISON_EXECUTED");');
    if (mode === 'extra-directory') fs.mkdirSync(path.join(value.root, 'unused'));
    if (mode === 'file-symlink') { const copy=path.join(value.directory,'outside.mjs'); fs.renameSync(target,copy); fs.symlinkSync(copy,target); }
    if (mode === 'directory-symlink') { const source=path.join(value.root,'tools'), copy=path.join(value.directory,'outside-tools'); fs.renameSync(source,copy); fs.symlinkSync(copy,source); }
    if (mode === 'root-symlink') { const copy=path.join(value.directory,'outside-bundle'); fs.renameSync(value.root,copy); fs.symlinkSync(copy,value.root); }
    if (mode.startsWith('current-')) { const file=`ordered-current-${mode.slice(8)}.mjs`; fs.copyFileSync(new URL(file,import.meta.url),path.join(value.root,'tools',file)); }
    child(value, `await assert.rejects(import(url), /private historical/);`);
  });
}

test('loaded ESM cannot hide subsequent source or manifest drift', t => {
  const value=fixture(t);
  child(value, `const module=await import(url); module.buildOrderedCurrentPrivateHistoricalPacketV1(); for(const name of ['tools/ordered-current-private.mjs','manifest.json']) { const file=root+'/'+name,raw=fs.readFileSync(file); fs.appendFileSync(file,' '); assert.throws(()=>module.buildOrderedCurrentPrivateHistoricalPacketV1(), /private historical/); fs.writeFileSync(file,raw); } module.buildOrderedCurrentPrivateHistoricalPacketV1();`);
});

test('post-derivation verification refuses a source change during packet construction', t => {
  const value=fixture(t);
  child(value, `const module=await import(url); const file=root+'/sql/0080_authorization_worker_ordered_current_integrity.sql'; const raw=fs.readFileSync(file); const read=fs.readFileSync; let reads=0; fs.readFileSync=function(input,...args) { const result=read.call(this,input,...args); if(String(input).includes('0080_authorization_worker_ordered_current_integrity.sql')&&++reads===3) fs.appendFileSync(file,' '); return result; }; try { assert.throws(()=>module.buildOrderedCurrentPrivateHistoricalPacketV1(), /private historical/); } finally {fs.readFileSync=read; fs.writeFileSync(file,raw);} assert.equal(reads>=3,true);`);
});
