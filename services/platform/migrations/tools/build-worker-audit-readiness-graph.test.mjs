import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import crypto from 'node:crypto';
import {auditWorkerBoundary} from './worker-audit-readiness-boundary.mjs';

const directory=path.dirname(fileURLToPath(import.meta.url));
const input=process.env.ZASP_AUDIT_READINESS_CAPTURE;
if(!input) {
  test('audit graph requires an independently captured composed catalog',{skip:'explicit composed capture required'},()=>{});
} else {
  const captured=JSON.parse(fs.readFileSync(input));
  const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
  for(const [name,mutate] of [
    ['wrapper body',c=>{c.functions.find(f=>f.signature==='zasp_sa_attack_lab_live_fingerprint()').source+=' ';}],
    ['wrapper frame',c=>{c.functions.find(f=>f.signature==='zasp_sa_attack_lab_live_fingerprint()').definition+=' ';}],
    ['wrapper owner',c=>{c.functions.find(f=>f.signature==='zasp_sa_attack_lab_live_fingerprint()').owner='other';}],
    ['wrapper ACL',c=>{c.functions.find(f=>f.signature==='zasp_sa_attack_lab_live_fingerprint()').acl=null;}],
    ['audit owner',c=>{c.functions.find(f=>f.signature==='zasp_authorization80_audit.guard_ready()').owner='other';}],
    ['audit roster',c=>{c.functions=c.functions.filter(f=>f.signature!=='zasp_authorization80_audit.catalog_ready()');}],
    ['saved canonical source',c=>{c.functions.find(f=>f.signature==='zasp_sa_attack_lab_prior.budget_fingerprint()').definition+=' ';}],
    ['saved canonical ACL',c=>{c.functions.find(f=>f.signature==='zasp_sa_attack_lab_prior.budget_fingerprint()').acl=null;}],
  ])test('audit compiler refuses '+name,()=>{
    const c=structuredClone(captured);mutate(c);
    assert.throws(()=>auditWorkerBoundary(c,{hash,quote:x=>x}),/exact.*required/);
  });
  const generator=process.env.ZASP_AUDIT_GRAPH_GENERATOR??path.join(directory,'build-worker-audit-readiness-graph.mjs');
  const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-audit-graph-'));
  const sql=path.join(scratch,'candidate.sql'),manifest=path.join(scratch,'manifest.json');
  const result=spawnSync(process.execPath,[generator,input,sql,manifest],{encoding:'utf8'});
  test('composed graph retains the public audit boundary as an original opaque call',()=>{
    assert.equal(result.status,0,result.stderr);
    const m=JSON.parse(fs.readFileSync(manifest));
    assert(!m.expanded.some(x=>x.signature==='zasp_sa_attack_lab_live_fingerprint()'));
    assert(!m.expanded.some(x=>x.signature.startsWith('zasp_authorization80_audit.')));
    for(const r of m.regions) {
      assert(!r.expanded.some(x=>x.signature.startsWith('zasp_authorization80_audit.')));
      assert(!r.materialized.includes('zasp_sa_export_live_fingerprint()'));
      assert(!r.materialized.includes('zasp_sa_webhook_live_fingerprint()'));
    }
    assert(fs.readFileSync(sql,'utf8').includes('public.zasp_sa_attack_lab_live_fingerprint()'));
  });
  test('composed graph separately authenticates the audit boundary and saved original roster',()=>{
    assert.equal(result.status,0,result.stderr);
    const m=JSON.parse(fs.readFileSync(manifest));
    assert.equal(m.auditBoundary?.saved.length,6);
    assert.equal(m.auditBoundary?.live.length,13);
    const source=fs.readFileSync(sql,'utf8');
    assert(source.includes('audit worker exact saved predecessor changed'));
    assert(source.includes('audit worker exact boundary changed'));
    assert(source.includes('zasp_authorization80_audit.catalog_ready()'));
    assert(source.includes('audit worker saved boundary changed'));
    assert(source.includes('INSERT INTO zasp_authorization80_worker.predecessor_functions'));
    assert(source.indexOf('DO $audit_worker_boundary$')<source.indexOf('DO $higher_readiness$'));
  });
}
