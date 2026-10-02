import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const directory=path.dirname(fileURLToPath(import.meta.url));
const input=process.env.ZASP_READINESS_CAPTURE;
if(!input){
 test('external readiness capture unavailable without ZASP_READINESS_CAPTURE',{skip:'retained installed static catalog is not present in this checkout'},()=>{});
}else{
const generator=path.join(directory,'build-worker-readiness-graph.mjs');
const captured=JSON.parse(fs.readFileSync(input));
function run(t,mutate) {
  const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-readiness-generator-'));
  const artifact=structuredClone(captured);
  if(mutate)mutate(artifact);
  const source=path.join(scratch,'captured.json'),sql=path.join(scratch,'candidate.sql'),manifest=path.join(scratch,'manifest.json');
  fs.writeFileSync(source,JSON.stringify(artifact),{flag:'wx',mode:0o600});
  const args=[generator,source,sql,manifest];
  return {scratch,sql,manifest,args,result:spawnSync(process.execPath,args,{encoding:'utf8'})};
}
test('deterministic graph preserves fixed leaves, offsets and nested fallbacks',t=>{
  const r=run(t);
  assert.equal(r.result.status,0,r.result.stderr);
  const manifest=JSON.parse(fs.readFileSync(r.manifest)),sql=fs.readFileSync(r.sql,'utf8');
  assert.equal(manifest.expanded.length,52);
  assert.equal(manifest.expanded.filter(x=>x.parameter).length,3);
  assert(!manifest.expanded.some(x=>x.signature==='zasp_inventory_live_fingerprint()'));
  assert(!manifest.expanded.some(x=>x.signature==='zasp_authorization80.runtime_audit_ready()'));
  for(const fn of manifest.expanded) {
    const original=captured.functions.find(x=>x.signature===fn.signature).source;
    for(const edit of fn.edits) assert.equal(original.slice(edit.start,edit.end),edit.text);
  }
  assert.match(sql,/current_user=''zasp_discovery_authority'' THEN \(WITH/);
  assert.match(sql,/SELECT CASE WHEN \(SELECT value FROM readiness_0\) THEN \(WITH/);
  assert.equal(sql.split('END $readiness_graph$;').length-1,1);
  assert.equal(sql.split("EXECUTE replace(definition_value,original_value,").length-1,1);
  assert.equal(sql.split("regexp_replace(btrim(original_value),';[[:space:]]*$','')").length-1,2);
  // The actual root starts WITH. It must remain a scalar subquery after the
  // materialized CTE list, not become a second adjacent WITH clause.
  assert.match(captured.functions.find(x=>x.signature==='zasp_temporal77.base67_fingerprint()').source.trim(),/^WITH\s/i);
  assert(sql.includes("substring(ctes FROM length(catalog_cte)+2)||' SELECT ('||source_value||')) ELSE ('"));
  assert(!sql.includes("substring(ctes FROM length(catalog_cte)+2)||' '||source_value"));
  assert.equal(spawnSync(process.execPath,[...r.args,'--check'],{encoding:'utf8'}).status,0);
  fs.appendFileSync(r.sql,'-- altered generation\n');
  const bad=spawnSync(process.execPath,[...r.args,'--check'],{encoding:'utf8'});
  assert.notEqual(bad.status,0);assert.match(bad.stderr,/generated readiness artifact differs/);
});
for(const [name,change] of [
  ['different owner',f=>{f.owner='zasp_inventory_authority';}],
  ['different path',f=>{f.config=['search_path=public, pg_catalog'];}],
  ['strict null contract',f=>{f.strict=true;}],
  ['volatile frame',f=>{f.volatility='v';}],
  ['parameter zero-row query',f=>{f.source+=' FROM (SELECT 1 WHERE false) unsafe';}],
]) test('rejects '+name,t=>{
  const r=run(t,c=>change(c.functions.find(x=>x.signature==='zasp_authorization79.ready(text)')));
  assert.notEqual(r.result.status,0);
  assert.match(r.result.stderr,/ineligible frame|parameter body outer FROM/);
});
test('rejects an overloaded selected identity instead of choosing map order',t=>{
  const r=run(t,c=>{
    const f=structuredClone(c.functions.find(x=>x.signature==='zasp_authorization79.ready(text)'));
    f.signature='zasp_authorization79.ready(integer)';f.arguments='c integer';c.functions.push(f);
  });
  assert.notEqual(r.result.status,0);assert.match(r.result.stderr,/ambiguous selected function call/);
});

test('higher regions preserve opaque dynamic position and distinct nullable roots',t=>{
  const r=run(t);
  assert.equal(r.result.status,0,r.result.stderr);
  const manifest=JSON.parse(fs.readFileSync(r.manifest));
  assert.deepEqual(manifest.regions?.map(x=>x.signature),[
    'zasp_temporal68.predecessor_ready(text,text)',
    'zasp_temporal68.ready(text,text)',
    'zasp_temporal78.ready(text,text)',
  ]);
  const [pred,ready68,ready78]=manifest.regions;
  const original=captured.functions.find(x=>x.signature===pred.signature).source;
  assert.equal(pred.prefix+pred.originalExpression+pred.suffix,original);
  assert.match(pred.suffix,/FOREACH n IN ARRAY/);
  assert.match(pred.prefix,/c IS DISTINCT FROM/);
  assert.match(pred.prefix,/f IS DISTINCT FROM/);
  for(const region of manifest.regions){
    assert(!region.materialized.includes('zasp_temporal68.predecessor_ready(text,text)'));
    assert(!region.expanded.some(x=>x.signature==='zasp_inventory_live_fingerprint()'));
    assert.equal(region.query.match(/THEN zasp_authorization80_worker.catalog_ready\(\)/g)?.length,1);
  }
  assert.match(ready68.query,/zasp_temporal68\.predecessor_ready\(/);
  assert.match(ready68.originalExpression,/SELECT COALESCE/);
  assert.doesNotMatch(ready78.originalExpression,/COALESCE/);
  assert.match(ready78.prefix,/SELECT c=.* AND f=.* AND /s);
  assert.match(pred.query,/pg_get_functiondef/);
});
for(const [name,change] of [
  ['additional statement',f=>{f.source=f.source.replace('BEGIN','BEGIN PERFORM 1;');}],
  ['exception handler',f=>{f.source=f.source.replace(/END\s*$/, 'EXCEPTION WHEN OTHERS THEN RETURN false; END');}],
  ['wrong wrapper frame',f=>{f.owner='zasp_inventory_authority';}],
]) test('higher graph rejects '+name,t=>{
  const r=run(t,c=>change(c.functions.find(x=>x.signature==='zasp_temporal76.catalog_ready()')));
  assert.notEqual(r.result.status,0);
  assert.match(r.result.stderr,/higher readiness/);
});

test('actual static PL predicate qualifies scalar c, f and oid bindings',t=>{
  const r=run(t);
  assert.equal(r.result.status,0,r.result.stderr);
  const regions=JSON.parse(fs.readFileSync(r.manifest)).regions;
  const predicate=regions[0].query;
  // Native73824 internal_position74071 identified this exact bare c. It is
  // ambiguous with predecessor_ready(c,f), unlike the old SQL-only root.
  assert.doesNotMatch(predicate,/SELECT c='8b358e/);
  assert.match(predicate,/SELECT higher_argument_\d+\.c='8b358e/);
  assert.match(regions[2].query,/higher_argument_\d+\.f='5c5952/);
  assert.match(predicate,/signature=higher_argument_\d+\.function_value::regprocedure/);
  assert.match(predicate,/to_regprocedure\(signature\)=higher_argument_\d+\.value/);
  const aliases=[...regions[2].query.matchAll(/AS (higher_argument_\d+)\)/g)].map(x=>x[1]);
  assert.equal(new Set(aliases).size,aliases.length,'each emitted scalar call needs its own binding scope');
});
test('qualification preserves quoted parameter text and qualified member names',t=>{
  const r=run(t,c=>{
    const f=c.functions.find(x=>x.signature==='zasp_authorization79.ready(text)');
    f.source=f.source.trim()+" AND 'c'='c' AND $$c f$$=$$c f$$ AND (SELECT q.c FROM public.readiness_probe q)";
  });
  assert.equal(r.result.status,0,r.result.stderr);
  const query=JSON.parse(fs.readFileSync(r.manifest)).regions[0].query;
  assert(query.includes("'c'='c' AND $$c f$$=$$c f$$ AND (SELECT q.c FROM public.readiness_probe q)"));
});
test('qualification refuses unreviewed parameter shadows instead of rebinding them',t=>{
  const r=run(t,c=>{
    const f=c.functions.find(x=>x.signature==='zasp_authorization79.ready(text)');
    f.source=f.source.trim()+" AND (SELECT c FROM (SELECT true AS c) local_row)";
  });
  assert.notEqual(r.result.status,0);
  assert.match(r.result.stderr,/higher readiness .*shadow/);
});

test('static PL closure qualifies the copied ACL ordinality without changing its recipe',t=>{
  const r=run(t);
  assert.equal(r.result.status,0,r.result.stderr);
  const manifest=JSON.parse(fs.readFileSync(r.manifest));
  const region=manifest.regions[0];
  assert(!region.query.includes('END ORDER BY n)::text FROM jsonb_array_elements(acl) WITH ORDINALITY x(a,n)'), 'native95907 must not retain ambient n in its copied SQL');
  assert(region.query.includes('END ORDER BY x.n)::text FROM jsonb_array_elements(acl) WITH ORDINALITY x(a,n)'));
  const edit=region.expanded.find(x=>x.signature==='zasp_sa_export_live_fingerprint()').copyEdits;
  assert.deepEqual(edit,[{from:'ORDER BY n)::text FROM jsonb_array_elements(acl) WITH ORDINALITY x(a,n)',to:'ORDER BY x.n)::text FROM jsonb_array_elements(acl) WITH ORDINALITY x(a,n)'}]);
  const original=captured.functions.find(x=>x.signature==='zasp_sa_export_live_fingerprint()');
  assert(original.source.includes(edit[0].from));
  assert(!original.source.includes(edit[0].to));
  const payload=JSON.parse(fs.readFileSync(r.sql,'utf8').split('$higher_records$')[1]);
  const pin=payload.records.find(x=>x.signature===original.signature);
  assert.equal(pin.sourceHash,manifest.expanded.find(x=>x.signature===original.signature).sourceHash,'copied qualification must not rebase original function pin');
});
for(const name of ['c','f','n','retired','actual']) test('static closure refuses unbound ambient '+name,t=>{
  const r=run(t,c=>{
    const f=c.functions.find(x=>x.signature==='zasp_sa_export_live_fingerprint()');
    f.source=f.source.replace("SELECT encode(digest(convert_to(string_agg(value",`SELECT encode(digest(convert_to(string_agg(${name}||value`);
  });
  assert.notEqual(r.result.status,0);
  assert.match(r.result.stderr,/higher readiness unbound ambient/);
});
}
