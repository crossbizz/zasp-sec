import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {
  compileOrderedDirectPrivateRoutinesV1,
  compileOrderedPrivateRoutines,
  withOrderedDirectFrameClosureV1,
  withOrderedFrameClosure,
} from './ordered-current-private.mjs';

const template=fs.readFileSync(new URL('../sql/0080_authorization_worker_ordered_current_integrity.sql',import.meta.url),'utf8');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const namespace='zasp_authorization80_ordered_current.';
const declarations=[
 ['canonical',['value'],['jsonb'],'jsonb','text','i',true,['search_path=pg_catalog']],
 ['normalize_rows',['rows','expected_manifest'],['jsonb','text'],'jsonb,text','jsonb','i',true,['search_path=pg_catalog']],
 ['catalog',['expected_manifest'],['text'],'text','boolean','v',false,['search_path=pg_catalog']],
 ['require',['expected_manifest'],['text'],'text','void','v',false,['search_path=pg_catalog']],
 ['function_definition_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['function_identity_arguments_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['function_identity_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['relation_identity_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['type_identity_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['format_type_public',['type_oid','type_modifier'],['oid','integer'],'oid integer','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['column_default_public',['default_oid'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['constraint_definition_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['constraint_definition_pretty_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['index_definition_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['trigger_definition_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['trigger_definition_pretty_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['trigger_when_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['policy_using_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['policy_check_public',['value'],['oid'],'oid','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['policy_view_using_public',['namespace_name','relation_name','policy_name'],['text','text','text'],'text text text','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['policy_view_check_public',['namespace_name','relation_name','policy_name'],['text','text','text'],'text text text','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
 ['index_view_definition_public',['namespace_name','relation_name','index_name'],['text','text','text'],'text text text','text','s',false,['search_path=pg_catalog, public','TimeZone=UTC']],
];

function removeRoutine(sql,name){
 const start=sql.indexOf(`CREATE FUNCTION ${namespace}${name}(`),tail=' FROM PUBLIC;',stop=sql.indexOf(tail,start);
 assert.ok(start>=0&&stop>start,`test fixture routine ${name}`);
 return sql.slice(0,start)+sql.slice(stop+tail.length);
}

test('legacy private compiler and three-adapter assembler remain byte-identical',()=>{
 assert.equal(sha(JSON.stringify(compileOrderedPrivateRoutines(template))),'a7504bf408c8d2c3d0df520fac3e62e628d08dc10833301bf826b37b6720aaf1');
 const framed=withOrderedFrameClosure(template);
 assert.equal(sha(framed),'cd7d6ba57ed04ea992cfdb52d01148127bdbcd03c009c5f0ec3a575c14faeba5');
 assert.equal(sha(JSON.stringify(compileOrderedPrivateRoutines(framed))),'08c3cb7090f3e1f89f249ef6f2fc4a13bfd75531c5238469cff40914e380430c');
});

test('closed direct assembler emits one schema and exact twenty-two-routine source facts',()=>{
 const sql=withOrderedDirectFrameClosureV1(template),compiled=compileOrderedDirectPrivateRoutinesV1(sql);
 assert.equal((sql.match(/CREATE SCHEMA zasp_authorization80_ordered_current/g)??[]).length,1);
 assert.equal((sql.match(/CREATE FUNCTION /g)??[]).length,22);
 assert.equal(compiled.facts.length,22);
 assert.deepEqual(compiled.declarations.map(row=>row.identity),declarations.map(([name,,types])=>namespace+name+'('+types.join(',')+')'));
 const facts=new Map(compiled.facts.map(row=>[JSON.parse(row.identity)[1],row.fact]));
 for(const [name,names,types,,result,volatility,strict,config] of declarations){
  const fact=facts.get(namespace+name+'('+types.join(',')+')');
  assert.ok(fact,name);assert.deepEqual(fact.argument_names,names,name);assert.deepEqual(fact.input_types,types,name);
  assert.equal(fact.result_type,result,name);assert.equal(fact.volatility,volatility,name);assert.equal(fact.strict,strict,name);assert.deepEqual(fact.config,config,name);
  assert.equal(fact.owner,'zasp_discovery_authority',name);assert.equal(fact.acl,'{zasp_discovery_authority=X/zasp_discovery_authority}',name);
  assert.equal(fact.language,'plpgsql',name);assert.equal(fact.security_definer,false,name);assert.equal(fact.parallel,'u',name);assert.equal(fact.leakproof,false,name);
  assert.equal(fact.binary,null,name);assert.equal(fact.sql_body,null,name);assert.equal(fact.returns_set,false,name);assert.equal(fact.cost,100,name);assert.equal(fact.rows,0,name);
  assert.equal(fact.argument_modes,null,name);assert.equal(fact.argument_defaults,null,name);assert.equal(fact.default_count,0,name);assert.equal(fact.variadic_type,null,name);assert.equal(fact.support,null,name);assert.equal(fact.transforms,null,name);
 }
 assert.match(sql,/count\(\*\)=18 AND count\(DISTINCT p\.proname\)=18/);
 assert.ok(sql.indexOf('count(*)=18 AND count(DISTINCT p.proname)=18')<sql.indexOf('-- ordered-current:direct-collector-begin'));
});

test('closed direct compiler refuses adapter source, frame, arity and routine-set drift',()=>{
 const sql=withOrderedDirectFrameClosureV1(template);
 const gateStart=sql.indexOf(' IF (WITH expected AS (VALUES '),gateStop=sql.indexOf(' END IF;\n',gateStart)+10,gate=sql.slice(gateStart,gateStop);
 assert.ok(gateStart>=0&&gateStop>gateStart,'test fixture direct admission gate');
 const mutations=[
  sql.replace('RETURN value::pg_catalog.regclass::pg_catalog.text;','RETURN NULL;'),
  sql.replace('RETURNS pg_catalog.text LANGUAGE plpgsql STABLE SECURITY INVOKER PARALLEL UNSAFE','RETURNS pg_catalog.text LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER PARALLEL UNSAFE'),
  sql.replace("SET search_path=pg_catalog,public SET TimeZone='UTC'","SET search_path=pg_catalog SET TimeZone='UTC'"),
  sql.replace('format_type_public(type_oid pg_catalog.oid, type_modifier integer)','format_type_public(type_oid pg_catalog.oid)'),
  removeRoutine(sql,'policy_check_public'),
  sql+"\nCREATE FUNCTION zasp_authorization80_ordered_current.extra(value pg_catalog.oid) RETURNS pg_catalog.text LANGUAGE plpgsql STABLE SECURITY INVOKER AS $body$ BEGIN RETURN NULL; END $body$;\n",
  sql+sql.slice(sql.indexOf(`CREATE FUNCTION ${namespace}relation_identity_public(`),sql.indexOf('ALTER FUNCTION',sql.indexOf(`CREATE FUNCTION ${namespace}relation_identity_public(`))),
  gate+'\n'+sql.slice(0,gateStart)+sql.slice(gateStop),
 ];
 for(const changed of mutations)assert.throws(()=>compileOrderedDirectPrivateRoutinesV1(changed),/direct private closure/);
});

test('closed direct compiler refuses later effective routine statements',()=>{
 const sql=withOrderedDirectFrameClosureV1(template),identity='zasp_authorization80_ordered_current.relation_identity_public';
 const mutations=[
  sql+`\nALTER FUNCTION ${identity}(pg_catalog.oid) IMMUTABLE;\n`,
  sql+`\nCREATE OR REPLACE FUNCTION ${identity}(value pg_catalog.oid) RETURNS pg_catalog.text LANGUAGE plpgsql STABLE SECURITY INVOKER PARALLEL UNSAFE SET search_path=pg_catalog,public SET TimeZone='UTC' AS $body$BEGIN RETURN NULL; END$body$;\n`,
  sql+`\nALTER ROUTINE ${identity}(pg_catalog.oid) IMMUTABLE;\n`,
  sql+`\nDROP FUNCTION ${identity}(pg_catalog.oid);\n`,
  sql+`\nGRANT EXECUTE ON FUNCTION ${identity}(pg_catalog.oid) TO PUBLIC;\n`,
  sql+`\nDO $poison$ BEGIN EXECUTE 'ALTER FUNCTION ${identity}(pg_catalog.oid) IMMUTABLE'; END $poison$;\n`,
  sql+`\nGRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA zasp_authorization80_ordered_current TO PUBLIC;\n`,
 ];
 for(const changed of mutations)assert.throws(()=>compileOrderedDirectPrivateRoutinesV1(changed),/direct private closure/);
});

test('closed direct assembler refuses non-base or ambiguously anchored templates',()=>{
 const extended=withOrderedDirectFrameClosureV1(template);
 for(const changed of [
  extended,
  template.replace('  -- ordered-current:direct-collector-begin',''),
  template.replace(" IF current_user<>'zasp_discovery_authority'"," IF current_user<>'zasp_discovery_authority'\n IF current_user<>'zasp_discovery_authority'"),
  template+"\nCREATE FUNCTION public.unexpected() RETURNS void LANGUAGE plpgsql AS $$ BEGIN END $$;\n",
 ])assert.throws(()=>withOrderedDirectFrameClosureV1(changed),/direct private closure/);
});
