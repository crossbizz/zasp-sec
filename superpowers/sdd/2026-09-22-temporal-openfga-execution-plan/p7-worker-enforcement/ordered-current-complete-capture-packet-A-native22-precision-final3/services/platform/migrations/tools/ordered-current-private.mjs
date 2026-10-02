// Independent declarations for the newly introduced private routines.
import fs from 'node:fs';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {definitionInstallSQL,definitionAdmissionSQL,definitionAdapter,definitionBody,identityArgumentsAdapter,identityArgumentsBody,identityAdapter,identityBody} from './ordered-current-deparse-frame.mjs';
import {directFrameAdaptersV1,directFrameAdmissionSQL,directFrameInstallSQL} from './ordered-current-direct-frame-v1.mjs';
const namespace='zasp_authorization80_ordered_current';
const frameDeclarations=[[definitionAdapter,definitionBody],[identityArgumentsAdapter,identityArgumentsBody],[identityAdapter,identityBody]];
const frameDDL=definitionInstallSQL.slice(definitionInstallSQL.indexOf('CREATE FUNCTION '));
const directPrefix=definitionInstallSQL+'\n';
if(!directFrameInstallSQL.startsWith(directPrefix))throw Error('ordered-current direct private closure install prefix');
const directAdditionalDDL=directFrameInstallSQL.slice(directPrefix.length);
const directAdditionalAdapters=directFrameAdaptersV1.slice(frameDeclarations.length);
const directFail=message=>{throw Error('ordered-current direct private closure '+message);};
// Preserve the reference template itself. Its 35 admitted nonroutine facts are
// unchanged; only this successor assembly introduces the three new routines.
export function withOrderedFrameClosure(template){
  compileOrderedPrivateRoutines(template);
  if(template.includes('function_definition_public'))throw Error('frame closure already present');
  const gate=" IF current_user<>'zasp_discovery_authority'";
  if(template.split(gate).length!==2)throw Error('private frame gate anchor');
  let sql=template.replace(gate,()=>" IF ("+definitionAdmissionSQL+") IS DISTINCT FROM true THEN RETURN false; END IF;\n"+gate);
  const last="  'zasp_authorization80_ordered_current.require(text)']) signature";
  if(sql.split(last).length!==2)throw Error('private closure anchor');
  sql=sql.replace(last,()=>"  'zasp_authorization80_ordered_current.require(text)',\n"+frameDeclarations.map(([name])=>"  '"+name+"(oid)'").join(',\n')+"]) signature");
  const cleanup='ALTER FUNCTION zasp_authorization80_ordered_current.canonical(jsonb) OWNER';
  if(sql.split(cleanup).length!==2)throw Error('private frame DDL anchor');
  return sql.replace(cleanup,()=>frameDDL+'\n\n'+cleanup);
}
const declarations=[
  ['canonical',['value'],['jsonb'],'text','IMMUTABLE',true],
  ['normalize_rows',['rows','expected_manifest'],['jsonb','text'],'jsonb','IMMUTABLE',true],
  ['catalog',['expected_manifest'],['text'],'boolean','VOLATILE',false],
  ['require',['expected_manifest'],['text'],'void','VOLATILE',false]
];
function compileEvaluatorRoutines(sql){
  const matches=[...sql.matchAll(/CREATE FUNCTION zasp_authorization80_ordered_current\.([a-z_]+)\(([^)]*)\) RETURNS ([a-z]+)\nLANGUAGE plpgsql (IMMUTABLE|VOLATILE)( STRICT)? SECURITY INVOKER SET search_path=pg_catalog AS (\$[a-z_]+\$)([\s\S]*?)\6;/g)];
  if(matches.length!==4)throw Error('private declaration count changed');
  const facts=declarations.map(([name,names,types,result,volatility,strict])=>{
    const selected=matches.filter(m=>m[1]===name),args=names.map((n,i)=>n+' '+types[i]).join(', ');
    if(selected.length!==1)throw Error('private declaration missing');
    const m=selected[0];if(m[2]!==args||m[3]!==result||m[4]!==volatility||Boolean(m[5])!==strict)throw Error('private declaration changed');
    const signature=namespace+'.'+name+'('+types.join(',')+')';
    return {kind:'routine',identity:canonicalOrderedJSON(['private-routines',signature]),fact:{
      source:m[7],binary:null,sql_body:null,kind:'f',owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',language:'plpgsql',
      security_definer:false,volatility:volatility==='IMMUTABLE'?'i':'v',strict,parallel:'u',leakproof:false,config:['search_path=pg_catalog'],returns_set:false,cost:100,rows:0,
      input_types:types,all_types:null,argument_names:names,argument_modes:null,argument_defaults:null,default_count:0,variadic_type:null,result_type:result,support:null,transforms:null
    }};
  });
  return facts;
}
export function compileOrderedPrivateRoutines(sql){
  const facts=compileEvaluatorRoutines(sql);
  const hasFrames=sql.includes('CREATE FUNCTION '+definitionAdapter+'(');
  if(sql.match(/CREATE FUNCTION /g)?.length!==(hasFrames?7:4))throw Error('private declaration count changed');
  if(hasFrames&&!sql.includes(frameDDL))throw Error('private frame declaration changed');
  if(hasFrames)for(const [name,body] of frameDeclarations)facts.push({kind:'routine',identity:canonicalOrderedJSON(['private-routines',name+'(oid)']),fact:{...facts[0].fact,source:body,strict:false,volatility:'s',config:['search_path=pg_catalog, public','TimeZone=UTC'],input_types:['oid'],argument_names:['value'],result_type:'text'}});
  const fields=Object.keys(facts[0].fact);
  return {facts,rules:[{id:'private-routines',kind:'routine',namespaces:[namespace],identities:[],fields}],declarations:[...declarations.map(([name,names,types,result])=>({identity:namespace+'.'+name+'('+types.join(',')+')',argumentNames:names,inputTypes:types,resultType:result})),...(hasFrames?frameDeclarations.map(([name])=>({identity:name+'(oid)',argumentNames:['value'],inputTypes:['oid'],resultType:'text'})):[])]};
}
export function privateObjectRules(){
  const fields={namespace:['owner','acl'],relation:['kind','owner','acl','row_security','forced_row_security','options'],column:['name','position','type','not_null','default','acl','identity','generated'],constraint:['definition','validated','deferrable','deferred','constraint_type','no_inherit'],index:['definition','valid','ready','live','unique','primary','exclusion'],policy:['command','permissive','roles','using','check'],trigger:['enabled','definition','function','internal','deferrable','deferred','arguments','event_bits','when','old_table','new_table'],view:['definition','owner','acl','options'],rewrite:['event','enabled','instead','definition']};
  fields.type=['kind','category','owner','acl','relation','element','array','base','not_null','default','collation','input','output','receive','send','analyze','subscript','length','by_value','alignment','storage','delimiter','preferred','defined','type_modifier','dimensions'];
  return Object.entries(fields).map(([kind,fields])=>({id:'private-'+kind,kind,namespaces:[namespace],identities:[],fields}));
}

const shortType=value=>value.replace(/^pg_catalog\./,'');
const adapterIdentity=adapter=>adapter.name+'('+adapter.args.map(([,type])=>shortType(type)).join(',')+')';
const adapterDDL=adapter=>`CREATE FUNCTION ${adapter.name}(${adapter.args.map(([name,type])=>name+' '+type).join(', ')})
RETURNS pg_catalog.text LANGUAGE plpgsql STABLE SECURITY INVOKER PARALLEL UNSAFE
SET search_path=pg_catalog,public SET TimeZone='UTC'
AS $body$${adapter.body}$body$;
ALTER FUNCTION ${adapter.name}(${adapter.args.map(([,type])=>type).join(', ')}) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION ${adapter.name}(${adapter.args.map(([,type])=>type).join(', ')}) FROM PUBLIC;`;
const directRoster=directFrameAdaptersV1.map(adapter=>adapterIdentity(adapter));
const directGate=" IF ("+directFrameAdmissionSQL+") IS DISTINCT FROM true THEN RETURN false; END IF;\n";
const directBaseTemplate=fs.readFileSync(new URL('../sql/0080_authorization_worker_ordered_current_integrity.sql',import.meta.url),'utf8');

function assembleOrderedDirectFrameClosureV1(template){
  if(typeof template!=='string')directFail('template');
  try{compileOrderedPrivateRoutines(template);}catch{directFail('base template');}
  for(const anchor of ['  -- ordered-current:direct-collector-begin','  -- ordered-current:direct-collector-end','-- ordered-current:embedded-expectations'])if(template.split(anchor).length!==2)directFail('template anchor');
  let sql;
  try{sql=withOrderedFrameClosure(template);}catch{directFail('frame assembly');}
  const definitionGate=" IF ("+definitionAdmissionSQL+") IS DISTINCT FROM true THEN RETURN false; END IF;\n";
  if(sql.split(definitionGate).length!==2)directFail('admission anchor');
  sql=sql.replace(definitionGate,()=>directGate+definitionGate);
  const rosterEnd="  '"+identityAdapter+"(oid)']) signature";
  if(sql.split(rosterEnd).length!==2)directFail('routine roster anchor');
  sql=sql.replace(rosterEnd,()=>"  '"+identityAdapter+"(oid)',\n"+directAdditionalAdapters.map(adapter=>"  '"+adapterIdentity(adapter)+"'").join(',\n')+"]) signature");
  const cleanup='ALTER FUNCTION zasp_authorization80_ordered_current.canonical(jsonb) OWNER';
  if(sql.split(cleanup).length!==2)directFail('adapter DDL anchor');
  sql=sql.replace(cleanup,()=>directAdditionalDDL+'\n'+cleanup);
  return sql;
}
let directProgramV1;
const expectedOrderedDirectFrameClosureV1=()=>directProgramV1??=assembleOrderedDirectFrameClosureV1(directBaseTemplate);

export function withOrderedDirectFrameClosureV1(template){
  const sql=assembleOrderedDirectFrameClosureV1(template);
  compileOrderedDirectPrivateRoutinesV1(sql);
  return sql;
}
export function compileOrderedDirectPrivateRoutinesV1(sql){
  if(typeof sql!=='string')directFail('source');
  if(sql!==expectedOrderedDirectFrameClosureV1())directFail('complete statement program');
  const functions=sql.match(/CREATE FUNCTION /g)??[];
  if(functions.length!==22||(sql.match(/CREATE SCHEMA zasp_authorization80_ordered_current AUTHORIZATION zasp_discovery_authority;/g)??[]).length!==1)directFail('declaration count');
  let facts;
  try{facts=compileEvaluatorRoutines(sql);}catch{directFail('evaluator declaration');}
  const names=[...sql.matchAll(/CREATE FUNCTION zasp_authorization80_ordered_current\.([a-z_]+)\(/g)].map(match=>namespace+'.'+match[1]);
  const expectedNames=[...declarations.map(([name])=>namespace+'.'+name),...directFrameAdaptersV1.map(adapter=>adapter.name)];
  if(names.length!==22||new Set(names).size!==22||expectedNames.some(name=>!names.includes(name)))directFail('routine set');
  for(const adapter of directFrameAdaptersV1)if(sql.split(adapterDDL(adapter)).length!==2)directFail('adapter declaration '+adapter.name);
  const rosterStart="IF EXISTS(SELECT 1 FROM unnest(ARRAY[\n  'zasp_authorization80_ordered_current.canonical(jsonb)',",rosterEnd="]) signature";
  const rosterAt=sql.indexOf(rosterStart),rosterStop=sql.indexOf(rosterEnd,rosterAt),roster=rosterAt<0||rosterStop<0?[]:[...sql.slice(rosterAt,rosterStop).matchAll(/'([^']+)'/g)].map(match=>match[1]);
  const evaluatorRoster=declarations.map(([name,,types])=>namespace+'.'+name+'('+types.join(',')+')');
  const expectedRoster=[...evaluatorRoster,...directRoster];
  if(roster.length!==22||new Set(roster).size!==22||expectedRoster.some(identity=>!roster.includes(identity)))directFail('routine roster');
  const catalog=facts.find(row=>row.identity===canonicalOrderedJSON(['private-routines',namespace+'.catalog(text)']))?.fact.source;
  if(typeof catalog!=='string'||!catalog.includes(directGate)||catalog.indexOf(directGate)>catalog.indexOf('  -- ordered-current:direct-collector-begin'))directFail('admission gate');
  const base=facts[0].fact;
  for(const adapter of directFrameAdaptersV1){
    const types=adapter.args.map(([,type])=>shortType(type)),names=adapter.args.map(([name])=>name),identity=adapterIdentity(adapter);
    facts.push({kind:'routine',identity:canonicalOrderedJSON(['private-routines',identity]),fact:{...base,source:adapter.body,strict:false,volatility:'s',config:['search_path=pg_catalog, public','TimeZone=UTC'],input_types:types,argument_names:names,result_type:'text'}});
  }
  const fields=Object.keys(facts[0].fact);
  return {facts,rules:[{id:'private-routines',kind:'routine',namespaces:[namespace],identities:[],fields}],declarations:[...declarations.map(([name,names,types,result])=>({identity:namespace+'.'+name+'('+types.join(',')+')',argumentNames:names,inputTypes:types,resultType:result})),...directFrameAdaptersV1.map(adapter=>({identity:adapterIdentity(adapter),argumentNames:adapter.args.map(([name])=>name),inputTypes:adapter.args.map(([,type])=>shortType(type)),resultType:'text'}))]};
}
