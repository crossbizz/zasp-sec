import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
 admitOrderedDirectFrameSourceV1,
 bindOrderedDirectFrameV1,
 directFrameAdaptersV1,
 directFrameAdmissionSQL,
 directFrameExpressionV1,
 directFrameInstallSQL,
 directFrameRuleFieldMatrixV1,
 directFrameRulesV1,
 directFrameVersion,
} from './ordered-current-direct-frame-v1.mjs';

const manifestPath='/private/tmp/zasp-recovery80-native-driver-metadata-fix.rumZaA/capture-manifest-accepted-v2.json';
const artifactOptIn=process.env.ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED==='1';
const manifest=artifactOptIn&&fs.existsSync(manifestPath)?JSON.parse(fs.readFileSync(manifestPath)):null;
const coveragePath=manifest&&path.join(manifest.packetBytes.A.packetDirectory,'services/platform/migrations/ordered_current/consolidated-capture-coverage-v2.json');
const artifactTest=(name,fn)=>test(name,{skip:coveragePath&&fs.existsSync(coveragePath)?false:'fixed source coverage unavailable or not opted in'},fn);
function sqlParenthesisDepth(sql){
 let depth=0,minimum=0,quoted=false;
 for(let index=0;index<sql.length;index++){
  const character=sql[index];
  if(character==="'"){
   if(quoted&&sql[index+1]==="'"){index++;continue;}
   quoted=!quoted;
  }else if(!quoted&&character==='('){depth++;}
  else if(!quoted&&character===')'){depth--;minimum=Math.min(minimum,depth);}
 }
 return {depth,minimum,quoted};
}

test('direct frame v1 closes the complete current rule-field universe',()=>{
 assert.equal(directFrameVersion,1);
 assert.equal(directFrameRuleFieldMatrixV1.length,50);
 assert.equal(directFrameRuleFieldMatrixV1.reduce((sum,rule)=>sum+rule.fields.length,0),321);
 assert.equal(directFrameRuleFieldMatrixV1.flatMap(rule=>rule.fields).filter(field=>field.adapter!==null).length,76);
 assert.equal(Object.isFrozen(directFrameRuleFieldMatrixV1[0].fields[0]),true);
 assert.equal(Object.isFrozen(directFrameRulesV1[0].selector),true);
});

test('direct frame v1 declares all fixed adapters and a hard admission gate',()=>{
 const signatures={
  function_definition_public:['value'],function_identity_arguments_public:['value'],function_identity_public:['value'],
  relation_identity_public:['value'],type_identity_public:['value'],format_type_public:['type_oid','type_modifier'],column_default_public:['default_oid'],
  constraint_definition_public:['value'],constraint_definition_pretty_public:['value'],index_definition_public:['value'],
  trigger_definition_public:['value'],trigger_definition_pretty_public:['value'],trigger_when_public:['value'],policy_using_public:['value'],policy_check_public:['value'],
  policy_view_using_public:['namespace_name','relation_name','policy_name'],policy_view_check_public:['namespace_name','relation_name','policy_name'],index_view_definition_public:['namespace_name','relation_name','index_name'],
 };
 assert.equal(directFrameAdaptersV1.length,18);
 assert.match(directFrameAdmissionSQL,/count\(\*\)=18/);
 assert.match(directFrameAdmissionSQL,/count\(DISTINCT p\.proname\)=18/);
 assert.match(directFrameAdmissionSQL,/COALESCE\(bool_and\(\(\n/);
 assert.match(directFrameAdmissionSQL,/p\.prosqlbody IS NULL\) IS TRUE\),false\) AS admitted/);
 assert.deepEqual(sqlParenthesisDepth(directFrameAdmissionSQL),{depth:0,minimum:0,quoted:false});
 assert.equal(new Set(directFrameAdaptersV1.map(adapter=>adapter.name)).size,18);
 assert.match(directFrameInstallSQL,/format_type_public\(type_oid pg_catalog\.oid, type_modifier integer\)/);
 assert.doesNotMatch(directFrameInstallSQL,/pg_catalog\.integer/);
 assert.match(directFrameAdmissionSQL,/JOIN pg_catalog\.pg_proc p ON p\.proname=e\.column1\n/);
 assert.doesNotMatch(directFrameAdmissionSQL,/ON p\.proname=e\.column1 AND p\.proargtypes/);
 for(const adapter of directFrameAdaptersV1){
  assert.match(directFrameInstallSQL,new RegExp(`CREATE FUNCTION ${adapter.name.replaceAll('.','\\.')}\\(`));
  assert.ok(directFrameAdmissionSQL.includes(adapter.body));
  assert.deepEqual(adapter.args.map(argument=>argument[0]),signatures[adapter.name.split('.').at(-1)]);
 }
});

test('direct frame v1 binds exact rules, source expressions and call arities',()=>{
 assert.doesNotThrow(()=>bindOrderedDirectFrameV1(structuredClone(directFrameRulesV1)));
 const changed=structuredClone(directFrameRulesV1);changed[0].fields.pop();
 assert.throws(()=>bindOrderedDirectFrameV1(changed),/direct frame v1 rule binding/);
 const risky=/pg_get_|format_type|::reg(?:class|type|procedure)::text|^(?:qual|with_check|indexdef)$/;
 assert.deepEqual(directFrameRuleFieldMatrixV1.flatMap(rule=>rule.fields.filter(field=>risky.test(field.source)&&field.adapter===null)),[]);
 assert.equal(directFrameExpressionV1('worker-edge:gateway_projected24:4','constraint','definition_pretty','unused'),'zasp_authorization80_ordered_current.constraint_definition_pretty_public(k.oid)');
 assert.equal(directFrameExpressionV1('worker-edge:runtime_projected40:4','constraint','definition','unused'),'zasp_authorization80_ordered_current.constraint_definition_public(k.oid)');
 assert.equal(directFrameExpressionV1('worker-edge:runtime_projected50_search:9','trigger','definition','unused'),'zasp_authorization80_ordered_current.trigger_definition_public(t.oid)');
 assert.match(directFrameAdaptersV1.find(adapter=>adapter.name.endsWith('constraint_definition_public')).body,/pg_get_constraintdef\(value\);/);
 assert.match(directFrameAdaptersV1.find(adapter=>adapter.name.endsWith('constraint_definition_pretty_public')).body,/pg_get_constraintdef\(value,true\);/);
 assert.match(directFrameAdaptersV1.find(adapter=>adapter.name.endsWith('index_definition_public')).body,/pg_get_indexdef\(value\);/);
 assert.match(directFrameAdaptersV1.find(adapter=>adapter.name.endsWith('trigger_definition_public')).body,/pg_get_triggerdef\(value\);/);
 assert.match(directFrameAdaptersV1.find(adapter=>adapter.name.endsWith('trigger_definition_pretty_public')).body,/pg_get_triggerdef\(value,true\);/);
});

test('direct frame source admission refuses a missing gate',()=>{
 assert.throws(()=>admitOrderedDirectFrameSourceV1('SELECT 1'),/direct frame v1 admission gate/);
});

artifactTest('direct frame matrix exactly matches the pinned accepted source coverage',()=>{
 const raw=fs.readFileSync(coveragePath),coverage=JSON.parse(raw),byId=new Map(coverage.rawRules.map(rule=>[rule.id,rule]));
 assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),'67e214f69821c113b58078b5fc38e7504e33fb5748d7ad56de1fce01f85ed5c4');
 for(let index=0;index<directFrameRuleFieldMatrixV1.length;index++){
  const matrix=directFrameRuleFieldMatrixV1[index],captured=byId.get(matrix.id);
  assert.deepEqual(directFrameRulesV1[index],captured.originRule);
  assert.equal(matrix.kind,captured.kind);
  assert.equal(matrix.siteSHA256,captured.sourceSite.siteSHA256);
  assert.deepEqual(matrix.fields.map(field=>field.name),captured.fields);
  assert.deepEqual(matrix.fields.map(field=>field.source),captured.projections);
 }
});
