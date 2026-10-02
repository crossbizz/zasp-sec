import test from 'node:test';
import assert from 'node:assert/strict';
import {compileOrderedCaptureRule,assertCaptureSelectSQL} from './ordered-current-capture-sql.mjs';
const site={sourceIdentity:'fixture()',sourceSHA256:'a'.repeat(64),definitionSHA256:'b'.repeat(64),siteSHA256:'c'.repeat(64),start:0,end:1,frame:{config:['search_path=pg_catalog, public']}};
const routine={id:'test:routine',kind:'routine',fields:['definition'],fieldTypes:{definition:'text'},projections:['pg_get_functiondef(p.oid)'],from:"FROM pg_proc p WHERE p.oid IN(SELECT signature::regprocedure FROM zasp_temporal72.predecessor_functions)",sourceSite:site,sourceMaxRows:null,refusalMaxRows:10000,canonicalClass:'pg_proc',handleExpression:"'pg_proc:'||p.oid::text||':0'"};
test('source-selected handles precede canonical keys without deparse in demand',()=>{
 const r=compileOrderedCaptureRule(routine);
 assert.match(r.demand,/signature::regprocedure/);
 assert.doesNotMatch(r.demand,/pg_get_functiondef/);
 assert.match(r.keys,/\$1::jsonb/);
 assert.doesNotMatch(r.keys,/signature::regprocedure|predecessor_functions/);
 assert.match(r.original,/pg_get_functiondef\(p.oid\)/);
 assert.match(r.original,/'identity',NULL/);
 assert.equal(r.rules['test:routine'].rosterRuleId,'test:routine:keys');
 assert.equal(r.rules['test:routine:keys'].demandRuleId,'test:routine:demand');
});
test('membership bags preserve duplicate tuple multiplicity without grantor identity',()=>{
 const r=compileOrderedCaptureRule({...routine,id:'test:membership',kind:'membership_bag',bag:true,canonicalClass:undefined,handleExpression:undefined,fields:['granted_role','member_role','admin_option'],fieldTypes:{granted_role:'text',member_role:'text',admin_option:'boolean'},projections:['granted.rolname','member.rolname','membership.admin_option'],from:'FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member'});
 assert.match(r.original,/count\(\*\)/);assert.match(r.original,/GROUP BY fact/);
 assert.doesNotMatch(r.original,/grantor/);assert.equal(r.demand,null);assert.equal(r.keys,null);
});
test('query audit distinguishes quoted definitions from executable writes',()=>{
 assert.doesNotThrow(()=>assertCaptureSelectSQL("SELECT 'CREATE FUNCTION x() RETURNS text AS $$ UPDATE x $$'::text"));
 assert.doesNotThrow(()=>assertCaptureSelectSQL('SELECT $$CREATE FUNCTION; DELETE FROM x$$::text'));
 for(const q of ['SELECT 1; DELETE FROM x','WITH x AS (DELETE FROM x RETURNING *) SELECT * FROM x','SELECT public.zasp_execution_readiness()','SELECT 1 LIMIT 1'])assert.throws(()=>assertCaptureSelectSQL(q),/capture SQL/);
});
test('quoted callable names and standard-conforming string boundaries remain executable tokens',()=>{
 for(const q of ['SELECT public."zasp_execution_readiness"()','SELECT "pg_catalog"."pg_sleep"(1)',"SELECT zasp_temporal72 /*x*/ . ready('a','b')",String.raw`SELECT '\'; DELETE FROM x --'`])assert.throws(()=>assertCaptureSelectSQL(q),/capture SQL/);
 assert.doesNotThrow(()=>assertCaptureSelectSQL(String.raw`SELECT E'\'; DELETE FROM x --'`));
});
test('unknown key kinds and incomplete source shapes refuse, no fallback bag',()=>{
 assert.throws(()=>compileOrderedCaptureRule({...routine,canonicalClass:'arbitrary_catalog'}),/canonical class/);
 assert.throws(()=>compileOrderedCaptureRule({...routine,fields:['definition','missing']}),/field/);
});
test('type handles acquire canonical regtype identities without publishing numeric OIDs',()=>{
 const r=compileOrderedCaptureRule({...routine,id:'test:type',kind:'type',fields:['name'],fieldTypes:{name:'text'},projections:['t.typname::text'],from:'FROM pg_type t WHERE t.oid IN(SELECT atttypid FROM pg_attribute WHERE attrelid=42 AND attnum>0)',canonicalClass:'pg_type',handleExpression:"'pg_type:'||t.oid::text||':0'"});
 assert.match(r.keys,/c.oid::regtype::text/);assert.doesNotMatch(r.keys,/pg_attribute|attrelid=42/);
 assert.equal(r.rules['test:type'].rosterRuleId,'test:type:keys');
 assert.match(r.original,/'identity',NULL/);
});
