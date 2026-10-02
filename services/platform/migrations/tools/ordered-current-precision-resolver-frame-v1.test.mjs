import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import * as catalog from './ordered-current-catalog.mjs';
import * as privateCompiler from './ordered-current-private.mjs';
import * as closure from './ordered-current-source-closure-v1.mjs';
import {lowerOrderedTemporal72Catalog} from './ordered-current-temporal72.mjs';
import {compareFacts,canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {compileOrderedTransforms} from './ordered-current-transform-compiler.mjs';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';
import {definitionFrame,admitFramedTransformSource} from './ordered-current-deparse-frame.mjs';
const resolver=await import('./ordered-current-precision-resolver-frame-v1.mjs').catch(()=>({}));
const contract=JSON.parse(fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url)));
const rules=lowerOrderedTemporal72Catalog(contract).rules;
const template=fs.readFileSync(new URL('../sql/0080_authorization_worker_ordered_current_integrity.sql',import.meta.url),'utf8');
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const adapter='zasp_authorization80_ordered_current.function_resolve_public';
const sourceBody='\nBEGIN\n RETURN pg_catalog.to_regprocedure(value)::pg_catalog.oid;\nEND\n';
const successor=()=>{assert.equal(typeof catalog.compileOrderedPrecisionResolverCollectorV1,'function');return catalog.compileOrderedPrecisionResolverCollectorV1(rules);};
const assemble=()=>{assert.equal(typeof privateCompiler.withOrderedPrecisionResolverClosureV1,'function');return privateCompiler.withOrderedPrecisionResolverClosureV1(template);};

// Break caught: changing the original collector to fix the active evaluator
// invalidates frozen historical captures and direct22 authority.
test('legacy collector private7 and direct22 retain independent before-byte digests',()=>{
 assert.equal(sha(catalog.compileOrderedCollector(rules).sql),'219cf55e454f27415a7f1693363ae74f4fb2a1af74d34d1561d73ebb1caf71a3');
 assert.equal(sha(privateCompiler.withOrderedFrameClosure(template)),'cd7d6ba57ed04ea992cfdb52d01148127bdbcd03c009c5f0ec3a575c14faeba5');
 assert.equal(sha(privateCompiler.withOrderedDirectFrameClosureV1(template)),'654e2e1e2e445b4cee82a5cbbb5fe01b5ad1093a23650f4333c5ea1813d66845');
});

// Break caught: widening or flattening the source CASE/scalar or dropping the
// admission demand gate can run a forged resolver or turn saved NULL into live.
test('successor changes only selected guard resolver with materialized CASE admission',()=>{
 const built=successor(),legacy=catalog.compileOrderedCollector(rules).sql;
 const oldEdge='pg_catalog.to_regprocedure(signature)=p.oid';
 const gated=`CASE WHEN (SELECT admitted FROM precision_resolver_admission) IS TRUE THEN ${adapter}(signature) ELSE NULL::pg_catalog.oid END=p.oid`;
 assert.ok(built.sql.includes('precision_resolver_admission AS MATERIALIZED ('+resolver.precisionResolverAdmissionSQLV1+')'));
 assert.equal(built.sql.replace('WITH precision_resolver_admission AS MATERIALIZED ('+resolver.precisionResolverAdmissionSQLV1+'),\n','WITH ').replace(gated,oldEdge),legacy);
 assert.equal(built.sourceSHA256,sha(built.sql));
 assert.equal(built.installable,false);
 assert.equal(built.admissionSQL,resolver.precisionResolverAdmissionSQLV1);
 assert.equal(resolver.admitOrderedPrecisionResolverSourceV1(built.sql),true);
 for(const changed of [built.sql.replace('(signature)','(definition)'),built.sql.replace(adapter,'public.attacker'),built.sql.replace(adapter,'"zasp_authorization80_ordered_current"."function_resolve_public"'),built.sql.replace(gated,adapter+'(signature)=p.oid'),built.sql+' UNION ALL SELECT '+adapter+'(signature)',built.sql+' UNION ALL SELECT public.attacker()'])assert.throws(()=>resolver.admitOrderedPrecisionResolverSourceV1(changed),/precision|collector|unadmitted|quoted/);
 const moved=structuredClone(rules);moved.at(-1).id='another-site';
 assert.throws(()=>catalog.compileOrderedPrecisionResolverCollectorV1(moved),/precision.*(rule|site)/);
 const widened=structuredClone(rules);widened.at(-1).selector={field:'namespace',equals:'public'};
 assert.throws(()=>catalog.compileOrderedPrecisionResolverCollectorV1(widened),/precision.*(rule|site)/);
});

// Break caught: the real routine input_types descriptor contains PostgreSQL's
// WITH ORDINALITY row-source clause; treating that token pair as a new CTE
// blocks the combined collector before private8 assembly.
test('successor admits the real input_types descriptor in the complete routine collector',()=>{
 const precisionRule=rules.find(rule=>rule.id==='temporal72:precision-function');
 const diagnosticRule={...structuredClone(precisionRule),id:'diagnostic-input-types',fields:['input_types']};
 const built=catalog.compileOrderedPrecisionResolverCollectorV1([...rules,diagnosticRule]);
 const descriptor='ARRAY(SELECT args.unnest::regtype::text FROM pg_catalog.unnest(p.proargtypes) WITH ORDINALITY AS args(unnest, ordinality) ORDER BY args.ordinality)';
 assert.ok(built.sql.includes(descriptor));
 assert.equal(resolver.admitOrderedPrecisionResolverSourceV1(built.sql),true);
});

// Break caught: a lexical exception for the catalog expression must not turn
// arbitrary WITH, alternate row sources, aliases, or clause placement into a
// broader SQL-parser whitelist.
test('successor confines WITH ORDINALITY allowance to the pinned full-collector shape',()=>{
 const descriptor='ARRAY(SELECT args.unnest::regtype::text FROM pg_catalog.unnest(p.proargtypes) WITH ORDINALITY AS args(unnest, ordinality) ORDER BY args.ordinality)';
 const full=successor().sql+'\nUNION ALL\nSELECT '+descriptor;
 const changed=[
  full.replace('pg_catalog.unnest(p.proargtypes) WITH ORDINALITY','pg_catalog.other(p.proargtypes) WITH ORDINALITY'),
  full.replace('AS args(unnest, ordinality) ORDER BY args.ordinality','AS forged(unnest, ordinality) ORDER BY forged.ordinality'),
  full.replace('WITH ORDINALITY','WITH SELECT'),
  full.replace('WITH ORDINALITY AS args(unnest, ordinality) ORDER BY args.ordinality','WITH ORDINALITY AS args(unnest, ordinality)'),
 ];
 for(const source of changed)assert.throws(()=>resolver.admitOrderedPrecisionResolverSourceV1(source),/precision|collector|unadmitted|query/);
 assert.equal(resolver.admitOrderedPrecisionResolverSourceV1(full),true);
});

// Break caught: oid->text adapter assumptions or stale catalog facts conceal a
// text->oid resolver or changed gate; dropped/unknown/late program poisons pass.
test('complete successor program independently compiles eight typed routine facts and rejects poison',()=>{
 const sql=assemble();
 assert.equal(typeof privateCompiler.compileOrderedPrecisionPrivateRoutinesV1,'function');
 const compile=privateCompiler.compileOrderedPrecisionPrivateRoutinesV1;
 const compiled=compile(sql),row=compiled.facts.find(r=>r.identity===JSON.stringify(['private-routines',adapter+'(text)']));
 assert.equal(compiled.facts.length,8);
 assert.deepEqual(row.fact,{source:sourceBody,binary:null,sql_body:null,kind:'f',owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',language:'plpgsql',security_definer:false,volatility:'s',strict:false,parallel:'u',leakproof:false,config:['search_path=pg_catalog, public'],returns_set:false,cost:100,rows:0,input_types:['text'],all_types:null,argument_names:['value'],argument_modes:null,argument_defaults:null,default_count:0,variadic_type:null,result_type:'oid',support:null,transforms:null});
 assert.deepEqual(compiled.declarations.at(-1),{identity:adapter+'(text)',argumentNames:['value'],inputTypes:['text'],resultType:'oid'});
 const catalogRow=compiled.facts.find(r=>JSON.parse(r.identity)[1].endsWith('.catalog(text)'));
 assert.ok(catalogRow.fact.source.indexOf(resolver.precisionResolverAdmissionSQLV1)<catalogRow.fact.source.indexOf('-- ordered-current:direct-collector-begin'));
 const begin='  -- ordered-current:direct-collector-begin',end='  -- ordered-current:direct-collector-end';
 const inserted=sql.slice(0,sql.indexOf(begin))+begin+'\n'+successor().sql+'\n'+sql.slice(sql.indexOf(end));
 assert.ok(compile(inserted).facts.find(r=>r.identity===catalogRow.identity).fact.source.includes(successor().sql));
 for(const changed of [sql+'\nALTER FUNCTION '+adapter+'(text) SECURITY DEFINER;',sql+'\nDO $$ BEGIN NULL; END $$;',sql+'\nGRANT EXECUTE ON FUNCTION '+adapter+'(text) TO PUBLIC;',sql+'\n'+resolver.precisionResolverInstallSQLV1,sql.replace(sourceBody,'\nBEGIN\n RETURN NULL;\nEND\n'),sql.replace("  '"+adapter+"(text)'", "  '"+adapter+"(oid)'"),sql.replace('RETURNS pg_catalog.oid LANGUAGE','RETURNS pg_catalog.text LANGUAGE')])assert.throws(()=>compile(changed),/precision private/);
 for(const field of Object.keys(row.fact)){const changed=structuredClone(compiled.facts);const target=changed.find(r=>r.identity===row.identity);target.fact[field]=target.fact[field]===null?'poison':null;assert.equal(compareFacts(compiled.facts,changed),false,field);}
});

// Break caught: compiler->packet loses actual catalog body/new typed declaration
// or silently changes the preserved source-template7/direct22 authority.
test('successor attached source authority rechecks actual private8 facts without recasting history',()=>{
 const sql=assemble(),compiled=privateCompiler.compileOrderedPrecisionPrivateRoutinesV1(sql),base=closure.admitOrderedCurrentSourceClosureV1();
 assert.equal(base.private.ordinaryFrameRoutineCount,7);
 assert.equal(base.private.directFrameRoutineCount,22);
 assert.ok(closure.orderedCurrentSourceClosureModulesV1.includes('ordered-current-precision-resolver-frame-v1.mjs'));
 assert.equal(typeof closure.attachOrderedCurrentPrecisionPrivateAuthorityV1,'function');
 const packet=closure.attachOrderedCurrentPrecisionPrivateAuthorityV1(base,sql,compiled);
 assert.equal(packet.private.ordinaryFrameRoutineCount,8);
 assert.equal(packet.private.routineFactsSHA256,sha(canonicalOrderedJSON(compiled.facts)));
 assert.equal(packet.private.assemblyAuthority,'generator-in-memory-precision-resolver-v1');
 assert.equal(packet.installable,false);assert.equal(packet.nativeVerified,false);
 const witness={kind:'generator-in-memory-precision-resolver-v1',sql,privateClosure:compiled};
 assert.doesNotThrow(()=>closure.assertOrderedCurrentAttachedSourceClosureV1(packet,contract,witness));
 for(const facts of [compiled.facts.slice(1),[...compiled.facts,compiled.facts[0]]])assert.throws(()=>closure.attachOrderedCurrentPrecisionPrivateAuthorityV1(base,sql,{...compiled,facts}),/private.*closure/);
 const changed=structuredClone(packet);changed.private.ordinaryFrameDeclarations.at(-1).resultType='text';
 assert.throws(()=>closure.assertOrderedCurrentAttachedSourceClosureV1(changed,contract,witness),/mismatch/);
});

test('public resolver and catalog import paths remain cycle-safe',()=>{
 for(const name of ['ordered-current-precision-resolver-frame-v1.mjs','ordered-current-catalog.mjs','ordered-current-private.mjs']){
 const result=spawnSync(process.execPath,['--input-type=module','-e',`await import(${JSON.stringify(new URL(name,import.meta.url).href)})`],{encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);
 }
});

const inPrivate=collector=>{
 const sql=assemble(),begin='  -- ordered-current:direct-collector-begin',end='  -- ordered-current:direct-collector-end';
 return sql.slice(0,sql.indexOf(begin))+begin+'\n'+collector+'\n'+sql.slice(sql.indexOf(end));
};
const refuseAtBothBoundaries=collector=>{
 let admissionError,compilerError;
 try{resolver.admitOrderedPrecisionResolverSourceV1(collector);}catch(error){admissionError=error;}
 try{privateCompiler.compileOrderedPrecisionPrivateRoutinesV1(inPrivate(collector));}catch(error){compilerError=error;}
 // Exercise both real paths before assertions, including in the RED run.
 assert.deepEqual([Boolean(admissionError),Boolean(compilerError)],[true,true]);
 assert.match(admissionError.message,/precision|collector|unterminated/);
 assert.match(compilerError.message,/precision private/);
};

// Break caught: exact admission text can remain while a nested declaration or
// relation alias uses the same reserved result name. Both trust boundaries
// must reject these sources, not merely the ordinary collector constructor.
for(const [name,identifier] of [['plain','precision_resolver_admission'],['quoted','"precision_resolver_admission"'],['commented','/* binding */ precision_resolver_admission /* binding */'],['quoted-commented','/* binding */ "precision_resolver_admission" /* binding */']]){
 for(const placement of ['nested-cte','relation-alias'])test('resolver admission rejects '+placement+' '+name+' binding shadow at both boundaries',()=>{
  const original=successor().sql;
  const changed=placement==='nested-cte'?original.replace('direct_routine AS MATERIALIZED (SELECT','direct_routine AS MATERIALIZED (WITH '+identifier+' AS (SELECT true AS admitted) SELECT'):
   original.replace(' AS fact FROM pg_catalog.pg_proc p JOIN',' AS fact FROM (SELECT true AS admitted) '+identifier+' CROSS JOIN pg_catalog.pg_proc p JOIN');
  assert.notEqual(changed,original);
  refuseAtBothBoundaries(changed);
 });
}

const breakout=') SELECT NULL::jsonb INTO live_rows FROM live;\nRETURN true;\nWITH live AS MATERIALIZED (\n SELECT NULL::text AS kind,NULL::text AS identity,NULL::jsonb AS fact WHERE false';
// Break caught: bytes outside the collector anchors can stay identical while
// an inner fragment closes/reopens the surrounding PL/pgSQL query container.
for(const [name,suffix] of [
 ['exact-breakout',breakout],
 ['commented-breakout',breakout.replace('RETURN true','/* query close */ RETURN /* procedural */ true')],
 ['quoted-breakout',breakout.replace('FROM live','FROM "live"')],
 ['unbalanced-close',')'],['unbalanced-open','('],
 ['statement-separator','; SELECT NULL'],
 ['procedural-without-separator',' RETURN true'],
 ['literal-body-delimiter'," UNION ALL SELECT 'routine','identity',pg_catalog.jsonb_build_object('payload','$catalog$')"],
 ['comment-body-delimiter',' /* $catalog$ */'],
 ['dollar-quoted-body-delimiter',' UNION ALL SELECT $payload$ $catalog$ $payload$'],
 ['unterminated-literal'," UNION ALL SELECT 'unterminated"],
 ['unterminated-comment',' /* unterminated'],
])test('resolver admission rejects '+name+' query/body escape at both boundaries',()=>{
 const changed=successor().sql+suffix;
 refuseAtBothBoundaries(changed);
});

// Positive seam caught: containment hardening must not reject the actual
// combined ordinary/13-transform collector or harmless quoted punctuation.
test('contained direct plus all source transforms retains private8 compilation and formatter admission',()=>{
 const transforms=compileOrderedTransforms([...lowerOrderedTemporalTransforms(contract).recipes,...lowerOrderedPublicFunctionTransforms(contract).recipes],{definitionFrame}).sql;
 const combined='SELECT kind,identity,fact FROM (\n'+successor().sql+'\n) direct_catalog\nUNION ALL\nSELECT kind,identity,fact FROM (\n'+transforms+'\n) transformed_catalog';
 assert.equal(admitFramedTransformSource(resolver.inspectOrderedPrecisionResolverSourceV1(combined)),true);
 assert.equal(privateCompiler.compileOrderedPrecisionPrivateRoutinesV1(inPrivate(combined)).facts.length,8);
 const quoted=successor().sql+" UNION ALL SELECT 'routine','identity',pg_catalog.jsonb_build_object('payload',';) RETURN true; (') /* ;) RETURN true; ( */";
 assert.equal(resolver.admitOrderedPrecisionResolverSourceV1(quoted),true);
 assert.equal(privateCompiler.compileOrderedPrecisionPrivateRoutinesV1(inPrivate(quoted)).facts.length,8);
});

// Break caught: LF-only comment masking disagrees with PostgreSQL at raw CR;
// the successor must refuse the byte rather than leave downstream masks split.
for(const [name,suffix] of [
 ['CR-comment-breakout',' -- comment\r'+breakout.replaceAll('\n',' ')+'\n'],
 ['raw-CR-literal'," UNION ALL SELECT 'routine','identity',pg_catalog.jsonb_build_object('payload','raw\rCR')"],
])test('successor refuses '+name+' at both lexical boundaries',()=>{
 refuseAtBothBoundaries(successor().sql+suffix);
});

// Break caught: PostgreSQL sees dollar-bearing aliases as identifiers, while
// the legacy core mask wrongly hides an unreviewed call between embedded tags.
for(const [name,suffix] of [
 ['unquoted-dollar-aliases'," UNION ALL SELECT 'routine' AS a$tag$, public.unreviewed_function() AS b$tag$, '{}'::jsonb"],
 ['quoted-dollar-identifier'," UNION ALL SELECT 'routine' AS \"a$tag$\",'identity','{}'::jsonb"],
])test('successor refuses '+name+' at both lexical boundaries',()=>{
 refuseAtBothBoundaries(successor().sql+suffix);
});

// Proper dollar strings remain lexical literals, including arbitrary-looking
// call/statement text. Only raw enclosing $catalog$ or identifier use refuses.
test('properly tokenized dollar literals and LF comments preserve contained private8 source',()=>{
 const sql=successor().sql+" UNION ALL SELECT $tag$public.unreviewed_function(); ()$tag$, $$precision_resolver_admission$$,pg_catalog.jsonb_build_object('payload',$text$;) RETURN true; ($text$) -- ordinary LF comment\n";
 assert.equal(resolver.admitOrderedPrecisionResolverSourceV1(sql),true);
 assert.equal(privateCompiler.compileOrderedPrecisionPrivateRoutinesV1(inPrivate(sql)).facts.length,8);
});
