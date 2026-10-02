// Representative catalog mutations are separate from expected-storage tampering.
// Every operand comes from the fixed source-built descriptors/facts, never a DB.
import crypto from 'node:crypto';
import {native379SQLProgram} from './ordered-current-native379-semantics-v1.mjs';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const canonical=x=>JSON.stringify(x,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const literal=x=>"'"+x.replaceAll("'","''")+"'";
const ident=x=>'"'+x.replaceAll('"','""')+'"';
const fail=x=>{throw Error('ordered-current native379 coverage '+x);};
const family=id=>id.includes(':')?id.slice(0,id.lastIndexOf(':')):id;
const schema='zasp_authorization80_ordered_current';
const kinds=['worker_registration','namespace','routine','relation','column','constraint','policy','trigger','saved_function','saved_view','index','runtime_registration','view','rewrite','type','membership','column_name','policy_view','information_column','global_constraint','index_view','fixed_runtime_profile','role','saved_constraint','foreign_key_trigger','class_index','column_all'];
function recipe(rule,facts){
 const negative={
  'private-routines':`CREATE FUNCTION ${schema}.native379_probe() RETURNS text LANGUAGE sql AS 'SELECT NULL::text'`,
  'private-relation':`CREATE TABLE ${schema}.native379_probe(value text)`,
  'private-column':`ALTER TABLE ${schema}.expected ADD COLUMN native379_probe text`,
  'private-constraint':`ALTER TABLE ${schema}.expected ADD CONSTRAINT native379_probe CHECK (true)`,
  'private-index':`CREATE INDEX native379_probe ON ${schema}.expected(kind)`,
  'private-policy':`CREATE POLICY native379_probe ON ${schema}.expected USING(false)`,
  'private-trigger':`CREATE TRIGGER native379_probe BEFORE UPDATE ON ${schema}.expected FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()`,
  'private-view':`CREATE VIEW ${schema}.native379_probe AS SELECT 1 AS value`,
  'private-rewrite':`CREATE VIEW ${schema}.native379_probe AS SELECT 1 AS value`,
  'private-type':`CREATE TYPE ${schema}.native379_probe AS ENUM('probe')`,
  'native-memberships':'GRANT zasp_temporal_accounting TO zasp_security_agent_worker',
 };
 if(negative[rule.id])return {sql:negative[rule.id],fact:null,objects:{schemas:[schema]},operands:{ruleId:rule.id,kind:rule.kind,namespace:rule.id==='native-memberships'?'zasp_temporal_accounting':schema,object:rule.id==='native-memberships'?{granted:'zasp_temporal_accounting',member:'zasp_security_agent_worker',admin:false}:{name:'native379_probe',relation:schema+'.expected'},expectedKeyDelta:'add'},alternative:{reason:rule.expectedFacts===0?'approved descriptor has an empty live key universe; add an exactly selected catalog object':'add an exactly selected catalog object without corrupting evaluator dependencies',descriptorSHA256:rule.declarationSHA256,originalExpectedFacts:rule.expectedFacts,selector:rule.id==='native-memberships'?"granted.rolname='zasp_temporal_accounting' OR member.rolname IN(nativeRoles)":`namespace=${literal(schema)}`,effect:rule.kind==='rewrite'?'CREATE VIEW creates its _RETURN pg_rewrite row':rule.kind==='type'?'CREATE TYPE creates enum and array pg_type rows':'new selected key is absent from approved expected facts'}};
 const fact=facts[0];if(!fact)return null;
 const raw=JSON.parse(fact.identity)[1],target=raw.startsWith('[')?JSON.parse(raw):raw,f=fact.fact,k=rule.kind;
 let sql,field,before,after,objects={},operands={ruleId:rule.id,kind:k,identity:fact.identity,target};
 if(k==='namespace'){field=Object.hasOwn(f,'acl')?'acl':'acl_text_or_empty';sql=`GRANT CREATE ON SCHEMA ${target} TO PUBLIC`;objects={schemas:[target]};after='PUBLIC CREATE privilege present';}
 else if(k==='routine'){field=Object.hasOwn(f,'owner')?'owner':'inventory_owner';sql=`ALTER FUNCTION ${target} OWNER TO zasp_security_agent_worker`;objects={routines:[target]};after='zasp_security_agent_worker';}
 else if(k==='view'&&!Object.hasOwn(f,'owner')){field='definition';after=`SELECT * FROM (${f.definition.trim().replace(/;$/,'')}) AS native379_original WHERE false`;sql=`CREATE OR REPLACE VIEW ${target} AS ${after}`;objects={schemas:[target.split('.')[0]]};}
 else if(k==='relation'||k==='view'){field='owner';sql=`ALTER ${k==='view'?'VIEW':'TABLE'} ${target} OWNER TO zasp_security_agent_worker`;objects={schemas:[target.split('.')[0]]};after='zasp_security_agent_worker';}
 else if(['worker_registration','runtime_registration','fixed_runtime_profile'].includes(k)){
  const relation=target[0];field=k==='fixed_runtime_profile'?'name':'fingerprint';after=k==='fixed_runtime_profile'?(f.name==='canonical61-temporal78-authorization79-80-v1'?'canonical61-authorization79-80-v1':'canonical61-temporal78-authorization79-80-v1'):'0'.repeat(64);sql=`ALTER TABLE ${relation} DISABLE TRIGGER USER; UPDATE ${relation} SET ${field}=${literal(after)} WHERE singleton=true`;objects={relations:[relation]};operands={...operands,relation,key:{singleton:true}};
 }
 else if(['saved_function','saved_view','saved_constraint'].includes(k)){
  const relation=k==='saved_function'?target[0]+'.predecessor_functions':target[0],key=target[1],column='signature';field='definition';after=f.definition+'\n-- native379-source-drift';sql=`ALTER TABLE ${relation} DISABLE TRIGGER USER; UPDATE ${relation} SET definition=${literal(after)} WHERE ${column}=${literal(key)}`;objects={relations:[relation]};operands={...operands,relation,key:{[column]:key}};
 }
 else if(k==='constraint'||k==='global_constraint'){const [relation,name]=target;field='key';sql=`ALTER TABLE ${relation} RENAME CONSTRAINT ${ident(name)} TO native379_probe`;objects={schemas:[relation.split('.')[0]]};after='native379_probe';}
 else if(k==='policy'||k==='policy_view'){const relation=k==='policy'?target[0]:target[0]+'.'+target[1],name=k==='policy'?target[1]:target[2];field='key';sql=`ALTER POLICY ${ident(name)} ON ${relation} RENAME TO native379_probe`;objects={schemas:[relation.split('.')[0]]};after='native379_probe';}
 else if(k==='trigger'){const [relation,name]=target;field='enabled';after=f.enabled==='D'?'O':'D';sql=`ALTER TABLE ${relation} ${after==='D'?'DISABLE':'ENABLE'} TRIGGER ${ident(name)}`;objects={schemas:[relation.split('.')[0]]};}
 else if(k==='foreign_key_trigger'){field='enabled';after='D';sql=`ALTER TABLE ${f.trigger_relation} DISABLE TRIGGER ALL`;objects={schemas:[f.trigger_relation.split('.')[0]]};operands={...operands,relation:f.relation,triggerRelation:f.trigger_relation,constraint:f.name,function:f.function,eventBits:f.event_bits};}
 else if(['index','class_index','index_view'].includes(k)){field='key';const name=k==='index_view'?target[0]+'.'+target[2]:target;sql=`ALTER INDEX ${name} RENAME TO native379_probe`;objects={schemas:[name.split('.')[0]]};after='native379_probe';}
 else if(k==='role'){field='login';after=!f.login;sql=`ALTER ROLE ${ident(target)} ${after?'LOGIN':'NOLOGIN'}`;objects={schemas:[]};}
 else if(['column','column_name','column_all','information_column'].includes(k)){
  const relation=k==='information_column'?target[0]+'.'+target[1]:target[0],name=f.name??(k==='column_name'?target[1]:null);if(!name)fail('column operand '+rule.id);field='key';after='native379_probe';sql=`ALTER TABLE ${relation} RENAME COLUMN ${ident(name)} TO native379_probe`;objects={schemas:[relation.split('.')[0]]};operands={...operands,relation,column:name};
 }else return null;
 before=field==='key'?target:f[field];
 if(before===undefined)fail('field not admitted '+rule.id+':'+field);
 if(before===after)fail('mutation is no-op '+rule.id);
 return {sql,fact,objects,operands:{...operands,field,before,after}};
}
export function buildNative379CatalogCoverage({rules,byRule,sourceForRule,entry}){
 const families=[...new Set(rules.map(r=>family(r.id)))],actualKinds=[...new Set(rules.map(r=>r.kind))];
 if(actualKinds.length!==kinds.length||kinds.some(k=>!actualKinds.includes(k)))fail('unknown/missing structural kind');
 const controls=[],created=new Map();
 const probe=`SELECT CASE WHEN (${entry.independentAdmission.sql}) THEN ${schema}.catalog(${entry.manifestLiteral}) ELSE false END AS value`;
 function make(candidates){
  // Prefer a positive exact fact for a family; all-zero families use the fixed
  // negative-universe recipe. Kind coverage is generated independently below.
  let selected;
  for(const rule of candidates){const r=recipe(rule,byRule.get(rule.id));if(r){selected={rule,r};break;}}
  if(!selected)fail('no executable mutation for '+candidates.map(r=>r.id).join(','));
  const {rule,r}=selected;if(created.has(rule.id))return created.get(rule.id);
  const id='coverage:'+rule.id,mutation={operation:'execute-fixed-catalog-sql',...r,sqlSHA256:sha(r.sql)};delete mutation.fact;delete mutation.objects;
  const control={id,controlClass:'evaluator-rule',phase:'drift',category:'catalog-coverage',ruleIds:[rule.id],facts:r.fact?[{kind:r.fact.kind,identity:r.fact.identity,factSHA256:sha(canonical(r.fact.fact))}]:[],sourceSite:sourceForRule(rule),ruleDeclarationSHA256:rule.declarationSHA256,mutation,mutationSHA256:sha(canonical(mutation)),expected:{outcome:'refuse',rows:[{value:false}],sqlState:null,firstError:null,boundary:'independently-admitted-complete-catalog-equality'}};
	  const prefix='['+JSON.stringify(rule.id)+',';
	  const exact=r.fact?`SELECT EXISTS(SELECT 1 FROM ${schema}.expected WHERE kind=${literal(r.fact.kind)} AND identity=${literal(r.fact.identity)} AND fact=${literal(canonical(r.fact.fact))}::jsonb) AS value`:`SELECT NOT EXISTS(SELECT 1 FROM ${schema}.expected WHERE kind=${literal(rule.kind)} AND left(identity,${prefix.length})=${literal(prefix)}) AS value`;
	  control.mutation.operands={...control.mutation.operands,obligationAssertion:{ruleId:rule.id,kind:rule.kind,sql:exact,sqlSHA256:sha(exact)}};control.mutationSHA256=sha(canonical(control.mutation));
	  controls.push(native379SQLProgram(control,{setup:r.sql,probe,expected:{outcome:'rows',rows:[{value:false}],sqlState:null},objects:r.objects,searchPath:'pg_catalog',preconditions:[exact]}));created.set(rule.id,id);return id;
 }
 const coverage={format:'native379-family-kind-coverage-v1',definition:'family is the prefix before the final colon; a colon-free rule id is its own family',ruleCount:379,families:families.map(id=>{const rows=rules.filter(r=>family(r.id)===id);return {id,ruleIds:rows.map(r=>r.id),controlIds:[make(rows)]};}),kinds:kinds.map(id=>{const rows=rules.filter(r=>r.kind===id);return {id,ruleIds:rows.map(r=>r.id),controlIds:[make(rows)]};})};
 assertNative379CatalogCoverage(coverage,controls,rules);
 return {coverage,controls};
}
export function assertNative379CatalogCoverage(coverage,controls,rules){
 const group=(which,key)=>{
  const expected=new Map();for(const rule of rules){const id=key(rule);if(!expected.has(id))expected.set(id,[]);expected.get(id).push(rule.id);}
  if(coverage[which].length!==expected.size||new Set(coverage[which].map(x=>x.id)).size!==expected.size)fail('missing/extra/duplicate '+which);
  for(const row of coverage[which]){
   if(canonical(row.ruleIds)!==canonical(expected.get(row.id))||!row.controlIds.length||new Set(row.controlIds).size!==row.controlIds.length)fail('wrong rule membership '+row.id);
   for(const id of row.controlIds){const c=controls.find(c=>c.id===id);if(!c||c.phase!=='drift'||c.category!=='catalog-coverage'||!c.ruleIds.some(id=>row.ruleIds.includes(id))||!c.program.steps.some(s=>s.id==='mutate'&&s.sql===c.mutation.sql)||!Object.keys(c.mutation.operands).length)fail('non-executable coverage '+id);}
  }
 };
 if(rules.length!==379||new Set(rules.map(r=>r.id)).size!==379)fail('rule universe');group('families',r=>family(r.id));group('kinds',r=>r.kind);
}
