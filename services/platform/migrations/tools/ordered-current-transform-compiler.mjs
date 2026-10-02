// Closed build-time AST. No runtime caller can supply SQL or choose operators.
import {canonicalOrderedJSON,admitCollectorSource,normalizeOrderedFacts} from './build-ordered-current-integrity.mjs';
import {compileOrderedCollector} from './ordered-current-catalog.mjs';
import crypto from 'node:crypto';
import {definitionFrame,definitionAdapter,identityArgumentsAdapter,identityAdapter,frameVersion,definitionAdmissionSQL,admitFramedTransformSource} from './ordered-current-deparse-frame.mjs';
const framedLeaves=Object.freeze({definition:definitionAdapter,identity_arguments:identityArgumentsAdapter,identity:identityAdapter});
const fieldTypes={identity:'string',name:'string',identity_arguments:'string',owner:'string',acl:'string',definition:'string',namespace_name:'string',volatility:'string',parallel:'string',config_text_or_empty:'string',security_definer:'boolean',strict:'boolean',leakproof:'boolean'};
const fields=new Set(Object.keys(fieldTypes));
// These four source branches predate their :function recipe suffix. This is a
// closed join between reviewed capture and recipe identities, not normalization.
const publicRawIds={
  'public:sa_attack_lab:function':'raw-transform:public:sa_attack_lab',
  'public:sa_export:function':'raw-transform:public:sa_export',
  'public:sa_multistep:function':'raw-transform:public:sa_multistep',
  'public:sa_webhook:function':'raw-transform:public:sa_webhook',
};
const rawId=id=>Object.hasOwn(publicRawIds,id)?publicRawIds[id]:'raw-transform:'+id;
const schemas=new Set(['zasp_temporal74','zasp_temporal77','zasp_temporal78','zasp_authorization80_worker']);
const keys=value=>Object.keys(value).sort().join(',');
const text=value=>{if(typeof value!=='string')throw Error('transform text required');canonicalOrderedJSON(value);return value;};
const signature=value=>{text(value);if(!/^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*\([a-z0-9_, [\]]*\)$/.test(value))throw Error('transform qualified signature required');};
const quote=value=>"'"+text(value).replaceAll("'","''")+"'";
export function validateOrderedWorkerSourceRecipeContractV1(rows,{count,prefix}){
  if(arguments.length!==2||!Array.isArray(rows)||!Number.isSafeInteger(count)||typeof prefix!=='string')throw Error('worker source recipe contract inputs');
  if(rows.length!==count)throw Error('worker source recipe contract count');
  const ids=new Set();
  for(const row of rows){
    if(!row||typeof row.ruleId!=='string'||!row.ruleId.startsWith(prefix)||ids.has(row.ruleId)||typeof row.sourceIdentity!=='string'||!row.sourceIdentity||!/^([a-f0-9]{64})$/.test(row.siteSHA256)||!Array.isArray(row.projections)||!row.projections.length||!row.frame||!Array.isArray(row.frame.config)||Object.hasOwn(row,'expectedFacts')||Object.hasOwn(row,'expectedRows'))throw Error('worker source recipe contract row');
    ids.add(row.ruleId);
  }
}
function validate(ast,callback=()=>{}){
  let nodes=0;
  const compatible=types=>{const present=[...new Set(types.filter(type=>type!=='null'))];if(present.length>1)throw Error('transform type mismatch');return present[0]??'null';};
  const visit=(node,depth=0)=>{
    if(++nodes>512||depth>48||!node||Object.getPrototypeOf(node)!==Object.prototype)throw Error('invalid transform AST');
    const shape=keys(node);
    let type='string';
    switch(node.op){
      case 'field':if(shape!=='field,op'||!fields.has(node.field))throw Error('unknown transform field');type=fieldTypes[node.field];break;
      case 'literal':if(shape!=='op,value'||node.value!==null&&typeof node.value!=='string')throw Error('invalid transform literal');if(node.value!==null)text(node.value);else type='null';break;
      case 'replace':if(shape!=='from,input,op,to')throw Error('invalid replace AST');text(node.from);text(node.to);compatible(['string',visit(node.input,depth+1)]);break;
      case 'coalesce':if(shape!=='args,op'||!Array.isArray(node.args)||node.args.length<2)throw Error('invalid coalesce AST');type=compatible(node.args.map(n=>visit(n,depth+1)));break;
      case 'identity-case':{
        if(shape!=='cases,else,op'||!Array.isArray(node.cases)||!node.cases.length)throw Error('invalid identity CASE');
        const seen=new Set(),types=[];for(const arm of node.cases){if(!arm||keys(arm)!=='identity,then')throw Error('invalid CASE arm');signature(arm.identity);if(seen.has(arm.identity))throw Error('duplicate CASE identity');seen.add(arm.identity);types.push(visit(arm.then,depth+1));}types.push(visit(node.else,depth+1));type=compatible(types);break;
      }
      case 'saved-scalar':if(shape!=='field,op,schema,signature'||!schemas.has(node.schema)||!['definition','acl'].includes(node.field))throw Error('unapproved saved scalar');signature(node.signature);break;
      default:throw Error('unknown transform op');
    }
    callback(node);
    return type;
  };return visit(ast);
}
export function compileOrderedTransformAST(ast,framed=false){
  validate(ast);
  const emit=(node,expectedType='string')=>{
    const inferred=validate(node),resultType=inferred==='null'?expectedType:inferred;
    switch(node.op){
      case 'field':return framed&&Object.hasOwn(framedLeaves,node.field)?"(CASE WHEN true=(SELECT admitted FROM definition_frame_admission) THEN "+framedLeaves[node.field]+"((fact->>'routine_oid')::pg_catalog.oid) ELSE NULL::text END)":node.field==='identity'?'object_identity':"(fact->>"+quote(node.field)+')'+(fieldTypes[node.field]==='boolean'?'::boolean':'');
      case 'literal':return node.value===null?'NULL::'+(expectedType==='boolean'?'boolean':'text'):quote(node.value)+'::text';
      case 'replace':return 'pg_catalog.replace('+emit(node.input)+','+quote(node.from)+','+quote(node.to)+')';
      case 'coalesce':return 'COALESCE('+node.args.map(arg=>emit(arg,resultType)).join(',')+')';
      case 'identity-case':return '(CASE '+node.cases.map(arm=>'WHEN object_identity::regprocedure='+quote(arm.identity)+'::regprocedure THEN '+emit(arm.then,resultType)).join(' ')+' ELSE '+emit(node.else,resultType)+' END)';
      case 'saved-scalar':return '(SELECT '+node.field+'::text FROM '+node.schema+'.predecessor_functions WHERE signature='+quote(node.signature)+')';
    }
  };return emit(ast);
}
function bindTransform(ast,environment){
  // Bind every syntactic relation/column/reg-object before conditional scalar
  // demand. Only row cardinality evaluation itself follows the selected arm.
  validate(ast,node=>{
    if(node.op==='identity-case')for(const arm of node.cases)if(!environment?.identities?.has(arm.identity))throw Error('original regprocedure binding');
    if(node.op==='saved-scalar'){
      const table=environment?.savedTables?.[node.schema];
      if(!table||!Array.isArray(table.rows)||!Array.isArray(table.columns)||!table.columns.includes('signature')||!table.columns.includes(node.field))throw Error('saved relation/column binding');
    }
  });
}
export function evaluateOrderedTransform(ast,row,environment){
  bindTransform(ast,environment);
  validate(ast,node=>{if(node.op==='field'&&(!Object.hasOwn(row,node.field)||row[node.field]!==null&&typeof row[node.field]!==fieldTypes[node.field]))throw Error('transform input field binding/type');});
  const evaluate=node=>{
    switch(node.op){
      case 'field':return row[node.field];
      case 'literal':return node.value;
      case 'replace':{const value=evaluate(node.input);return value===null?null:node.from===''?value:value.replaceAll(node.from,()=>node.to);}
      case 'coalesce':{for(const arg of node.args){const value=evaluate(arg);if(value!==null)return value;}return null;}
      case 'identity-case':{const arm=node.cases.find(arm=>row.identity===arm.identity);return evaluate(arm?arm.then:node.else);}
      case 'saved-scalar':{
        const selected=environment.savedTables[node.schema].rows.filter(r=>r.signature===node.signature);
        if(selected.length>1)throw Error('original scalar has multiple rows');
        if(!selected.length)return null;
        const value=selected[0][node.field];if(value!==null&&typeof value!=='string')throw Error('invalid saved scalar text');return value;
      }
    }
  };return evaluate(ast);
}
function validateRecipe(recipe,callback=()=>{}){
  if(!recipe||recipe.kind!=='routine'||typeof recipe.ruleId!=='string'||!recipe.ruleId||!recipe.fields||Object.getPrototypeOf(recipe.fields)!==Object.prototype||!Object.keys(recipe.fields).length||Object.keys(recipe.fields).some(field=>!fields.has(field)))throw Error('invalid transform recipe fields');
  for(const [field,ast] of Object.entries(recipe.fields)){
    const type=validate(ast,callback);
    if(type!=='null'&&type!==fieldTypes[field])throw Error('transform output field type');
  }
}
export function compileOrderedTransforms(recipes,options){
  const framed=options!==undefined;
  if(framed&&(!options||keys(options)!=='definitionFrame'||options.definitionFrame!==definitionFrame))throw Error('unsupported definition frame');
  if(!Array.isArray(recipes)||!recipes.length)throw Error('empty transform recipes');
  const ids=new Set(),rawRules=[];
  for(const recipe of recipes){
    const required=new Set();validateRecipe(recipe,node=>{if(node.op==='field'){if(framed&&Object.hasOwn(framedLeaves,node.field))required.add('routine_oid');else if(node.field!=='identity')required.add(node.field);}});
    if(ids.has(recipe.ruleId))throw Error('duplicate transform recipe');ids.add(recipe.ruleId);
    if(!required.size)throw Error('missing source projections');
    rawRules.push({id:(framed?'raw-framed-v2:':'')+rawId(recipe.ruleId),kind:'routine',namespaces:[],identities:[],fields:[...required],selector:structuredClone(recipe.selector)});
  }
  const raw=compileOrderedCollector(rawRules);
  const projections=recipes.map(recipe=>"SELECT 'routine'::text AS kind, '['||pg_catalog.to_json("+quote(recipe.ruleId)+"::text)::text||','||pg_catalog.to_json(object_identity)::text||']' AS identity, pg_catalog.jsonb_build_object("+Object.keys(recipe.fields).sort().flatMap(field=>[quote(field),compileOrderedTransformAST(recipe.fields[field],framed)]).join(',')+") AS fact FROM transform_inputs WHERE rule_id="+quote((framed?'raw-framed-v2:':'')+rawId(recipe.ruleId))+(framed?' AND (SELECT admitted FROM definition_frame_admission)':''));
  const sql="WITH "+(framed?'definition_frame_admission AS MATERIALIZED ('+definitionAdmissionSQL+'),\n':'')+"transform_inputs AS MATERIALIZED (SELECT identity::jsonb->>0 AS rule_id, identity::jsonb->>1 AS object_identity, fact FROM (\n"+raw.sql+'\n) transform_raw)\n'+projections.join('\nUNION ALL\n');
  if(framed)admitFramedTransformSource(sql);else admitCollectorSource(sql);
  return {sql,recipes:recipes.length,rawRules,...(framed?{definitionFrame,frameVersion,admissionSQL:definitionAdmissionSQL}:{}),sourceSHA256:crypto.createHash('sha256').update(sql).digest('hex')};
}
export function projectOrderedTransforms(recipes,rawFacts,environment,options){
  // The prior references were collected under pg_catalog. No formatter can
  // turn them into an independently observed original-frame definition.
  if(options!==undefined)throw Error('framed reference requires independently accepted original-frame observations');
  const input=normalizeOrderedFacts(rawFacts),output=[],ids=new Set();
  for(const recipe of recipes){
    validateRecipe(recipe);
    if(ids.has(recipe.ruleId))throw Error('duplicate transform recipe');ids.add(recipe.ruleId);
    for(const ast of Object.values(recipe.fields))bindTransform(ast,environment);
    for(const raw of input){
      if(raw.kind!=='routine')continue;
      const key=JSON.parse(raw.identity);
      if(!Array.isArray(key)||key.length!==2||key.some(v=>typeof v!=='string')||canonicalOrderedJSON(key)!==raw.identity)throw Error('invalid raw transform key');
      if(key[0]!==rawId(recipe.ruleId))continue;
      const row={...raw.fact,identity:key[1]};
      const fact=Object.fromEntries(Object.entries(recipe.fields).map(([field,ast])=>[field,evaluateOrderedTransform(ast,row,environment)]));
      output.push({kind:'routine',identity:canonicalOrderedJSON([recipe.ruleId,key[1]]),fact});
    }
  }
  return normalizeOrderedFacts(output);
}
