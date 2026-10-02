// Offline projection of the thirteen accepted original-frame transform inputs.
// Capture has already evaluated original CASE and saved-scalar branches. This
// component proves and applies only the source-pinned outer replacements.
import crypto from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {admitOrderedCurrentReferenceIntakeV2} from './ordered-current-reference-intake-v2.mjs';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {formatOrderedProconfigText,lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';

const fail=message=>{throw Error(`ordered-current transform reference ${message}`);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const same=isDeepStrictEqual;
const plain=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const inputFields=['aPacketRoot','aRaw','bPacketRoot','bRaw','compiledReleaseRaw','coverageRaw','sourceContractRaw'];
const counts={
 'temporal:70.fingerprint:function':91,
 'temporal:71.fingerprint:function':47,
 'temporal:74.outbox65_fingerprint:function':6,
 'temporal:74.owner66_fingerprint:function':10,
 'temporal:75.fingerprint:function':15,
 'temporal:77.domain67_fingerprint:function':9,
 'temporal:78.predecessor73_fingerprint:function':10,
 'temporal:78.predecessor76_fingerprint:function':12,
 'temporal:78.predecessor76_fingerprint:executor-function':4,
 'public:sa_attack_lab:function':46,
 'public:sa_export:function':79,
 'public:sa_multistep:function':7,
 'public:sa_webhook:function':44,
};
const ruleIds=Object.keys(counts);
const booleans=new Set(['security_definer','strict','leakproof']);
const witnesses=['config_json','config_raw','config_dims','config_ndims','config_bounds'];
const witnessTypes={config_json:'json?',config_raw:'text?',config_dims:'text?',config_ndims:'integer?',config_bounds:'json?'};
const witnessProjections=['to_jsonb(p.proconfig)','p.proconfig::text','array_dims(p.proconfig)','array_ndims(p.proconfig)','(SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)'];
const sourceLeaves={identity:'p.oid::regprocedure::text',namespace_name:'n.nspname',name:'p.proname',identity_arguments:'pg_get_function_identity_arguments(p.oid)',owner:'p.proowner::regrole::text',acl:'p.proacl::text',definition:'pg_get_functiondef(p.oid)',security_definer:'p.prosecdef',volatility:'p.provolatile',parallel:'p.proparallel',strict:'p.proisstrict',leakproof:'p.proleakproof',config_text_or_empty:"COALESCE(p.proconfig::text,'')"};

function parse(raw,label){try{return JSON.parse(raw);}catch{fail(`${label} JSON`);}}
function exactObject(value,fields){return plain(value)&&same(Object.keys(value).sort(),fields.slice().sort());}
function quote(value){return "'"+value.replaceAll("'","''")+"'";}
function one(values,label){if(values.length!==1)fail(`${label} (${values.length})`);return values[0];}
function frame(node){return Object.fromEntries(['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'].map(key=>[key,node[key]]));}

// Bounded scanners shared in shape with capture closure. They recognize only
// the pinned concat_ws projection and complete replace(input,literal,literal).
function projections(text){
 const at=text.indexOf('concat_ws(');if(at<0)fail('source concat_ws boundary');let depth=1,quoted=false,begin=at+10;const parts=[];
 for(let index=begin;index<text.length;index++){
  const character=text[index];
  if(character==="'"){if(quoted&&text[index+1]==="'"){index++;continue;}quoted=!quoted;continue;}
  if(quoted)continue;if(character==='(')depth++;else if(character===')'&&--depth===0){parts.push(text.slice(begin,index).trim());return {fields:parts.slice(2),from:text.slice(index+1).trim()};}else if(character===','&&depth===1){parts.push(text.slice(begin,index).trim());begin=index+1;}
 }
 fail('source projection boundary');
}
function replaceArguments(expression){
 if(!expression.startsWith('replace(')||!expression.endsWith(')'))return null;
 const begin=8,parts=[];let depth=0,quoted=false,start=begin;
 for(let index=begin;index<expression.length-1;index++){
  const character=expression[index];
  if(character==="'"){if(quoted&&expression[index+1]==="'"){index++;continue;}quoted=!quoted;continue;}
  if(quoted)continue;if(character==='(')depth++;else if(character===')'){if(depth===0)fail('replacement close boundary');depth--;}else if(character===','&&depth===0){parts.push(expression.slice(start,index).trim());start=index+1;}
 }
 if(quoted||depth!==0)fail('replacement source boundary');parts.push(expression.slice(start,-1).trim());if(parts.length!==3)fail('replacement arity');return parts;
}
function literal(expression){const match=expression.match(/^'((?:[^']|'')*)'$/);if(!match)fail('replacement literal');return match[1].replaceAll("''", "'");}
function sourceResidual(expression){const outer=[];let input=expression,args;while((args=replaceArguments(input))!==null){outer.push({from:literal(args[1]),to:literal(args[2])});input=args[0];}return {terminal:input,replacements:outer.reverse()};}
function recipeResidual(ast){const outer=[];let terminal=ast;while(terminal?.op==='replace'){if(!exactObject(terminal,['op','input','from','to'])||typeof terminal.from!=='string'||typeof terminal.to!=='string')fail('recipe replacement AST');outer.push({from:terminal.from,to:terminal.to});terminal=terminal.input;}return {terminal,replacements:outer.reverse()};}

function sourceExpression(ast,nested=false){
 if(!plain(ast)||typeof ast.op!=='string')fail('recipe terminal AST');
 if(ast.op==='field'){if(!exactObject(ast,['op','field'])||!Object.hasOwn(sourceLeaves,ast.field))fail('recipe field terminal');return sourceLeaves[ast.field];}
 if(ast.op==='literal'){if(!exactObject(ast,['op','value'])||typeof ast.value!=='string')fail('recipe literal terminal');return quote(ast.value);}
 if(ast.op==='coalesce'){if(!exactObject(ast,['op','args'])||!Array.isArray(ast.args)||ast.args.length<2)fail('recipe coalesce terminal');return 'COALESCE('+ast.args.map(item=>sourceExpression(item,nested)).join(',')+')';}
 if(ast.op==='identity-case'){
  if(!exactObject(ast,['op','cases','else'])||!Array.isArray(ast.cases)||!ast.cases.length)fail('recipe identity CASE terminal');
  const saved=ast.cases.map(item=>{if(!exactObject(item,['identity','then'])||typeof item.identity!=='string'||!plain(item.then)||item.then.op!=='saved-scalar'||!exactObject(item.then,['op','schema','signature','field'])||item.then.signature!==item.identity)return fail('recipe saved CASE arm');return item.then;});
  const first=saved[0];if(saved.some(item=>item.schema!==first.schema||item.field!==first.field))fail('recipe saved CASE grouping');
  const identities=ast.cases.map(item=>item.identity),condition=identities.length===1?`p.oid=${quote(identities[0])}::regprocedure`:`p.oid IN(${identities.map(identity=>quote(identity)+'::regprocedure').join(',')})`,signature=identities.length===1?quote(identities[0]):'p.oid::regprocedure::text';
  return `CASE WHEN ${condition} THEN${nested?'':' '}(SELECT ${first.field} FROM ${first.schema}.predecessor_functions WHERE signature=${signature}) ELSE ${sourceExpression(ast.else,true)} END`;
 }
 fail(`unsupported captured terminal ${ast.op}`);
}

function outputFieldTypes(recipe){return Object.fromEntries(Object.keys(recipe.fields).map(field=>[field,booleans.has(field)?'boolean':'text?']));}
function expectedSourceSite(site,node){return {sourceIdentity:site.identity,sourceSHA256:site.sourceSHA256,definitionSHA256:site.definitionSHA256,siteSHA256:site.sha256,start:site.start,end:site.end,frame:frame(node)};}
function exactFramePlan(coverage){
 const expected={role:'zasp_discovery_authority',searchPath:'pg_catalog, public',timeZone:'UTC',derivation:'source-proof',sourceFrameProofSHA256:'6c09fd7b1981d3a0e74cadb7a324b29cb3d4a5a5c3fee4b61a6e90ef6c0c8124'};
 if(coverage.sourceFrameVersion!==2||!same(coverage.framePlan?.executionFrames?.sourceDiscoveryPublic,expected))fail('source frame plan');for(const id of ruleIds)if(coverage.framePlan?.ruleFrames?.[id]!=='sourceDiscoveryPublic')fail(`${id} source frame binding`);return expected;
}
function validatePublicHelper(recipe,siteExpression,capturedExpression,callerSelector,coverage,contract){
 const family=recipe.ruleId.match(/^public:([a-z_]+):function$/)?.[1];if(!family)fail(`${recipe.ruleId} public family`);
 const helperIdentity=`public.zasp_${family}_function_identity(oid)`;
 if(siteExpression!==`public.zasp_${family}_function_identity(p.oid)`||capturedExpression!==sourceLeaves.definition)fail(`${recipe.ruleId} helper call terminal`);
 const algebra=one(coverage.runtimeAlgebra.filter(item=>item.ruleId===`public:${family}:pure-helper-algebra`),`${recipe.ruleId} helper algebra`),node=one(contract.nodes.filter(item=>item.identity===helperIdentity),`${recipe.ruleId} helper source`),expected={sourceIdentity:node.identity,sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,siteSHA256:node.sourceSHA256,start:0,end:Buffer.byteLength(node.source),frame:frame(node)};
 for(const [field,value] of Object.entries(expected))if(!same(algebra[field],value))fail(`${recipe.ruleId} helper ${field}`);
 if(sha(node.source)!==node.sourceSHA256||sha(node.definition)!==node.definitionSHA256||algebra.sourceExpression!==node.source||algebra.callerSelector!==callerSelector||algebra.disposition!=='selected-helper-source-algebra'||!same(algebra.children,[{ruleId:recipe.ruleId,field:'definition'}])||!same(algebra.sourceChildren,[]))fail(`${recipe.ruleId} helper provenance`);
 const source=sourceResidual(node.source.trim().replace(/^SELECT\s+/,'')),ast=recipeResidual(recipe.fields.definition);
 if(source.terminal!=='pg_get_functiondef(value)'||sourceExpression(ast.terminal)!==capturedExpression||!same(source.replacements,ast.replacements))fail(`${recipe.ruleId} helper residual correspondence`);
 return {replacements:ast.replacements,helper:{sourceIdentity:node.identity,sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,siteSHA256:node.sourceSHA256}};
}

function validateSources(contract,coverage){
 const temporal=lowerOrderedTemporalTransforms(contract),pub=lowerOrderedPublicFunctionTransforms(contract),recipes=[...temporal.recipes,...pub.recipes];
 if(recipes.length!==13||!same(recipes.map(item=>item.ruleId),ruleIds))fail('recipe coverage or order');
 const sites=[...temporal.sites,...pub.sites],nodes=new Map(contract.nodes.map(node=>[node.identity,node])),framePlan=exactFramePlan(coverage),rules=[];
 for(const recipe of recipes){
  const captured=one(coverage.rawRules.filter(item=>item.id===recipe.ruleId),`${recipe.ruleId} coverage rule`),site=one(sites.filter(item=>item.sha256===recipe.siteSHA256),`${recipe.ruleId} recipe site`),node=nodes.get(site.identity);
  if(!node||captured.kind!=='routine'||captured.executionFrameId!=='sourceDiscoveryPublic'||captured.sourceSite===undefined)fail(`${recipe.ruleId} coverage boundary`);
  const sourceSite=expectedSourceSite(site,node);if(!same(captured.sourceSite,sourceSite))fail(`${recipe.ruleId} source site`);
  const recipeFields=Object.keys(recipe.fields),extra=recipe.ruleId.startsWith('public:')?witnesses:[],expectedFields=[...recipeFields,...extra];
  if(!same(captured.fields,expectedFields)||!same(Object.keys(captured.fieldTypes),expectedFields))fail(`${recipe.ruleId} captured fields`);for(const field of recipeFields)if(captured.fieldTypes[field]!== (booleans.has(field)?'boolean':'text?'))fail(`${recipe.ruleId} captured type ${field}`);for(const field of extra)if(captured.fieldTypes[field]!==witnessTypes[field])fail(`${recipe.ruleId} witness type ${field}`);
  const parsed=projections(site.text),selected=parsed.fields;if(captured.from!==parsed.from||selected.length!==recipeFields.length||captured.projections.length!==expectedFields.length)fail(`${recipe.ruleId} projection count or selector`);let residual;
  for(let index=0;index<recipeFields.length;index++){
   const field=recipeFields[index],ast=recipeResidual(recipe.fields[field]),source=sourceResidual(selected[index]),capturedExpression=captured.projections[index];
   if(field==='definition'&&recipe.ruleId.startsWith('public:')){residual=validatePublicHelper(recipe,selected[index],capturedExpression,captured.from,coverage,contract);continue;}
   if(source.terminal!==capturedExpression)fail(`${recipe.ruleId} ${field} source terminal correspondence`);
   if(sourceExpression(ast.terminal)!==capturedExpression)fail(`${recipe.ruleId} ${field} AST terminal correspondence`);
   if(!same(source.replacements,ast.replacements))fail(`${recipe.ruleId} ${field} replacement correspondence`);
   if(field==='definition')residual={replacements:ast.replacements,helper:null};else if(ast.replacements.length)fail(`${recipe.ruleId} unexpected non-definition residual`);
  }
  if(!residual)fail(`${recipe.ruleId} definition residual`);if(extra.length&&!same(captured.projections.slice(recipeFields.length),witnessProjections))fail(`${recipe.ruleId} config witness projections`);
  const residualProof={terminalDisposition:'already-evaluated-original-source-expression',savedRowsRead:0,replacements:residual.replacements,...(residual.helper?{helper:residual.helper}:{})};
  rules.push({id:recipe.ruleId,kind:'routine',fields:recipeFields,fieldTypes:outputFieldTypes(recipe),sourceSite,executionFrameId:'sourceDiscoveryPublic',captureFields:expectedFields,residual:residualProof,expectedRows:counts[recipe.ruleId],frame:framePlan});
 }
 return rules;
}

function validateConfig(fact,ruleId){
 const text=fact.config_text_or_empty,raw=fact.config_raw,json=fact.config_json,dims=fact.config_dims,ndims=fact.config_ndims,bounds=fact.config_bounds;
 if(typeof text!=='string'||text!==(raw??''))fail(`${ruleId} config raw text`);
 if(json===null){if(raw!==null||dims!==null||ndims!==null||bounds!==null)fail(`${ruleId} null config witness`);return;}
 if(!Array.isArray(json)||json.some(item=>item!==null&&typeof item!=='string'))fail(`${ruleId} config JSON type`);
 if(json.length===0){if(raw!=='{}'||dims!==null||ndims!==null||bounds!==null||formatOrderedProconfigText(json,{dimensions:null,lowerBound:null,upperBound:null})!==raw)fail(`${ruleId} empty config witness`);return;}
 if(ndims!==1||dims!==`[1:${json.length}]`||!same(bounds,[[1,json.length]])||formatOrderedProconfigText(json,{dimensions:1,lowerBound:1,upperBound:json.length})!==raw)fail(`${ruleId} config dimension witness`);
}
function valid(type,value){if(value===null)return type.endsWith('?');if(type==='boolean')return typeof value==='boolean';return typeof value==='string';}
function exactPair(a,b,rules){
 const ids=new Set(rules.map(rule=>rule.id)),left=a.rawInputs.filter(row=>ids.has(row.ruleId)),right=b.rawInputs.filter(row=>ids.has(row.ruleId));
 if(left.length!==380||right.length!==380||!same(left,right))fail('A/B exact unnormalized transform rows');const totals=new Map();for(const row of left)totals.set(row.ruleId,(totals.get(row.ruleId)??0)+row.multiplicity);for(const rule of rules)if((totals.get(rule.id)??0)!==rule.expectedRows)fail(`${rule.id} capture count`);return left;
}
function applyResidual(value,pairs){if(value===null)return null;if(typeof value!=='string')fail('definition text type');for(const pair of pairs)value=value.replaceAll(pair.from,()=>pair.to);return value;}
function projectRows(rows,rules){
 const byId=new Map(rules.map(rule=>[rule.id,rule])),output=[];
 for(const row of rows){
  const rule=byId.get(row.ruleId);if(!rule)continue;if(row.multiplicity!==1||typeof row.identity!=='string'||!row.identity)fail(`${row.ruleId} capture row`);if(!same(Object.keys(row.fact).sort(),rule.captureFields.slice().sort()))fail(`${row.ruleId} capture fact fields`);if(row.ruleId.startsWith('public:'))validateConfig(row.fact,row.ruleId);
  const fact={};for(const field of rule.fields){const value=field==='definition'?applyResidual(row.fact[field],rule.residual.replacements):row.fact[field];if(!valid(rule.fieldTypes[field],value))fail(`${row.ruleId} output type ${field}`);fact[field]=value;}
  output.push({kind:'routine',identity:JSON.stringify([rule.id,row.identity]),fact,source:{ruleId:rule.id,captureIdentity:row.identity,sourceIdentity:rule.sourceSite.sourceIdentity,sourceSHA256:rule.sourceSite.sourceSHA256,definitionSHA256:rule.sourceSite.definitionSHA256,siteSHA256:rule.sourceSite.siteSHA256,executionFrameId:rule.executionFrameId,keyFrame:'pg_catalog-roster',captureFrame:'sourceDiscoveryPublic',factIdentityDisposition:rule.fields.includes('identity')?'captured-original-source-frame-field':'not-projected'}});
 }
 output.sort((left,right)=>Buffer.compare(Buffer.from(left.identity),Buffer.from(right.identity)));return output;
}
function planSHA(rules){return sha(JSON.stringify(rules));}

export function assertOrderedCurrentTransformReferenceV2(value){
 if(!exactObject(value,['status','installable','transformRules','expectedRows','provenance'])||value.status!=='SOURCE-BOUND-TRANSFORM-EXPECTED-PROJECTION'||value.installable!==false||!Array.isArray(value.transformRules)||!Array.isArray(value.expectedRows)||!plain(value.provenance))fail('result envelope');
 if(value.transformRules.length!==13||value.expectedRows.length!==380||value.provenance.residualPlanSHA256!==planSHA(value.transformRules)||value.provenance.expectedRowsSHA256!==sha(JSON.stringify(value.expectedRows)))fail('result coverage or residual plan');
 const rules=new Map();let expected=0;
 for(const rule of value.transformRules){
  if(!exactObject(rule,['id','kind','fields','fieldTypes','sourceSite','executionFrameId','captureFields','residual','expectedRows','frame'])||rules.has(rule.id)||counts[rule.id]!==rule.expectedRows||rule.kind!=='routine'||rule.executionFrameId!=='sourceDiscoveryPublic'||!Array.isArray(rule.fields)||!plain(rule.fieldTypes)||!exactObject(rule.sourceSite,['sourceIdentity','sourceSHA256','definitionSHA256','siteSHA256','start','end','frame'])||!plain(rule.residual)||rule.residual.terminalDisposition!=='already-evaluated-original-source-expression'||rule.residual.savedRowsRead!==0||!Array.isArray(rule.residual.replacements))fail('transform rule');
  if(!hex(rule.sourceSite.sourceSHA256)||!hex(rule.sourceSite.definitionSHA256)||!hex(rule.sourceSite.siteSHA256)||!Number.isSafeInteger(rule.sourceSite.start)||!Number.isSafeInteger(rule.sourceSite.end)||rule.sourceSite.start<0||rule.sourceSite.end<=rule.sourceSite.start||!same(rule.frame,{role:'zasp_discovery_authority',searchPath:'pg_catalog, public',timeZone:'UTC',derivation:'source-proof',sourceFrameProofSHA256:'6c09fd7b1981d3a0e74cadb7a324b29cb3d4a5a5c3fee4b61a6e90ef6c0c8124'}))fail(`${rule.id} source proof`);
  if(!same(Object.keys(rule.fieldTypes),rule.fields)||!same(rule.captureFields,[...rule.fields,...(rule.id.startsWith('public:')?witnesses:[])]))fail(`${rule.id} rule fields`);for(const pair of rule.residual.replacements)if(!plain(pair)||!hex(pair.from)||!/^<[a-z-]+>$/.test(pair.to))fail(`${rule.id} residual pair`);rules.set(rule.id,rule);expected+=rule.expectedRows;
 }
 if(expected!==380)fail('expected row total');const keys=new Set(),totals=new Map();
 for(const row of value.expectedRows){
  if(!exactObject(row,['kind','identity','fact','source'])||row.kind!=='routine'||!plain(row.fact)||!exactObject(row.source,['ruleId','captureIdentity','sourceIdentity','sourceSHA256','definitionSHA256','siteSHA256','executionFrameId','keyFrame','captureFrame','factIdentityDisposition'])||typeof row.identity!=='string')fail('expected row');let key;try{key=JSON.parse(row.identity);}catch{fail('row key JSON');}
  const rule=rules.get(row.source.ruleId);if(!rule||!Array.isArray(key)||key.length!==2||key[0]!==rule.id||key[1]!==row.source.captureIdentity||row.identity!==JSON.stringify(key)||keys.has(row.identity))fail('row key');keys.add(row.identity);
  if(!same(Object.keys(row.fact),rule.fields))fail(`${rule.id} output fields`);for(const field of rule.fields)if(!valid(rule.fieldTypes[field],row.fact[field]))fail(`${rule.id} output type`);for(const field of ['sourceIdentity','sourceSHA256','definitionSHA256','siteSHA256'])if(row.source[field]!==rule.sourceSite[field])fail(`${rule.id} row source ${field}`);
  if(row.source.executionFrameId!==rule.executionFrameId||row.source.keyFrame!=='pg_catalog-roster'||row.source.captureFrame!=='sourceDiscoveryPublic'||row.source.factIdentityDisposition!==(rule.fields.includes('identity')?'captured-original-source-frame-field':'not-projected'))fail(`${rule.id} row frame`);totals.set(rule.id,(totals.get(rule.id)??0)+1);
 }
 for(const rule of value.transformRules)if((totals.get(rule.id)??0)!==rule.expectedRows)fail(`${rule.id} output count`);
 if(value.provenance.frameComparison?.mode!=='exact-unnormalized-independent-A-B-transform-rows'||value.provenance.frameComparison?.rules!==13||value.provenance.frameComparison?.rows!==380||value.provenance.frameComparison?.normalizationApplied!==false||value.provenance.residualBoundary!=='captured-original-expression-results-plus-ordered-definition-replacements'||value.provenance.savedInputDisposition!=='never-read; original CASE and scalar behavior completed during fixed capture')fail('projection provenance');return value;
}

export function projectOrderedCurrentTransformReferenceV2(input){
 if(!exactObject(input,inputFields))fail('input fields');
 const intake=admitOrderedCurrentReferenceIntakeV2(input),contract=parse(input.sourceContractRaw,'source contract'),coverage=parse(input.coverageRaw,'coverage'),transformRules=validateSources(contract,coverage),selected=exactPair(intake.observations.A,intake.observations.B,transformRules),expectedRows=projectRows(selected,transformRules),residualPlanSHA256=planSHA(transformRules),expectedRowsSHA256=sha(JSON.stringify(expectedRows));
 return assertOrderedCurrentTransformReferenceV2({status:'SOURCE-BOUND-TRANSFORM-EXPECTED-PROJECTION',installable:false,transformRules,expectedRows,provenance:{source:intake.source,comparison:intake.comparison,allowances:intake.allowances,frames:intake.provenance,sourceFrameVersion:2,sourceFrame:coverage.framePlan.executionFrames.sourceDiscoveryPublic,frameComparison:{mode:'exact-unnormalized-independent-A-B-transform-rows',rules:13,rows:380,normalizationApplied:false},canonicalKeySource:'admitted-capture-pg_catalog-roster-identity',residualBoundary:'captured-original-expression-results-plus-ordered-definition-replacements',savedInputDisposition:'never-read; original CASE and scalar behavior completed during fixed capture',configDisposition:'captured PostgreSQL text is output; JSON/raw/dimension/bounds are validation-only',residualPlanSHA256,expectedRowsSHA256}});
}
