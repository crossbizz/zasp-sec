import crypto from 'node:crypto';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms,formatOrderedProconfigText} from './ordered-current-public-function-transforms.mjs';
import {compileOrderedTransforms} from './ordered-current-transform-compiler.mjs';
import {compileOrderedCollector} from './ordered-current-catalog.mjs';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const quote=s=>"'"+s.replaceAll("'","''")+"'";

// Closed packet builder, not a runtime general SQL parser. The caller below
// admits full contract/source pins before this bounded lexical extraction.
export function splitTransformBranch(text){
  if(typeof text!=='string'||text.length>20000)throw Error('original branch bounds');
  const prefix=text.match(/^\s*(?:(?:UNION ALL\s+)|(?:WITH identities\(value\) AS \(\s*))?SELECT\s+(concat_ws\()/);
  if(!prefix)throw Error('original branch prefix');
  const begin=prefix[0].lastIndexOf('concat_ws('),start=prefix[0].length;
  let depth=1,quoted=null,part=start,finish=-1;const args=[];
  for(let i=start;i<text.length;i++){
    const c=text[i];
    if(quoted){if(c===quoted){if(text[i+1]===quoted)i++;else quoted=null;}continue;}
    if(c==="'"||c==='"'){quoted=c;continue;}
    if(text.slice(i,i+2)==='--'||text.slice(i,i+2)==='/*'||c==='$'||c===';')throw Error('original branch lexical form');
    if(c==='(')depth++;
    if(c===')'&&--depth===0){args.push(text.slice(part,i));finish=i+1;break;}
    if(c===','&&depth===1){args.push(text.slice(part,i));part=i+1;}
  }
  if(finish<0||quoted||args[0]!=="'|'"||!["'function'","'executor-function'"].includes(args[1])||args.length<3)throw Error('original branch arguments');
  const tail=text.slice(finish);
  if(!/^ FROM pg_proc p\b/.test(tail)||/[;$]|--|\/\*/.test(tail))throw Error('original branch tail');
  return {expressions:args.slice(2),tail,line:text.slice(begin,finish)};
}
export function originalTransformProjection(site,fields){
  if(!site||sha(site.text)!==site.sha256||!Array.isArray(fields)||new Set(fields).size!==fields.length||fields.some(f=>!/^[a-z_]+$/.test(f)))throw Error('original projection pin/fields');
  const branch=splitTransformBranch(site.text);
  if(fields.length!==branch.expressions.length)throw Error('original projection arity');
  return "SELECT p.oid::text AS object_oid, pg_catalog.jsonb_build_object("+fields.flatMap((f,i)=>[quote(f),branch.expressions[i]]).join(',')+") AS fact, "+branch.line+' AS line'+branch.tail;
}

const ids=[
  ['temporal:70.fingerprint:function',91],['temporal:71.fingerprint:function',47],['temporal:74.outbox65_fingerprint:function',6],['temporal:74.owner66_fingerprint:function',10],['temporal:75.fingerprint:function',15],['temporal:77.domain67_fingerprint:function',9],['temporal:78.predecessor73_fingerprint:function',10],['temporal:78.predecessor76_fingerprint:function',12],['temporal:78.predecessor76_fingerprint:executor-function',4],
  ['public:sa_attack_lab:function',46],['public:sa_export:function',79],['public:sa_multistep:function',7],['public:sa_webhook:function',44],
];
const bools=new Set(['security_definer','strict','leakproof']);
export function buildOrderedTransformAcceptance(contract){
  const temporal=lowerOrderedTemporalTransforms(contract),pub=lowerOrderedPublicFunctionTransforms(contract),recipes=[...temporal.recipes,...pub.recipes],sites=[...temporal.sites,...pub.sites];
  if(JSON.stringify(recipes.map(r=>r.ruleId))!==JSON.stringify(ids.map(([id])=>id)))throw Error('thirteen recipe coverage');
  const compiled=compileOrderedTransforms(recipes); // Refuses until typed extension is present.
  const rules=recipes.map((r,i)=>{
    // Independently fixed original field positions; never name control values
    // from a mutated AST's insertion order.
    const fields=r.ruleId.startsWith('public:')?[...(r.ruleId==='public:sa_multistep:function'?[]:['namespace_name']),'name','identity_arguments','owner','security_definer','volatility','parallel','strict','leakproof','config_text_or_empty','acl','definition']:
      r.ruleId.endsWith(':executor-function')?['identity','owner','acl','definition']:['name','identity_arguments','owner','acl','definition'];
    if(JSON.stringify(Object.keys(r.fields))!==JSON.stringify(fields))throw Error('original field position mapping');
    const site=sites.find(s=>s.sha256===r.siteSHA256),branch=splitTransformBranch(site.text),candidate=compileOrderedTransforms([r]);
    const parts=fields.map(f=>bools.has(f)?"(fact->>"+quote(f)+')::boolean':"fact->>"+quote(f));
    const projection={id:r.ruleId,cap:ids[i][1],fields,fieldTypes:Object.fromEntries(fields.map(f=>[f,bools.has(f)?'boolean':'string'])),sourceIdentity:r.sourceIdentity,sourceSHA256:r.sourceSHA256,definitionSHA256:r.definitionSHA256,siteSHA256:r.siteSHA256,
      originalSQL:originalTransformProjection(site,fields),candidateSQL:"SELECT kind,identity,fact,pg_catalog.concat_ws('|',"+quote(site.type)+','+parts.join(',')+") AS line FROM (\n"+candidate.sql+'\n) projected',
      witnessSQL:r.ruleId.startsWith('public:')?"SELECT pg_catalog.jsonb_build_object('objectOID',p.oid::text,'identity',p.oid::regprocedure::text,'config',p.proconfig,'dimensions',pg_catalog.array_ndims(p.proconfig),'lowerBound',pg_catalog.array_lower(p.proconfig,1),'upperBound',pg_catalog.array_upper(p.proconfig,1),'originalText',COALESCE(p.proconfig::text,''))"+branch.tail:null,
      rosterSQL:'SELECT p.oid::text AS object_oid,p.oid::regprocedure::text AS identity'+branch.tail,
      originalFrame:{role:'zasp_discovery_authority',searchPath:'pg_catalog, public',timeZone:'UTC'},candidateFrame:{role:'zasp_discovery_authority',searchPath:'pg_catalog',timeZone:'UTC'}};
    return {...projection,originalAggregateSQL:"SELECT pg_catalog.string_agg(line,E'\\n' ORDER BY line) FROM ("+projection.originalSQL+") original_lines",candidateAggregateSQL:"SELECT pg_catalog.string_agg(line,E'\\n' ORDER BY line) FROM ("+projection.candidateSQL+") candidate_lines"};
  });
  const target='public.zasp_sa_multistep_live_fingerprint()',node=contract.nodes.find(n=>n.identity===target);
  const fixedConfig="SELECT pg_catalog.jsonb_build_object('objectOID',p.oid::text,'identity',p.oid::regprocedure::text,'config',p.proconfig,'dimensions',pg_catalog.array_ndims(p.proconfig),'lowerBound',pg_catalog.array_lower(p.proconfig,1),'upperBound',pg_catalog.array_upper(p.proconfig,1),'originalText',COALESCE(p.proconfig::text,'')) FROM pg_catalog.pg_proc p WHERE p.oid="+quote(target)+'::regprocedure';
  const copy=['ALTER TABLE zasp_temporal74.predecessor_functions RENAME TO __ordered_transform_original','CREATE TABLE zasp_temporal74.predecessor_functions AS TABLE zasp_temporal74.__ordered_transform_original','GRANT SELECT ON zasp_temporal74.predecessor_functions TO zasp_discovery_authority'];
  const outbox='temporal:74.outbox65_fingerprint:function',owner='temporal:74.owner66_fingerprint:function',publicRule='public:sa_multistep:function';
  const capture="signature='zasp_temporal65.capture()'",legacy="signature='zasp_temporal66.legacy_visible(text,text,text,text)'";
  const make=(id,ruleIDs,setup=[],extra={})=>({id,ruleIDs,setup,write:id!=='pristine',mode:'compare',sqlState:'',mustChange:false,expectNonstandard:false,probeSQL:'',witnessSQL:'',...extra});
  const config=(id,expression,expectNonstandard=false)=>make(id,[],['UPDATE pg_catalog.pg_proc SET proconfig='+expression+' WHERE oid='+quote(target)+'::regprocedure'],{mode:'config',witnessSQL:fixedConfig,expectNonstandard});
  const sourceAddition='\n -- 033bf2ffa9d4a60121d4f20436ff7de36d1421b62f849254a09048caf75998e6 2941a7ee76eb6af211f0329a9f16bace0b63dbdd22023280a98a4baa55529d98 6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92\n';
  if(node.definition.split(node.source).length!==2)throw Error('fixed replacement source anchor');
  const cases=[
    make('pristine',ids.map(([id])=>id),[],{mode:'pristine'}),
    config('config-null','NULL'),config('config-empty',"ARRAY[]::text[]"),config('config-quoted',"ARRAY['search_path=pg_catalog, public','','NULL',NULL,'x=a\"b','x=a\\b']::text[]"),config('config-nonstandard',"'[0:0]={application_name=probe}'::text[]",true),
    make('owner',[publicRule],['ALTER FUNCTION '+target+' OWNER TO zasp_test'],{mustChange:true}),
    make('acl',[publicRule],['GRANT EXECUTE ON FUNCTION '+target+' TO PUBLIC'],{mustChange:true}),
    make('replacement',[publicRule],[node.definition.replace(node.source,node.source+sourceAddition)],{mustChange:true}),
    make('constraint-duplicate',[],[],{mode:'constraint',sqlState:'23505',probeSQL:'INSERT INTO zasp_temporal74.predecessor_functions SELECT * FROM zasp_temporal74.predecessor_functions WHERE '+capture}),
    make('constraint-null',[],[],{mode:'constraint',sqlState:'23502',probeSQL:"INSERT INTO zasp_temporal74.predecessor_functions(signature,definition,owner_name,acl) VALUES('__ordered_transform_probe__',NULL,'probe','')"}),
    make('saved-missing',[outbox],[...copy,'DELETE FROM zasp_temporal74.predecessor_functions WHERE '+capture],{mustChange:true}),
    make('saved-null-definition',[outbox],[...copy,'UPDATE zasp_temporal74.predecessor_functions SET definition=NULL WHERE '+capture],{mustChange:true}),
    make('saved-null-acl',[owner],[...copy,'UPDATE zasp_temporal74.predecessor_functions SET acl=NULL WHERE '+legacy],{mustChange:true}),
    make('saved-duplicate-definition',[outbox],[...copy,'INSERT INTO zasp_temporal74.predecessor_functions SELECT * FROM zasp_temporal74.predecessor_functions WHERE '+capture],{sqlState:'21000'}),
    make('saved-duplicate-acl',[owner],[...copy,'INSERT INTO zasp_temporal74.predecessor_functions SELECT * FROM zasp_temporal74.predecessor_functions WHERE '+legacy],{sqlState:'21000'}),
    make('saved-unselected-duplicate',[owner],[...copy,'INSERT INTO zasp_temporal74.predecessor_functions SELECT * FROM zasp_temporal74.predecessor_functions WHERE '+capture]),
    make('saved-missing-column',[outbox],[...copy,'ALTER TABLE zasp_temporal74.predecessor_functions DROP COLUMN definition'],{sqlState:'42703'}),
    make('saved-missing-relation',[outbox],[copy[0]],{sqlState:'42P01'}),
    make('literal-missing',[outbox],['ALTER FUNCTION zasp_temporal65.capture() RENAME TO __ordered_transform_capture'],{sqlState:'42883'}),
  ];
  return {format:'ordered-transform-acceptance-v1',status:'NATIVE-UNVERIFIED',sourceContractSHA256:'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6',maxRows:380,maxBytes:16777216,observerSeconds:30,sqlSeconds:10,lockSeconds:3,cleanupSeconds:3,rules,compiledSQL:compiled.sql,compiledSHA256:compiled.sourceSHA256,rawSQL:compileOrderedCollector(compiled.rawRules).sql,rawRules:compiled.rawRules,reserved:['temporal77-demand-boundary'],rawDisposition:'intermediate observations only; never expected truth',target:{identity:target,definition:node.definition,definitionSHA256:node.definitionSHA256},cases};
}
export function validateTransformConfigWitnesses(rows,expectNonstandard){
  if(!Array.isArray(rows)||!rows.length||rows.length>176||typeof expectNonstandard!=='boolean')throw Error('config witness bounds');
  const seen=new Set(),identities=new Set();let compared=0,refused=0;
  for(const r of rows){
    if(!r||Object.keys(r).sort().join(',')!=='config,dimensions,identity,lowerBound,objectOID,originalText,upperBound'||typeof r.objectOID!=='string'||!/^\d{1,10}$/.test(r.objectOID)||seen.has(r.objectOID)||typeof r.identity!=='string'||!r.identity||r.identity.length>4096||identities.has(r.identity)||typeof r.originalText!=='string')throw Error('config witness shape');
    seen.add(r.objectOID);identities.add(r.identity);
    const metadata={dimensions:r.dimensions,lowerBound:r.lowerBound,upperBound:r.upperBound};
    if(expectNonstandard){
      if(rows.length!==1||!Array.isArray(r.config)||r.config.length!==1||typeof r.config[0]!=='string'||r.dimensions!==1||r.lowerBound!==0||r.upperBound!==0||!r.originalText.startsWith('[0:0]='))throw Error('nonstandard witness mismatch');
      let denied=false;try{formatOrderedProconfigText(r.config,metadata);}catch{denied=true;}
      if(!denied)throw Error('nonstandard config accepted');refused++;
    }else{if(formatOrderedProconfigText(r.config,metadata)!==r.originalText)throw Error('original config text mismatch');compared++;}
  }
  return {compared,refused};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
  if(process.argv.length!==3||process.argv[2]!=='--validate-observations')throw Error('closed transform packet operation required');
  const raw=fs.readFileSync(0);if(!raw.length||raw.length>16*1024*1024)throw Error('config observation bytes');
  const input=JSON.parse(raw);if(Object.keys(input).sort().join(',')!=='expectNonstandard,witnesses')throw Error('config observation envelope');
  console.log(JSON.stringify(validateTransformConfigWitnesses(input.witnesses,input.expectNonstandard)));
}
