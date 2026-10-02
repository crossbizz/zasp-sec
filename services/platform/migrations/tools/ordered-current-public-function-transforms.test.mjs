import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {lowerOrderedPublicFunctionTransforms,formatOrderedProconfigText} from './ordered-current-public-function-transforms.mjs';
import {lowerOrderedPublicCatalog} from './ordered-current-public-selectors.mjs';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const bytes=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
assert.equal(sha(bytes),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
const contract=JSON.parse(bytes),families=['sa_attack_lab','sa_export','sa_multistep','sa_webhook'];
const lower=()=>lowerOrderedPublicFunctionTransforms(contract);
const recipe=(o,f)=>{const r=o.recipes.find(r=>r.ruleId===`public:${f}:function`);assert.ok(r,`missing ${f} recipe`);return r;};
// Test-only AST consumer. Expected outputs below are hand-derived literals.
function run(ast,row){
  switch(ast.op){
    case 'field':assert.ok(Object.hasOwn(row,ast.field),`missing raw ${ast.field}`);return row[ast.field];
    case 'literal':return ast.value;
    case 'coalesce':for(const a of ast.args){const v=run(a,row);if(v!==null)return v;}return null;
    case 'replace':{const v=run(ast.input,row);return v===null?null:v.split(ast.from).join(ast.to);}
    default:assert.fail('not a closed pure AST');
  }
}
function selected(s,row){
  if(s.all)return s.all.every(x=>selected(x,row));
  if(s.any)return s.any.some(x=>selected(x,row));
  const v=row[s.field];if(v===null||v===undefined)return false;
  if(Object.hasOwn(s,'equals'))return v===s.equals;
  if(Object.hasOwn(s,'startsWith'))return v.startsWith(s.startsWith);
  if(Object.hasOwn(s,'like'))return new RegExp('^'+[...s.like].map(c=>c==='%'?'[\\s\\S]*':c==='_'?'[\\s\\S]':c.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('')+'$').test(v);
  assert.fail('unknown selector');
}
test('four function recipes retain exact pinned branch bytes and exclude mixed export and schedule transforms',()=>{
  const o=lower(),original=lowerOrderedPublicCatalog(contract);
  assert.deepEqual(o.recipes.map(r=>r.ruleId),families.map(f=>`public:${f}:function`));assert.equal(o.sites.length,4);
  for(const s of o.sites){assert.deepEqual(s,original.sites.find(x=>x.sha256===s.sha256));const n=contract.nodes.find(n=>n.identity===s.identity);assert.equal(Buffer.from(n.source).subarray(s.start,s.end).toString(),s.text);const r=recipe(o,s.family),old=original.obligations.find(x=>x.type==='original-transformation'&&x.siteSHA256===s.sha256);assert.deepEqual(r.selector,old.selector);assert.equal(r.sourceSHA256,n.sourceSHA256);assert.equal(r.definitionSHA256,n.definitionSHA256);}
});
test('all four pure helpers replace only their own constants, all occurrences, in original nested order',()=>{
  const o=lower();for(const [family,body,want,tags] of [
    ['sa_attack_lab','e0f037ec8948a4d574ae33f37e9554d9ff6539785b7d601d7c96685a66c01776|f44bc966ef77ab523a80ace71b59defbe709c1fdbefd69ccfc40cacaf16d7ba8|e0f037ec8948a4d574ae33f37e9554d9ff6539785b7d601d7c96685a66c01776','<compiled-checksum>|<compiled-fingerprint>|<compiled-checksum>',['<compiled-checksum>','<compiled-fingerprint>']],
    ['sa_export','5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985/8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f','<compiled-checksum>/<compiled-fingerprint>',['<compiled-checksum>','<compiled-fingerprint>']],
    ['sa_multistep','033bf2ffa9d4a60121d4f20436ff7de36d1421b62f849254a09048caf75998e6/2941a7ee76eb6af211f0329a9f16bace0b63dbdd22023280a98a4baa55529d98/6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92','<compiled-checksum>/<compiled-fingerprint>/<registered-fingerprint>',['<compiled-checksum>','<compiled-fingerprint>','<registered-fingerprint>']],
    ['sa_webhook','f5021eaf0e9954cba9ab16b4ae1e0ee57e9ea85d909b44eeffe6ac853d0073f4/e89317deca2aabbeb6e35bbe303d8245ba8ea0dbda6351c2d1b2e458e79842f1','<compiled-checksum>/<compiled-fingerprint>',['<compiled-checksum>','<compiled-fingerprint>']],
  ]){const r=recipe(o,family);assert.equal(run(r.fields.definition,{definition:body}),want);assert.equal(run(r.fields.definition,{definition:null}),null);assert.equal(run(r.fields.definition,{definition:''}),'');assert.equal(run(r.fields.definition,{definition:'unrelated Ω\n$& <compiled-checksum>'}),'unrelated Ω\n$& <compiled-checksum>');const actual=[];let ast=r.fields.definition;while(ast.op==='replace'){actual.unshift(ast.to);ast=ast.input;}assert.deepEqual(actual,tags);assert.deepEqual(ast,{op:'field',field:'definition'});}
  assert.equal(run(recipe(o,'sa_export').fields.definition,{definition:'e0f037ec8948a4d574ae33f37e9554d9ff6539785b7d601d7c96685a66c01776'}),'e0f037ec8948a4d574ae33f37e9554d9ff6539785b7d601d7c96685a66c01776');
});
test('projection keeps original field order, raw owner and ACL, booleans and exact config text',()=>{
  const o=lower(),tail=['name','identity_arguments','owner','security_definer','volatility','parallel','strict','leakproof','config_text_or_empty','acl','definition'];
  const row={namespace_name:'public',name:'f',identity_arguments:'arg text',owner:'unaliased_owner',security_definer:false,volatility:'s',parallel:'u',strict:false,leakproof:true,config_text_or_empty:'{"search_path=pg_catalog, public","x=one,two"}',acl:'{b=X/live_owner,a=X/live_owner}',definition:'body'};
  for(const family of families){const r=recipe(o,family);assert.deepEqual(Object.keys(r.fields),family==='sa_multistep'?tail:['namespace_name',...tail]);for(const k of Object.keys(r.fields))assert.deepEqual(run(r.fields[k],row),row[k]);assert.equal(run(r.fields.acl,{acl:null}),'');assert.equal(run(r.fields.acl,{acl:''}),'');assert.equal(run(r.fields.config_text_or_empty,{config_text_or_empty:''}),'');assert.throws(()=>run(r.fields.config_text_or_empty,{config:['search_path=pg_catalog, public']}),/missing raw/);}
});
test('selectors preserve prior whole namespace, public-only prefixes, manual family and LIKE underscore wildcard',()=>{
  const o=lower();for(const [family,namespace,name,want] of [
    ['sa_attack_lab','zasp_sa_attack_lab_prior','unrelated',true],['sa_attack_lab','public','zasp_sa_attack_lab_new',true],['sa_attack_lab','other','zasp_sa_attack_lab_new',false],['sa_attack_lab','public','zaspXsaXattackXlabXnew',false],
    ['sa_export','zasp_sa_export_prior','unrelated',true],['sa_export','public','zasp_sa_manual_new',true],['sa_export','other','zasp_sa_manual_new',false],
    ['sa_multistep','public','zasp_sa_multistep_new',true],['sa_multistep','zasp_sa_multistep_prior','zasp_sa_multistep_new',false],
    ['sa_webhook','zasp_sa_webhook_prior','unrelated',true],['sa_webhook','public','prefixsecurityXagentYwebhooksuffix',true],['sa_webhook','other','security_agent_webhook',false],['sa_webhook','public','securityagentwebhook',false],['sa_webhook','public',null,false],
  ])assert.equal(selected(recipe(o,family).selector,{namespace,name}),want,`${family}:${namespace}:${name}`);
});
test('each helper has independent full source, definition and thirteen frame pins with no live helper AST',()=>{
  const o=lower();assert.equal(o.obligations.filter(x=>x.type==='helper-frame-and-deparse').length,4);
  for(const family of families){const x=o.obligations.find(x=>x.ruleId===`public:${family}:function`&&x.type==='helper-frame-and-deparse');assert.ok(x);const n=contract.nodes.find(n=>n.identity===x.helper.identity);assert.equal(x.helper.source,n.source);assert.equal(x.helper.sourceSHA256,sha(n.source));assert.equal(x.helper.definitionSHA256,sha(n.definition));assert.equal(x.helper.start,0);assert.equal(x.helper.end,Buffer.byteLength(n.source));assert.deepEqual(x.helper.config,['search_path=pg_catalog, public']);assert.equal(x.helper.arguments,'value oid');assert.equal(x.helper.security_definer,false);const ops=[];function walk(a){ops.push(a.op);if(a.input)walk(a.input);for(const x of a.args??[])walk(x);}Object.values(recipe(o,family).fields).forEach(walk);assert.ok(ops.every(x=>['field','literal','replace','coalesce'].includes(x)));}
});
test('typed passthrough and config reconstruction remain explicit integration blockers, not pretend comparison completion',()=>{
  const o=lower();assert.equal(o.unsupported.length,4);for(const family of families){const x=o.unsupported.find(x=>x.ruleId===`public:${family}:function`);assert.ok(x);assert.equal(x.type,'typed-reference-integration');assert.deepEqual(x.booleanFields,['security_definer','strict','leakproof']);assert.equal(x.configField,'config_text_or_empty');assert.ok(o.obligations.some(x=>x.ruleId===`public:${family}:function`&&x.type==='frame-resolution-and-aggregation'));}
});
test('rehashed helper or enclosing source/definition drift and all frame changes refuse before recipes',()=>{
  for(const family of families)for(const suffix of ['function_identity(oid)','live_fingerprint()']){const identity=`public.zasp_${family}_${suffix}`;for(const change of [n=>{n.source+=' ';n.sourceSHA256=sha(n.source);},n=>{n.definition+=' ';n.definitionSHA256=sha(n.definition);},...Object.entries({owner:'other',acl:null,config:['search_path=public'],language:'plpgsql',volatility:'v',parallel:'s',strict:true,leakproof:true,security_definer:true,cost:101,rows:1,arguments:'changed oid',result:'jsonb'}).map(([k,v])=>n=>{n[k]=v;})]){const c=structuredClone(contract);change(c.nodes.find(n=>n.identity===identity));assert.throws(()=>lowerOrderedPublicFunctionTransforms(c),identity);}}
});
test('missing or duplicate helper/parent nodes refuse; output is deterministic and contract stays untouched',()=>{
  for(const family of families)for(const suffix of ['function_identity(oid)','live_fingerprint()'])for(const mode of ['missing','duplicate']){const c=structuredClone(contract),identity=`public.zasp_${family}_${suffix}`,n=c.nodes.find(n=>n.identity===identity);if(mode==='missing')c.nodes=c.nodes.filter(x=>x!==n);else c.nodes.push(n);assert.throws(()=>lowerOrderedPublicFunctionTransforms(c));}
  const before=JSON.stringify(contract);assert.deepEqual(lower(),lower());assert.equal(JSON.stringify(contract),before);
});
test('proconfig formatter preserves array order, SQL NULL distinctions and exact text-array quoting',()=>{
  for(const [value,want] of [[null,''],[[],'{}'],[['search_path=pg_catalog, public'],'{"search_path=pg_catalog, public"}'],[['z=2','a=1'],'{z=2,a=1}'],[['',null,'NULL','null','NuLl'],'{"",NULL,"NULL","null","NuLl"}'],[['{a}','a,b','a"b','a\\b'],'{"{a}","a,b","a\\"b","a\\\\b"}'],[[' a','a\t','a\n','a\r','a\v','a\f'],'{" a","a\t","a\n","a\r","a\v","a\f"}'],[['Ω','a=b','a|b'],'{Ω,a=b,a|b}']])assert.equal(formatOrderedProconfigText(value,value===null||value.length===0?{dimensions:null,lowerBound:null,upperBound:null}:{dimensions:1,lowerBound:1,upperBound:value.length}),want);
});
test('proconfig formatter rejects missing, scalar, nested or nontext elements rather than flattening JSON',()=>{
  for(const value of [undefined,'{}',{},false,0,[[]],[{}],[undefined],[true],[1]])assert.throws(()=>formatOrderedProconfigText(value,{dimensions:1,lowerBound:1,upperBound:1}));
  const sparse=new Array(2);sparse[1]='a';assert.throws(()=>formatOrderedProconfigText(sparse,{dimensions:1,lowerBound:1,upperBound:2}));
});
test('proconfig requires explicit matching dimension witnesses and rejects lost or nonstandard bounds',()=>{
  for(const value of [null,[],['a']])for(const metadata of [undefined,null,{},[],{dimensions:'1',lowerBound:1,upperBound:1},{dimensions:1,lowerBound:0,upperBound:0},{dimensions:2,lowerBound:1,upperBound:1},{dimensions:1,lowerBound:1,upperBound:1,extra:true}])assert.throws(()=>formatOrderedProconfigText(value,metadata));
  assert.throws(()=>formatOrderedProconfigText(['a'],{dimensions:null,lowerBound:null,upperBound:null}));
  assert.throws(()=>formatOrderedProconfigText(['a'],{dimensions:1,lowerBound:1,upperBound:2}));
  for(const value of [null,[]])assert.throws(()=>formatOrderedProconfigText(value,{dimensions:1,lowerBound:1,upperBound:0}));
});
