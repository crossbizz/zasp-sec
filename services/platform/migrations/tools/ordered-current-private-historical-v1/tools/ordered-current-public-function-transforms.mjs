import crypto from 'node:crypto';
import {lowerOrderedPublicCatalog} from './ordered-current-public-selectors.mjs';

const helpers={
  sa_attack_lab:['435982d3cec909e52bb23b879ad4173e9cc4ef7ea2f5cf300f9c5509a7fe4f93','68dd9aee0c86d39aee037f4ebc146920b441b55e2b5490a8198e38b17872d9be',2],
  sa_export:['7516dc92c30322085700fb1ad8e5bd4449293bea3ee58cce68c02c80fdf14f55','27ecca3af7cf769fa912517555e209f5360893399bfe3925965ee31dd2f23100',2],
  sa_multistep:['060b3224780e18f785fd3ad1d5e801e3d99bbad3370c4bf1a78693479fe68d7a','0fe214988ae1c929c629a72d22323e6336e8fd9a4379acd95e9cdc58a3b27e62',3],
  sa_webhook:['ebeea04c053b4140d7d5524caab99a389d9696f983b74a57c09afe47075a125f','90af2205a8ec379cd4aa2947a053938522e62b4287cefd1dd817b84f2c2791a3',2],
};
const helperFrame={owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',config:['search_path=pg_catalog, public'],language:'sql',volatility:'s',parallel:'u',strict:false,leakproof:false,security_definer:false,cost:100,rows:0,arguments:'value oid',result:'text'};
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const field=field=>({op:'field',field});

function pinnedHelper(contract,family){
  const identity=`public.zasp_${family}_function_identity(oid)`,nodes=contract.nodes.filter(n=>n.identity===identity);
  if(nodes.length!==1)throw Error('public transform helper cardinality');
  const n=nodes[0],[sourceSHA256,definitionSHA256]=helpers[family];
  if(n.sourceSHA256!==sourceSHA256||n.definitionSHA256!==definitionSHA256||typeof n.source!=='string'||typeof n.definition!=='string'||sha(n.source)!==sourceSHA256||sha(n.definition)!==definitionSHA256)throw Error('public transform helper source pin');
  for(const [key,value] of Object.entries(helperFrame))if(JSON.stringify(n[key])!==JSON.stringify(value))throw Error('public transform helper frame pin');
  return {identity,sourceSHA256,definitionSHA256,start:0,end:Buffer.byteLength(n.source),source:n.source,...structuredClone(helperFrame)};
}

export function lowerOrderedPublicFunctionTransforms(contract){
  // The accepted selector lowerer independently pins every containing source,
  // definition and frame. Only these four full function branches are consumed.
  const original=lowerOrderedPublicCatalog(contract);
  const sites=original.sites.filter(s=>Object.hasOwn(helpers,s.family)&&s.type==='function');
  if(sites.length!==4)throw Error('public function transform coverage');
  const recipes=[],obligations=[],unsupported=[];
  for(const site of sites){
    const helper=pinnedHelper(contract,site.family);
    const old=original.obligations.find(o=>o.type==='original-transformation'&&o.siteSHA256===site.sha256);
    if(!old||!old.selector)throw Error('public original transform selector missing');
    const binding={ruleId:`public:${site.family}:function`,sourceIdentity:site.identity,sourceSHA256:site.sourceSHA256,definitionSHA256:site.definitionSHA256,siteSHA256:site.sha256,selector:structuredClone(old.selector)};
    let definition=field('definition');
    const pairs=[...helper.source.matchAll(/,'([a-f0-9]{64})','(<[a-z-]+>)'\)/g)];
    if(pairs.length!==helpers[site.family][2])throw Error('public helper replacement coverage');
    // Full source is pinned above. Its textual pair order is inner-to-outer.
    for(const [,from,to] of pairs)definition={op:'replace',input:definition,from,to};
    const fields={};
    if(site.family!=='sa_multistep')fields.namespace_name=field('namespace_name');
    for(const name of ['name','identity_arguments','owner','security_definer','volatility','parallel','strict','leakproof','config_text_or_empty'])fields[name]=field(name);
    fields.acl={op:'coalesce',args:[field('acl'),{op:'literal',value:''}]};
    fields.definition=definition;
    recipes.push({...binding,kind:'routine',fields});
    obligations.push({...binding,type:'helper-frame-and-deparse',helper,required:'Preserve original helper SQL invocation, binding/error and pg_get_functiondef semantics under its pinned pg_catalog, public frame; collection must not call the application helper. Definition input is exact raw deparse from the equivalent frame, never source body or a target-derived expected value. Expanding these pure replacements does not by itself establish invocation/frame error equivalence.'});
    obligations.push({...binding,type:'frame-resolution-and-aggregation',required:'Retain original containing frame, relation/column/regnamespace binding failures, complete selector including negative universe and LIKE underscores, and every selected field in original order. No owner alias, ACL sorting/default expansion, helper invocation, or saved export normalization. Preserve typed boolean and char values, concat_ws SQL NULL skipping, UNION ALL multiplicity, sorted newline aggregate, empty aggregate NULL, UTF8 and digest. Mixed saved/export and schedule branches remain outside this component.'});
    const integration={...binding,type:'typed-reference-integration',booleanFields:['security_definer','strict','leakproof'],configField:'config_text_or_empty',required:'Central compiler/reference must support exact typed routine pass-through and original COALESCE(proconfig::text,\'\'). Do not flatten booleans into arbitrary strings or use JSON array serialization as PostgreSQL text. Reconstruct config only after proving standard one-dimensional lower-bound-1, empty or NULL array shape; raw JSON arrays lose dimensions/lower bounds. Until equivalent raw reference fields/frame and SQL compiler are integrated these recipes are not comparison-ready.',disposition:'unresolved central typed-field/config-reference and native equivalence gate'};
    obligations.push(integration);unsupported.push(structuredClone(integration));
  }
  return {recipes,sites,obligations,unsupported};
}

// Exact text[] element formatting for this original COALESCE projection only.
// Metadata must come from the corresponding PostgreSQL array_ndims/lower/upper
// facts, not be inferred from JSON. Native witness integration remains a gate.
export function formatOrderedProconfigText(value,metadata){
  if(!metadata||typeof metadata!=='object'||Array.isArray(metadata)||Object.keys(metadata).sort().join(',')!=='dimensions,lowerBound,upperBound')throw Error('proconfig dimension witness required');
  if(value!==null&&!Array.isArray(value))throw Error('proconfig must be a captured text array or NULL');
  if(value===null||value.length===0){
    if(metadata.dimensions!==null||metadata.lowerBound!==null||metadata.upperBound!==null)throw Error('proconfig empty dimension witness mismatch');
    return value===null?'':'{}';
  }
  if(metadata.dimensions!==1||metadata.lowerBound!==1||metadata.upperBound!==value.length)throw Error('proconfig noncanonical or mismatched dimensions');
  const elements=[];
  for(let i=0;i<value.length;i++){
    if(!Object.hasOwn(value,i))throw Error('proconfig missing element');
    const item=value[i];
    if(item===null){elements.push('NULL');continue;}
    if(typeof item!=='string')throw Error('proconfig element must be text or NULL');
    const quoted=item===''||/^null$/i.test(item)||/[{},"\\ \t\n\r\v\f]/.test(item);
    elements.push(quoted?'"'+item.replace(/["\\]/g,c=>'\\'+c)+'"':item);
  }
  return '{'+elements.join(',')+'}';
}
