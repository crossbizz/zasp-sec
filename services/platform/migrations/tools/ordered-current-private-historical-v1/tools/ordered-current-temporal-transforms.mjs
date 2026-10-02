import {lowerOrderedTemporalCatalog} from './ordered-current-temporal-selectors.mjs';

// The accepted lowerer verifies complete captured bodies, definitions and frames
// before returning any site. This module never recognizes unpinned caller SQL.
const selected={
  '70.fingerprint':['function'],
  '71.fingerprint':['function'],
  '74.outbox65_fingerprint':['function'],
  '74.owner66_fingerprint':['function'],
  '75.fingerprint':['function'],
  '77.domain67_fingerprint':['function'],
  '78.predecessor73_fingerprint':['function'],
  '78.predecessor76_fingerprint':['function','executor-function'],
  '78.predecessor77_fingerprint':['function','effective-policy-boundary'],
};
const field=field=>({op:'field',field});
const literal=value=>({op:'literal',value});
const coalesce=(...args)=>({op:'coalesce',args});
const saved=(schema,signature,field)=>({op:'saved-scalar',schema,signature,field});
const cases=(schema,signatures,fieldName,fallback)=>({op:'identity-case',cases:signatures.map(identity=>({identity,then:saved(schema,identity,fieldName)})),else:fallback});
const worker74=[
  'zasp_temporal74.takeover(text,text,text,text)',
  'zasp_temporal74.context(text,text,text,text)',
  'zasp_temporal74.context_parent(text,text,text,text,jsonb)',
  'zasp_temporal74.load_plan(jsonb)',
];
function originalDefinition(family) {
  const raw=field('definition');
  switch(family){
    case '70.fingerprint':case '71.fingerprint':case '75.fingerprint':return raw;
    case '74.outbox65_fingerprint':return cases('zasp_temporal74',['zasp_temporal65.capture()','zasp_temporal65.fingerprint()'],'definition',raw);
    case '74.owner66_fingerprint':return cases('zasp_temporal74',['zasp_temporal66.fingerprint()'],'definition',raw);
    case '77.domain67_fingerprint':return cases('zasp_temporal77',['zasp_temporal67.base_fingerprint()','zasp_temporal67.fingerprint()'],'definition',raw);
    case '78.predecessor73_fingerprint':return cases('zasp_temporal78',['zasp_temporal73.unresolved(text,text,text,text)','zasp_temporal73.fingerprint()'],'definition',raw);
    case '78.predecessor76_fingerprint':return cases('zasp_temporal78',['zasp_temporal76.executor74_fingerprint()','zasp_temporal76.fingerprint()'],'definition',cases('zasp_authorization80_worker',worker74,'definition',raw));
    default:throw Error('unclosed temporal definition transform');
  }
}
function replacedDefinition(site) {
  let input=originalDefinition(site.family);
  const pairs=[...site.text.matchAll(/,'([a-f0-9]{64})','(<[a-z-]+>)'\)/g)];
  const expected=site.type==='executor-function'?0:site.family.startsWith('74.')?2:site.family==='77.domain67_fingerprint'?3:4;
  if(pairs.length!==expected)throw Error('temporal replacement coverage mismatch');
  // Text encounters the innermost replacement first. Preserve that exact order.
  for(const [,from,to] of pairs)input={op:'replace',input,from,to};
  return input;
}

export function lowerOrderedTemporalTransforms(contract) {
  const original=lowerOrderedTemporalCatalog(contract);
  const sites=original.sites.filter(s=>selected[s.family]?.includes(s.type));
  if(sites.length!==11)throw Error('temporal transform site coverage mismatch');
  const recipes=[],obligations=[],unsupported=[];
  for(const site of sites){
    const originalObligation=original.obligations.find(o=>o.type==='original-transformation'&&o.siteSHA256===site.sha256);
    if(!originalObligation)throw Error('temporal original transform obligation missing');
    const ruleId=`temporal:${site.family}:${site.type}`;
    const binding={ruleId,sourceIdentity:site.identity,siteSHA256:site.sha256,sourceSHA256:site.sourceSHA256,definitionSHA256:site.definitionSHA256,selector:structuredClone(originalObligation.selector)};
    if(site.family==='78.predecessor77_fingerprint'){
      const x={...binding,type:'original-transformation',source:site.text,required:'Retain original dynamic saved signature::regprocedure membership (including cast errors, LIKE wildcard, NULL and cardinality) before fixed saved put_source and ordered_writer_definition helper branches. The fixed identity-case/saved-scalar AST cannot express this live membership/helper. Do not prune apparently unreachable cases, freeze saved identities, call a helper during collection, or substitute raw definition equality.'};
      obligations.push(x);unsupported.push({...x,reason:x.required,disposition:'unresolved exact original transform; no partial recipe'});continue;
    }
    let acl=coalesce(field('acl'),literal(''));
    if(site.family==='74.owner66_fingerprint')acl=cases('zasp_temporal74',['zasp_temporal66.legacy_visible(text,text,text,text)'],'acl',acl);
    const fields=site.type==='function'?{name:field('name'),identity_arguments:field('identity_arguments')}:{identity:field('identity')};
    Object.assign(fields,{owner:field('owner'),acl,definition:replacedDefinition(site)});
    recipes.push({...binding,kind:'routine',fields});
    obligations.push({...binding,type:'frame-resolution-and-aggregation',required:'Preserve pinned original frame and literal regnamespace/regprocedure resolution errors; fixed identity cases compare original resolved identities, not fixture aliases. Bind all syntactic relations, columns and literal reg-objects even on unselected branches. Only scalar row evaluation follows the selected branch: zero rows NULL, multiple rows error, no coalesce unless explicitly represented. Capture raw nullable ACL text and raw owner without sorting/default expansion. Preserve concat_ws NULL skipping, selected field order, UNION ALL multiplicity, sorted newline aggregate, empty aggregate NULL, UTF8 and digest. AST translation alone does not establish reference completeness, SQL error order or digest equivalence.'});
  }
  return {recipes,sites,obligations,unsupported};
}
