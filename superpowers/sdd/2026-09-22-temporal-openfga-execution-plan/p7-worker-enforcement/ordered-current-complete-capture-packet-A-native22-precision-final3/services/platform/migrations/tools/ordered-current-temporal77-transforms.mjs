// Source representation only. A demand-frame cannot be flattened into the
// outer catalog query: helper-local bindings belong to its selected call path.
import crypto from 'node:crypto';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const helperIdentity='zasp_authorization80_worker.ordered_writer_definition(oid)';
const helperSourceSHA256='59ea633911328f4f05136e7b9818ed5e45e449c0b4f1705f02191233b0e04696';
const helperDefinitionSHA256='c93753702e031b6fd99de4bf73a8c4514df60b5412d76e646f3475428781486b';
const expectedFrame={owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',config:['search_path=pg_catalog, public'],language:'sql',security_definer:false,volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,arguments:'value oid',result:'text'};
const field=field=>({op:'field',field});
const saved=schema=>({op:'saved-current-scalar',schema,field:'definition',key:'identity::regprocedure::text'});
const identityCase=(identity,then,otherwise)=>({op:'identity-case',cases:[{identity,then}],else:otherwise});
const put='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)';
const base='zasp_temporal77.base67_fingerprint()';

export function lowerOrderedTemporal77Transforms(contract){
  const original=lowerOrderedTemporalTransforms(contract);
  const sites=original.sites.filter(site=>site.family==='78.predecessor77_fingerprint');
  if(sites.length!==2||new Set(sites.map(site=>site.type)).size!==2||!sites.some(site=>site.type==='function')||!sites.some(site=>site.type==='effective-policy-boundary'))throw Error('temporal77 source site coverage');
  const helpers=contract.nodes.filter(node=>node.identity===helperIdentity);
  if(helpers.length!==1)throw Error('temporal77 helper identity coverage');
  const helper=helpers[0];
  if(helper.sourceSHA256!==helperSourceSHA256||sha(helper.source)!==helperSourceSHA256||helper.definitionSHA256!==helperDefinitionSHA256||sha(helper.definition)!==helperDefinitionSHA256)throw Error('temporal77 helper source pin');
  const frame=Object.fromEntries(Object.keys(expectedFrame).map(key=>[key,helper[key]]));
  if(JSON.stringify(frame)!==JSON.stringify(expectedFrame))throw Error('temporal77 helper frame pin');
  const helperBindings=[...helper.source.matchAll(/'([^']+)'::regprocedure/g)].map(match=>match[1]);
  if(helperBindings.length!==15||new Set(helperBindings).size!==15||helperBindings.at(-1)!==base)throw Error('temporal77 helper binding coverage');
  const helperExpression={op:'identity-case',cases:helperBindings.map(identity=>({identity,then:saved('zasp_authorization80_worker')})),else:field('definition')};
  const demand={op:'demand-frame',identity:helperIdentity,sourceSHA256:helperSourceSHA256,definitionSHA256:helperDefinitionSHA256,frame:structuredClone(frame),argument:field('identity'),bindings:[...helperBindings],expression:helperExpression};
  const definition={op:'saved-membership-case',schema:'zasp_temporal78',pattern:'zasp_temporal77.%',cast:'regprocedure',then:saved('zasp_temporal78'),else:identityCase(put,saved('zasp_authorization80_worker'),identityCase(base,demand,field('definition')))};
  const recipes=[],obligations=[],unsupported=[];
  for(const site of sites){
    const prior=original.unsupported.find(row=>row.siteSHA256===site.sha256);
    if(!prior)throw Error('temporal77 prior obligation absent');
    const binding={ruleId:prior.ruleId,sourceIdentity:site.identity,sourceSHA256:site.sourceSHA256,definitionSHA256:site.definitionSHA256,siteSHA256:site.sha256,selector:structuredClone(prior.selector)};
    let transformed=structuredClone(definition);
    const replacements=[...site.text.matchAll(/,'([a-f0-9]{64})','(<[a-z-]+>)'\)/g)];
    if(replacements.length!==(site.type==='function'?4:0))throw Error('temporal77 replacement coverage');
    for(const [,from,to] of replacements)transformed={op:'replace',input:transformed,from,to};
    const fields=site.type==='function'?{name:field('name'),identity_arguments:field('identity_arguments')}:{identity:field('identity')};
    Object.assign(fields,{owner:field('owner'),acl:{op:'coalesce',args:[field('acl'),{op:'literal',value:''}]},definition:transformed});
    recipes.push({...binding,kind:'routine',fields});
    obligations.push({...binding,type:'saved-membership-and-scalar',required:'Evaluate the original saved signature LIKE pattern, including wildcard underscores; cast selected signatures to regprocedure freshly under the original frame. Preserve membership NULL/duplicate behavior without multiplying outer rows. Correlated saved scalar keys use original frame-dependent regprocedure text; zero rows NULL, multiple rows error. Do not freeze saved signatures or convert LIKE into a literal-prefix predicate. SQL binding/planner/error order and original aggregate/digest remain native gates.'});
    obligations.push({...binding,type:'selected-helper-frame',helperIdentity,helperSourceSHA256,helperDefinitionSHA256,frame:structuredClone(frame),bindings:[...helperBindings],required:'Resolve all15 helper-local literals and its saved relation/column only on the selected helper-call path, in the original SECURITY INVOKER and pg_catalog, public frame. Do not move those bindings to outer-query entry or erase apparently unselected helper branches. No application helper call is permitted in the direct collector.'});
    unsupported.push({...binding,type:'demand-frame-compilation',reason:'Compilation remains blocked until the selected helper-call demand/frame boundary can be emitted without eager helper-local binding or application helper calls. These proposed nodes are representation only; the existing central compiler must reject them.'});
  }
  return {recipes,sites,helperBindings,helper:{identity:helperIdentity,sourceSHA256:helperSourceSHA256,definitionSHA256:helperDefinitionSHA256,frame},obligations,unsupported};
}
