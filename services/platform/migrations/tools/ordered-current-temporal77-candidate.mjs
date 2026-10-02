// A source-pinned candidate only. Native demand/plan/error parity is required
// before these two branches can enter the direct collector.
import crypto from 'node:crypto';
import {admitCollectorSource,canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {lowerOrderedTemporal77Transforms} from './ordered-current-temporal77-transforms.mjs';
const quote=value=>{canonicalOrderedJSON(value);if(typeof value!=='string')throw Error('candidate text required');return "'"+value.replaceAll("'","''")+"'";};
const keys=value=>Object.keys(value).sort().join(',');
const fields={identity:'p.live_oid::regprocedure::text',name:'p.proname::text',identity_arguments:'pg_catalog.pg_get_function_identity_arguments(p.live_oid)',owner:'p.proowner::regrole::text',acl:'p.proacl::text',definition:'pg_catalog.pg_get_functiondef(p.live_oid)'};

export function compileOrderedTemporal77Candidate(contract){
  // Callers provide only the fully pinned source contract, never arbitrary AST
  // or helper bindings. The companion checks both complete sources and frames.
  const lowered=lowerOrderedTemporal77Transforms(contract);
  const emit=node=>{
    switch(node.op){
      case 'field':if(keys(node)!=='field,op'||!Object.hasOwn(fields,node.field))throw Error('candidate field');return fields[node.field];
      case 'literal':if(keys(node)!=='op,value'||node.value!==null&&typeof node.value!=='string')throw Error('candidate literal');return node.value===null?'NULL::text':quote(node.value)+'::text';
      case 'replace':if(keys(node)!=='from,input,op,to')throw Error('candidate replace');return 'pg_catalog.replace('+emit(node.input)+','+quote(node.from)+','+quote(node.to)+')';
      case 'coalesce':if(keys(node)!=='args,op'||!Array.isArray(node.args)||node.args.length!==2)throw Error('candidate coalesce');return 'COALESCE('+node.args.map(emit).join(',')+')';
      case 'identity-case':if(keys(node)!=='cases,else,op'||!Array.isArray(node.cases)||node.cases.length!==1)throw Error('candidate outer CASE');return '(CASE '+node.cases.map(arm=>'WHEN p.live_oid='+quote(arm.identity)+'::regprocedure THEN '+emit(arm.then)).join(' ')+' ELSE '+emit(node.else)+' END)';
      case 'saved-current-scalar':
        if(keys(node)!=='field,key,op,schema'||!['zasp_temporal78','zasp_authorization80_worker'].includes(node.schema)||node.field!=='definition'||node.key!=='identity::regprocedure::text')throw Error('candidate saved scalar');
        return '(SELECT definition FROM '+node.schema+'.predecessor_functions WHERE signature=p.live_oid::regprocedure::text)';
      case 'saved-membership-case':
        if(keys(node)!=='cast,else,op,pattern,schema,then'||node.schema!=='zasp_temporal78'||node.pattern!=='zasp_temporal77.%'||node.cast!=='regprocedure')throw Error('candidate membership');
        return '(CASE WHEN p.live_oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE '+quote(node.pattern)+') THEN '+emit(node.then)+' ELSE '+emit(node.else)+' END)';
      case 'demand-frame':{
        const h=lowered.helper;
        if(keys(node)!=='argument,bindings,definitionSHA256,expression,frame,identity,op,sourceSHA256'||node.identity!==h.identity||node.sourceSHA256!==h.sourceSHA256||node.definitionSHA256!==h.definitionSHA256||canonicalOrderedJSON(node.frame)!==canonicalOrderedJSON(h.frame)||canonicalOrderedJSON(node.bindings)!==canonicalOrderedJSON(lowered.helperBindings)||canonicalOrderedJSON(node.argument)!=='{"field":"identity","op":"field"}')throw Error('candidate helper demand');
        const expected={op:'identity-case',cases:lowered.helperBindings.map(identity=>({identity,then:{op:'saved-current-scalar',schema:'zasp_authorization80_worker',field:'definition',key:'identity::regprocedure::text'}})),else:{op:'field',field:'definition'}};
        if(canonicalOrderedJSON(node.expression)!==canonicalOrderedJSON(expected))throw Error('candidate helper expression');
        // Text literals are cast only within this selected correlated SubPlan.
        // p.live_oid is the actual pg_proc Var, not a substituted identity OID.
        return '(WITH demanded AS MATERIALIZED (SELECT p.live_oid AS value, (CASE WHEN p.live_oid IS NULL THEN NULL::text[] ELSE ARRAY['+node.bindings.map(quote).join(',')+']::text[] END)::regprocedure[]::oid[] AS resolved) SELECT CASE WHEN d.value = ANY(d.resolved) THEN (SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=d.value::regprocedure::text) ELSE pg_catalog.pg_get_functiondef(d.value) END FROM demanded AS d)';
      }
      default:throw Error('candidate unknown operator');
    }
  };
  const projections=lowered.recipes.map(recipe=>{
    let predicate;
    if(canonicalOrderedJSON(recipe.selector)==='{"equals":"zasp_temporal77","field":"namespace"}')predicate="p.pronamespace='zasp_temporal77'::regnamespace";
    else{
      const identities=['zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)','zasp_temporal67.base_fingerprint()','zasp_temporal67.fingerprint()'];
      if(canonicalOrderedJSON(recipe.selector)!==canonicalOrderedJSON({any:identities.map(identity=>({field:'identity',equals:identity}))}))throw Error('candidate selector');
      predicate='p.oid IN('+identities.map(identity=>quote(identity)+'::regprocedure').join(',')+')';
    }
    return "SELECT 'routine'::text AS kind, '['||pg_catalog.to_json("+quote(recipe.ruleId)+"::text)::text||','||pg_catalog.to_json(p.live_oid::regprocedure::text)::text||']' AS identity, pg_catalog.jsonb_build_object("+Object.keys(recipe.fields).sort().flatMap(field=>[quote(field),emit(recipe.fields[field])]).join(',')+") AS fact FROM (SELECT p.oid AS live_oid, p.proname, p.proowner, p.proacl FROM pg_catalog.pg_proc p WHERE "+predicate+') p';
  });
  const sql=projections.join('\nUNION ALL\n');
  admitCollectorSource(sql);
  return {sql,sourceSHA256:crypto.createHash('sha256').update(sql).digest('hex'),installable:false,native_unverified:true,recipes:2,helperBindings:lowered.helperBindings,helper:lowered.helper,sites:lowered.sites,obligations:lowered.obligations,gates:['selected/unselected helper demand and original first-error ordering','correlated local MATERIALIZED SubPlan without eager/global cast evaluation','original membership/cast/scalar NULL, duplicate and permission behavior','independent helper source/frame admission and original/collector frame parity','complete two-branch projection and aggregate/digest obligations']};
}
