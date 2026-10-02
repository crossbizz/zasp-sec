import {admitCollectorSource,inspectOrderedCallTokens} from './build-ordered-current-integrity.mjs';

// A separate text->oid lane. No schema creation, generic formatter tuple or
// executable assembly runs here; the original caller remains pg_catalog/UTC.
export const precisionResolverAdapterV1='zasp_authorization80_ordered_current.function_resolve_public';
export const precisionResolverBodyV1='\nBEGIN\n RETURN pg_catalog.to_regprocedure(value)::pg_catalog.oid;\nEND\n';
export const precisionResolverInstallSQLV1=`CREATE FUNCTION ${precisionResolverAdapterV1}(value pg_catalog.text)
RETURNS pg_catalog.oid LANGUAGE plpgsql STABLE SECURITY INVOKER PARALLEL UNSAFE
SET search_path=pg_catalog,public
AS $body$${precisionResolverBodyV1}$body$;
ALTER FUNCTION ${precisionResolverAdapterV1}(pg_catalog.text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION ${precisionResolverAdapterV1}(pg_catalog.text) FROM PUBLIC;`;
const quote=s=>"'"+s.replaceAll("'","''")+"'";
// Argument type belongs inside bool_and: a same-name overload must be counted
// and refused, not removed by the WHERE/JOIN. NULL predicates also refuse.
export const precisionResolverAdmissionSQLV1=`SELECT count(*)=1 AND count(DISTINCT p.proname)=1 AND COALESCE(bool_and((
 n.nspowner='zasp_discovery_authority'::pg_catalog.regrole
 AND n.nspacl::text='{zasp_discovery_authority=UC/zasp_discovery_authority}'
 AND p.proowner='zasp_discovery_authority'::pg_catalog.regrole
 AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}'
 AND l.lanname='plpgsql' AND p.prokind='f' AND NOT p.prosecdef
 AND p.provolatile='s' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof
 AND p.proretset=false AND p.prorettype='pg_catalog.oid'::pg_catalog.regtype
 AND p.pronargs=1 AND p.proargtypes='25'::pg_catalog.oidvector
 AND p.proargnames=ARRAY['value']::pg_catalog.text[]
 AND p.proallargtypes IS NULL AND p.proargmodes IS NULL
 AND p.pronargdefaults=0 AND p.proargdefaults IS NULL AND p.provariadic=0
 AND p.prosupport=0 AND p.protrftypes IS NULL AND p.procost=100 AND p.prorows=0
 AND p.proconfig=ARRAY['search_path=pg_catalog, public']::pg_catalog.text[]
 AND p.prosrc=${quote(precisionResolverBodyV1)} AND p.probin IS NULL AND p.prosqlbody IS NULL
 ) IS TRUE),false) AS admitted
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE n.nspname='zasp_authorization80_ordered_current'
 AND p.proname='function_resolve_public'`;

const guards=['batch_insert','batch_update','stage_insert','claim_version','reconciliation','outbox','delivery'];
const sourceExpression="CASE WHEN p.oid='public.zasp_production_runtime_precision_live_fingerprint()'::regprocedure THEN (SELECT definition FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_production_runtime_precision_live_fingerprint()') ELSE CASE WHEN p.oid IN("+guards.map(name=>"'public.zasp_runtime_precision_"+name+"_guard()'::regprocedure").join(',')+") THEN (SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE pg_catalog.to_regprocedure(signature)=p.oid) ELSE pg_catalog.pg_get_functiondef(p.oid) END END";
const resolverGate=`CASE WHEN (SELECT admitted FROM precision_resolver_admission) IS TRUE THEN ${precisionResolverAdapterV1}(signature) ELSE NULL::pg_catalog.oid END`;
const framedExpression=sourceExpression.replace('pg_catalog.to_regprocedure(signature)',resolverGate);
export function precisionResolverExpressionV1(original){
 if(original!==sourceExpression)throw Error('precision resolver source edge changed');
 return framedExpression;
}

// Bounded containment/binding inspection for compiler SELECT/CTE programs, not
// an arbitrary SQL parser. Preserve literals and comments as lexical units;
// never let their parentheses, keywords or semicolons affect query containers.
function containedQueryTokens(sql){
 const fail=reason=>{throw Error('precision resolver collector '+reason);};
 if(typeof sql!=='string'||sql.includes('\0')||sql.includes('$catalog$'))fail('source/function-body delimiter');
 if(sql.includes('\r'))fail('raw CR unsupported by LF-only inspection contract');
 const tokens=[],containers=[];
 const push=(value,start,end,type='symbol')=>{
  if(['word','identifier'].includes(type)&&value.includes('$'))fail('dollar-bearing identifier');
  tokens.push({value,start,end,type,depth:containers.length});
 };
 const quoteEnd=(start,quote,escapes=false)=>{
  let i=start+1;
  while(i<sql.length){
   if(sql[i]==='\\'){
    if(escapes){i+=2;continue;}
    if(quote==="'")fail('ambiguous ordinary string escape');
   }
   if(sql[i]===quote){if(sql[i+1]===quote){i+=2;continue;}return i+1;}
   i++;
  }
  fail('unterminated quote');
 };
 for(let i=0;i<sql.length;){
  const start=i,c=sql[i];
  if(/\s/.test(c)){i++;continue;}
  if(sql.startsWith('--',i)){const end=sql.indexOf('\n',i+2);i=end<0?sql.length:end+1;continue;}
  if(sql.startsWith('/*',i)){
   let nesting=1;i+=2;
   while(i<sql.length&&nesting){if(sql.startsWith('/*',i)){nesting++;i+=2;}else if(sql.startsWith('*/',i)){nesting--;i+=2;}else i++;}
   if(nesting)fail('unterminated comment');continue;
  }
  if(/^u&["']/i.test(sql.slice(i,i+3)))fail('unsupported Unicode quote');
  if((c==='e'||c==='E')&&sql[i+1]==="'"){i=quoteEnd(i+1,"'",true);push('',start,i,'literal');continue;}
  if(c==="'"){i=quoteEnd(i,c);push('',start,i,'literal');continue;}
  if(c==='"'){i=quoteEnd(i,c);push(sql.slice(start+1,i-1).replaceAll('""','"').toLowerCase(),start,i,'identifier');continue;}
  if(c==='$'){
   const tag=sql.slice(i).match(/^\$(?:[a-z_][a-z0-9_]*)?\$/i)?.[0];
   if(!tag)fail('unsupported dollar token');
   const end=sql.indexOf(tag,i+tag.length);if(end<0)fail('unterminated dollar quote');
   i=end+tag.length;push('',start,i,'literal');continue;
  }
  if(/[a-z_]/i.test(c)){
   i++;while(i<sql.length&&/[a-z0-9_$]/i.test(sql[i]))i++;
   const value=sql.slice(start,i).toLowerCase();
   if(['return','raise','perform','declare','begin','loop','if','into','execute','call','do','insert','update','delete','merge','create','alter','drop','grant','revoke','set','copy'].includes(value))fail('procedural/non-read-only statement');
   push(value,start,i,'word');continue;
  }
  if(/[0-9]/.test(c)){i++;while(i<sql.length&&/[0-9.]/.test(sql[i]))i++;push(sql.slice(start,i),start,i,'number');continue;}
  if(c===';')fail('statement terminator');
  if(c==='('||c==='['){push(c,start,++i);containers.push(tokens.length-1);continue;}
  if(c===')'||c===']'){
   const opening=containers.pop();
   if(opening===undefined||tokens[opening].value!==(c===')'?'(':'['))fail('unbalanced query container');
   push(c,start,++i);tokens[opening].mate=tokens.length-1;tokens.at(-1).mate=opening;continue;
  }
  if(!',.:=<>!+-*/|%&~^'.includes(c))fail('unsupported lexical token');
  push(c,start,++i);
 }
 if(containers.length)fail('unbalanced query container');
 const bindings=[],visited=new Set();
 const pinnedInputTypesOrdinality=(at,end)=>{
  const before=['pg_catalog','.','unnest','(','p','.','proargtypes',')'];
  const after=['ordinality','as','args','(','unnest',',','ordinality',')','order','by','args','.','ordinality'];
  return at>=before.length&&at+after.length<end&&
   before.every((value,offset)=>tokens[at-before.length+offset]?.value===value)&&
   after.every((value,offset)=>tokens[at+1+offset]?.value===value);
 };
 const query=(start,end)=>{
  if(visited.has(start))return;visited.add(start);
  let i=start;
  if(tokens[i]?.type!=='word'||!['with','select'].includes(tokens[i].value))fail('single SELECT/CTE required');
  if(tokens[i].value==='with'){
   i++;
   for(;;){
    const name=tokens[i++];
    if(!name||!['word','identifier'].includes(name.type)||tokens[i++]?.value!=='as')fail('unsupported CTE declaration');
    if(tokens[i]?.value==='not'){i++;if(tokens[i++]?.value!=='materialized')fail('unsupported CTE materialization');}
    else if(tokens[i]?.value==='materialized')i++;
    const open=tokens[i];if(open?.value!=='('||open.mate>=end)fail('CTE query container');
    query(i+1,open.mate);
    bindings.push({name,visibleStart:open.mate+1,visibleEnd:end});i=open.mate+1;
    if(tokens[i]?.value!==',')break;i++;
   }
  }
  if(tokens[i]?.type!=='word'||tokens[i].value!=='select')fail('single SELECT/CTE required');
  for(let at=i+1;at<end;at++){
   if(tokens[at].mate>at){at=tokens[at].mate;continue;}
   if(tokens[at].type!=='word')continue;
   if(tokens[at].value==='with'&&!pinnedInputTypesOrdinality(at,end))fail('multiple query statements');
   if(tokens[at].value==='select'&&tokens[at-1]?.value!=='union'&&!(tokens[at-1]?.value==='all'&&tokens[at-2]?.value==='union'))fail('multiple query statements');
  }
 };
 query(0,tokens.length);
 // A WITH in a FROM/CTE/scalar subquery has its own actual lexical scope. Only
 // the declaration's complete query may bind the reserved resolver reference.
 for(let at=0;at<tokens.length;at++)if(tokens[at].value==='('&&['with','select'].includes(tokens[at+1]?.value))query(at+1,tokens[at].mate);
 return {tokens,bindings,fail};
}
// Only inspection copies are rewritten. Requiring the complete selected field,
// exact source CASE/scalar and exact admission CTE rules out relocated calls,
// different arguments, quoted aliases and missing demand gates.
export function inspectOrderedPrecisionResolverSourceV1(sql){
 const {tokens,bindings,fail}=containedQueryTokens(sql);
 const calls=inspectOrderedCallTokens(sql).filter(t=>t.name===precisionResolverAdapterV1);
 const field="'precision_definition',"+framedExpression;
 const admission='precision_resolver_admission AS MATERIALIZED ('+precisionResolverAdmissionSQLV1+')';
 if(calls.length!==1||sql.split(field).length!==2||sql.split(admission).length!==2)throw Error('precision resolver collector source/gate placement');
 const at=sql.indexOf(field),expected=at+field.indexOf(precisionResolverAdapterV1);
 if(calls[0].start!==expected||!sql.slice(expected).startsWith(precisionResolverAdapterV1+'(signature)'))throw Error('precision resolver collector argument/site');
 const reserved=tokens.filter(t=>t.value==='precision_resolver_admission');
 const declaration=bindings.filter(b=>b.name.value==='precision_resolver_admission');
 const referenceStart=at+field.indexOf('precision_resolver_admission');
 if(reserved.length!==2||declaration.length!==1||reserved[0].start!==sql.indexOf(admission)||reserved[1].start!==referenceStart||declaration[0].name!==reserved[0])fail('admission binding shadow/placement');
 const reference=tokens.indexOf(reserved[1]);
 if(reference<declaration[0].visibleStart||reference>=declaration[0].visibleEnd)fail('admission reference outside CTE scope');
 return sql.replace(resolverGate,'pg_catalog.to_regprocedure(signature)');
}
export function admitOrderedPrecisionResolverSourceV1(sql){
 admitCollectorSource(inspectOrderedPrecisionResolverSourceV1(sql));
 return true;
}
