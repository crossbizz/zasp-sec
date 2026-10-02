import {admitCollectorSource,inspectOrderedCallTokens} from './build-ordered-current-integrity.mjs';

// One compiler-owned core-deparser adapter, not a runtime path/SQL dispatcher.
export const definitionFrame='pg_catalog, public';
export const definitionAdapter='zasp_authorization80_ordered_current.function_definition_public';
export const definitionBody='\nBEGIN\n RETURN pg_catalog.pg_get_functiondef(value);\nEND\n';
export const identityArgumentsAdapter='zasp_authorization80_ordered_current.function_identity_arguments_public';
export const identityAdapter='zasp_authorization80_ordered_current.function_identity_public';
export const identityArgumentsBody='\nBEGIN\n RETURN pg_catalog.pg_get_function_identity_arguments(value);\nEND\n';
export const identityBody='\nBEGIN\n RETURN value::pg_catalog.regprocedure::pg_catalog.text;\nEND\n';
export const frameVersion=2;
const adapters=Object.freeze([
 {name:definitionAdapter,body:definitionBody},
 {name:identityArgumentsAdapter,body:identityArgumentsBody},
 {name:identityAdapter,body:identityBody},
]);
const q=s=>"'"+s.replaceAll("'","''")+"'";
export const definitionInstallSQL=`CREATE SCHEMA zasp_authorization80_ordered_current AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization80_ordered_current FROM PUBLIC;
${adapters.map(a=>`CREATE FUNCTION ${a.name}(value pg_catalog.oid)
RETURNS pg_catalog.text LANGUAGE plpgsql STABLE SECURITY INVOKER PARALLEL UNSAFE
SET search_path=pg_catalog,public SET TimeZone='UTC'
AS $body$${a.body}$body$;
ALTER FUNCTION ${a.name}(pg_catalog.oid) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION ${a.name}(pg_catalog.oid) FROM PUBLIC;`).join('\n')}`;

// This predicate never calls the adapter or an application function. It is
// embedded independently by the client/entry and again before SQL invocation.
export const definitionAdmissionSQL=`SELECT count(*)=3 AND count(DISTINCT p.proname)=3 AND COALESCE(bool_and((
 n.nspowner='zasp_discovery_authority'::pg_catalog.regrole
 AND n.nspacl::text='{zasp_discovery_authority=UC/zasp_discovery_authority}'
 AND p.proowner='zasp_discovery_authority'::pg_catalog.regrole
 AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}'
 AND l.lanname='plpgsql' AND p.prokind='f' AND NOT p.prosecdef
 AND p.provolatile='s' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof
 AND p.proretset=false AND p.prorettype='pg_catalog.text'::pg_catalog.regtype
 AND p.pronargs=1 AND p.proargtypes='26'::pg_catalog.oidvector
 AND p.proargnames=ARRAY['value']::pg_catalog.text[]
 AND p.proallargtypes IS NULL AND p.proargmodes IS NULL
 AND p.pronargdefaults=0 AND p.proargdefaults IS NULL AND p.provariadic=0
 AND p.prosupport=0 AND p.protrftypes IS NULL AND p.procost=100 AND p.prorows=0
 AND p.proconfig=ARRAY['search_path=pg_catalog, public','TimeZone=UTC']::pg_catalog.text[]
 AND p.prosrc=CASE p.proname ${adapters.map(a=>'WHEN '+q(a.name.split('.').at(-1))+' THEN '+q(a.body)).join(' ')} ELSE NULL END AND p.probin IS NULL AND p.prosqlbody IS NULL
 ) IS TRUE),false) AS admitted
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE n.nspname='zasp_authorization80_ordered_current'
 AND p.proname IN('function_definition_public','function_identity_arguments_public','function_identity_public')`;

export function admitFramedTransformSource(sql){
 const allowed=new Map([[definitionAdapter,'pg_catalog.pg_get_functiondef'],[identityArgumentsAdapter,'pg_catalog.pg_get_function_identity_arguments'],[identityAdapter,'pg_catalog.pg_get_function_identity_arguments']]);
 const tokens=inspectOrderedCallTokens(sql).filter(t=>allowed.has(t.name));
 if(!tokens.length)throw Error('missing fixed core-deparser edge');
 let inspected=sql;
 // Rewriting a copy is solely for the existing core-callee lexical inspection;
 // emitted SQL and actual fact values are never rewritten.
 for(const t of tokens.toReversed())inspected=inspected.slice(0,t.start)+allowed.get(t.name)+inspected.slice(t.start+t.name.length);
 admitCollectorSource(inspected);
 return true;
}
