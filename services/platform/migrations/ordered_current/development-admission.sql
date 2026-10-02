SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('kind',kind,'identity',identity,'fact',fact) ORDER BY identity COLLATE "C"),'[]'::jsonb) FROM (
WITH direct_routine AS MATERIALIZED (SELECT p.oid::regprocedure::text AS identity, n.nspname::text AS namespace, p.proname::text AS selector_name, pg_catalog.jsonb_build_object('acl',p.proacl::text,'all_types',p.proallargtypes::regtype[]::text[],'argument_defaults',p.proargdefaults::text,'argument_modes',p.proargmodes::text[],'argument_names',p.proargnames,'binary',p.probin,'config',p.proconfig,'cost',p.procost,'default_count',p.pronargdefaults,'input_types',ARRAY(SELECT args.unnest::regtype::text FROM pg_catalog.unnest(p.proargtypes) WITH ORDINALITY AS args(unnest, ordinality) ORDER BY args.ordinality),'kind',p.prokind::text,'language',l.lanname::text,'leakproof',p.proleakproof,'owner',p.proowner::regrole::text,'parallel',p.proparallel::text,'result_type',p.prorettype::regtype::text,'returns_set',p.proretset,'rows',p.prorows,'security_definer',p.prosecdef,'source',p.prosrc::text,'sql_body',p.prosqlbody::text,'strict',p.proisstrict,'support',CASE WHEN p.prosupport=0 THEN NULL ELSE p.prosupport::regprocedure::text END,'transforms',p.protrftypes::regtype[]::text[],'variadic_type',CASE WHEN p.provariadic=0 THEN NULL ELSE p.provariadic::regtype::text END,'volatility',p.provolatile::text) AS fact FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE ((n.nspname::text IN('zasp_authorization80_ordered_current') OR false)))
SELECT 'routine'::text AS kind, '['||pg_catalog.to_json('private-routines'::text)::text||','||pg_catalog.to_json(identity)::text||']' AS identity, pg_catalog.jsonb_build_object('acl',fact->'acl','all_types',fact->'all_types','argument_defaults',fact->'argument_defaults','argument_modes',fact->'argument_modes','argument_names',fact->'argument_names','binary',fact->'binary','config',fact->'config','cost',fact->'cost','default_count',fact->'default_count','input_types',fact->'input_types','kind',fact->'kind','language',fact->'language','leakproof',fact->'leakproof','owner',fact->'owner','parallel',fact->'parallel','result_type',fact->'result_type','returns_set',fact->'returns_set','rows',fact->'rows','security_definer',fact->'security_definer','source',fact->'source','sql_body',fact->'sql_body','strict',fact->'strict','support',fact->'support','transforms',fact->'transforms','variadic_type',fact->'variadic_type','volatility',fact->'volatility') AS fact FROM direct_routine WHERE ((namespace IN('zasp_authorization80_ordered_current') OR false))
) private_admission WHERE current_user='zasp_discovery_authority' AND pg_catalog.current_setting('search_path')='pg_catalog' AND (SELECT count(*)=3 AND count(DISTINCT p.proname)=3 AND COALESCE(bool_and((
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
 AND p.prosrc=CASE p.proname WHEN 'function_definition_public' THEN '
BEGIN
 RETURN pg_catalog.pg_get_functiondef(value);
END
' WHEN 'function_identity_arguments_public' THEN '
BEGIN
 RETURN pg_catalog.pg_get_function_identity_arguments(value);
END
' WHEN 'function_identity_public' THEN '
BEGIN
 RETURN value::pg_catalog.regprocedure::pg_catalog.text;
END
' ELSE NULL END AND p.probin IS NULL AND p.prosqlbody IS NULL
 ) IS TRUE),false) AS admitted
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE n.nspname='zasp_authorization80_ordered_current'
 AND p.proname IN('function_definition_public','function_identity_arguments_public','function_identity_public')) IS TRUE;
