-- Preserve only the exact retained writer definitions while the independent
-- worker catalog binds the actual replacements and their unchanged ACLs.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('public.zasp_security_agent_temporary_policy_live_fingerprint()'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure,
 'zasp_temporal77.base67_fingerprint()'::regprocedure);

CREATE FUNCTION zasp_authorization80_worker.ordered_writer_definition(value oid) RETURNS text
 LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $definition$
 SELECT CASE WHEN value IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'zasp_sa_multistep_prior.application(text,text,jsonb)'::regprocedure,
 'zasp_sa_multistep_prior.application_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'zasp_sa_multistep_prior.cleanup(text,text,jsonb)'::regprocedure,
 'public.zasp_security_agent_claim_session_policy_effects(text,text,integer,integer)'::regprocedure,
 'public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)'::regprocedure,
 'public.zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)'::regprocedure,
 'public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_temporary_policy_live_fingerprint()'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure,
 'zasp_temporal77.base67_fingerprint()'::regprocedure)
 THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=value::regprocedure::text)
 ELSE pg_get_functiondef(value) END
$definition$;

DO $ordered_writer_catalog$ DECLARE d text;p record;needle text;BEGIN
 SELECT pg_get_functiondef('public.zasp_sa_multistep_function_identity(oid)'::regprocedure) INTO d;
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION public.zasp_sa_multistep_function_identity(value oid)','FUNCTION zasp_authorization80_worker.ordered_writer_normalized_identity(value oid)');
 d:=zasp_authorization80_worker.ordered62_replace(d,'pg_get_functiondef(value)','zasp_authorization80_worker.ordered_writer_definition(value)');
 EXECUTE d;

 -- The live28 predecessor is the measured remaining leaf: three changed
 -- writers plus this exact fingerprint's self identity. Preserve every other
 -- function, ACL, table, column, policy, trigger and inherited27 contribution.
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_policy_deployment_execution_live_fingerprint()';
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION public.zasp_policy_deployment_execution_live_fingerprint()','FUNCTION zasp_authorization80_worker.ordered_projected28()');
 d:=zasp_authorization80_worker.ordered62_replace(d,'pg_get_functiondef(procedure.oid)',$fixed$CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure)
 THEN zasp_authorization80_worker.ordered_writer_definition(procedure.oid) ELSE pg_get_functiondef(procedure.oid) END$fixed$);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_security_agent_temporary_policy_live_fingerprint()';
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION public.zasp_security_agent_temporary_policy_live_fingerprint()','FUNCTION zasp_authorization80_worker.ordered_projected22()');
 d:=zasp_authorization80_worker.ordered62_replace(d,'pg_get_functiondef(procedure.oid)','zasp_authorization80_worker.ordered_writer_definition(procedure.oid)');
 EXECUTE d;

 -- Extend the effective private gateway projections, not their saved older
 -- copies. Their existing fixed gateway identity substitutions stay intact.
 FOR p IN SELECT oid FROM pg_proc WHERE oid IN('zasp_authorization80_worker.gateway_projected18()'::regprocedure,'zasp_authorization80_worker.gateway_projected24()'::regprocedure,'zasp_authorization80_worker.gateway_projected27()'::regprocedure) LOOP
  d:=pg_get_functiondef(p.oid);
  d:=zasp_authorization80_worker.ordered62_replace(d,'ELSE pg_get_functiondef(procedure.oid) END','ELSE zasp_authorization80_worker.ordered_writer_definition(procedure.oid) END');
  EXECUTE d;
 END LOOP;
 SELECT pg_get_functiondef('public.zasp_security_agent_budgets_function_identity(oid)'::regprocedure) INTO d;
 -- Root's existing gateway/self identities precede this ELSE. Preserve its
 -- readiness-pin normalization and select only this batch's exact originals.
 d:=zasp_authorization80_worker.ordered62_replace(d,'ELSE pg_get_functiondef(function_value) END','ELSE zasp_authorization80_worker.ordered_writer_definition(function_value) END');
 EXECUTE d;

 -- Native77 already moved the effective67 recipe into this private function.
 -- Keep its deployment_compile exception and both public67 wrappers intact.
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal77.base67_fingerprint()';
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered67 direct identity anchors changed';END IF;
 d:=replace(d,needle,'zasp_authorization80_worker.ordered_writer_definition(p.oid)');
 d:=zasp_authorization80_worker.ordered62_replace(d,'ELSE public.zasp_sa_multistep_function_identity(p.oid) END','ELSE zasp_authorization80_worker.ordered_writer_normalized_identity(p.oid) END');
 EXECUTE d;
END $ordered_writer_catalog$;

CREATE OR REPLACE FUNCTION public.zasp_security_agent_temporary_policy_live_fingerprint() RETURNS text
 LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $gate$
 SELECT CASE WHEN zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.ordered_projected22() ELSE NULL END
$gate$;

CREATE OR REPLACE FUNCTION public.zasp_policy_deployment_execution_live_fingerprint() RETURNS text
 LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $gate$
 SELECT CASE WHEN zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.ordered_projected28() ELSE NULL END
$gate$;
