-- Refuse concurrent changes in the migration runner before acquiring this set.
LOCK TABLE public.zasp_runtime_batch_authorities,public.zasp_runtime_stage_work,public.zasp_runtime_candidate_snapshots IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>49)
 OR NOT COALESCE(public.zasp_production_runtime_correlation_routing_security_ready(),false)
 OR public.zasp_production_runtime_correlation_routing_live_fingerprint() IS DISTINCT FROM (SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_correlation_routing_fingerprint')
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_stage_work WHERE stage='correlate' AND implementation_version<>'runtime-correlation-v1')
 OR EXISTS(SELECT 1 FROM public.zasp_runtime_candidate_snapshots)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing rollback rejected';END IF;
END
$guard$;
DROP TRIGGER zasp_runtime_correlation_claim_version ON public.zasp_runtime_stage_work;
DROP FUNCTION public.zasp_runtime_correlation_claim_version_guard();

DO $claims$
DECLARE definition text;needle text:='WHERE stage_row.stage=stage_value AND (stage_value<>''correlate'' OR stage_row.implementation_version=''runtime-correlation-v1'' OR allow_v2 AND stage_row.implementation_version=''runtime-correlation-v2'') AND';
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean)'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing claim rollback rejected';END IF;
 definition:=replace(definition,'FUNCTION public.zasp_runtime_claim_stage_compatible(worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer, allow_v2 boolean)','FUNCTION public.zasp_runtime_claim_stage(worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer)');
 definition:=replace(definition,needle,'WHERE stage_row.stage=stage_value AND');
 definition:=replace(definition,'DECLARE stage_value text;authority_value text;result_value jsonb;prior_capability text;','DECLARE stage_value text;authority_value text;result_value jsonb;');
 definition:=replace(definition,E'\n IF worker_value IS NULL OR lease_token_value IS NULL OR lease_seconds IS NULL OR claim_limit IS NULL OR allow_v2 IS NULL OR (allow_v2 AND stage_value<>''correlate'') THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''runtime routing capability rejected'';END IF;','');
 definition:=replace(definition,E' prior_capability:=COALESCE(current_setting(''zasp.runtime_correlation_claim_version'',true),'''');\n PERFORM set_config(''zasp.runtime_correlation_claim_version'',CASE WHEN allow_v2 THEN ''runtime-correlation-v2'' ELSE ''runtime-correlation-v1'' END,true);\n','');
 definition:=replace(definition,E' PERFORM set_config(''zasp.runtime_correlation_claim_version'',prior_capability,true);\n','');
 EXECUTE definition;
END
$claims$;
DROP FUNCTION public.zasp_runtime_claim_correlation_v2(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean);

DO $routing$
DECLARE definition text;needle text:='(''correlate'',3,''runtime-correlation-v2'')';
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)'::regprocedure) INTO STRICT definition;
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing producer rollback rejected';END IF;
 EXECUTE replace(definition,needle,'(''correlate'',3,''runtime-correlation-v1'')');
END
$routing$;
DROP FUNCTION public.zasp_production_runtime_acceptance_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_acceptance_readiness_v48(text,text) RENAME TO zasp_production_runtime_acceptance_readiness;
DROP FUNCTION public.zasp_production_runtime_correlation_routing_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_correlation_routing_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_correlation_routing_security_ready();
DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 49','later_release."version" > 48'),'later."version">49','later."version">48'),'later."version" > 49','later."version" > 48');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime routing compatibility rollback rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_correlation_routing_fingerprint';
DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_correlation_routing_checksum';
