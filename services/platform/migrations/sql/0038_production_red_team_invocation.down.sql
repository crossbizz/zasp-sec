DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>38)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_red_team_invocation_fingerprint' AND value='8c373c0aa7c2fabcfd2e46b0d2bf05a078f68b0f1257e2866083e996de880a0b')
 OR NOT public.zasp_production_red_team_invocation_security_ready()
 OR public.zasp_production_red_team_invocation_live_fingerprint()<>'8c373c0aa7c2fabcfd2e46b0d2bf05a078f68b0f1257e2866083e996de880a0b' THEN
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team invocation rollback rejected';
 END IF;
END
$guard$;

DO $terminal$
DECLARE definition text; prior text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer)'::regprocedure) INTO STRICT definition;
 prior:=definition;
 definition:=replace(definition,'state=''cancelled'',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,completed_at=transaction_timestamp()','state=''cancelled'',completed_at=transaction_timestamp()');
 IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team cancellation patch rejected';END IF;
 prior:=definition;
 definition:=replace(definition,'state=''failed'',error_code=''exhausted'',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,completed_at=transaction_timestamp()','state=''failed'',error_code=''exhausted'',completed_at=transaction_timestamp()');
 IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team exhaustion patch rejected';END IF;
 EXECUTE definition;
END
$terminal$;
DROP FUNCTION public.zasp_production_red_team_safety_readiness(text,text);
ALTER FUNCTION public.zasp_production_red_team_safety_readiness_v37(text,text) RENAME TO zasp_production_red_team_safety_readiness;
REVOKE ALL ON FUNCTION public.zasp_production_red_team_safety_readiness(text,text) FROM PUBLIC;
DROP FUNCTION public.zasp_red_team_invocation_readiness(text,text);
DROP FUNCTION public.zasp_production_red_team_invocation_readiness(text,text);
DROP FUNCTION public.zasp_production_red_team_invocation_live_fingerprint();
DROP FUNCTION public.zasp_production_red_team_invocation_security_ready();
DROP FUNCTION public.zasp_red_team_resolve_invocation(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_red_team_resolve_target(text,text,text,text,text);
ALTER FUNCTION public.zasp_red_team_resolve_target_v37(text,text,text,text,text) RENAME TO zasp_red_team_resolve_target;
REVOKE ALL ON FUNCTION public.zasp_red_team_resolve_target(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_red_team_resolve_target(text,text,text,text,text) TO zasp_red_team_adapter;
DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 38','later_release."version" > 37'),'later."version">38','later."version">37'),'later."version" > 38','later."version" > 37');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team invocation compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;


DELETE FROM public.zasp_schema_metadata WHERE key='production_red_team_invocation_fingerprint';
