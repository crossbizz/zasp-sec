DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>37)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_red_team_safety_fingerprint' AND value='ad8addf9cc9d2ecd620253234f01030d694612a6246135c437fc667e33eb35ca')
 OR NOT public.zasp_production_red_team_safety_security_ready()
 OR public.zasp_production_red_team_safety_live_fingerprint()<>'ad8addf9cc9d2ecd620253234f01030d694612a6246135c437fc667e33eb35ca' THEN
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety rollback rejected';
 END IF;
END
$guard$;
DROP FUNCTION public.zasp_production_runtime_queue_replay_readiness(text,text);
ALTER FUNCTION public.zasp_production_runtime_queue_replay_readiness_v36(text,text) RENAME TO zasp_production_runtime_queue_replay_readiness;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_queue_replay_readiness(text,text) FROM PUBLIC;
DROP FUNCTION public.zasp_production_red_team_safety_readiness(text,text);
DROP FUNCTION public.zasp_production_red_team_safety_live_fingerprint();
DROP FUNCTION public.zasp_production_red_team_safety_security_ready();
DO $admission$
DECLARE definition text; original text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_red_team_create_definition(text,text,text,text,text,text,text,text,text,jsonb,jsonb,text)'::regprocedure) INTO STRICT definition;original:=definition;
 definition:=replace(definition,'zasp_red_team_safety_authorized(organization_value,workspace_value,environment_value,target_value,target_kind_value,safety_value)','zasp_red_team_target_valid(organization_value,workspace_value,environment_value,target_value,target_kind_value)');
 IF definition=original THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety admission source rejected';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_red_team_update_definition(text,text,text,text,text,text,bigint,text,text,text,jsonb,jsonb,boolean,text)'::regprocedure) INTO STRICT definition;original:=definition;
 definition:=replace(definition,'zasp_red_team_safety_authorized(organization_value,workspace_value,environment_value,target_value,target_kind_value,safety_value)','zasp_red_team_target_valid(organization_value,workspace_value,environment_value,target_value,target_kind_value)');
 IF definition=original THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety admission source rejected';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)'::regprocedure) INTO STRICT definition;original:=definition;
 definition:=replace(definition,'zasp_red_team_safety_authorized(organization_id,workspace_id,environment_id,target_id,target_kind,safety)','zasp_red_team_target_valid(organization_id,workspace_id,environment_id,target_id,target_kind)');
 IF definition=original THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety admission source rejected';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer)'::regprocedure) INTO STRICT definition;original:=definition;
 definition:=replace(definition,'zasp_red_team_safety_authorized(organization_id,workspace_id,environment_id,target_id,target_kind,safety)','zasp_red_team_target_valid(organization_id,workspace_id,environment_id,target_id,target_kind)');
 IF definition=original THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety admission source rejected';END IF;
 EXECUTE definition;
END
$admission$;

DROP FUNCTION public.zasp_red_team_safety_authorized(text,text,text,text,text,jsonb);
DO $target$
DECLARE definition text; inserted text := $inserted$ AND EXISTS(SELECT 1 FROM zasp_environments environment_row WHERE (environment_row.organization_id,environment_row.workspace_id,environment_row.id)=(organization_value,workspace_value,environment_value) AND environment_row.environment_class IN('development','test','staging'))
$inserted$;
BEGIN
 SELECT pg_get_functiondef('public.zasp_red_team_target_valid(text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 IF position(inserted IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety restoration rejected';END IF;
 EXECUTE replace(definition,inserted,'');
END
$target$;
DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 37','later_release."version" > 36'),'later."version">37','later."version">36'),'later."version" > 37','later."version" > 36');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='red team safety compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;


DELETE FROM public.zasp_schema_metadata WHERE key='production_red_team_safety_fingerprint';
