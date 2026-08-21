DO $rollback_guard$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='security_agent_execution_controls_fingerprint' AND value='8b228f9e7424846ef07a73d598166ab30c24e5f7e4bd74628a9d208fe41768c8') OR zasp_security_agent_controls_live_fingerprint()<>'8b228f9e7424846ef07a73d598166ab30c24e5f7e4bd74628a9d208fe41768c8' OR NOT zasp_security_agent_controls_security_ready() OR NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-controls-v1') OR EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>20) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent controls rollback rejected';END IF;
  IF EXISTS(SELECT 1 FROM zasp_security_agent_request_receipts WHERE operation='setSecurityAgentExecutionControl') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent controls rollback blocked by durable mutations';END IF;
END
$rollback_guard$;

DROP FUNCTION public.zasp_security_agent_controls_readiness(text,text);
DROP FUNCTION public.zasp_security_agent_controls_live_fingerprint();
DROP FUNCTION public.zasp_security_agent_controls_security_ready();
DROP FUNCTION public.zasp_security_agent_mutate_execution_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text);
DROP FUNCTION public.zasp_security_agent_execution_control_detail(text,text,text);
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_set_kill_switch(text,text,text,text,boolean,bigint,text,text,text) TO zasp_security_agent_api;
REVOKE SELECT ON TABLE public.zasp_environments FROM zasp_discovery_authority;

ALTER TABLE public.zasp_security_agent_request_receipts DROP CONSTRAINT zasp_security_agent_request_receipts_operation_check;
ALTER TABLE public.zasp_security_agent_request_receipts ADD CONSTRAINT zasp_security_agent_request_receipts_operation_check
  CHECK(operation IN('activateSecurityAgent','simulateSecurityAgent','runSecurityAgent','cancelSecurityAgentRun','decideSecurityAgentApproval'));

DELETE FROM public.zasp_schema_metadata WHERE key='security_agent_execution_controls_fingerprint';
UPDATE public.zasp_schema_metadata SET value='identity-administration-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-controls-v1';

DO $product_release_restore$ DECLARE definition text;original_definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'security-agent-controls-v1','identity-administration-v1');
 definition:=replace(definition,'release."version" = 20','release."version" = 19');
 definition:=replace(definition,'release."name" = ''security_agent_controls''','release."name" = ''identity_administration''');
 definition:=replace(definition,'later_release."version" > 20','later_release."version" > 19');
 IF definition=original_definition OR position('identity-administration-v1' IN definition)=0 OR position('release."version" = 19' IN definition)=0 OR position('release."name" = ''identity_administration''' IN definition)=0 OR position('later_release."version" > 19' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v19 compatibility restore failed';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'security-agent-controls-v1','identity-administration-v1');
 definition:=replace(replace(definition,'release."version"=20','release."version"=19'),'release."version" = 20','release."version" = 19');
 definition:=replace(replace(definition,'release."name"=''security_agent_controls''','release."name"=''identity_administration'''),'release."name" = ''security_agent_controls''','release."name" = ''identity_administration''');
 definition:=replace(replace(definition,'later."version">20','later."version">19'),'later."version" > 20','later."version" > 19');
 IF definition=original_definition OR position('identity-administration-v1' IN definition)=0 OR position('identity_administration' IN definition)=0 OR position('release."version"=19' IN definition)=0 AND position('release."version" = 19' IN definition)=0 OR position('later."version">19' IN definition)=0 AND position('later."version" > 19' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v19 compatibility restore failed';END IF;
 EXECUTE definition;
END $product_release_restore$;
