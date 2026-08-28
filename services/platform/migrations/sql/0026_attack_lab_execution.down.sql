DO $rollback_guard$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='attack-lab-execution-v1') OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>26)
	    OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='attack_lab_execution_fingerprint' AND value='fb752d90dd53bbfcee0e6bd75fa2a61c745fa7a37c66afa73d0c632840c3ee8f')
	    OR NOT public.zasp_attack_lab_execution_security_ready() OR public.zasp_attack_lab_execution_live_fingerprint()<>'fb752d90dd53bbfcee0e6bd75fa2a61c745fa7a37c66afa73d0c632840c3ee8f'
    OR EXISTS(SELECT 1 FROM public.zasp_attack_lab_credential_bindings) OR EXISTS(SELECT 1 FROM public.zasp_attack_lab_runs) OR EXISTS(SELECT 1 FROM public.zasp_attack_lab_cleanup_checkpoints) OR EXISTS(SELECT 1 FROM public.zasp_attack_lab_outbox) OR EXISTS(SELECT 1 FROM public.zasp_attack_lab_request_receipts) OR EXISTS(SELECT 1 FROM public.zasp_attack_lab_audit) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='attack lab execution rollback rejected';
 END IF;
END
$rollback_guard$;

DROP FUNCTION public.zasp_attack_lab_execution_readiness(text,text);
DROP FUNCTION public.zasp_attack_lab_execution_live_fingerprint();
DROP FUNCTION public.zasp_attack_lab_execution_security_ready();
DROP FUNCTION public.zasp_attack_lab_finish_cleanup(text,text,text,text,text,bytea,bytea);
DROP FUNCTION public.zasp_attack_lab_begin_cleanup(text,text,text,text,text,bytea,bytea,text,text,boolean,boolean,text,jsonb,text,text,text,bytea,bigint);
DROP FUNCTION public.zasp_attack_lab_resolve_egress(text,text,text,text,text);
DROP FUNCTION public.zasp_attack_lab_mark_running(text,text,text,text,text,bytea,bytea,text);
DROP FUNCTION public.zasp_attack_lab_begin_provisioning(text,text,text,text,text,bytea,bytea);
DROP FUNCTION public.zasp_attack_lab_retry_run(text,text,text,text,text,bytea,bytea,text,timestamptz);
DROP FUNCTION public.zasp_attack_lab_heartbeat_run(text,text,text,text,text,bytea,integer);
DROP FUNCTION public.zasp_attack_lab_claim_run(text,text,text,text,text,bytea,integer);
DROP FUNCTION public.zasp_attack_lab_retry_outbox(text,text,text,text,text,bytea,integer,text);
DROP FUNCTION public.zasp_attack_lab_ack_outbox(text,text,text,text,text,bytea,text);
DROP FUNCTION public.zasp_attack_lab_heartbeat_outbox(text,bytea,integer,integer);
DROP FUNCTION public.zasp_attack_lab_claim_outbox(text,bytea,integer,integer);
DROP FUNCTION public.zasp_attack_lab_rerun(text,text,text,text,text,text,bigint,text,text);
DROP FUNCTION public.zasp_attack_lab_cancel_run(text,text,text,text,text,text,bigint,text);
DROP FUNCTION public.zasp_attack_lab_create_run(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_attack_lab_get_run(text,text,text,text);
DROP FUNCTION public.zasp_attack_lab_list_runs(text,text,text,timestamptz,text,integer);
DROP FUNCTION public.zasp_attack_lab_mutation_result(text,text,text,text,text,text,text,text,jsonb);
DROP FUNCTION public.zasp_attack_lab_run_json(public.zasp_attack_lab_runs);
DROP FUNCTION public.zasp_attack_lab_principals_ready();
DROP FUNCTION public.zasp_attack_lab_revoke_credential_binding(text,text,text,text,bigint);
DROP FUNCTION public.zasp_attack_lab_register_credential_binding(text,text,text,text,text,text,text,bigint,bytea,timestamptz);
DROP FUNCTION public.zasp_attack_lab_principal_ready(text);
DO $principal_cleanup$
DECLARE binding record;
BEGIN
 EXECUTE 'REVOKE zasp_attack_lab_controller,zasp_attack_lab_outbox_worker,zasp_attack_lab_proxy FROM zasp_discovery_authority CASCADE';
 FOR binding IN SELECT principal_name,authority_role FROM public.zasp_attack_lab_principal_bindings LOOP EXECUTE format('REVOKE %I FROM %I',binding.authority_role,binding.principal_name);END LOOP;
END
$principal_cleanup$;
DROP FUNCTION public.zasp_attack_lab_register_principals(text,text,text,text);
DROP TABLE public.zasp_attack_lab_audit;
DROP TABLE public.zasp_attack_lab_request_receipts;
DROP TABLE public.zasp_attack_lab_outbox_fairness;
DROP TABLE public.zasp_attack_lab_outbox;
DROP TABLE public.zasp_attack_lab_cleanup_checkpoints;
DROP TABLE public.zasp_attack_lab_attempts;
DROP TABLE public.zasp_attack_lab_runs;
DROP TABLE public.zasp_attack_lab_credential_bindings;
DROP TABLE public.zasp_attack_lab_principal_bindings;
DROP ROLE zasp_attack_lab_controller;
DROP ROLE zasp_attack_lab_outbox_worker;
DROP ROLE zasp_attack_lab_proxy;
DELETE FROM public.zasp_schema_metadata WHERE key='attack_lab_execution_fingerprint';
UPDATE public.zasp_schema_metadata SET value='red-team-execution-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='attack-lab-execution-v1';

DO $product_release_restore$
DECLARE definition text;original_definition text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'attack-lab-execution-v1','red-team-execution-v1');definition:=replace(definition,'release."version" = 26','release."version" = 25');definition:=replace(definition,'release."name" = ''attack_lab_execution''','release."name" = ''red_team_execution''');definition:=replace(definition,'later_release."version" > 26','later_release."version" > 25');IF definition=original_definition OR position('red-team-execution-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v25 compatibility restore failed';END IF;EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'attack-lab-execution-v1','red-team-execution-v1');definition:=replace(replace(definition,'release."version"=26','release."version"=25'),'release."version" = 26','release."version" = 25');definition:=replace(replace(definition,'release."name"=''attack_lab_execution''','release."name"=''red_team_execution'''),'release."name" = ''attack_lab_execution''','release."name" = ''red_team_execution''');definition:=replace(replace(definition,'later."version">26','later."version">25'),'later."version" > 26','later."version" > 25');IF definition=original_definition OR position('red-team-execution-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v25 compatibility restore failed';END IF;EXECUTE definition;
END
$product_release_restore$;
