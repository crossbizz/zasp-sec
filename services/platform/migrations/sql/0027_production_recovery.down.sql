DO $rollback_guard$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_core_schema' AND value='production-recovery-v1') OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>27)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_recovery_fingerprint' AND value='26f5f366b915dad467cca9d7c7941946f359b4884f53c48afb3b089d54179e6d')
  OR NOT public.zasp_recovery_execution_security_ready() OR public.zasp_recovery_execution_live_fingerprint()<>'26f5f366b915dad467cca9d7c7941946f359b4884f53c48afb3b089d54179e6d'
  OR EXISTS(SELECT 1 FROM public.zasp_recovery_backups) OR EXISTS(SELECT 1 FROM public.zasp_recovery_restores) OR EXISTS(SELECT 1 FROM public.zasp_recovery_holds WHERE state<>'released') OR EXISTS(SELECT 1 FROM public.zasp_recovery_outbox WHERE state<>'published') OR EXISTS(SELECT 1 FROM public.zasp_recovery_request_receipts) OR EXISTS(SELECT 1 FROM public.zasp_recovery_audit) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production recovery rollback rejected';
 END IF;
END
$rollback_guard$;

DROP FUNCTION public.zasp_recovery_execution_readiness(text,text);DROP FUNCTION public.zasp_recovery_execution_live_fingerprint();DROP FUNCTION public.zasp_recovery_execution_security_ready();
DROP FUNCTION public.zasp_recovery_fail_operation(text,text,text,text,text,text,bytea,text,integer,jsonb);DROP FUNCTION public.zasp_recovery_finish_restore(text,text,text,text,text,bytea,jsonb,jsonb,jsonb);DROP FUNCTION public.zasp_recovery_checkpoint_restore(text,text,text,text,text,bytea,text,text,jsonb);DROP FUNCTION public.zasp_recovery_finish_backup(text,text,text,text,text,bytea,jsonb);DROP FUNCTION public.zasp_recovery_projection_page(text,text,text,text,text,text,integer);DROP FUNCTION public.zasp_recovery_validate_scope(text,text,text);DROP FUNCTION public.zasp_recovery_capture_page(text,text,text,text,text,bytea,text,text,integer);DROP FUNCTION public.zasp_recovery_release_hold(text,text,text,text,text,bytea);DROP FUNCTION public.zasp_recovery_begin_hold(text,text,text,text,text,bytea);DROP FUNCTION public.zasp_recovery_heartbeat_operation(text,text,text,text,text,text,bytea,integer);DROP FUNCTION public.zasp_recovery_claim_delivery(text,text,text,text,text,text,bytea,integer);DROP FUNCTION public.zasp_recovery_claim_operation(text,text,bytea,integer,integer);
DROP FUNCTION public.zasp_recovery_retry_outbox(text,text,text,text,text,bytea,integer,text);DROP FUNCTION public.zasp_recovery_ack_outbox(text,text,text,text,text,bytea,text);DROP FUNCTION public.zasp_recovery_heartbeat_outbox(text,text,bytea,integer,integer);DROP FUNCTION public.zasp_recovery_claim_outbox(text,text,bytea,integer,integer);DROP FUNCTION public.zasp_recovery_get_restore(text,text,text,text);DROP FUNCTION public.zasp_recovery_get_backup(text,text,text,text);DROP FUNCTION public.zasp_recovery_create_restore(text,text,text,text,text,text,text,text,text,text,bytea,jsonb,bytea);DROP FUNCTION public.zasp_recovery_create_backup(text,text,text,text,text,text,text,integer,text,text,bytea);
DROP FUNCTION public.zasp_recovery_cleanup_evidence_valid(text,text,text,jsonb);
DO $drop_guards$
DECLARE trigger_value record;
BEGIN
 FOR trigger_value IN SELECT class.relname table_name,trigger.tgname trigger_name FROM pg_trigger trigger JOIN pg_class class ON class.oid=trigger.tgrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND trigger.tgfoid='public.zasp_recovery_guard_scope_mutation()'::regprocedure AND NOT trigger.tgisinternal ORDER BY class.relname LOOP
  EXECUTE format('DROP TRIGGER %I ON public.%I',trigger_value.trigger_name,trigger_value.table_name);
 END LOOP;
END
$drop_guards$;
DROP FUNCTION public.zasp_recovery_guard_scope_mutation();DROP FUNCTION public.zasp_recovery_scope_mutable(text,text,text);DROP FUNCTION public.zasp_recovery_principals_ready();DROP FUNCTION public.zasp_recovery_principal_ready(text);
DO $principal_cleanup$
DECLARE binding record;
BEGIN
 EXECUTE 'REVOKE zasp_recovery_worker,zasp_recovery_outbox_worker FROM zasp_discovery_authority CASCADE';
 FOR binding IN SELECT principal_name,authority_role FROM public.zasp_recovery_principal_bindings LOOP EXECUTE format('REVOKE %I FROM %I',binding.authority_role,binding.principal_name);END LOOP;
END
$principal_cleanup$;
DROP FUNCTION public.zasp_recovery_register_principals(text,text,text);
DROP TABLE public.zasp_recovery_audit;DROP TABLE public.zasp_recovery_request_receipts;DROP TABLE public.zasp_recovery_fairness;DROP TABLE public.zasp_recovery_outbox;DROP TABLE public.zasp_recovery_holds;DROP TABLE public.zasp_recovery_restores;DROP TABLE public.zasp_recovery_backups;DROP TABLE public.zasp_recovery_principal_bindings;
DROP ROLE zasp_recovery_worker;DROP ROLE zasp_recovery_outbox_worker;
DELETE FROM public.zasp_schema_metadata WHERE key='production_recovery_fingerprint';UPDATE public.zasp_schema_metadata SET value='attack-lab-execution-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='production-recovery-v1';

DO $product_release_restore$
DECLARE definition text;original_definition text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'production-recovery-v1','attack-lab-execution-v1');definition:=replace(definition,'release."version" = 27','release."version" = 26');definition:=replace(definition,'release."name" = ''production_recovery''','release."name" = ''attack_lab_execution''');definition:=replace(definition,'later_release."version" > 27','later_release."version" > 26');IF definition=original_definition OR position('attack-lab-execution-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v26 compatibility restore failed';END IF;EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'production-recovery-v1','attack-lab-execution-v1');definition:=replace(replace(definition,'release."version"=27','release."version"=26'),'release."version" = 27','release."version" = 26');definition:=replace(replace(definition,'release."name"=''production_recovery''','release."name"=''attack_lab_execution'''),'release."name" = ''production_recovery''','release."name" = ''attack_lab_execution''');definition:=replace(replace(definition,'later."version">27','later."version">26'),'later."version" > 27','later."version" > 26');IF definition=original_definition OR position('attack-lab-execution-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v26 compatibility restore failed';END IF;EXECUTE definition;
END
$product_release_restore$;
