DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>36)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_runtime_queue_replay_fingerprint' AND value='8b04d86fd127ae1e1d3b54414cf467d06816faa2fad8f9b92f0f2a5a83550ac6')
 OR NOT public.zasp_production_runtime_queue_replay_security_ready()
 OR public.zasp_production_runtime_queue_replay_live_fingerprint()<>'8b04d86fd127ae1e1d3b54414cf467d06816faa2fad8f9b92f0f2a5a83550ac6' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime queue replay rollback rejected';
 END IF;
END
$guard$;

DROP FUNCTION public.zasp_production_integration_webhook_readiness(text,text);
ALTER FUNCTION public.zasp_production_integration_webhook_readiness_v35(text,text) RENAME TO zasp_production_integration_webhook_readiness;
REVOKE ALL ON FUNCTION public.zasp_production_integration_webhook_readiness(text,text) FROM PUBLIC;
DROP FUNCTION public.zasp_production_runtime_queue_replay_readiness(text,text);
DROP FUNCTION public.zasp_production_runtime_queue_replay_live_fingerprint();
DROP FUNCTION public.zasp_production_runtime_queue_replay_security_ready();

DO $repair$
DECLARE definition text; inserted text := $inserted$ -- v36: exact durable outbox identity permits at-least-once publication.
 IF FOUND AND delivery_row.batch_generation=generation_value AND delivery_row.message_digest=message_digest_value AND delivery_row.message_id<>message_value THEN
  IF batch_row.state='unknown' OR delivery_row.disposition='unknown' THEN
   RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','unknown','replayed',true);
  END IF;
  IF batch_row.state IN('succeeded','failed','quarantined') THEN
   RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','ack_terminal','replayed',true);
  END IF;
  IF delivery_row.disposition NOT IN('held','ack_pending') THEN
   RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','unknown','replayed',true);
  END IF;
  IF delivery_row.lease_expires_at>transaction_timestamp() AND delivery_row.visibility_deadline>transaction_timestamp() THEN
   RETURN jsonb_build_object('batch_id',batch_value,'generation',generation_value,'disposition','ack_duplicate','replayed',true);
  END IF;
  UPDATE zasp_runtime_deliveries existing SET message_id=message_value,receive_count=receive_count_value,provider_ack_digest=NULL,lease_expires_at=transaction_timestamp()
   WHERE (existing.organization_id,existing.workspace_id,existing.environment_id,existing.batch_id)=(organization_value,workspace_value,environment_value,batch_value);
  delivery_row.message_id:=message_value;delivery_row.receive_count:=receive_count_value;delivery_row.lease_expires_at:=transaction_timestamp();
 END IF;
$inserted$;
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer)'::regprocedure) INTO STRICT definition;
 IF position(inserted IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime queue replay restoration rejected';END IF;
 EXECUTE replace(definition,inserted,'');
END
$repair$;

DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 36','later_release."version" > 35'),'later."version">36','later."version">35'),'later."version" > 36','later."version" > 35');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime queue replay compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;
DO $acceptance$
DECLARE definition text; prior text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)'::regprocedure) INTO STRICT definition;prior:=definition;
 definition:=replace(definition,$from$IF batch_row.state IN('queued','processing','succeeded','failed','quarantined') AND ($from$,$to$IF batch_row.state='queued' AND ($to$);
 IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime acceptance replay source rejected';END IF;
 EXECUTE definition;
END
$acceptance$;


DELETE FROM public.zasp_schema_metadata WHERE key='production_runtime_queue_replay_fingerprint';
