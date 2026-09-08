DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>35)
 OR NOT public.zasp_production_integration_webhook_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=35 AND name='production_integration_webhook'),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime queue replay prerequisite rejected';
 END IF;
END
$guard$;

DO $compatibility$
DECLARE definition text; prior text; function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 35','later_release."version" > 36'),'later."version">35','later."version">36'),'later."version" > 35','later."version" > 36');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime queue replay compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

DO $repair$
DECLARE definition text; anchor text := $anchor$ IF FOUND AND (delivery_row.batch_generation,delivery_row.message_id,delivery_row.message_digest) IS DISTINCT FROM (generation_value,message_value,message_digest_value) THEN$anchor$;
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer)'::regprocedure) INTO STRICT definition;
 IF position(anchor IN definition)=0 OR position('v36: exact durable outbox identity' IN definition)>0 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime queue replay source rejected';
 END IF;
 EXECUTE replace(definition,anchor,$replacement$ -- v36: exact durable outbox identity permits at-least-once publication.
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
 IF FOUND AND (delivery_row.batch_generation,delivery_row.message_id,delivery_row.message_digest) IS DISTINCT FROM (generation_value,message_value,message_digest_value) THEN$replacement$);
END
$repair$;

DO $acceptance$
DECLARE definition text; prior text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)'::regprocedure) INTO STRICT definition;prior:=definition;
 definition:=replace(definition,$from$IF batch_row.state='queued' AND ($from$,$to$IF batch_row.state IN('queued','processing','succeeded','failed','quarantined') AND ($to$);
 IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime acceptance replay source rejected';END IF;
 EXECUTE definition;
END
$acceptance$;


CREATE FUNCTION public.zasp_production_runtime_queue_replay_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_integration_webhook_security_ready()
 AND EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE procedure.oid='public.zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer)'::regprocedure AND owner.rolname='zasp_discovery_authority' AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',procedure.oid,'EXECUTE') AND has_function_privilege('zasp_runtime_coordinator',procedure.oid,'EXECUTE'))
$security$;

CREATE FUNCTION public.zasp_production_runtime_queue_replay_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_integration_webhook_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_claim_delivery','zasp_runtime_commit_reserved_batch','zasp_production_runtime_queue_replay_security_ready')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_production_runtime_queue_replay_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=36 AND name='production_runtime_queue_replay' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>36) AND zasp_production_runtime_queue_replay_security_ready() AND zasp_production_runtime_queue_replay_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_queue_replay_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_queue_replay_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_queue_replay_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_queue_replay_security_ready(),public.zasp_production_runtime_queue_replay_live_fingerprint(),public.zasp_production_runtime_queue_replay_readiness(text,text) FROM PUBLIC;

ALTER FUNCTION public.zasp_production_integration_webhook_readiness(text,text) RENAME TO zasp_production_integration_webhook_readiness_v35;
CREATE FUNCTION public.zasp_production_integration_webhook_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=35 AND name='production_integration_webhook' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_integration_webhook_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_queue_replay_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=36),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_queue_replay_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_integration_webhook_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_integration_webhook_readiness(text,text) FROM PUBLIC;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_queue_replay_fingerprint', '8b04d86fd127ae1e1d3b54414cf467d06816faa2fad8f9b92f0f2a5a83550ac6');
