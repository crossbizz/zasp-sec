DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>39)
 OR NOT public.zasp_production_red_team_artifacts_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=39),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_red_team_artifacts_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sessions prerequisite rejected';
 END IF;
END
$guard$;

CREATE TABLE public.zasp_runtime_session_events (
 organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),
 workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),
 environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
 event_id text NOT NULL CHECK(zasp_valid_product_id(event_id)),
 session_id text CHECK(session_id IS NULL OR zasp_valid_product_id(session_id)),
 agent_id text CHECK(agent_id IS NULL OR zasp_valid_product_id(agent_id)),
 confidence text NOT NULL CHECK(confidence IN('exact','strong','probable','unattributed')),
 source text NOT NULL CHECK(source IN('otlp','tetragon')),
 event_class text NOT NULL CHECK(event_class IN('tool','process','file','network')),
 action text NOT NULL CHECK(action IN('invoke','exec','exit','read','write','connect','accept')),
 title text NOT NULL CHECK(length(title) BETWEEN 1 AND 256 AND title !~ '[[:cntrl:]]'),
 evidence_id text NOT NULL CHECK(zasp_valid_product_id(evidence_id)),
 event_time timestamptz NOT NULL CHECK(isfinite(event_time)),
 projected_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,event_id),
 CHECK((confidence IN('exact','strong') AND session_id IS NOT NULL AND agent_id IS NOT NULL) OR (confidence IN('probable','unattributed') AND session_id IS NULL AND agent_id IS NULL))
);
CREATE INDEX zasp_runtime_session_events_timeline_idx ON public.zasp_runtime_session_events(organization_id,workspace_id,environment_id,session_id,event_time,event_id);
CREATE TABLE public.zasp_runtime_session_projection_receipts (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 batch_id text NOT NULL,batch_generation bigint NOT NULL CHECK(batch_generation>0),
 receipt_digest bytea NOT NULL CHECK(octet_length(receipt_digest)=32),
 event_ids text[] NOT NULL CHECK(cardinality(event_ids) BETWEEN 1 AND 1000),
 PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id,batch_generation),
 FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id) REFERENCES public.zasp_runtime_batches(organization_id,workspace_id,environment_id,id)
);
ALTER TABLE public.zasp_runtime_session_events OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_session_projection_receipts OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_session_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_session_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_session_projection_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_session_projection_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_runtime_session_events_authority ON public.zasp_runtime_session_events TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_session_projection_receipts_authority ON public.zasp_runtime_session_projection_receipts TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_runtime_session_events,public.zasp_runtime_session_projection_receipts FROM PUBLIC;

ALTER FUNCTION public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) RENAME TO zasp_runtime_finish_stage_v39;
REVOKE ALL ON FUNCTION public.zasp_runtime_finish_stage_v39(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) FROM PUBLIC,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker;
CREATE FUNCTION public.zasp_runtime_finish_stage(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text,attempt_value integer,input_digest_value bytea,implementation_value text,outcome_value text,effect_digest_value bytea,result_reference_value text,result_version_value text,result_digest_value bytea,error_class_value text,retry_after_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $legacy$
BEGIN
 IF zasp_runtime_stage_for_session()='complete' AND outcome_value='succeeded' THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session projection required';
 END IF;
 RETURN zasp_runtime_finish_stage_v39(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,lease_token_value,attempt_value,input_digest_value,implementation_value,outcome_value,effect_digest_value,result_reference_value,result_version_value,result_digest_value,error_class_value,retry_after_seconds);
END
$legacy$;

CREATE FUNCTION public.zasp_runtime_finish_session_projection(organization_value text,workspace_value text,environment_value text,batch_value text,generation_value bigint,worker_value text,lease_token_value text,attempt_value integer,input_digest_value bytea,implementation_value text,outcome_value text,effect_digest_value bytea,result_reference_value text,result_version_value text,result_digest_value bytea,error_class_value text,retry_after_seconds integer,receipt_bytes bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
DECLARE predecessor zasp_runtime_stage_work%ROWTYPE;complete_row zasp_runtime_stage_work%ROWTYPE;receipt_value jsonb;item jsonb;event_value zasp_runtime_session_events%ROWTYPE;retained zasp_runtime_session_events%ROWTYPE;result_value jsonb;ids text[]:='{}';digest_value bytea;
BEGIN
 IF num_nulls(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,lease_token_value,attempt_value,input_digest_value,implementation_value,outcome_value,effect_digest_value,result_reference_value,result_version_value,result_digest_value,retry_after_seconds,receipt_bytes)>0
 OR NOT COALESCE(zasp_runtime_principal_ready('zasp_runtime_coordinator') AND zasp_runtime_stage_for_session()='complete' AND outcome_value='succeeded' AND implementation_value='runtime-complete-v1' AND octet_length(receipt_bytes) BETWEEN 1 AND 4194304,false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session projection authority rejected';
 END IF;
 SELECT * INTO predecessor FROM zasp_runtime_stage_work WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation,stage)=(organization_value,workspace_value,environment_value,batch_value,generation_value,'project') FOR SHARE;
 IF NOT FOUND OR predecessor.state<>'succeeded' OR predecessor.result_digest IS DISTINCT FROM digest(receipt_bytes,'sha256') OR predecessor.effect_digest IS DISTINCT FROM input_digest_value THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session predecessor receipt rejected';
 END IF;
 SELECT * INTO complete_row FROM zasp_runtime_stage_work WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation,stage)=(organization_value,workspace_value,environment_value,batch_value,generation_value,'complete') FOR UPDATE;
 IF NOT FOUND OR complete_row.predecessor_digest IS DISTINCT FROM predecessor.effect_digest OR complete_row.input_digest IS DISTINCT FROM input_digest_value THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session receipt binding rejected';
 END IF;
 receipt_value:=convert_from(receipt_bytes,'UTF8')::jsonb;
 IF NOT COALESCE(jsonb_typeof(receipt_value)='object' AND receipt_value->>'schema'='runtime-projection-receipt-v1' AND receipt_value->>'implementation_version'='runtime-projection-v1'
 AND (receipt_value->>'organization_id',receipt_value->>'workspace_id',receipt_value->>'environment_id',receipt_value->>'batch_id')=(organization_value,workspace_value,environment_value,batch_value)
 AND receipt_value->>'generation'=generation_value::text AND receipt_value->>'effect_digest'=encode(input_digest_value,'hex') AND input_digest_value=effect_digest_value
 AND jsonb_typeof(receipt_value->'items')='array' AND jsonb_array_length(receipt_value->'items') BETWEEN 1 AND 1000,false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session receipt shape rejected';
 END IF;
 result_value:=zasp_runtime_finish_stage_v39(organization_value,workspace_value,environment_value,batch_value,generation_value,worker_value,lease_token_value,attempt_value,input_digest_value,implementation_value,outcome_value,effect_digest_value,result_reference_value,result_version_value,result_digest_value,error_class_value,retry_after_seconds);
 FOR item IN SELECT value FROM jsonb_array_elements(receipt_value->'items') LOOP
  event_value.organization_id:=organization_value;event_value.workspace_id:=workspace_value;event_value.environment_id:=environment_value;
  event_value.event_id:=item->>'event_id';event_value.session_id:=NULLIF(item->>'session_id','');event_value.agent_id:=NULLIF(item->>'agent_id','');
  event_value.confidence:=item->>'confidence';event_value.source:=item->>'source';event_value.event_class:=item->>'event_class';event_value.action:=item->>'action';
  event_value.title:=item->>'title';event_value.evidence_id:=item->>'evidence_id';event_value.event_time:=(item->>'event_time')::timestamptz;event_value.projected_at:=transaction_timestamp();
  IF event_value.event_id=ANY(ids) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session duplicate event rejected';END IF;
  ids:=array_append(ids,event_value.event_id);
  INSERT INTO zasp_runtime_session_events SELECT (event_value).* ON CONFLICT DO NOTHING;
  SELECT * INTO STRICT retained FROM zasp_runtime_session_events WHERE (organization_id,workspace_id,environment_id,event_id)=(organization_value,workspace_value,environment_value,event_value.event_id);
  IF (to_jsonb(retained)-'projected_at') IS DISTINCT FROM (to_jsonb(event_value)-'projected_at') THEN
   RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime session event replay conflict';
  END IF;
 END LOOP;
 digest_value:=digest(receipt_bytes,'sha256');
 INSERT INTO zasp_runtime_session_projection_receipts VALUES(organization_value,workspace_value,environment_value,batch_value,generation_value,digest_value,ids) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_runtime_session_projection_receipts WHERE (organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,event_ids)=(organization_value,workspace_value,environment_value,batch_value,generation_value,digest_value,ids)) THEN
  RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='runtime session receipt replay conflict';
 END IF;
 RETURN result_value;
END
$finish$;
ALTER FUNCTION public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer),public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) TO zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) TO zasp_runtime_coordinator;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 39','later_release."version" > 40'),'later."version">39','later."version">40'),'later."version" > 39','later."version" > 40');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime sessions compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_runtime_sessions_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_red_team_artifacts_security_ready()
 AND NOT EXISTS(SELECT 1 FROM pg_class WHERE oid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass) AND (NOT relrowsecurity OR NOT relforcerowsecurity OR relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority')))
 AND NOT EXISTS(SELECT 1 FROM pg_roles role_value WHERE role_value.rolname IN('zasp_discovery_api','zasp_security_agent_api','zasp_runtime_coordinator','zasp_runtime_projection_worker','zasp_runtime_ingest') AND (has_table_privilege(role_value.oid,'public.zasp_runtime_session_events','SELECT,INSERT,UPDATE,DELETE') OR has_table_privilege(role_value.oid,'public.zasp_runtime_session_projection_receipts','SELECT,INSERT,UPDATE,DELETE')))
 AND NOT has_function_privilege('zasp_runtime_coordinator','public.zasp_runtime_finish_stage_v39(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer)','EXECUTE')
 AND EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE procedure.oid='public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure AND owner.rolname='zasp_discovery_authority' AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND has_function_privilege('zasp_runtime_coordinator',procedure.oid,'EXECUTE') AND NOT has_function_privilege('public',procedure.oid,'EXECUTE') AND NOT has_function_privilege('zasp_discovery_api',procedure.oid,'EXECUTE'))
$security$;

CREATE FUNCTION public.zasp_production_runtime_sessions_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_red_team_artifacts_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_runtime_sessions_readiness','zasp_production_runtime_sessions_security_ready','zasp_runtime_finish_stage','zasp_runtime_finish_stage_v39','zasp_runtime_finish_session_projection')
 UNION ALL SELECT concat_ws('|','table',relname,relowner::regrole::text,relrowsecurity,relforcerowsecurity,COALESCE(relacl::text,'')) FROM pg_class WHERE oid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass)
 UNION ALL SELECT concat_ws('|','constraint',conname,pg_get_constraintdef(oid),convalidated) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass)
 UNION ALL SELECT concat_ws('|','column',attrelid::regclass::text,attname,format_type(atttypid,atttypmod),attnotnull) FROM pg_attribute WHERE attrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass) AND attnum>0 AND NOT attisdropped
 UNION ALL SELECT concat_ws('|','policy',schemaname,tablename,policyname,roles::text,cmd,qual,with_check) FROM pg_policies WHERE schemaname='public' AND tablename IN('zasp_runtime_session_events','zasp_runtime_session_projection_receipts')
 UNION ALL SELECT concat_ws('|','index',indexname,indexdef) FROM pg_indexes WHERE schemaname='public' AND tablename IN('zasp_runtime_session_events','zasp_runtime_session_projection_receipts')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_sessions_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=40 AND name='production_runtime_sessions' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>40) AND zasp_production_runtime_sessions_security_ready() AND zasp_production_runtime_sessions_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_sessions_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_sessions_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_sessions_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_sessions_security_ready(),public.zasp_production_runtime_sessions_live_fingerprint(),public.zasp_production_runtime_sessions_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_sessions_readiness(text,text) TO zasp_runtime_coordinator;
ALTER FUNCTION public.zasp_production_red_team_artifacts_readiness(text,text) RENAME TO zasp_production_red_team_artifacts_readiness_v39;
CREATE FUNCTION public.zasp_production_red_team_artifacts_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=39 AND name='production_red_team_artifacts' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_red_team_artifacts_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_sessions_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=40),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sessions_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_red_team_artifacts_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_red_team_artifacts_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_red_team_artifacts_readiness(text,text) TO zasp_red_team_worker;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_sessions_fingerprint', '7f965cecd58fa1cec602bd85f4b7ac81a9984f8216bf51444a17b31194311063');
