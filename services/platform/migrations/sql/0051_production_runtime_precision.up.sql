DO $guard$
BEGIN
 IF NOT COALESCE(public.zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=50),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision predecessor rejected';END IF;
END $guard$;

-- Keep exact predecessor bodies for reversal, inaccessible to runtime roles.
-- The complete release fingerprint includes the schema and every saved body.
CREATE SCHEMA zasp_precision_predecessor AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_precision_predecessor FROM PUBLIC;
DO $save$
DECLARE item record;definition text;signature text;
BEGIN
 FOR item IN SELECT p.oid,p.proname,pg_get_function_identity_arguments(p.oid) arguments FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN(
 'zasp_runtime_claim_stage_compatible','zasp_runtime_claim_stage_sandbox_compatible','zasp_runtime_correlation_claim_version_guard','zasp_runtime_session_claim_version_guard',
 'zasp_runtime_commit_reserved_batch','zasp_runtime_reserve_batch','zasp_runtime_lookup_acceptance',
 'zasp_runtime_claim_reconciliation','zasp_runtime_release_reconciliation','zasp_runtime_finish_reconciliation','zasp_runtime_quarantine_reconciliation',
 'zasp_runtime_claim_outbox','zasp_runtime_heartbeat_outbox','zasp_runtime_ack_outbox','zasp_runtime_retry_outbox',
 'zasp_runtime_claim_delivery','zasp_runtime_heartbeat_delivery','zasp_runtime_release_delivery','zasp_runtime_ack_delivery',
 'zasp_workflow_mutate','zasp_risk_mutate','zasp_production_security_agent_attack_path_security_ready','zasp_production_workflow_compatibility_security_ready',
 'zasp_production_runtime_sandbox_binding_readiness') LOOP
  definition:=pg_get_functiondef(item.oid);
  EXECUTE replace(definition,'FUNCTION public.'||item.proname||'(','FUNCTION zasp_precision_predecessor.'||item.proname||'(');
  signature:='zasp_precision_predecessor.'||item.proname||'('||item.arguments||')';
  EXECUTE 'ALTER FUNCTION '||signature||' OWNER TO zasp_discovery_authority';
  EXECUTE 'REVOKE ALL ON FUNCTION '||signature||' FROM PUBLIC';
 END LOOP;
END $save$;

-- precision fragments

-- The fragments stay private until all inherited checks use this release.
DO $activate_fragments$
DECLARE signature text;definition text;needle text:='zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key=''production_runtime_sandbox_binding_fingerprint''))';
BEGIN
 FOREACH signature IN ARRAY ARRAY['zasp_runtime_freeze_precise_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)','zasp_runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'] LOOP
  definition:=pg_get_functiondef(('public.'||signature)::regprocedure);
  IF strpos(definition,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision inherited readiness rejected';END IF;
  EXECUTE replace(definition,needle,'zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key=''production_runtime_precision_fingerprint''))');
 END LOOP;
END $activate_fragments$;

-- Also fence the directly granted v17 reserve and already-entered old bodies.
ALTER TABLE public.zasp_runtime_batch_authorities ADD CONSTRAINT zasp_runtime_precision_source_check CHECK(payload_schema_version<>'runtime-event-v2' OR source_kind='tetragon');

-- AFTER INSERT runs after the enrollment-domain trigger and its sensor/FK
-- waits. A previously entered v17 reserve must not retain V2 authority after
-- readiness changes while it is waiting, even if it bypassed the new wrapper.
CREATE FUNCTION public.zasp_runtime_precision_batch_insert_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF (NEW.payload_schema_version='runtime-event-v2' OR NEW.source_kind='otlp' AND NEW.payload_schema_version='runtime-event-v1') AND NOT COALESCE(zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision authority unavailable';END IF;
 RETURN NEW;
END $guard$;
ALTER FUNCTION public.zasp_runtime_precision_batch_insert_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_batch_insert_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_precision_batch_insert AFTER INSERT ON public.zasp_runtime_batch_authorities FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_precision_batch_insert_guard();

CREATE FUNCTION public.zasp_runtime_precision_stage_insert_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
DECLARE source_value text;schema_value text;
BEGIN
 SELECT b.source_kind,b.payload_schema_version INTO source_value,schema_value FROM zasp_runtime_batch_authorities b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.batch_id,b.batch_generation)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation);
 IF schema_value='runtime-event-v2' OR source_value='otlp' AND schema_value='runtime-event-v1' THEN
  IF NOT COALESCE(zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision authority unavailable';END IF;
  IF NOT COALESCE(CASE WHEN schema_value='runtime-event-v2' THEN (NEW.stage,NEW.stage_order,NEW.implementation_version) IN(('archive',1,'runtime-archive-v2'),('index',2,'runtime-index-v2'),('correlate',3,'runtime-correlation-v4'),('project',4,'runtime-projection-v3'),('complete',5,'runtime-complete-v3')) ELSE (NEW.stage,NEW.stage_order,NEW.implementation_version) IN(('archive',1,'runtime-archive-v1'),('index',2,'runtime-index-v1'),('correlate',3,'runtime-correlation-v3'),('project',4,'runtime-projection-v2'),('complete',5,'runtime-complete-v2')) END,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime precision stage tuple rejected';END IF;
 END IF;
 RETURN NEW;
END $guard$;
ALTER FUNCTION public.zasp_runtime_precision_stage_insert_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_stage_insert_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_precision_stage_insert BEFORE INSERT ON public.zasp_runtime_stage_work FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_precision_stage_insert_guard();

-- Reuse the verified stage-wide scheduling algorithm, including holds,
-- exhaustion cascades, per-organization fairness, deliveries and predecessors.
DO $claims$
DECLARE definition text;needle text;replacement text;expected integer;stage text;function_name text;role_name text;
 readiness text:='IF NOT COALESCE(zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key=''production_runtime_precision_fingerprint'')),false) THEN RAISE EXCEPTION USING ERRCODE=''55000'',MESSAGE=''runtime precision authority unavailable'';END IF;';
BEGIN
 SELECT pg_get_functiondef('public.zasp_runtime_claim_stage_sandbox_compatible(text,text,integer,integer,boolean)'::regprocedure) INTO STRICT definition;
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('FUNCTION public.zasp_runtime_claim_stage_sandbox_compatible(', 'FUNCTION public.zasp_runtime_claim_stage_precision_compatible(',1),
  ('allow_v3 boolean','expected_stage text',1),
  ('allow_v3 IS NULL OR (allow_v3 AND stage_value<>''correlate'')','expected_stage IS NULL OR stage_value IS DISTINCT FROM expected_stage',1),
  ('(stage_value<>''correlate'' OR stage_row.implementation_version=''runtime-correlation-v1'' OR allow_v3 AND stage_row.implementation_version IN(''runtime-correlation-v2'',''runtime-correlation-v3''))',
   '(CASE stage_value WHEN ''archive'' THEN stage_row.implementation_version IN(''runtime-archive-v1'',''runtime-archive-v2'') WHEN ''index'' THEN stage_row.implementation_version IN(''runtime-index-v1'',''runtime-index-v2'') WHEN ''correlate'' THEN stage_row.implementation_version IN(''runtime-correlation-v1'',''runtime-correlation-v2'',''runtime-correlation-v3'',''runtime-correlation-v4'') WHEN ''project'' THEN stage_row.implementation_version IN(''runtime-projection-v1'',''runtime-projection-v2'',''runtime-projection-v3'') WHEN ''complete'' THEN stage_row.implementation_version IN(''runtime-complete-v1'',''runtime-complete-v2'',''runtime-complete-v3'') ELSE false END)',2),
  ('zasp.runtime_correlation_claim_version','zasp.runtime_precision_claim_version',3),
  ('CASE WHEN allow_v3 THEN ''runtime-correlation-v3'' ELSE ''runtime-correlation-v1'' END','CASE stage_value WHEN ''archive'' THEN ''runtime-archive-v2'' WHEN ''index'' THEN ''runtime-index-v2'' WHEN ''correlate'' THEN ''runtime-correlation-v4'' WHEN ''project'' THEN ''runtime-projection-v3'' WHEN ''complete'' THEN ''runtime-complete-v3'' END',1),
  (' WITH exhausted AS (',' '||readiness||E'\n WITH exhausted AS (',1),
  (' RETURN result_value;',' '||readiness||E'\n RETURN result_value;',1)
 ) changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision claim predecessor rejected: '||needle;END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
 FOR stage,function_name,role_name IN SELECT * FROM (VALUES
  ('archive','zasp_runtime_claim_archive_v2','zasp_runtime_archive_worker'),('index','zasp_runtime_claim_index_v2','zasp_runtime_index_worker'),('correlate','zasp_runtime_claim_correlation_v4','zasp_runtime_correlation_worker'),('project','zasp_runtime_claim_projection_v3','zasp_runtime_projection_worker'),('complete','zasp_runtime_claim_completion_v3','zasp_runtime_coordinator')
 ) entries(stage,function_name,role_name) LOOP
  EXECUTE format('CREATE FUNCTION public.%I(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS %L',function_name,
   'BEGIN '||readiness||' RETURN zasp_runtime_claim_stage_precision_compatible(worker_value,lease_token_value,lease_seconds,claim_limit,'||quote_literal(stage)||'); END');
  EXECUTE format('ALTER FUNCTION public.%I(text,text,integer,integer) OWNER TO zasp_discovery_authority',function_name);
  EXECUTE format('REVOKE ALL ON FUNCTION public.%I(text,text,integer,integer) FROM PUBLIC',function_name);
  EXECUTE format('GRANT EXECUTE ON FUNCTION public.%I(text,text,integer,integer) TO %I',function_name,role_name);
 END LOOP;
 -- Both legacy helpers otherwise select every archive/index implementation.
 FOREACH function_name IN ARRAY ARRAY['zasp_runtime_claim_stage_compatible','zasp_runtime_claim_stage_sandbox_compatible'] LOOP
  definition:=pg_get_functiondef(('public.'||function_name||'(text,text,integer,integer,boolean)')::regprocedure);
  needle:='WHERE stage_row.stage=stage_value AND';
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision old claim filter rejected';END IF;
  EXECUTE replace(definition,needle,needle||' (stage_value NOT IN(''archive'',''index'') OR stage_value=''archive'' AND stage_row.implementation_version=''runtime-archive-v1'' OR stage_value=''index'' AND stage_row.implementation_version=''runtime-index-v1'') AND');
 END LOOP;
END $claims$;
ALTER FUNCTION public.zasp_runtime_claim_stage_precision_compatible(text,text,integer,integer,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_stage_precision_compatible(text,text,integer,integer,text) FROM PUBLIC;

-- Existing guards still police old capabilities; the complete reader can
-- consume their historical versions without changing the caller's marker.
DO $historical_guards$
DECLARE definition text;name text;needle text:='AND NOT COALESCE(';
BEGIN
 FOREACH name IN ARRAY ARRAY['zasp_runtime_correlation_claim_version_guard','zasp_runtime_session_claim_version_guard'] LOOP
  definition:=pg_get_functiondef(('public.'||name||'()')::regprocedure);
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision old guard rejected';END IF;
  EXECUTE replace(definition,needle,'AND NOT COALESCE((current_setting(''zasp.runtime_precision_claim_version'',true)=CASE NEW.stage WHEN ''correlate'' THEN ''runtime-correlation-v4'' WHEN ''project'' THEN ''runtime-projection-v3'' WHEN ''complete'' THEN ''runtime-complete-v3'' END AND zasp_runtime_stage_for_session()=NEW.stage AND zasp_runtime_principal_ready(CASE NEW.stage WHEN ''correlate'' THEN ''zasp_runtime_correlation_worker'' WHEN ''project'' THEN ''zasp_runtime_projection_worker'' WHEN ''complete'' THEN ''zasp_runtime_coordinator'' END)) OR ');
 END LOOP;
END $historical_guards$;

CREATE FUNCTION public.zasp_runtime_precision_claim_version_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
DECLARE expected text;authority text;
BEGIN
 IF NEW.attempt>OLD.attempt OR NEW.state='failed' AND NEW.last_error_class='exhausted' AND (OLD.state IN('pending','retryable') OR OLD.state='leased' AND OLD.lease_expires_at<=transaction_timestamp()) THEN
  IF NOT COALESCE(zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision authority unavailable';END IF;
  IF (CASE NEW.stage WHEN 'archive' THEN NEW.implementation_version='runtime-archive-v1' WHEN 'index' THEN NEW.implementation_version='runtime-index-v1' WHEN 'correlate' THEN NEW.implementation_version IN('runtime-correlation-v1','runtime-correlation-v2','runtime-correlation-v3') WHEN 'project' THEN NEW.implementation_version IN('runtime-projection-v1','runtime-projection-v2') WHEN 'complete' THEN NEW.implementation_version IN('runtime-complete-v1','runtime-complete-v2') ELSE false END) THEN RETURN NEW;END IF;
  expected:=CASE NEW.stage WHEN 'archive' THEN 'runtime-archive-v2' WHEN 'index' THEN 'runtime-index-v2' WHEN 'correlate' THEN 'runtime-correlation-v4' WHEN 'project' THEN 'runtime-projection-v3' WHEN 'complete' THEN 'runtime-complete-v3' END;
  authority:=CASE NEW.stage WHEN 'archive' THEN 'zasp_runtime_archive_worker' WHEN 'index' THEN 'zasp_runtime_index_worker' WHEN 'correlate' THEN 'zasp_runtime_correlation_worker' WHEN 'project' THEN 'zasp_runtime_projection_worker' WHEN 'complete' THEN 'zasp_runtime_coordinator' END;
  IF NOT COALESCE(NEW.implementation_version=expected AND current_setting('zasp.runtime_precision_claim_version',true)=expected AND zasp_runtime_stage_for_session()=NEW.stage AND zasp_runtime_principal_ready(authority),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime precision claim version rejected';END IF;
 END IF;
 RETURN NEW;
END $guard$;
ALTER FUNCTION public.zasp_runtime_precision_claim_version_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_claim_version_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_precision_claim_version BEFORE UPDATE ON public.zasp_runtime_stage_work FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_precision_claim_version_guard();

-- Keep the scoped V1/V2 search selection unchanged. The new reader returns the
-- receipt implementation explicitly, independent of its own reader capability.
DO $search$
DECLARE definition text;needle text;replacement text;expected integer;
BEGIN
 definition:=pg_get_functiondef('public.zasp_runtime_sandbox_search_claim(text,text,integer)'::regprocedure);
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('FUNCTION public.zasp_runtime_sandbox_search_claim(','FUNCTION public.zasp_runtime_precise_search_claim(',1),
  ('DECLARE work ','DECLARE prior_capability text;work ',1),
  (E'BEGIN\n',E'BEGIN\n prior_capability:=COALESCE(current_setting(''zasp.runtime_precision_search_claim'',true),'''');\n PERFORM set_config(''zasp.runtime_precision_search_claim'',''runtime-projection-v3'',true);\n',1),
  ('project.implementation_version IN(''runtime-projection-v1'',''runtime-projection-v2'')','project.implementation_version IN(''runtime-projection-v1'',''runtime-projection-v2'',''runtime-projection-v3'')',2),
  ('  RETURN jsonb_build_object(',E'  PERFORM set_config(''zasp.runtime_precision_search_claim'',prior_capability,true);\n  RETURN jsonb_build_object(''projection_implementation_version'',(SELECT project.implementation_version FROM zasp_runtime_stage_work project WHERE (project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation)=(work.organization_id,work.workspace_id,work.environment_id,work.batch_id,work.batch_generation) AND project.stage=''project'' AND project.state=''succeeded''),',1),
  (' RETURN NULL;',E' PERFORM set_config(''zasp.runtime_precision_search_claim'',prior_capability,true);\n RETURN NULL;',1)
 ) changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision search predecessor rejected: '||needle;END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
END $search$;
ALTER FUNCTION public.zasp_runtime_precise_search_claim(text,text,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precise_search_claim(text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_precise_search_claim(text,text,integer) TO zasp_runtime_index_worker;

CREATE FUNCTION public.zasp_runtime_precision_search_claim_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF (NEW.attempt>OLD.attempt OR NEW.state='quarantined' AND OLD.state IN('pending','leased') AND OLD.attempt>=100 AND (OLD.lease_until IS NULL OR OLD.lease_until<=clock_timestamp()))
 AND NOT EXISTS(SELECT 1 FROM zasp_runtime_stage_work project WHERE (project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation) AND project.stage='project' AND project.state='succeeded' AND project.implementation_version IN('runtime-projection-v1','runtime-projection-v2'))
 AND NOT COALESCE(current_setting('zasp.runtime_precision_search_claim',true)='runtime-projection-v3' AND zasp_runtime_principal_ready('zasp_runtime_index_worker') AND EXISTS(SELECT 1 FROM zasp_runtime_stage_work project WHERE (project.organization_id,project.workspace_id,project.environment_id,project.batch_id,project.batch_generation)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation) AND project.stage='project' AND project.state='succeeded' AND project.implementation_version='runtime-projection-v3'),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime precision search claim rejected';END IF;
 RETURN NEW;
END $guard$;
ALTER FUNCTION public.zasp_runtime_precision_search_claim_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_search_claim_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_precision_search_claim BEFORE UPDATE ON public.zasp_runtime_sandbox_search_outbox FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_precision_search_claim_guard();

-- Installing51 activates sandbox-aware routing for fresh OTLP commits. Work
-- remains queued until the correlation3/project2/complete2 superset consumers
-- are deployed. Accepted history returns before stage creation, unchanged.
-- Commit reads persisted source/schema under its batch lock, not a caller flag.
DO $routing$
DECLARE definition text;needle text;replacement text;expected integer;
 readiness text:='IF batch_row.payload_schema_version=''runtime-event-v2'' OR batch_row.source_kind=''otlp'' AND batch_row.payload_schema_version=''runtime-event-v1'' THEN PERFORM zasp_runtime_precision_transport_ready();END IF;';
BEGIN
 definition:=pg_get_functiondef('public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text)'::regprocedure);
 needle:='stage_value.version_value,CASE WHEN stage_value.stage_order=1';
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision producer predecessor rejected';END IF;
 definition:=replace(definition,needle,'CASE WHEN batch_row.payload_schema_version=''runtime-event-v2'' THEN CASE stage_value.stage WHEN ''archive'' THEN ''runtime-archive-v2'' WHEN ''index'' THEN ''runtime-index-v2'' WHEN ''correlate'' THEN ''runtime-correlation-v4'' WHEN ''project'' THEN ''runtime-projection-v3'' WHEN ''complete'' THEN ''runtime-complete-v3'' END WHEN batch_row.source_kind=''otlp'' AND batch_row.payload_schema_version=''runtime-event-v1'' THEN CASE stage_value.stage WHEN ''archive'' THEN ''runtime-archive-v1'' WHEN ''index'' THEN ''runtime-index-v1'' WHEN ''correlate'' THEN ''runtime-correlation-v3'' WHEN ''project'' THEN ''runtime-projection-v2'' WHEN ''complete'' THEN ''runtime-complete-v2'' END ELSE stage_value.version_value END,CASE WHEN stage_value.stage_order=1');
 needle:=' IF batch_row.state NOT IN(''uploading'',''unknown'') THEN';
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision producer schema rejected';END IF;
 definition:=replace(definition,needle,' IF batch_row.payload_schema_version=''runtime-event-v2'' AND batch_row.source_kind<>''tetragon'' THEN RAISE EXCEPTION USING ERRCODE=''22023'',MESSAGE=''runtime precision source rejected'';END IF;'||chr(10)||needle);
 -- Validate after the batch row wait, and again before both replay and fresh
 -- returns. Later blocking inserts must not outlive the pinned release.
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  (' IF batch_row.state NOT IN(''uploading'',''unknown'') THEN',readiness||chr(10)||' IF batch_row.state NOT IN(''uploading'',''unknown'') THEN',1),
  ('THEN RETURN jsonb_build_object(', 'THEN '||readiness||' RETURN jsonb_build_object(',1),
  (' RETURN result_value;',readiness||chr(10)||' RETURN result_value;',1)
 ) changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime semantic readiness predecessor rejected';END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
 definition:=pg_get_functiondef('public.zasp_runtime_lookup_acceptance(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer,text,text,text,text)'::regprocedure);
 needle:='schema_value=''runtime-event-v1''';
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision acceptance predecessor rejected';END IF;
 EXECUTE replace(definition,needle,'(schema_value=''runtime-event-v1'' OR schema_value=''runtime-event-v2'' AND source_value=''tetragon'')');
END $routing$;

CREATE OR REPLACE FUNCTION public.zasp_runtime_reserve_batch(locator_value bytea,secret_value bytea,audience_value text,batch_value text,idempotency_value text,content_digest_value bytea,source_kind_value text,media_type_value text,schema_version_value text,payload_size_value bigint,event_count_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $reserve$
DECLARE result_value jsonb;
BEGIN
 IF schema_version_value='runtime-event-v2' AND source_kind_value IS DISTINCT FROM 'tetragon' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime precision source rejected';END IF;
 IF NOT COALESCE(zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision authority unavailable';END IF;
 result_value:=zasp_runtime_reserve_batch_v17(locator_value,secret_value,audience_value,batch_value,idempotency_value,content_digest_value,source_kind_value,media_type_value,schema_version_value,payload_size_value,event_count_value);
 IF NOT COALESCE(zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision authority unavailable';END IF;
 RETURN result_value;
END $reserve$;

-- Recovery readers declare their codec capability separately from durable
-- completion. Preserve the predecessor algorithm and restrict all three claim
-- mutation branches, not merely the returned leases.
CREATE FUNCTION public.zasp_runtime_precision_reconciliation_ready() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $ready$
BEGIN
 IF NOT zasp_discovery_principal_ready('zasp_runtime_ingest') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime reconciliation principal rejected';END IF;
 IF NOT COALESCE(zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision recovery unavailable';END IF;
END $ready$;
ALTER FUNCTION public.zasp_runtime_precision_reconciliation_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_reconciliation_ready() FROM PUBLIC;

DO $recovery$
DECLARE definition text;needle text;replacement text;expected integer;item record;
BEGIN
 definition:=pg_get_functiondef('public.zasp_runtime_claim_reconciliation(text,text,integer,integer)'::regprocedure);
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('FUNCTION public.zasp_runtime_claim_reconciliation(worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer)','FUNCTION public.zasp_runtime_precision_claim_reconciliation(worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer, allow_v2 boolean)',1),
  ('DECLARE response jsonb;','DECLARE response jsonb;prior_capability text;',1),
  (E'BEGIN\n',E'BEGIN\n PERFORM zasp_runtime_precision_reconciliation_ready();\n IF worker_value IS NULL OR lease_token_value IS NULL OR lease_seconds IS NULL OR claim_limit IS NULL OR allow_v2 IS NULL THEN RAISE EXCEPTION USING ERRCODE=''22023'',MESSAGE=''runtime reconciliation claim rejected'';END IF;\n prior_capability:=COALESCE(current_setting(''zasp.runtime_precision_reconciliation_claim'',true),'''');\n PERFORM set_config(''zasp.runtime_precision_reconciliation_claim'',CASE WHEN allow_v2 THEN ''runtime-event-v2'' ELSE '''' END,true);\n',1),
  ('AND work_row.state NOT IN(''succeeded'',''quarantined'')','AND authority_row.batch_generation=work_row.batch_generation AND (authority_row.payload_schema_version=''runtime-event-v1'' OR allow_v2 AND authority_row.payload_schema_version=''runtime-event-v2'') AND work_row.state NOT IN(''succeeded'',''quarantined'')',1),
  ('UPDATE zasp_runtime_ingest_reconciliation_work SET state=CASE','UPDATE zasp_runtime_ingest_reconciliation_work work_row SET state=CASE',1),
  ('WHERE state=''leased'' AND lease_expires_at<=transaction_timestamp();','WHERE state=''leased'' AND lease_expires_at<=transaction_timestamp() AND EXISTS(SELECT 1 FROM zasp_runtime_batch_authorities authority_row WHERE (authority_row.organization_id,authority_row.workspace_id,authority_row.environment_id,authority_row.batch_id,authority_row.batch_generation)=(work_row.organization_id,work_row.workspace_id,work_row.environment_id,work_row.batch_id,work_row.batch_generation) AND (authority_row.payload_schema_version=''runtime-event-v1'' OR allow_v2 AND authority_row.payload_schema_version=''runtime-event-v2''));',1),
  ('WHERE work_row.state IN(''pending'',''retryable'')','WHERE authority_row.batch_generation=work_row.batch_generation AND (authority_row.payload_schema_version=''runtime-event-v1'' OR allow_v2 AND authority_row.payload_schema_version=''runtime-event-v2'') AND work_row.state IN(''pending'',''retryable'')',1),
  (' RETURN response;',E' PERFORM zasp_runtime_precision_reconciliation_ready();\n PERFORM set_config(''zasp.runtime_precision_reconciliation_claim'',prior_capability,true);\n RETURN response;',1)
 ) changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision recovery predecessor rejected: '||needle;END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
 -- Shared durable transitions retain existing lease and digest/replay rules.
 -- Recheck after waits and before every return, including terminal replay.
 FOR item IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN('zasp_runtime_release_reconciliation','zasp_runtime_finish_reconciliation','zasp_runtime_quarantine_reconciliation') LOOP
  definition:=pg_get_functiondef(item.oid);
  definition:=replace(definition,E'BEGIN\n',E'BEGIN\n PERFORM zasp_runtime_precision_reconciliation_ready();\n');
  definition:=replace(definition,' RETURN ',E' PERFORM zasp_runtime_precision_reconciliation_ready();\n RETURN ');
  EXECUTE definition;
 END LOOP;
END $recovery$;
ALTER FUNCTION public.zasp_runtime_precision_claim_reconciliation(text,text,integer,integer,boolean) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_claim_reconciliation(text,text,integer,integer,boolean) FROM PUBLIC;
CREATE OR REPLACE FUNCTION public.zasp_runtime_claim_reconciliation(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
 SELECT zasp_runtime_precision_claim_reconciliation(worker_value,lease_token_value,lease_seconds,claim_limit,false)
$claim$;
CREATE FUNCTION public.zasp_runtime_claim_reconciliation_v2(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
 SELECT zasp_runtime_precision_claim_reconciliation(worker_value,lease_token_value,lease_seconds,claim_limit,true)
$claim$;
ALTER FUNCTION public.zasp_runtime_claim_reconciliation_v2(text,text,integer,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_reconciliation_v2(text,text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_reconciliation_v2(text,text,integer,integer) TO zasp_runtime_ingest;

CREATE FUNCTION public.zasp_runtime_precision_reconciliation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM zasp_runtime_batch_authorities b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.batch_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id) AND b.payload_schema_version='runtime-event-v2') THEN
  IF NOT COALESCE(zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision recovery unavailable';END IF;
  -- The authenticated request finalizer may finish after a recovery lease
  -- expires. It does not declare a recovery-reader capability. Fence the old
  -- claim's retryable/exhausted cleanup here; observed completion is separate.
  IF NEW.attempt>OLD.attempt OR NEW.state='leased' AND (OLD.state,OLD.lease_owner,OLD.lease_token) IS DISTINCT FROM (NEW.state,NEW.lease_owner,NEW.lease_token) OR OLD.state='leased' AND OLD.lease_expires_at<=transaction_timestamp() AND NEW.state IN('retryable','exhausted') OR NEW.completion_worker='observed' AND NEW.state IS DISTINCT FROM OLD.state THEN
   IF NOT COALESCE(current_setting('zasp.runtime_precision_reconciliation_claim',true)='runtime-event-v2' AND zasp_discovery_principal_ready('zasp_runtime_ingest'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime precision recovery claim rejected';END IF;
  END IF;
 END IF;
 RETURN NEW;
END $guard$;
ALTER FUNCTION public.zasp_runtime_precision_reconciliation_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_reconciliation_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_precision_reconciliation BEFORE UPDATE ON public.zasp_runtime_ingest_reconciliation_work FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_precision_reconciliation_guard();

-- Queue publication declares codec support; physical delivery remains a shared
-- schema-agnostic v15 transport. Both are fenced by the complete release.
CREATE FUNCTION public.zasp_runtime_precision_transport_ready() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $ready$
BEGIN
 IF NOT COALESCE(zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision transport unavailable';END IF;
END $ready$;
ALTER FUNCTION public.zasp_runtime_precision_transport_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_transport_ready() FROM PUBLIC;

DO $outbox$
DECLARE definition text;needle text;replacement text;expected integer;
BEGIN
 definition:=pg_get_functiondef('public.zasp_runtime_claim_outbox(text,text,text,integer,integer)'::regprocedure);
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('FUNCTION public.zasp_runtime_claim_outbox(topic_value text, worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer)','FUNCTION public.zasp_runtime_precision_claim_outbox(topic_value text, worker_value text, lease_token_value text, lease_seconds integer, claim_limit integer, allow_v2 boolean)',1),
  ('DECLARE response jsonb;','DECLARE response jsonb;prior_capability text;',1),
  (E'BEGIN\n',E'BEGIN\n PERFORM zasp_runtime_precision_transport_ready();\n IF topic_value IS NULL OR worker_value IS NULL OR lease_token_value IS NULL OR lease_seconds IS NULL OR claim_limit IS NULL OR allow_v2 IS NULL THEN RAISE EXCEPTION USING ERRCODE=''22023'',MESSAGE=''runtime outbox claim rejected'';END IF;\n IF allow_v2 AND NOT zasp_discovery_principal_ready(''zasp_outbox_worker'') THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''runtime precise outbox principal rejected'';END IF;\n prior_capability:=COALESCE(current_setting(''zasp.runtime_precision_outbox_claim'',true),'''');\n PERFORM set_config(''zasp.runtime_precision_outbox_claim'',CASE WHEN allow_v2 THEN ''runtime-event-v2'' ELSE '''' END,true);\n',1),
  ('WHERE topic=topic_value AND attempt>=100','WHERE topic=topic_value AND (payload->>''payload_schema_version''=''runtime-event-v1'' OR allow_v2 AND payload->>''payload_schema_version''=''runtime-event-v2'') AND attempt>=100',1),
  ('WHERE candidate.topic=topic_value AND candidate.attempt<100','WHERE candidate.topic=topic_value AND (candidate.payload->>''payload_schema_version''=''runtime-event-v1'' OR allow_v2 AND candidate.payload->>''payload_schema_version''=''runtime-event-v2'') AND candidate.attempt<100',1),
  ('AND outbox.topic=topic_value AND outbox.attempt<100','AND outbox.topic=topic_value AND (outbox.payload->>''payload_schema_version''=''runtime-event-v1'' OR allow_v2 AND outbox.payload->>''payload_schema_version''=''runtime-event-v2'') AND outbox.attempt<100',1),
  (' RETURN response;',E' PERFORM zasp_runtime_precision_transport_ready();\n PERFORM set_config(''zasp.runtime_precision_outbox_claim'',prior_capability,true);\n RETURN response;',1)
 ) changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision outbox predecessor rejected: '||needle;END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
END $outbox$;
ALTER FUNCTION public.zasp_runtime_precision_claim_outbox(text,text,text,integer,integer,boolean) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_claim_outbox(text,text,text,integer,integer,boolean) FROM PUBLIC;
CREATE OR REPLACE FUNCTION public.zasp_runtime_claim_outbox(topic_value text,worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
 SELECT zasp_runtime_precision_claim_outbox(topic_value,worker_value,lease_token_value,lease_seconds,claim_limit,false)
$claim$;
CREATE FUNCTION public.zasp_runtime_claim_outbox_v2(topic_value text,worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
 SELECT zasp_runtime_precision_claim_outbox(topic_value,worker_value,lease_token_value,lease_seconds,claim_limit,true)
$claim$;
ALTER FUNCTION public.zasp_runtime_claim_outbox_v2(text,text,text,integer,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_claim_outbox_v2(text,text,text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_claim_outbox_v2(text,text,text,integer,integer) TO zasp_outbox_worker;

DO $transport$
DECLARE item record;definition text;
BEGIN
 FOR item IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN('zasp_runtime_heartbeat_outbox','zasp_runtime_ack_outbox','zasp_runtime_retry_outbox','zasp_runtime_claim_delivery','zasp_runtime_heartbeat_delivery','zasp_runtime_release_delivery','zasp_runtime_ack_delivery') LOOP
  definition:=pg_get_functiondef(item.oid);
  IF strpos(definition,E'BEGIN\n')=0 OR strpos(definition,' RETURN ')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision transport predecessor rejected';END IF;
  definition:=replace(definition,E'BEGIN\n',E'BEGIN\n PERFORM zasp_runtime_precision_transport_ready();\n');
  definition:=replace(definition,' RETURN ',E' PERFORM zasp_runtime_precision_transport_ready();\n RETURN ');
  EXECUTE definition;
 END LOOP;
END $transport$;

CREATE FUNCTION public.zasp_runtime_precision_outbox_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF OLD.topic='runtime-events' AND OLD.payload->>'payload_schema_version'='runtime-event-v2' OR NEW.topic='runtime-events' AND NEW.payload->>'payload_schema_version'='runtime-event-v2' THEN
  PERFORM zasp_runtime_precision_transport_ready();
  IF NEW.attempt>OLD.attempt OR NEW.state='leased' AND (OLD.state,OLD.lease_owner,OLD.lease_token) IS DISTINCT FROM (NEW.state,NEW.lease_owner,NEW.lease_token) OR NEW.state='exhausted' AND (OLD.state='failed' OR OLD.state='leased' AND OLD.lease_expires_at<=transaction_timestamp()) THEN
   IF NOT COALESCE(current_setting('zasp.runtime_precision_outbox_claim',true)='runtime-event-v2' AND zasp_discovery_principal_ready('zasp_outbox_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime precision outbox claim rejected';END IF;
  END IF;
 END IF;
 RETURN NEW;
END $guard$;
ALTER FUNCTION public.zasp_runtime_precision_outbox_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_outbox_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_precision_outbox BEFORE UPDATE ON public.zasp_discovery_outbox FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_precision_outbox_guard();

CREATE FUNCTION public.zasp_runtime_precision_delivery_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM zasp_runtime_batch_authorities b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.batch_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id) AND b.payload_schema_version='runtime-event-v2') THEN PERFORM zasp_runtime_precision_transport_ready();END IF;
 RETURN NEW;
END $guard$;
ALTER FUNCTION public.zasp_runtime_precision_delivery_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_delivery_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_precision_delivery BEFORE INSERT OR UPDATE ON public.zasp_runtime_deliveries FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_precision_delivery_guard();
CREATE FUNCTION public.zasp_runtime_precision_batch_update_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF OLD.payload_schema_version='runtime-event-v2' OR NEW.payload_schema_version='runtime-event-v2' OR OLD.source_kind='otlp' AND OLD.payload_schema_version='runtime-event-v1' OR NEW.source_kind='otlp' AND NEW.payload_schema_version='runtime-event-v1' THEN PERFORM zasp_runtime_precision_transport_ready();END IF;
 RETURN NEW;
END $guard$;
ALTER FUNCTION public.zasp_runtime_precision_batch_update_guard() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precision_batch_update_guard() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_precision_batch_update BEFORE UPDATE ON public.zasp_runtime_batch_authorities FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_precision_batch_update_guard();

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  definition:=pg_get_functiondef(function_name::regprocedure);prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 50','later_release."version" > 51'),'later."version">50','later."version">51'),'later."version" > 50','later."version" > 51');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END $compatibility$;

CREATE FUNCTION public.zasp_production_runtime_precision_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_sandbox_binding_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='zasp_precision_predecessor' OR n.nspname='public' AND (p.proname LIKE '%precision%' OR p.proname LIKE '%precise%' OR p.proname IN('zasp_runtime_claim_archive_v2','zasp_runtime_claim_index_v2','zasp_runtime_claim_correlation_v4','zasp_runtime_claim_projection_v3','zasp_runtime_claim_completion_v3','zasp_runtime_claim_reconciliation_v2','zasp_runtime_claim_outbox_v2'))
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_precision_predecessor'
 UNION ALL SELECT concat_ws('|','constraint',conrelid::regclass::text,conname,convalidated,pg_get_constraintdef(oid,true)) FROM pg_constraint WHERE conname='zasp_runtime_precision_source_check'
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,true),p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN('public.zasp_runtime_batch_authorities'::regclass,'public.zasp_runtime_stage_work'::regclass,'public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass,'public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass,'public.zasp_runtime_session_search_outbox'::regclass,'public.zasp_runtime_sandbox_search_outbox'::regclass,'public.zasp_runtime_ingest_reconciliation_work'::regclass,'public.zasp_runtime_ingest_reconciliation_state'::regclass,'public.zasp_discovery_outbox'::regclass,'public.zasp_discovery_outbox_topic_fairness'::regclass,'public.zasp_runtime_deliveries'::regclass) AND NOT t.tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_precision_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=51 AND name='production_runtime_precision' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_precision_checksum' AND value=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint' AND value=expected_fingerprint) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>51) AND zasp_production_runtime_sandbox_binding_security_ready() AND zasp_production_runtime_precision_live_fingerprint()=expected_fingerprint,false)
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_precision_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_precision_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_precision_live_fingerprint(),public.zasp_production_runtime_precision_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_precision_readiness(text,text) TO zasp_runtime_ingest,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_runtime_coordinator,zasp_discovery_worker,zasp_discovery_api,zasp_outbox_worker;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_freeze_precise_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) TO zasp_runtime_correlation_worker;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea) TO zasp_runtime_coordinator;
CREATE OR REPLACE FUNCTION public.zasp_production_runtime_sandbox_binding_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT COALESCE(expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=50 AND name='production_runtime_sandbox_binding' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_checksum' AND value=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_precision_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=51),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_precision_fingerprint')),false)
$compatibility$;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_precision_fingerprint', 'f22c0461b7ae0610e184e439c2c8b42fc2136ef5e293dc66b99faf01af7d9fdd');
