-- Native admissions are provenance, never a cached provider allow. Captures
-- contain no connector configuration, credential reference, or provider body.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE pronamespace='zasp_temporal72'::regnamespace AND proname IN('prepare_page','guard_page_effect','prepare_apply','commit_apply','record_page','settle','finish','scheduled_admit','public_request_sync','public_put_schedule','public_delete_schedule');
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_authorization80_temporal.projected72()'::regprocedure,'public.zasp_execution_record_public_mutation(text,text,text,text,text,text,jsonb,jsonb,text,text,bigint,text,text,text)'::regprocedure,'zasp_authorization79.capture()'::regprocedure);
CREATE TABLE zasp_authorization80_worker.discovery_schedule_grants(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,schedule_id text NOT NULL,version bigint NOT NULL,
 grantor_id text NOT NULL,identity jsonb NOT NULL,provenance jsonb NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,schedule_id,version));
CREATE TABLE zasp_authorization80_worker.discovery_associations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,job_id text NOT NULL,sync_id text NOT NULL,integration_id text NOT NULL,
 principal_id text NOT NULL,grantor_id text NOT NULL,source_kind text NOT NULL CHECK(source_kind IN('manual','schedule')),
 schedule_id text,schedule_version bigint,admission jsonb NOT NULL,provenance jsonb NOT NULL,deadline timestamptz NOT NULL,credential_facts jsonb NOT NULL,authority_until timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,job_id),UNIQUE(organization_id,workspace_id,environment_id,sync_id),CHECK((schedule_id IS NULL)=(schedule_version IS NULL)));
CREATE TABLE zasp_authorization80_worker.discovery_state(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,job_id text NOT NULL,state text NOT NULL,
 present boolean NOT NULL,current_source boolean NOT NULL,deadline timestamptz NOT NULL,authority_until timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,job_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,job_id) REFERENCES zasp_authorization80_worker.discovery_associations);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['discovery_schedule_grants','discovery_associations','discovery_state'] LOOP
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_authorization80_worker.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n);
  IF n<>'discovery_state' THEN EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_worker.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
  ELSE EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON zasp_authorization80_worker.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);END IF;
 END LOOP;
END $tables$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_capture_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $revision$
BEGIN
 IF TG_OP<>'UPDATE' OR (OLD.present,OLD.current_source,OLD.deadline,OLD.authority_until,OLD.state IN('admitted','collecting','partial','retryable','complete','applying')) IS DISTINCT FROM (NEW.present,NEW.current_source,NEW.deadline,NEW.authority_until,NEW.state IN('admitted','collecting','partial','retryable','complete','applying')) THEN
  PERFORM zasp_authorization79.touch(CASE WHEN TG_OP='DELETE' THEN OLD.organization_id ELSE NEW.organization_id END);
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $revision$;
CREATE TRIGGER worker_revision BEFORE INSERT OR UPDATE OR DELETE ON zasp_authorization80_worker.discovery_state FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.discovery72_capture_revision();

CREATE FUNCTION zasp_authorization80_worker.discovery72_schedule_identity(s zasp_temporal72.schedules) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $identity$
 SELECT jsonb_build_object('organization_id',s.organization_id,'workspace_id',s.workspace_id,'environment_id',s.environment_id,'schedule_id',s.id,'integration_id',s.integration_id,'cadence_seconds',s.cadence_seconds,'state',s.state,'version',s.version,'anchor_us',floor(extract(epoch FROM s.anchor)*1000000)::bigint,'created_us',floor(extract(epoch FROM s.created_at)*1000000)::bigint,'updated_us',floor(extract(epoch FROM s.updated_at)*1000000)::bigint,'parser_version',s.parser_version,'tool_version',s.tool_version)
$identity$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_admission_identity(r zasp_temporal72.runs) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $identity$
 SELECT jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'job_id',r.job_id,'sync_id',r.sync_id,'integration_id',r.integration_id,'schedule_id',r.schedule_id,'scheduled_for_us',floor(extract(epoch FROM r.scheduled_for)*1000000)::bigint,'request_digest',encode(r.request_digest,'hex'),'outbox_id',r.outbox_id,'connection_id',r.connection_id,'provider',r.provider,'integration_version',r.integration_version,'connection_version',r.connection_version,'configuration_digest',encode(r.configuration_digest,'hex'),'credential_digest',encode(digest(convert_to(r.credential_reference,'UTF8'),'sha256'),'hex'),'subject_kind',r.subject_kind,'subject_id',r.subject_id,'admitted_us',floor(extract(epoch FROM r.admitted_at)*1000000)::bigint,'deadline_us',floor(extract(epoch FROM r.deadline)*1000000)::bigint)
$identity$;

CREATE FUNCTION zasp_authorization80_worker.discovery72_credentials(r zasp_temporal72.runs) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $credentials$
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',c.id,'class',c.credential_class,'version',c.version,'status',c.status,'metadata',c.metadata,'rotated_from_id',c.rotated_from_id,'expires_us',floor(extract(epoch FROM c.expires_at)*1000000)::bigint) ORDER BY c.id),'[]'::jsonb) FROM public.zasp_connector_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.provider,c.credential_reference)=(r.organization_id,r.workspace_id,r.environment_id,r.integration_id,r.provider,r.credential_reference)
$credentials$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_store_association(r zasp_temporal72.runs,principal text,grantor text,kind text,schedule_version bigint,provenance jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $capture$
DECLARE a zasp_authorization80_worker.discovery_associations%ROWTYPE;credentials jsonb;until_value timestamptz;BEGIN
 IF r.job_id IS NULL OR NOT public.zasp_valid_product_id(principal) OR NOT public.zasp_valid_product_id(grantor) OR provenance IS NULL OR kind NOT IN('manual','schedule')
 OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_syncs s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.id,s.integration_id,s.request_digest,s.trigger_kind)=(r.organization_id,r.workspace_id,r.environment_id,r.sync_id,r.integration_id,r.request_digest,kind)
 AND s.principal_id=CASE kind WHEN 'manual' THEN grantor ELSE principal END)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_outbox b WHERE(b.organization_id,b.workspace_id,b.environment_id,b.id,b.topic)=(r.organization_id,r.workspace_id,r.environment_id,r.outbox_id,'discovery-jobs') AND b.payload=jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'job_id',r.job_id,'sync_id',r.sync_id,'integration_id',r.integration_id,'request_digest',encode(r.request_digest,'hex')) AND b.payload_digest=digest(convert_to(b.payload::text,'UTF8'),'sha256'))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery admission provenance rejected';END IF;
 credentials:=zasp_authorization80_worker.discovery72_credentials(r);
 SELECT LEAST(r.deadline,min(c.expires_at)) INTO until_value FROM public.zasp_connector_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.provider,c.credential_reference)=(r.organization_id,r.workspace_id,r.environment_id,r.integration_id,r.provider,r.credential_reference);
 a:=(r.organization_id,r.workspace_id,r.environment_id,r.job_id,r.sync_id,r.integration_id,principal,grantor,kind,r.schedule_id,schedule_version,zasp_authorization80_worker.discovery72_admission_identity(r),provenance,r.deadline,credentials,until_value);
 INSERT INTO zasp_authorization80_worker.discovery_associations SELECT a.* ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.discovery_associations old WHERE old=a) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery captured admission changed';END IF;
 INSERT INTO zasp_authorization80_worker.discovery_state VALUES(r.organization_id,r.workspace_id,r.environment_id,r.job_id,r.state,true,true,r.deadline,until_value) ON CONFLICT DO NOTHING;
END $capture$;

CREATE FUNCTION zasp_authorization80_worker.discovery72_capture_mutation(v public.zasp_workflow_idempotency) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $mutation$
DECLARE audit public.zasp_workflow_audit%ROWTYPE;s zasp_temporal72.schedules%ROWTYPE;r zasp_temporal72.runs%ROWTYPE;body jsonb;proof jsonb;g zasp_authorization80_worker.discovery_schedule_grants%ROWTYPE;BEGIN
 IF v.operation NOT IN('syncIntegration','putIntegrationSchedule') THEN RETURN;END IF;
 SELECT * INTO STRICT audit FROM public.zasp_workflow_audit a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.audit_id,a.correlation_id,a.principal_id,a.operation)=(v.organization_id,v.workspace_id,v.environment_id,v.response->>'audit_id',v.response->>'correlation_id',v.principal_id,v.operation);
 body:=v.response->'body';
 IF body IS NULL OR jsonb_typeof(body)<>'object' OR audit.resource_version IS DISTINCT FROM(v.response->>'version')::bigint THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery mutation receipt rejected';END IF;
 proof:=jsonb_build_object('audit_id',audit.audit_id,'audit_digest',encode(digest(convert_to(jsonb_build_array(audit.organization_id,audit.workspace_id,audit.environment_id,audit.audit_id,audit.correlation_id,audit.principal_id,audit.operation,audit.resource_kind,audit.resource_id,audit.resource_version)::text,'UTF8'),'sha256'),'hex'),'idempotency_key',v.idempotency_key,'request_digest',encode(v.request_digest,'hex'),'response_digest',encode(digest(convert_to(v.response::text,'UTF8'),'sha256'),'hex'));
 IF v.operation='putIntegrationSchedule' THEN
  SELECT * INTO STRICT s FROM zasp_temporal72.schedules WHERE(organization_id,workspace_id,environment_id,integration_id)=(v.organization_id,v.workspace_id,v.environment_id,audit.resource_id);
  IF audit.resource_kind<>'integration_schedule' OR body->>'integration_id' IS DISTINCT FROM s.integration_id OR(body->>'version')::bigint IS DISTINCT FROM s.version OR(body->>'cadence_seconds')::integer IS DISTINCT FROM s.cadence_seconds OR body->>'state' IS DISTINCT FROM s.state OR(body->>'created_at')::timestamptz IS DISTINCT FROM s.created_at OR(body->>'updated_at')::timestamptz IS DISTINCT FROM s.updated_at OR s.state='enabled' AND(body->>'next_run_at')::timestamptz IS DISTINCT FROM s.anchor THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery schedule provenance prerequisite';END IF;
  g:=(s.organization_id,s.workspace_id,s.environment_id,s.id,s.version,v.principal_id,zasp_authorization80_worker.discovery72_schedule_identity(s),proof);
  INSERT INTO zasp_authorization80_worker.discovery_schedule_grants SELECT g.* ON CONFLICT DO NOTHING;
  IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.discovery_schedule_grants old WHERE old=g) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery schedule provenance changed';END IF;
 ELSE
  SELECT * INTO STRICT r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,sync_id)=(v.organization_id,v.workspace_id,v.environment_id,audit.resource_id);
  IF audit.resource_kind<>'integration_sync' OR body->>'id' IS DISTINCT FROM r.sync_id OR body->>'integration_id' IS DISTINCT FROM r.integration_id OR r.schedule_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_syncs y WHERE(y.organization_id,y.workspace_id,y.environment_id,y.id,y.principal_id,y.idempotency_key,y.trigger_kind)=(r.organization_id,r.workspace_id,r.environment_id,r.sync_id,v.principal_id,v.idempotency_key,'manual')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery manual provenance prerequisite';END IF;
  PERFORM zasp_authorization80_worker.discovery72_store_association(r,public.zasp_discovery_canonical_id(r.organization_id,r.workspace_id,r.environment_id,'discovery_sync_service',r.sync_id),v.principal_id,'manual',NULL,proof);
 END IF;
END $mutation$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_mutation_capture() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $trigger$
BEGIN
 IF NEW.operation NOT IN('syncIntegration','putIntegrationSchedule') THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=session_user AND authority_role='zasp_discovery_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery provenance API session rejected';END IF;
 PERFORM zasp_authorization80_worker.discovery72_human_capture(NEW);
 PERFORM zasp_authorization80_worker.discovery72_capture_mutation(NEW);RETURN NULL;
END $trigger$;
CREATE TRIGGER zasp_authorization80_worker_discovery_admission AFTER INSERT ON public.zasp_workflow_idempotency FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.discovery72_mutation_capture();

CREATE FUNCTION zasp_authorization80_worker.discovery72_capture_scheduled(o text,w text,e text,j text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $scheduled$
DECLARE r zasp_temporal72.runs%ROWTYPE;s zasp_temporal72.schedules%ROWTYPE;g zasp_authorization80_worker.discovery_schedule_grants%ROWTYPE;BEGIN
 SELECT * INTO STRICT r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 SELECT * INTO STRICT s FROM zasp_temporal72.schedules WHERE(organization_id,workspace_id,environment_id,id,integration_id)=(o,w,e,r.schedule_id,r.integration_id);
 SELECT * INTO STRICT g FROM zasp_authorization80_worker.discovery_schedule_grants WHERE(organization_id,workspace_id,environment_id,schedule_id,version)=(o,w,e,s.id,s.version);
 IF s.state<>'enabled' OR s.updated_at>r.admitted_at OR r.scheduled_for<s.anchor OR g.identity IS DISTINCT FROM zasp_authorization80_worker.discovery72_schedule_identity(s) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery scheduled provenance prerequisite';END IF;
 PERFORM zasp_authorization80_worker.discovery72_store_association(r,s.id,g.grantor_id,'schedule',s.version,g.provenance);
END $scheduled$;

CREATE FUNCTION zasp_authorization80_worker.discovery72_capture_source() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $capture_source$
DECLARE old_value jsonb:=to_jsonb(OLD);new_value jsonb:=CASE WHEN TG_OP='DELETE' THEN NULL ELSE to_jsonb(NEW) END;keys text[];BEGIN
 IF TG_TABLE_SCHEMA='zasp_temporal72' AND TG_TABLE_NAME='runs' THEN
  IF TG_OP='DELETE' THEN UPDATE zasp_authorization80_worker.discovery_state SET present=false WHERE(organization_id,workspace_id,environment_id,job_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.job_id);
  ELSE UPDATE zasp_authorization80_worker.discovery_state SET state=NEW.state,current_source=current_source AND zasp_authorization80_worker.discovery72_admission_identity(OLD)=zasp_authorization80_worker.discovery72_admission_identity(NEW) WHERE(organization_id,workspace_id,environment_id,job_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.job_id);END IF;
 ELSIF TG_TABLE_SCHEMA='zasp_temporal72' AND TG_TABLE_NAME='schedules' THEN
  IF TG_OP='DELETE' OR zasp_authorization80_worker.discovery72_schedule_identity(OLD) IS DISTINCT FROM zasp_authorization80_worker.discovery72_schedule_identity(NEW) THEN
   UPDATE zasp_authorization80_worker.discovery_state st SET current_source=false FROM zasp_authorization80_worker.discovery_associations a WHERE(st.organization_id,st.workspace_id,st.environment_id,st.job_id)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id) AND(a.organization_id,a.workspace_id,a.environment_id,a.schedule_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.id);
  END IF;
 ELSE
  keys:=CASE TG_TABLE_NAME WHEN 'zasp_integrations' THEN ARRAY['organization_id','workspace_id','environment_id','id','kind','version','configuration','state','deleted_at'] WHEN 'zasp_integration_connections' THEN ARRAY['organization_id','workspace_id','environment_id','integration_id','id','provider','version','connection_reference','state','revoked_at'] WHEN 'zasp_discovery_connection_subjects' THEN ARRAY['organization_id','workspace_id','environment_id','integration_id','connection_id','provider','subject_kind','subject_id','connection_version','configuration_digest'] ELSE ARRAY['organization_id','workspace_id','environment_id','integration_id','id','provider','version','credential_class','credential_reference','status','metadata','expires_at','rotated_from_id'] END;
  IF TG_OP='DELETE' OR EXISTS(SELECT 1 FROM unnest(keys) k WHERE old_value->k IS DISTINCT FROM new_value->k) THEN
   UPDATE zasp_authorization80_worker.discovery_state st SET current_source=false FROM zasp_authorization80_worker.discovery_associations a WHERE(st.organization_id,st.workspace_id,st.environment_id,st.job_id)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id) AND(a.organization_id,a.workspace_id,a.environment_id,a.integration_id)=(old_value->>'organization_id',old_value->>'workspace_id',old_value->>'environment_id',CASE WHEN TG_TABLE_NAME='zasp_integrations' THEN old_value->>'id' ELSE old_value->>'integration_id' END);
  END IF;
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $capture_source$;
DO $triggers$ DECLARE relation regclass;BEGIN
 FOREACH relation IN ARRAY ARRAY['zasp_temporal72.runs'::regclass,'zasp_temporal72.schedules'::regclass,'public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_connection_subjects'::regclass,'public.zasp_connector_credentials'::regclass] LOOP
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_discovery_source BEFORE UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.discovery72_capture_source()',relation);
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_discovery_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',relation);
 END LOOP;
END $triggers$;

CREATE FUNCTION zasp_authorization80_worker.expire_discovery72(o text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $expiry$
BEGIN
 IF NOT zasp_authorization79.worker() OR NOT zasp_authorization79.locked(o) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery expiry session rejected';END IF;
 UPDATE zasp_authorization80_worker.discovery_state SET current_source=false WHERE organization_id=o AND current_source AND authority_until<=clock_timestamp();
END $expiry$;

-- Backfill only exact retained native evidence. No fabricated owner/delegation.
DO $backfill$ DECLARE v public.zasp_workflow_idempotency%ROWTYPE;s zasp_temporal72.schedules%ROWTYPE;r zasp_temporal72.runs%ROWTYPE;count_value integer;BEGIN
 FOR s IN SELECT * FROM zasp_temporal72.schedules WHERE state='enabled' LOOP
  SELECT count(*) INTO count_value FROM public.zasp_workflow_idempotency i JOIN public.zasp_workflow_audit a ON(a.organization_id,a.audit_id)=(i.organization_id,i.response->>'audit_id') WHERE(i.organization_id,i.workspace_id,i.environment_id,i.operation,a.resource_id,a.resource_version)=(s.organization_id,s.workspace_id,s.environment_id,'putIntegrationSchedule',s.integration_id,s.version);
  IF count_value<>1 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery schedule provenance prerequisite';END IF;
  SELECT i.* INTO STRICT v FROM public.zasp_workflow_idempotency i JOIN public.zasp_workflow_audit a ON(a.organization_id,a.audit_id)=(i.organization_id,i.response->>'audit_id') WHERE(i.organization_id,i.workspace_id,i.environment_id,i.operation,a.resource_id,a.resource_version)=(s.organization_id,s.workspace_id,s.environment_id,'putIntegrationSchedule',s.integration_id,s.version);
  PERFORM zasp_authorization80_worker.discovery72_capture_mutation(v);
 END LOOP;
 -- Terminal native runs also need immutable provenance for retained Activity
 -- receipt/cleanup retries. Missing proof is an installation gate, not a
 -- silent loss of recovery; active_discovery never delegates terminal work.
 FOR r IN SELECT * FROM zasp_temporal72.runs LOOP
  IF r.schedule_id IS NOT NULL THEN PERFORM zasp_authorization80_worker.discovery72_capture_scheduled(r.organization_id,r.workspace_id,r.environment_id,r.job_id);
  ELSE
   SELECT i.* INTO STRICT v FROM public.zasp_workflow_idempotency i JOIN public.zasp_workflow_audit a ON(a.organization_id,a.audit_id)=(i.organization_id,i.response->>'audit_id') WHERE(i.organization_id,i.workspace_id,i.environment_id,i.operation,a.resource_id)=(r.organization_id,r.workspace_id,r.environment_id,'syncIntegration',r.sync_id);
   PERFORM zasp_authorization80_worker.discovery72_capture_mutation(v);
  END IF;
 END LOOP;
END $backfill$;

CREATE VIEW zasp_authorization80_worker.active_discovery AS
 SELECT a.* FROM zasp_authorization80_worker.discovery_associations a JOIN zasp_authorization80_worker.discovery_state s USING(organization_id,workspace_id,environment_id,job_id)
 JOIN public.zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(a.organization_id,a.grantor_id)
 WHERE m.active AND s.present AND s.current_source AND s.authority_until>clock_timestamp() AND s.state IN('admitted','collecting','partial','retryable','complete','applying');
ALTER VIEW zasp_authorization80_worker.active_discovery OWNER TO zasp_discovery_authority;
DO $views$ DECLARE d text;BEGIN
 SELECT pg_get_viewdef('zasp_authorization79.members'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.members AS '||rtrim(d,E';\n ')||' UNION SELECT organization_id,''service''::text,principal_id,''''::text FROM zasp_authorization80_worker.active_discovery';
 SELECT pg_get_viewdef('zasp_authorization79.current_grants'::regclass) INTO d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.current_grants AS SELECT g.* FROM ('||rtrim(d,E';\n ')||$grants$) g WHERE NOT(g.principal_kind='service' AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.discovery_associations a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.sync_id)=(g.organization_id,g.workspace_id,g.environment_id,g.task_id)))
 UNION SELECT a.organization_id,a.workspace_id,a.environment_id,'integration'::text,a.integration_id,'service'::text,a.principal_id,p.permission,a.sync_id FROM zasp_authorization80_worker.active_discovery a CROSS JOIN(VALUES('manage_workflows'::text),('view'::text)) p(permission)$grants$;
END $views$;
