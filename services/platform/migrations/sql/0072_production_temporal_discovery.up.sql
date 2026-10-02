-- Discovery execution state belongs to72. No legacy queued job is inserted.
-- The public sync and required discovery SQS outbox remain product records.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal72 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal72 FROM PUBLIC;
CREATE TABLE zasp_temporal72.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal72.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE TABLE zasp_temporal72.principals(principal_name text PRIMARY KEY,authority_role text NOT NULL UNIQUE CHECK(authority_role IN('zasp_discovery_api','zasp_discovery_worker','zasp_discovery_scheduler','zasp_outbox_worker')));
-- These are new counterparts to public schedules/job authorities/checkpoints.
-- No reference to public.zasp_discovery_jobs or legacy schedule_runs exists.
CREATE TABLE zasp_temporal72.schedules(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,id text NOT NULL CHECK(public.zasp_valid_product_id(id)),integration_id text NOT NULL,
 cadence_seconds integer NOT NULL CHECK(cadence_seconds BETWEEN 300 AND 2678400),state text NOT NULL CHECK(state IN('enabled','disabled','deleted')),
 next_run_at timestamptz NOT NULL,anchor timestamptz NOT NULL,version bigint NOT NULL CHECK(version BETWEEN 1 AND 1000000),
 parser_version text NOT NULL DEFAULT 'parser_v1',tool_version text NOT NULL DEFAULT 'tool_v1',
 acknowledged_revision bigint NOT NULL DEFAULT 0 CHECK(acknowledged_revision>=0),delivered_revision bigint NOT NULL DEFAULT 0 CHECK(delivered_revision>=0),
 created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,id),UNIQUE(organization_id,workspace_id,environment_id,integration_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id) REFERENCES public.zasp_integrations(organization_id,workspace_id,environment_id,id));
INSERT INTO zasp_temporal72.schedules(organization_id,workspace_id,environment_id,id,integration_id,cadence_seconds,state,next_run_at,anchor,version,created_at,updated_at)
 SELECT organization_id,workspace_id,environment_id,id,integration_id,cadence_seconds,state,next_run_at,next_run_at,version,created_at,updated_at FROM public.zasp_discovery_schedules;
CREATE TABLE zasp_temporal72.runs(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,job_id text NOT NULL CHECK(public.zasp_valid_product_id(job_id)),sync_id text NOT NULL,integration_id text NOT NULL,
 schedule_id text,scheduled_for timestamptz,request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),outbox_id text NOT NULL,
 connection_id text NOT NULL,provider text NOT NULL CHECK(provider IN('aws','kubernetes','github','okta')),integration_version bigint NOT NULL,connection_version bigint NOT NULL,
 configuration jsonb NOT NULL,configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),credential_reference text NOT NULL,subject_kind text NOT NULL,subject_id text NOT NULL,
 admitted_at timestamptz NOT NULL,deadline timestamptz NOT NULL,CHECK(deadline=admitted_at+interval '24 hours'),
 state text NOT NULL DEFAULT 'admitted' CHECK(state IN('admitted','collecting','partial','complete','applying','succeeded','incomplete','retryable','denied','revoked','malformed','terminal','cancelled','outcome_unknown')),
 checkpoint_version bigint NOT NULL DEFAULT 0 CHECK(checkpoint_version BETWEEN 0 AND 10000),checkpoint_digest text NOT NULL DEFAULT '',retry_not_before timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,job_id),UNIQUE(organization_id,workspace_id,environment_id,sync_id),
 UNIQUE(organization_id,workspace_id,environment_id,schedule_id,scheduled_for),
 FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,sync_id) REFERENCES public.zasp_discovery_syncs(organization_id,workspace_id,environment_id,integration_id,id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,integration_id,connection_id) REFERENCES public.zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id),
 CHECK(public.zasp_execution_subject_valid(provider,subject_kind,subject_id)),CHECK((schedule_id IS NULL)=(scheduled_for IS NULL)));
-- Known-no-IO admission receipts while another run owns this provider resource.
-- No lease, generation, effect identity or dispatch capability is stored here.
CREATE TABLE zasp_temporal72.page_waits(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,job_id text NOT NULL,
 expected_version bigint NOT NULL CHECK(expected_version BETWEEN 0 AND 9999),expected_digest text NOT NULL,
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object'),not_before timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,job_id,expected_version),
 FOREIGN KEY(organization_id,workspace_id,environment_id,job_id) REFERENCES zasp_temporal72.runs(organization_id,workspace_id,environment_id,job_id));
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal72.page_waits FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE TABLE zasp_temporal72.page_effects(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,job_id text NOT NULL,
 expected_version bigint NOT NULL CHECK(expected_version BETWEEN 0 AND 9999),expected_digest text NOT NULL,
 effect_id text NOT NULL CHECK(effect_id ~ '^[0-9a-f]{64}$'),prepared_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 result jsonb,record_digest text,recorded_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,job_id,expected_version),UNIQUE(effect_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,job_id) REFERENCES zasp_temporal72.runs(organization_id,workspace_id,environment_id,job_id),
 CHECK((result IS NULL AND record_digest IS NULL AND recorded_at IS NULL) OR (jsonb_typeof(result)='object' AND record_digest ~ '^[0-9a-f]{64}$' AND recorded_at IS NOT NULL)));
CREATE TABLE zasp_temporal72.checkpoints(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,job_id text NOT NULL,
 version bigint NOT NULL CHECK(version BETWEEN 1 AND 10000),digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),effect_id text NOT NULL CHECK(effect_id ~ '^[0-9a-f]{64}$'),cursor jsonb NOT NULL,manifest jsonb NOT NULL,candidate jsonb,
 PRIMARY KEY(organization_id,workspace_id,environment_id,job_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,job_id) REFERENCES zasp_temporal72.runs(organization_id,workspace_id,environment_id,job_id));
CREATE TABLE zasp_temporal72.apply_effects(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,job_id text NOT NULL,
 effect_id text NOT NULL UNIQUE CHECK(effect_id ~ '^[0-9a-f]{64}$'),complete_digest text NOT NULL CHECK(complete_digest ~ '^[0-9a-f]{64}$'),
 prepared_at timestamptz NOT NULL DEFAULT clock_timestamp(),result jsonb,committed_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,job_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,job_id) REFERENCES zasp_temporal72.runs(organization_id,workspace_id,environment_id,job_id),
 CHECK((result IS NULL AND committed_at IS NULL) OR (jsonb_typeof(result)='object' AND committed_at IS NOT NULL)));
INSERT INTO zasp_temporal72.principals
 SELECT principal_name,authority_role FROM public.zasp_discovery_principal_bindings WHERE authority_role IN('zasp_discovery_api','zasp_discovery_worker','zasp_outbox_worker')
 UNION ALL SELECT principal_name,authority_role FROM public.zasp_discovery_execution_principals WHERE authority_role='zasp_discovery_scheduler';
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions','principals'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal72.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal72.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal72.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal72.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal72.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
DO $product_tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['schedules','runs','page_waits','page_effects','checkpoints','apply_effects'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal72.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal72.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal72.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal72.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
 END LOOP;
END $product_tables$;
-- Exact retained domain helpers, not copied orchestration. The independent72
-- pin includes these definitions and ACLs; readiness rereads their live shape.
INSERT INTO zasp_temporal72.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN(
 'public.zasp_discovery_canonical_id(text,text,text,text,text)'::regprocedure,
 'public.zasp_discovery_relationship_id(text,text,text,text,text,text,text)'::regprocedure,
 'public.zasp_execution_subject_valid(text,text,text)'::regprocedure,
 'public.zasp_execution_bump_freshness(text,text,text,text)'::regprocedure,
 'public.zasp_workflow_replay(text,text,text,text,text,text,jsonb)'::regprocedure,
 'public.zasp_execution_record_public_mutation(text,text,text,text,text,text,jsonb,jsonb,text,text,bigint,text,text,text)'::regprocedure,
 'public.zasp_execution_sync_body(text,text,text,text,text)'::regprocedure,
 'public.zasp_execution_sync_history(text,text,text,text,timestamp with time zone,text,integer)'::regprocedure,
 'public.zasp_execution_last_good_freshness(text,text,text,text)'::regprocedure,
 'public.zasp_execution_principal_ready(text)'::regprocedure,
 'public.zasp_execution_sync_version_trigger()'::regprocedure,
 'public.zasp_effective_scope_permissions(jsonb,text)'::regprocedure,
 'public.zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb)'::regprocedure,
 'public.zasp_inventory_validate_typed_entities(text,jsonb)'::regprocedure,
 'public.zasp_inventory_bind_typed_entities(text,text,text,text,text,jsonb)'::regprocedure,
 'public.zasp_inventory_live_fingerprint()'::regprocedure,
 'public.zasp_execution_claim_jobs(text,text,integer,integer)'::regprocedure,
 'public.zasp_execution_live_fingerprint()'::regprocedure,
 'public.zasp_discovery_schedule_replay_function_identity(oid)'::regprocedure,
 'public.zasp_production_runtime_precision_live_fingerprint()'::regprocedure,
 'public.zasp_execution_claim_outbox(text,text,text,integer,integer)'::regprocedure,
 'public.zasp_execution_heartbeat_outbox(text,text,text,integer,integer)'::regprocedure,
 'public.zasp_execution_ack_outbox(text,text,text,text,text,text,text,text)'::regprocedure,
 'public.zasp_execution_retry_outbox(text,text,text,text,text,text,text,integer,text)'::regprocedure,
 'public.zasp_discovery_ack_outbox(text,text,text,text,text,text,text)'::regprocedure,
 'public.zasp_discovery_retry_outbox(text,text,text,text,text,text,integer,text)'::regprocedure,
 'public.zasp_discovery_s3_object_reference(text)'::regprocedure,
 'public.zasp_valid_product_id(text)'::regprocedure);

-- These two bootstrap helpers retain the registered migration owner's identity.
-- Project only that validated identity for catalog portability. Raw saved rows,
-- live ownership and effective grants are never rewritten by this projection.
CREATE FUNCTION zasp_temporal72.migration_helper_identity(s text,o text,a text) RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $identity$
DECLARE migration_owner oid;helper record;BEGIN
 IF s NOT IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)') THEN RETURN NULL;END IF;
 SELECT c.relowner INTO migration_owner FROM pg_class c JOIN pg_class core ON core.oid='public.zasp_core_payloads'::regclass AND core.relowner=c.relowner
 JOIN public.zasp_discovery_principal_bindings b ON b.authority_role='zasp_discovery_authority' AND b.principal_name=c.relowner::regrole::text
 JOIN pg_roles r ON r.oid=c.relowner AND r.rolcanlogin
 WHERE c.oid='public.zasp_authorized_scopes'::regclass;
 IF migration_owner IS NULL OR o IS DISTINCT FROM migration_owner::regrole::text THEN RETURN NULL;END IF;
 SELECT p.proowner,p.proacl INTO helper FROM pg_proc p WHERE p.oid=to_regprocedure('public.'||s);
 IF NOT FOUND OR helper.proowner IS DISTINCT FROM migration_owner OR COALESCE(helper.proacl::text,'') IS DISTINCT FROM a THEN RETURN NULL;END IF;
 IF s='zasp_valid_product_id(text)' THEN
  IF helper.proacl IS NOT NULL THEN RETURN NULL;END IF;
  RETURN '<migration-authority>|<default-function-acl>';
 END IF;
 IF helper.proacl IS NULL OR NOT(SELECT count(*)=3 AND count(DISTINCT x.grantee)=3 AND bool_and(x.grantor=migration_owner AND NOT x.is_grantable AND x.privilege_type='EXECUTE' AND x.grantee IN(0,migration_owner,'zasp_discovery_api'::regrole)) FROM aclexplode(helper.proacl) x) THEN RETURN NULL;END IF;
 RETURN '<migration-authority>|<public,owner,discovery-api:execute;grantor:owner;grantable:false>';
END $identity$;

CREATE FUNCTION zasp_temporal72.roles_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $roles$
 SELECT (SELECT count(*)=4 FROM zasp_temporal72.principals)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.principals p LEFT JOIN pg_roles r ON r.rolname=p.principal_name LEFT JOIN pg_roles a ON a.rolname=p.authority_role
  WHERE r.oid IS NULL OR a.oid IS NULL OR NOT r.rolcanlogin OR NOT r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
  OR a.rolcanlogin OR a.rolinherit OR a.rolsuper OR a.rolcreatedb OR a.rolcreaterole OR a.rolreplication OR a.rolbypassrls
  OR NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND m.roleid=a.oid AND NOT m.admin_option)
  OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND (m.roleid<>a.oid OR m.admin_option))
  OR NOT EXISTS(SELECT 1 FROM (SELECT principal_name,authority_role FROM public.zasp_discovery_principal_bindings UNION ALL SELECT principal_name,authority_role FROM public.zasp_discovery_execution_principals) b WHERE (b.principal_name,b.authority_role)=(p.principal_name,p.authority_role)))
$roles$;
CREATE FUNCTION zasp_temporal72.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 BEGIN RETURN COALESCE(c='-- discovery72 checksum' AND f='-- discovery72 fingerprint'
 AND zasp_temporal71.ready('-- legacy71 checksum','-- legacy71 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_temporal72.registration)
 AND EXISTS(SELECT 1 FROM zasp_temporal72.registration WHERE checksum=c AND fingerprint=f)
 AND zasp_temporal72.roles_ready() AND zasp_temporal72.fingerprint()=f
 AND (SELECT count(*)=2 AND bool_and(zasp_temporal72.migration_helper_identity(signature,owner_name,acl) IS NOT NULL) FROM zasp_temporal72.predecessor_functions WHERE signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)'))
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.predecessor_functions s LEFT JOIN pg_proc p ON p.oid=to_regprocedure(s.signature) WHERE p.oid IS NULL OR (s.signature NOT IN('zasp_production_runtime_precision_live_fingerprint()','zasp_execution_claim_jobs(text,text,integer,integer)','zasp_execution_live_fingerprint()','zasp_discovery_schedule_replay_function_identity(oid)') AND pg_get_functiondef(p.oid) IS DISTINCT FROM s.definition) OR p.proowner::regrole::text IS DISTINCT FROM s.owner_name OR COALESCE(p.proacl::text,'') IS DISTINCT FROM s.acl),false);END
$ready$;
CREATE FUNCTION zasp_temporal72.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal72.ready('-- discovery72 checksum','-- discovery72 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal72.require_principal(a text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $principal$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='discovery isolation rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal72.current_ready() OR NOT EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=session_user AND authority_role=a)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery principal rejected';END IF;
END $principal$;

CREATE FUNCTION zasp_temporal72.principal_ready(a text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $principal_ready$
BEGIN PERFORM zasp_temporal72.require_principal(a);RETURN true;END $principal_ready$;

CREATE FUNCTION zasp_temporal72.start_receipt(r zasp_temporal72.runs) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $receipt$
 SELECT jsonb_build_object('ref',jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'run_id',r.job_id),'integration_id',r.integration_id,'input_digest',encode(r.request_digest,'hex'))
$receipt$;

-- Public transport helpers retain their lease protocol. This row guard closes
-- their membership-only bypass for rows atomically owned by72 admission.
CREATE FUNCTION zasp_temporal72.outbox_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
DECLARE r zasp_temporal72.runs%ROWTYPE;row_value public.zasp_discovery_outbox%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' THEN row_value:=NEW;ELSE row_value:=OLD;END IF;
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,outbox_id)=(row_value.organization_id,row_value.workspace_id,row_value.environment_id,row_value.id);
 IF NOT FOUND THEN
  IF TG_OP='DELETE' THEN RETURN OLD;END IF;
  -- An update cannot move a retained row into an owned identity.
  IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,outbox_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.id)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery outbox ownership rejected';END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery outbox ownership rejected';END IF;
 IF TG_OP='INSERT' THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=session_user AND authority_role IN('zasp_discovery_api','zasp_discovery_worker','zasp_discovery_scheduler')) OR NOT zasp_temporal72.current_ready()
  OR NEW.topic IS DISTINCT FROM 'discovery-jobs' OR NEW.payload_version IS DISTINCT FROM 1
  OR NEW.payload IS DISTINCT FROM jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'job_id',r.job_id,'sync_id',r.sync_id,'integration_id',r.integration_id,'request_digest',encode(r.request_digest,'hex'))
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery outbox admission rejected';END IF;
 ELSE
  PERFORM zasp_temporal72.require_principal('zasp_outbox_worker');
  IF (NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.id,NEW.topic,NEW.deterministic_key,NEW.payload_version,NEW.payload,NEW.payload_digest,NEW.created_at) IS DISTINCT FROM (OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.id,OLD.topic,OLD.deterministic_key,OLD.payload_version,OLD.payload,OLD.payload_digest,OLD.created_at) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery outbox identity rejected';END IF;
 END IF;
 RETURN NEW;
END $guard$;
CREATE TRIGGER zasp_temporal72_outbox_guard BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_discovery_outbox FOR EACH ROW EXECUTE FUNCTION zasp_temporal72.outbox_guard();
CREATE FUNCTION zasp_temporal72.claim_outbox(topic_value text,worker_value text,token_value text,seconds_value integer,limit_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $transport$
BEGIN PERFORM zasp_temporal72.require_principal('zasp_outbox_worker');RETURN public.zasp_execution_claim_outbox(topic_value,worker_value,token_value,seconds_value,limit_value);END $transport$;
CREATE FUNCTION zasp_temporal72.heartbeat_outbox(topic_value text,worker_value text,token_value text,seconds_value integer,count_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $transport$
BEGIN PERFORM zasp_temporal72.require_principal('zasp_outbox_worker');RETURN public.zasp_execution_heartbeat_outbox(topic_value,worker_value,token_value,seconds_value,count_value);END $transport$;
CREATE FUNCTION zasp_temporal72.ack_outbox(topic_value text,o text,w text,e text,id_value text,worker_value text,token_value text,ack_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $transport$
BEGIN PERFORM zasp_temporal72.require_principal('zasp_outbox_worker');RETURN public.zasp_execution_ack_outbox(topic_value,o,w,e,id_value,worker_value,token_value,ack_value);END $transport$;
CREATE FUNCTION zasp_temporal72.retry_outbox(topic_value text,o text,w text,e text,id_value text,worker_value text,token_value text,seconds_value integer,error_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $transport$
BEGIN PERFORM zasp_temporal72.require_principal('zasp_outbox_worker');RETURN public.zasp_execution_retry_outbox(topic_value,o,w,e,id_value,worker_value,token_value,seconds_value,error_value);END $transport$;

-- Extraction roots:13 request_sync's connector/version/subject checks and10
-- request_sync's product sync/outbox writes. The old queued-job insertion is
-- absent. Invoked only by72 admission under the current principal boundary.
-- Writes invoke public13 sync-version only on UPDATE; all product tables keep
-- their FORCE RLS policy for zasp_discovery_authority. No legacy lease helper.
CREATE FUNCTION zasp_temporal72.admit(o text,w text,e text,p text,i text,s text,j text,b text,k text,d bytea,trigger_value text,parser_value text,tool_value text,schedule_value text,due_value timestamptz) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $admit$
DECLARE integration_row public.zasp_integrations%ROWTYPE;connection_row public.zasp_integration_connections%ROWTYPE;subject_row public.zasp_discovery_connection_subjects%ROWTYPE;r zasp_temporal72.runs%ROWTYPE;payload jsonb;now_value timestamptz;
BEGIN
 IF NOT(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(p) AND public.zasp_valid_product_id(i) AND public.zasp_valid_product_id(s) AND public.zasp_valid_product_id(j) AND public.zasp_valid_product_id(b))
 OR octet_length(d)<>32 OR length(k) NOT BETWEEN 16 AND 128 OR trigger_value NOT IN('manual','schedule') OR parser_value!~'^[a-z][a-z0-9_.-]{1,63}$' OR tool_value!~'^[a-z][a-z0-9_.-]{1,63}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery admission rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'discovery72-admit',o,w,e,i,k),0));
 SELECT * INTO r FROM zasp_temporal72.runs WHERE (organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 IF FOUND THEN
  IF (r.sync_id,r.integration_id,r.request_digest,r.outbox_id) IS DISTINCT FROM(s,i,d,b) OR r.schedule_id IS DISTINCT FROM schedule_value OR r.scheduled_for IS DISTINCT FROM due_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery admission conflict';END IF;
  RETURN jsonb_build_object('outcome','admitted','start',zasp_temporal72.start_receipt(r));
 END IF;
 SELECT * INTO integration_row FROM public.zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,i) AND state IN('active','degraded') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery connector revoked';END IF;
 SELECT * INTO connection_row FROM public.zasp_integration_connections WHERE (organization_id,workspace_id,environment_id,integration_id,provider,state)=(o,w,e,i,integration_row.kind,'verified') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery connection revoked';END IF;
 SELECT * INTO subject_row FROM public.zasp_discovery_connection_subjects WHERE (organization_id,workspace_id,environment_id,integration_id,connection_id,provider,connection_version,configuration_digest)=(o,w,e,i,connection_row.id,integration_row.kind,connection_row.version,digest(convert_to(integration_row.configuration::text,'UTF8'),'sha256')) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery subject rejected';END IF;
 now_value:=clock_timestamp();
 INSERT INTO public.zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version,requested_at)
 VALUES(o,w,e,s,i,k,d,trigger_value,p,parser_value,tool_value,now_value);
 INSERT INTO zasp_temporal72.runs(organization_id,workspace_id,environment_id,job_id,sync_id,integration_id,schedule_id,scheduled_for,request_digest,outbox_id,connection_id,provider,integration_version,connection_version,configuration,configuration_digest,credential_reference,subject_kind,subject_id,admitted_at,deadline)
 VALUES(o,w,e,j,s,i,schedule_value,due_value,d,b,connection_row.id,integration_row.kind,integration_row.version,connection_row.version,integration_row.configuration,subject_row.configuration_digest,connection_row.connection_reference,subject_row.subject_kind,subject_row.subject_id,now_value,now_value+interval '24 hours') RETURNING * INTO r;
 payload:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'job_id',j,'sync_id',s,'integration_id',i,'request_digest',encode(d,'hex'));
 INSERT INTO public.zasp_discovery_outbox(organization_id,workspace_id,environment_id,id,topic,deterministic_key,payload_version,payload,payload_digest)
 VALUES(o,w,e,b,'discovery-jobs','sync:'||s,1,payload,digest(convert_to(payload::text,'UTF8'),'sha256'));
 PERFORM public.zasp_execution_bump_freshness(o,w,e,i);
 RETURN jsonb_build_object('outcome','admitted','start',zasp_temporal72.start_receipt(r));
END $admit$;

-- The nominal timestamp is a validated wakeup. Identity uses persisted oldest
-- due, then one atomic transaction advances over every elapsed cadence slot.
CREATE FUNCTION zasp_temporal72.scheduled_admit(o text,w text,e text,s text,i text,revision bigint,nominal timestamptz) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $scheduled$
DECLARE schedule_row zasp_temporal72.schedules%ROWTYPE;now_value timestamptz;wakeup_anchor timestamptz;temporal_tick boolean;seed text;due_text text;d bytea;k text;result jsonb;sync_value text;job_value text;outbox_value text;
BEGIN
 temporal_tick:=EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=session_user AND authority_role='zasp_discovery_worker');
 IF temporal_tick THEN PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');ELSE PERFORM zasp_temporal72.require_principal('zasp_discovery_scheduler');END IF;
 SELECT * INTO schedule_row FROM zasp_temporal72.schedules WHERE (organization_id,workspace_id,environment_id,id,integration_id)=(o,w,e,s,i) FOR UPDATE;
 IF NOT FOUND OR revision IS NULL OR schedule_row.version IS DISTINCT FROM revision OR schedule_row.state<>'enabled' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery schedule rejected';END IF;
 now_value:=clock_timestamp();
 wakeup_anchor:=schedule_row.anchor;
 IF temporal_tick AND date_trunc('second',wakeup_anchor)<>wakeup_anchor THEN wakeup_anchor:=date_trunc('second',wakeup_anchor)+interval '1 second';END IF;
 IF nominal IS NULL OR nominal>now_value OR nominal<wakeup_anchor OR mod(extract(epoch FROM nominal-wakeup_anchor),schedule_row.cadence_seconds)<>0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery occurrence rejected';END IF;
 IF schedule_row.next_run_at>now_value THEN RETURN jsonb_build_object('outcome','not_due');END IF;
 due_text:=to_char(schedule_row.next_run_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS');
 IF extract(microseconds FROM schedule_row.next_run_at)::bigint%1000000<>0 THEN due_text:=due_text||'.'||rtrim(to_char(schedule_row.next_run_at AT TIME ZONE 'UTC','US'),'0');END IF;
 due_text:=due_text||'Z';seed:=concat_ws(chr(31),s,i,due_text);
 sync_value:=public.zasp_discovery_canonical_id(o,w,e,'scheduled_sync',seed);job_value:=public.zasp_discovery_canonical_id(o,w,e,'scheduled_job',seed);outbox_value:=public.zasp_discovery_canonical_id(o,w,e,'scheduled_outbox',seed);
 d:=digest(convert_to(concat_ws(chr(31),'schedule-sync-v1',o,w,e,i,seed,schedule_row.parser_version,schedule_row.tool_version),'UTF8'),'sha256');
 k:=encode(digest(convert_to('schedule-idempotency-v1'||chr(31)||seed,'UTF8'),'sha256'),'hex');
 result:=zasp_temporal72.admit(o,w,e,s,i,sync_value,job_value,outbox_value,k,d,'schedule',schedule_row.parser_version,schedule_row.tool_version,s,schedule_row.next_run_at);
 UPDATE zasp_temporal72.schedules SET next_run_at=schedule_row.next_run_at+make_interval(secs=>((floor(extract(epoch FROM now_value-schedule_row.next_run_at)/schedule_row.cadence_seconds)+1)*schedule_row.cadence_seconds)::double precision)
 WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,s);
 RETURN result;
END $scheduled$;

CREATE FUNCTION zasp_temporal72.start_delivery(o text,w text,e text,j text,payload_value jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $start$
DECLARE r zasp_temporal72.runs%ROWTYPE;BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 IF NOT FOUND OR payload_value IS NULL OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_outbox b WHERE(b.organization_id,b.workspace_id,b.environment_id,b.id,b.topic,b.payload_version)=(o,w,e,r.outbox_id,'discovery-jobs',1) AND b.payload=payload_value AND b.payload_digest=digest(convert_to(b.payload::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery start delivery rejected';END IF;
 -- Loading an original start is evidence/readback, not fresh-effect authority.
 RETURN zasp_temporal72.start_receipt(r)||jsonb_build_object('continuation',jsonb_build_object('checkpoint_version',0,'receipt_digest','','deadline',r.deadline));
END $start$;

-- This is only a migration ownership decision, not authorization to perform
-- legacy work. The retained processor still validates its job/lease/connector.
CREATE FUNCTION zasp_temporal72.delivery_route(o text,w text,e text,j text,payload_value jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $route$
DECLARE owned boolean;legacy public.zasp_discovery_jobs%ROWTYPE;s public.zasp_discovery_syncs%ROWTYPE;canonical jsonb;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 owned:=EXISTS(SELECT 1 FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j));
 SELECT * INTO legacy FROM public.zasp_discovery_jobs WHERE(organization_id,workspace_id,environment_id,id,kind)=(o,w,e,j,'discovery');
 IF owned THEN
  IF FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ambiguous discovery ownership';END IF;
  RETURN jsonb_build_object('ownership','temporal','start',zasp_temporal72.start_delivery(o,w,e,j,payload_value));
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery ownership missing';END IF;
 SELECT * INTO s FROM public.zasp_discovery_syncs WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,legacy.authority_id);
 IF NOT FOUND OR EXISTS(SELECT 1 FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,sync_id)=(o,w,e,s.id)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery sync ownership rejected';END IF;
 canonical:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'job_id',j,'sync_id',s.id,'integration_id',s.integration_id,'request_digest',encode(legacy.request_digest,'hex'));
 IF payload_value IS DISTINCT FROM canonical OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_outbox b WHERE(b.organization_id,b.workspace_id,b.environment_id,b.topic,b.payload_version)=(o,w,e,'discovery-jobs',1) AND b.payload=canonical AND b.payload_digest=digest(convert_to(canonical::text,'UTF8'),'sha256'))
 OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_job_authorities a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.job_id,a.sync_id,a.integration_id,a.request_digest)=(o,w,e,j,s.id,s.integration_id,legacy.request_digest)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained discovery envelope rejected';END IF;
 RETURN jsonb_build_object('ownership','legacy','start',NULL);
END $route$;

--72 readiness includes the unchanged registered60 predecessor security
-- predicates through71/67.base_ready. Preserve the old exact principal gate.
CREATE FUNCTION zasp_temporal72.retained_principal_ready(a text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $retained$
BEGIN
 IF a='zasp_discovery_worker' THEN PERFORM zasp_temporal72.require_principal(a);RETURN public.zasp_execution_principal_ready(a);END IF;
 IF a IS NULL OR a NOT IN('zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker') OR current_setting('transaction_isolation')<>'read committed' THEN RETURN false;END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 RETURN zasp_temporal72.current_ready() AND public.zasp_execution_principal_ready(a)
 AND EXISTS(SELECT 1 FROM pg_roles r JOIN pg_roles authority ON authority.rolname=a WHERE r.rolname=session_user AND r.rolcanlogin AND r.rolinherit AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
 AND NOT(authority.rolcanlogin OR authority.rolinherit OR authority.rolsuper OR authority.rolcreatedb OR authority.rolcreaterole OR authority.rolreplication OR authority.rolbypassrls)
 AND EXISTS(SELECT 1 FROM pg_auth_members m WHERE(m.member,m.roleid,m.admin_option)=(r.oid,authority.oid,false))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND(m.roleid<>authority.oid OR m.admin_option)));
END $retained$;

CREATE FUNCTION zasp_temporal72.schedule_current(o text,w text,e text,s text,i text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $schedule$
DECLARE r zasp_temporal72.schedules%ROWTYPE;BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_scheduler');
 UPDATE zasp_temporal72.schedules SET delivered_revision=0,acknowledged_revision=0 WHERE(organization_id,workspace_id,environment_id,id,integration_id)=(o,w,e,s,i) RETURNING * INTO r;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery desired schedule rejected';END IF;
 RETURN jsonb_build_object('ref',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'schedule_id',s,'integration_id',i),'revision',r.version,'cadence_seconds',r.cadence_seconds,'anchor',r.anchor,'enabled',r.state='enabled');
END $schedule$;
CREATE FUNCTION zasp_temporal72.schedule_ack(o text,w text,e text,s text,i text,revision bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $schedule$
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_scheduler');
 UPDATE zasp_temporal72.schedules SET acknowledged_revision=revision WHERE(organization_id,workspace_id,environment_id,id,integration_id,version)=(o,w,e,s,i,revision);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery desired revision changed';END IF;
 RETURN jsonb_build_object('revision',revision);
END $schedule$;
CREATE FUNCTION zasp_temporal72.reconcile_due(o text,w text,e text,s text,i text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $schedule$
DECLARE r zasp_temporal72.schedules%ROWTYPE;result jsonb:=jsonb_build_object('outcome','not_due');BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_scheduler');
 SELECT * INTO r FROM zasp_temporal72.schedules WHERE(organization_id,workspace_id,environment_id,id,integration_id)=(o,w,e,s,i) FOR UPDATE;
 IF NOT FOUND OR r.acknowledged_revision<>r.version THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery schedule acknowledgement missing';END IF;
 IF r.state='enabled' AND r.next_run_at<=clock_timestamp() THEN result:=zasp_temporal72.scheduled_admit(o,w,e,s,i,r.version,r.next_run_at);END IF;
 UPDATE zasp_temporal72.schedules SET delivered_revision=r.version WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,s);
 RETURN result;
END $schedule$;
CREATE FUNCTION zasp_temporal72.pending_schedules(after_value text,all_value boolean,limit_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $schedule$
DECLARE result jsonb;BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_scheduler');
 IF after_value IS NULL OR all_value IS NULL OR limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery schedule page rejected';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'schedule_id',id,'integration_id',integration_id) ORDER BY page_key),'[]') INTO result FROM(SELECT *,concat_ws('/',organization_id,workspace_id,environment_id,id,integration_id) AS page_key FROM zasp_temporal72.schedules WHERE(all_value OR delivered_revision<>version) AND concat_ws('/',organization_id,workspace_id,environment_id,id,integration_id)>after_value ORDER BY page_key LIMIT limit_value) page;
 RETURN result;
END $schedule$;

-- Fresh effect authority is independent of a worker lease or retry attempt.
-- Calling this before an external send does not make check/send atomic; a lost
-- response remains product uncertainty and is never reclaimed by elapsed time.
CREATE FUNCTION zasp_temporal72.require_current_run(r zasp_temporal72.runs,budget timestamptz) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $current_run$
BEGIN
 IF budget IS NULL OR budget IS DISTINCT FROM r.deadline OR clock_timestamp()>=r.deadline THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery budget rejected';END IF;
 PERFORM 1 FROM public.zasp_integrations i JOIN public.zasp_integration_connections c ON (c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.id)=(i.organization_id,i.workspace_id,i.environment_id,i.id,r.connection_id)
 JOIN public.zasp_discovery_connection_subjects s ON (s.organization_id,s.workspace_id,s.environment_id,s.integration_id,s.connection_id)=(c.organization_id,c.workspace_id,c.environment_id,c.integration_id,c.id)
 WHERE(i.organization_id,i.workspace_id,i.environment_id,i.id,i.kind,i.version,i.configuration)=(r.organization_id,r.workspace_id,r.environment_id,r.integration_id,r.provider,r.integration_version,r.configuration)
 AND i.state IN('active','degraded') AND c.state='verified' AND (c.provider,c.version,c.connection_reference)=(r.provider,r.connection_version,r.credential_reference)
 AND(s.provider,s.subject_kind,s.subject_id,s.connection_version,s.configuration_digest)=(r.provider,r.subject_kind,r.subject_id,r.connection_version,r.configuration_digest)
 AND r.configuration_digest=digest(convert_to(i.configuration::text,'UTF8'),'sha256')
 AND CASE r.provider WHEN 'aws' THEN r.subject_kind='aws_account' AND r.subject_id=substring(i.configuration->>'role_arn' FROM '^arn:aws:iam::([0-9]{12}):role/')
 WHEN 'github' THEN EXISTS(SELECT 1 FROM public.zasp_connector_credentials credential WHERE(credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.credential_reference,credential.status)=(r.organization_id,r.workspace_id,r.environment_id,r.integration_id,r.provider,r.credential_reference,'active') AND credential.metadata->>'installation_id'=r.subject_id)
 WHEN 'okta' THEN EXISTS(SELECT 1 FROM public.zasp_connector_credentials credential WHERE(credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.credential_reference,credential.status)=(r.organization_id,r.workspace_id,r.environment_id,r.integration_id,r.provider,r.credential_reference,'active') AND credential.metadata->>'tenant'=r.subject_id)
 WHEN 'kubernetes' THEN r.subject_kind='kubernetes_cluster' ELSE false END FOR SHARE OF i,c,s;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery current connector rejected';END IF;
 IF r.schedule_id IS NOT NULL THEN
  PERFORM 1 FROM zasp_temporal72.schedules s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.id,s.integration_id,s.state)=(r.organization_id,r.workspace_id,r.environment_id,r.schedule_id,r.integration_id,'enabled') FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery schedule disabled';END IF;
 END IF;
END $current_run$;

CREATE FUNCTION zasp_temporal72.resume_input(r zasp_temporal72.runs) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $resume$
DECLARE c zasp_temporal72.checkpoints%ROWTYPE;prior public.zasp_discovery_cursors%ROWTYPE;
BEGIN
 SELECT * INTO c FROM zasp_temporal72.checkpoints WHERE(organization_id,workspace_id,environment_id,job_id)=(r.organization_id,r.workspace_id,r.environment_id,r.job_id);
 IF FOUND THEN RETURN jsonb_build_object('checkpoint_version',c.version,'checkpoint_effect_id',c.effect_id,'checkpoint_digest',encode(decode(c.digest,'hex'),'base64'),'cursor_provider',c.cursor->>'provider','cursor_version',c.cursor->>'version','cursor_value',c.cursor->>'value','checkpoint_manifest_reference',c.manifest->>'reference','checkpoint_manifest_key',c.manifest->>'key','checkpoint_manifest_version_id',c.manifest->>'version_id','checkpoint_manifest_checksum',encode(decode(c.manifest->>'checksum','hex'),'base64'),'checkpoint_manifest_size_bytes',(c.manifest->>'size_bytes')::bigint,'checkpoint_manifest_media_type',c.manifest->>'media_type','checkpoint_manifest_schema_version',c.manifest->>'schema_version');END IF;
 SELECT * INTO prior FROM public.zasp_discovery_cursors WHERE(organization_id,workspace_id,environment_id,integration_id,provider)=(r.organization_id,r.workspace_id,r.environment_id,r.integration_id,r.provider);
 IF FOUND THEN RETURN jsonb_build_object('cursor_provider',prior.provider,'cursor_version','cursor_v1','cursor_value',prior.cursor_value);END IF;
 RETURN '{}'::jsonb;
END $resume$;

-- Shared concurrency is receipt-owned, not lease-expiry-owned. Retained input
-- preparations remain pending until positive checkpoint or snapshot evidence.
CREATE TABLE zasp_temporal72.retained_dispatches(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,job_id text NOT NULL,attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 100),
 sync_id text NOT NULL,integration_id text NOT NULL,provider text NOT NULL,generation bigint NOT NULL CHECK(generation>0),snapshot_id text NOT NULL,
 worker_id text NOT NULL,token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),checkpoint_version bigint NOT NULL CHECK(checkpoint_version>=0),checkpoint_digest bytea,
 safe_completion_digest bytea,safe_checkpoint_version bigint,safe_checkpoint_digest bytea,
 raw_apply_digest bytea,normalized_relationships jsonb,
 CHECK((raw_apply_digest IS NULL AND normalized_relationships IS NULL) OR(raw_apply_digest IS NOT NULL AND octet_length(raw_apply_digest)=32 AND normalized_relationships IS NOT NULL AND jsonb_typeof(normalized_relationships)='array')),
 CHECK((checkpoint_version=0 AND checkpoint_digest IS NULL) OR(checkpoint_version>0 AND checkpoint_digest IS NOT NULL AND octet_length(checkpoint_digest)=32)),
 CHECK((safe_completion_digest IS NULL AND safe_checkpoint_version IS NULL AND safe_checkpoint_digest IS NULL) OR(safe_completion_digest IS NOT NULL AND safe_checkpoint_version IS NOT NULL AND safe_checkpoint_digest IS NOT NULL AND octet_length(safe_completion_digest)=32 AND safe_checkpoint_version>checkpoint_version AND octet_length(safe_checkpoint_digest)=32)),
 PRIMARY KEY(organization_id,workspace_id,environment_id,job_id,attempt),
 FOREIGN KEY(organization_id,workspace_id,environment_id,job_id) REFERENCES public.zasp_discovery_jobs(organization_id,workspace_id,environment_id,id));
ALTER TABLE zasp_temporal72.retained_dispatches OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal72.retained_dispatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal72.retained_dispatches FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal72.retained_dispatches TO zasp_discovery_authority USING(true) WITH CHECK(true);

-- Relationships are connector-owned observations, while their entity endpoints
-- may be shared. Preserve every existing scoped edge identity, including removed
-- observations. Raw provider IDs remain unchanged in versioned artifacts.
CREATE FUNCTION zasp_temporal72.normalize_relationships(o text,w text,e text,i text,source_value text,items jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $relationships$
DECLARE item jsonb;identity_value text;matches bigint;result jsonb:='[]'::jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(i) AND source_value IN('aws','kubernetes','github','okta') AND jsonb_typeof(items)='array' AND jsonb_array_length(items)<=20000,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='relationship scope rejected';END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(items) LOOP
  IF EXISTS(SELECT 1 FROM unnest(ARRAY['id','kind','source_native_id','from_entity_id','to_entity_id']) key WHERE jsonb_typeof(item->key) IS DISTINCT FROM 'string') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='raw relationship field type rejected';END IF;
  IF NOT COALESCE(jsonb_typeof(item)='object' AND item ?& ARRAY['id','kind','source_native_id','from_entity_id','to_entity_id','attributes'] AND item-ARRAY['id','kind','source_native_id','from_entity_id','to_entity_id','attributes']='{}'::jsonb AND public.zasp_valid_product_id(item->>'id') AND public.zasp_valid_product_id(item->>'from_entity_id') AND public.zasp_valid_product_id(item->>'to_entity_id') AND item->>'from_entity_id'<>item->>'to_entity_id' AND item->>'kind' ~ '^[a-z][a-z0-9_]{1,63}$' AND length(item->>'source_native_id') BETWEEN 1 AND 1024 AND jsonb_typeof(item->'attributes')='object' AND octet_length((item->'attributes')::text)<=65536,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='raw relationship rejected';END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(items) value GROUP BY value->>'id' HAVING count(*)>1) OR EXISTS(SELECT 1 FROM jsonb_array_elements(items) value GROUP BY value->>'source_native_id' HAVING count(*)>1) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ambiguous relationship rejected';END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(items) LOOP
  SELECT count(*),min(id) INTO matches,identity_value FROM public.zasp_inventory_relationships WHERE(organization_id,workspace_id,environment_id,integration_id,source,source_native_id)=(o,w,e,i,source_value,item->>'source_native_id');
  IF matches>1 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='ambiguous persisted relationship';END IF;
  IF matches=0 THEN identity_value:=public.zasp_discovery_relationship_id(o,w,e,i,source_value,item->>'kind',item->>'source_native_id');END IF;
  IF EXISTS(SELECT 1 FROM public.zasp_inventory_relationships WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,identity_value) AND (integration_id,source,source_native_id) IS DISTINCT FROM(i,source_value,item->>'source_native_id')) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='relationship identity collision';END IF;
  result:=result||jsonb_build_array(jsonb_set(item,'{id}',to_jsonb(identity_value)));
 END LOOP;
 RETURN result;
END $relationships$;

CREATE FUNCTION zasp_temporal72.apply_retained_snapshot(organization_value text,workspace_value text,environment_value text,job_value text,worker_value text,lease_token_value text,integration_value text,sync_value text,snapshot_value text,generation_value bigint,source_value text,manifest_reference_value text,manifest_key_value text,manifest_version_value text,manifest_checksum_value bytea,manifest_size_value bigint,manifest_media_value text,manifest_schema_value text,collected_value timestamptz,cursor_value text,parser_value text,tool_value text,entities_value jsonb,relationships_value jsonb,evidence_value jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $retained_apply$
DECLARE prepared zasp_temporal72.retained_dispatches%ROWTYPE;job public.zasp_discovery_jobs%ROWTYPE;raw_digest bytea;mapped jsonb;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT * INTO job FROM public.zasp_discovery_jobs WHERE(organization_id,workspace_id,environment_id,id,kind,state,lease_owner,lease_token)=(organization_value,workspace_value,environment_value,job_value,'discovery','leased',worker_value,lease_token_value) AND lease_expires_at>transaction_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained apply lease rejected';END IF;
 SELECT * INTO prepared FROM zasp_temporal72.retained_dispatches WHERE(organization_id,workspace_id,environment_id,job_id,attempt,sync_id,integration_id,provider,generation,snapshot_id,worker_id,token_digest)=(organization_value,workspace_value,environment_value,job_value,job.attempt,sync_value,integration_value,source_value,generation_value,snapshot_value,worker_value,digest(convert_to(lease_token_value,'UTF8'),'sha256')) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained apply preparation rejected';END IF;
 raw_digest:=digest(convert_to(jsonb_build_array(organization_value,workspace_value,environment_value,job_value,integration_value,sync_value,snapshot_value,generation_value,source_value,manifest_reference_value,manifest_key_value,manifest_version_value,encode(manifest_checksum_value,'hex'),manifest_size_value,manifest_media_value,manifest_schema_value,floor(extract(epoch FROM collected_value)*1000000)::bigint,cursor_value,parser_value,tool_value,entities_value,relationships_value,evidence_value)::text,'UTF8'),'sha256');
 IF prepared.raw_apply_digest IS NOT NULL THEN
  IF prepared.raw_apply_digest IS DISTINCT FROM raw_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='retained apply replay conflict';END IF;
  mapped:=prepared.normalized_relationships;
 ELSE
  mapped:=zasp_temporal72.normalize_relationships(organization_value,workspace_value,environment_value,integration_value,source_value,relationships_value);
  UPDATE zasp_temporal72.retained_dispatches SET raw_apply_digest=raw_digest,normalized_relationships=mapped WHERE(organization_id,workspace_id,environment_id,job_id,attempt)=(organization_value,workspace_value,environment_value,job_value,job.attempt);
 END IF;
 RETURN public.zasp_execution_apply_complete_snapshot(organization_value,workspace_value,environment_value,job_value,worker_value,lease_token_value,integration_value,sync_value,snapshot_value,generation_value,source_value,manifest_reference_value,manifest_key_value,manifest_version_value,manifest_checksum_value,manifest_size_value,manifest_media_value,manifest_schema_value,collected_value,cursor_value,parser_value,tool_value,entities_value,mapped,evidence_value);
END $retained_apply$;

CREATE FUNCTION zasp_temporal72.snapshot_committed(o text,w text,e text,s text) RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $committed$
 SELECT EXISTS(SELECT 1 FROM public.zasp_discovery_generation_reservations g
 JOIN public.zasp_discovery_snapshots snap ON(snap.organization_id,snap.workspace_id,snap.environment_id,snap.id,snap.integration_id,snap.sync_id,snap.source,snap.generation)=(g.organization_id,g.workspace_id,g.environment_id,g.snapshot_id,g.integration_id,g.sync_id,g.source,g.generation)
 JOIN public.zasp_discovery_snapshot_inputs input ON(input.organization_id,input.workspace_id,input.environment_id,input.snapshot_id,input.integration_id,input.source,input.generation)=(g.organization_id,g.workspace_id,g.environment_id,g.snapshot_id,g.integration_id,g.source,g.generation)
 JOIN public.zasp_discovery_syncs sync ON(sync.organization_id,sync.workspace_id,sync.environment_id,sync.id,sync.integration_id,sync.snapshot_id)=(g.organization_id,g.workspace_id,g.environment_id,g.sync_id,g.integration_id,g.snapshot_id)
 WHERE(g.organization_id,g.workspace_id,g.environment_id,g.sync_id)=(o,w,e,s) AND snap.complete AND snap.state='complete' AND sync.state='succeeded')
$committed$;

CREATE FUNCTION zasp_temporal72.active_owners(o text) RETURNS TABLE(workspace_id text,environment_id text,job_id text,integration_id text,provider text,ownership text) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $owners$
 SELECT r.workspace_id,r.environment_id,r.job_id,r.integration_id,r.provider,'temporal'::text FROM zasp_temporal72.runs r
 WHERE r.organization_id=o AND EXISTS(SELECT 1 FROM public.zasp_discovery_generation_reservations g WHERE(g.organization_id,g.workspace_id,g.environment_id,g.sync_id)=(r.organization_id,r.workspace_id,r.environment_id,r.sync_id))
 AND NOT(EXISTS(SELECT 1 FROM zasp_temporal72.apply_effects a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.job_id)=(r.organization_id,r.workspace_id,r.environment_id,r.job_id) AND a.result IS NOT NULL) AND zasp_temporal72.snapshot_committed(r.organization_id,r.workspace_id,r.environment_id,r.sync_id))
 AND (r.state IN('collecting','partial','retryable','complete','applying','outcome_unknown') OR EXISTS(SELECT 1 FROM zasp_temporal72.page_effects p WHERE(p.organization_id,p.workspace_id,p.environment_id,p.job_id)=(r.organization_id,r.workspace_id,r.environment_id,r.job_id) AND(p.result IS NULL OR p.result->>'outcome'='outcome_unknown')) OR EXISTS(SELECT 1 FROM zasp_temporal72.apply_effects a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.job_id)=(r.organization_id,r.workspace_id,r.environment_id,r.job_id) AND a.result IS NULL))
 UNION ALL
 SELECT a.workspace_id,a.environment_id,a.job_id,a.integration_id,a.provider,'legacy'::text FROM public.zasp_discovery_job_authorities a
 JOIN public.zasp_discovery_jobs job ON(job.organization_id,job.workspace_id,job.environment_id,job.id,job.kind,job.authority_id)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id,'discovery',a.sync_id)
 WHERE a.organization_id=o AND NOT zasp_temporal72.snapshot_committed(a.organization_id,a.workspace_id,a.environment_id,a.sync_id)
 AND (job.state='leased' AND job.lease_expires_at>clock_timestamp() OR EXISTS(SELECT 1 FROM public.zasp_discovery_generation_reservations g WHERE(g.organization_id,g.workspace_id,g.environment_id,g.sync_id)=(a.organization_id,a.workspace_id,a.environment_id,a.sync_id)))
$owners$;

CREATE FUNCTION zasp_temporal72.capacity_available(o text,w text,e text,j text,i text,p text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $capacity$
DECLARE active_count integer;maximum_active integer;already_owned boolean;resource_busy boolean;BEGIN
 SELECT count(*) FILTER(WHERE(owner.workspace_id,owner.environment_id,owner.job_id)<>(w,e,j)),COALESCE(bool_or((owner.workspace_id,owner.environment_id,owner.job_id)=(w,e,j)),false),COALESCE(bool_or((owner.workspace_id,owner.environment_id,owner.integration_id,owner.provider)=(w,e,i,p) AND(owner.workspace_id,owner.environment_id,owner.job_id)<>(w,e,j)),false) INTO active_count,already_owned,resource_busy FROM zasp_temporal72.active_owners(o) owner;
 SELECT COALESCE((SELECT max_active_jobs FROM public.zasp_discovery_execution_quotas WHERE organization_id=o),4) INTO maximum_active;
 RETURN NOT resource_busy AND(already_owned OR active_count<maximum_active);
END $capacity$;

CREATE FUNCTION zasp_temporal72.try_capacity_lock() RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $lock$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery acquisition requires current committed authority';END IF;
 -- Old claim locks quota before its job row; old input locks provider first.
 -- Never wait in the reverse order. No authority changes precede this check.
 RETURN pg_try_advisory_xact_lock(hashtextextended('zasp-execution-job-quota-claims',0));
END $lock$;

CREATE FUNCTION zasp_temporal72.retained_retry_safe(job public.zasp_discovery_jobs) RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $retry$
 SELECT NOT EXISTS(SELECT 1 FROM public.zasp_discovery_generation_reservations g WHERE(g.organization_id,g.workspace_id,g.environment_id,g.sync_id)=(job.organization_id,job.workspace_id,job.environment_id,job.authority_id))
 OR(job.state='retryable' AND job.completion_digest IS NOT NULL AND job.completion_result->>'state'='retryable' AND job.completion_result->>'id'=job.id AND(job.completion_result->>'attempt')::integer=job.attempt AND EXISTS(
 SELECT 1 FROM zasp_temporal72.retained_dispatches d
 JOIN public.zasp_discovery_job_checkpoints c ON(c.organization_id,c.workspace_id,c.environment_id,c.job_id,c.sync_id,c.integration_id,c.provider)=(d.organization_id,d.workspace_id,d.environment_id,d.job_id,d.sync_id,d.integration_id,d.provider)
 JOIN public.zasp_discovery_generation_reservations g ON(g.organization_id,g.workspace_id,g.environment_id,g.sync_id,g.integration_id,g.source,g.generation,g.snapshot_id)=(d.organization_id,d.workspace_id,d.environment_id,d.sync_id,d.integration_id,d.provider,d.generation,d.snapshot_id)
 JOIN public.zasp_discovery_syncs s ON(s.organization_id,s.workspace_id,s.environment_id,s.id)=(d.organization_id,d.workspace_id,d.environment_id,d.sync_id)
 WHERE(d.organization_id,d.workspace_id,d.environment_id,d.job_id,d.attempt)=(job.organization_id,job.workspace_id,job.environment_id,job.id,job.attempt) AND c.version>d.checkpoint_version AND c.checkpoint_digest=job.result_digest AND d.safe_completion_digest=job.completion_digest AND d.safe_checkpoint_version=c.version AND d.safe_checkpoint_digest=c.checkpoint_digest AND s.last_error_code='partial'))
$retry$;

CREATE FUNCTION zasp_temporal72.retained_bulk_eligible(job public.zasp_discovery_jobs) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $eligible$
DECLARE a public.zasp_discovery_job_authorities%ROWTYPE;BEGIN
 SELECT * INTO a FROM public.zasp_discovery_job_authorities WHERE(organization_id,workspace_id,environment_id,job_id,sync_id,request_digest)=(job.organization_id,job.workspace_id,job.environment_id,job.id,job.authority_id,job.request_digest);
 RETURN FOUND AND COALESCE(zasp_temporal72.retained_retry_safe(job),false) AND zasp_temporal72.capacity_available(a.organization_id,a.workspace_id,a.environment_id,a.job_id,a.integration_id,a.provider);
END $eligible$;

-- Only the still-callable13 bulk route changes. Its existing lock, limits,
-- claims and permission checks remain; filter before BOTH organization/job
-- LIMITs, then recheck in the row guard. SQL10/its runtime route is untouched.
DO $bulk_handoff$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_execution_claim_jobs(text,text,integer,integer)';
 needle:='job.kind=''discovery'' AND job.attempt<5';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery bulk eligibility shape rejected';END IF;
 d:=replace(d,needle,'job.kind=''discovery'' AND zasp_temporal72.retained_bulk_eligible(job) AND job.attempt<5');
 needle:='BEGIN'||chr(10)||' IF length(worker_value)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery bulk principal shape rejected';END IF;
 EXECUTE replace(d,needle,'BEGIN'||chr(10)||' PERFORM zasp_temporal72.require_principal(''zasp_discovery_worker'');'||chr(10)||' IF length(worker_value)');
END $bulk_handoff$;

CREATE FUNCTION zasp_temporal72.retained_claim_guard() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim_guard$
DECLARE a public.zasp_discovery_job_authorities%ROWTYPE;BEGIN
 IF OLD.kind='discovery' AND OLD.state='leased' AND NEW.state='retryable' AND NEW.completion_digest IS NOT NULL THEN
  UPDATE zasp_temporal72.retained_dispatches d SET safe_completion_digest=NEW.completion_digest,safe_checkpoint_version=c.version,safe_checkpoint_digest=c.checkpoint_digest FROM public.zasp_discovery_job_checkpoints c
  WHERE(d.organization_id,d.workspace_id,d.environment_id,d.job_id,d.attempt,d.worker_id,d.token_digest)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.id,OLD.attempt,OLD.lease_owner,digest(convert_to(OLD.lease_token,'UTF8'),'sha256'))
  AND(c.organization_id,c.workspace_id,c.environment_id,c.job_id,c.sync_id,c.integration_id,c.provider)=(d.organization_id,d.workspace_id,d.environment_id,d.job_id,d.sync_id,d.integration_id,d.provider) AND c.version>d.checkpoint_version AND c.checkpoint_digest=NEW.result_digest AND d.safe_completion_digest IS NULL;
 END IF;
 IF NEW.kind<>'discovery' OR NEW.state<>'leased' OR(OLD.state='leased' AND NEW.attempt=OLD.attempt AND NEW.lease_owner=OLD.lease_owner AND NEW.lease_token=OLD.lease_token) THEN RETURN NEW;END IF;
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT * INTO a FROM public.zasp_discovery_job_authorities WHERE(organization_id,workspace_id,environment_id,job_id,sync_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.id,NEW.authority_id);
 IF NOT FOUND OR a.request_digest IS DISTINCT FROM NEW.request_digest THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained discovery ownership missing';END IF;
 -- Row omission is the old bulk RETURNING contract. Direct old delivery may
 -- fail its NOT NULL sync update; the supported72 wrapper returns typed busy.
 IF NOT zasp_temporal72.try_capacity_lock() OR NOT COALESCE(zasp_temporal72.retained_retry_safe(OLD),false) OR NOT zasp_temporal72.capacity_available(a.organization_id,a.workspace_id,a.environment_id,a.job_id,a.integration_id,a.provider) THEN RETURN NULL;END IF;
 RETURN NEW;
END $claim_guard$;
CREATE TRIGGER zasp_temporal72_retained_claim BEFORE UPDATE ON public.zasp_discovery_jobs FOR EACH ROW EXECUTE FUNCTION zasp_temporal72.retained_claim_guard();

CREATE FUNCTION zasp_temporal72.reservation_guard() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $reservation_guard$
DECLARE r zasp_temporal72.runs%ROWTYPE;job public.zasp_discovery_jobs%ROWTYPE;g public.zasp_discovery_generation_reservations%ROWTYPE;checkpoint_value bigint;checkpoint_digest_value bytea;BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery generation evidence immutable';END IF;
 IF NOT zasp_temporal72.try_capacity_lock() THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='discovery capacity acquisition contended';END IF;
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,sync_id,integration_id,provider)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.sync_id,NEW.integration_id,NEW.source);
 SELECT j.* INTO job FROM public.zasp_discovery_jobs j JOIN public.zasp_discovery_job_authorities a ON(a.organization_id,a.workspace_id,a.environment_id,a.job_id,a.sync_id,a.request_digest)=(j.organization_id,j.workspace_id,j.environment_id,j.id,j.authority_id,j.request_digest) WHERE(a.organization_id,a.workspace_id,a.environment_id,a.sync_id,a.integration_id,a.provider)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.sync_id,NEW.integration_id,NEW.source);
 IF(r.job_id IS NULL)=(job.id IS NULL) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery generation ownership ambiguous';END IF;
 IF NOT zasp_temporal72.capacity_available(NEW.organization_id,NEW.workspace_id,NEW.environment_id,COALESCE(r.job_id,job.id),NEW.integration_id,NEW.source) THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='discovery collection already active';END IF;
 IF r.job_id IS NOT NULL THEN
  PERFORM zasp_temporal72.require_current_run(r,r.deadline);
 ELSE
  IF job.state<>'leased' OR job.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained discovery lease missing';END IF;
  IF EXISTS(SELECT 1 FROM zasp_temporal72.retained_dispatches d WHERE(d.organization_id,d.workspace_id,d.environment_id,d.job_id,d.attempt)=(job.organization_id,job.workspace_id,job.environment_id,job.id,job.attempt)) THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='retained discovery preparation unresolved';END IF;
  SELECT * INTO g FROM public.zasp_discovery_generation_reservations WHERE(organization_id,workspace_id,environment_id,sync_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.sync_id);
  IF FOUND THEN
   -- An already allocated generation may have reached provider IO before72
   -- was installed. Only an exact prior safe completion permits another send.
   IF NOT EXISTS(SELECT 1 FROM zasp_temporal72.retained_dispatches d JOIN public.zasp_discovery_job_checkpoints c ON(c.organization_id,c.workspace_id,c.environment_id,c.job_id,c.sync_id,c.integration_id,c.provider,c.version,c.checkpoint_digest)=(d.organization_id,d.workspace_id,d.environment_id,d.job_id,d.sync_id,d.integration_id,d.provider,d.safe_checkpoint_version,d.safe_checkpoint_digest)
    WHERE(d.organization_id,d.workspace_id,d.environment_id,d.job_id,d.attempt,d.sync_id,d.integration_id,d.provider,d.generation,d.snapshot_id)=(job.organization_id,job.workspace_id,job.environment_id,job.id,job.attempt-1,g.sync_id,g.integration_id,g.source,g.generation,g.snapshot_id)
    AND d.safe_completion_digest IS NOT NULL AND d.safe_checkpoint_version>d.checkpoint_version AND d.safe_checkpoint_digest=job.result_digest) THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='retained prior generation preparation unresolved';END IF;
  ELSE g:=NEW;END IF;
  SELECT version,checkpoint_digest INTO checkpoint_value,checkpoint_digest_value FROM public.zasp_discovery_job_checkpoints WHERE(organization_id,workspace_id,environment_id,job_id)=(job.organization_id,job.workspace_id,job.environment_id,job.id);
  INSERT INTO zasp_temporal72.retained_dispatches(organization_id,workspace_id,environment_id,job_id,attempt,sync_id,integration_id,provider,generation,snapshot_id,worker_id,token_digest,checkpoint_version,checkpoint_digest) VALUES(job.organization_id,job.workspace_id,job.environment_id,job.id,job.attempt,job.authority_id,NEW.integration_id,NEW.source,g.generation,g.snapshot_id,job.lease_owner,digest(convert_to(job.lease_token,'UTF8'),'sha256'),COALESCE(checkpoint_value,0),checkpoint_digest_value);
 END IF;
 RETURN NEW;
END $reservation_guard$;
CREATE TRIGGER zasp_temporal72_reservation BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_discovery_generation_reservations FOR EACH ROW EXECUTE FUNCTION zasp_temporal72.reservation_guard();

CREATE FUNCTION zasp_temporal72.claim_retained_delivery(o text,w text,e text,j text,worker_value text,token_value text,seconds_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $retained_claim$
DECLARE job public.zasp_discovery_jobs%ROWTYPE;a public.zasp_discovery_job_authorities%ROWTYPE;locked boolean;BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 IF worker_value IS NULL OR token_value IS NULL OR seconds_value IS NULL OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(token_value) NOT BETWEEN 16 AND 128 OR seconds_value NOT BETWEEN 5 AND 900 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid retained delivery claim';END IF;
 locked:=zasp_temporal72.try_capacity_lock();
 SELECT * INTO job FROM public.zasp_discovery_jobs WHERE(organization_id,workspace_id,environment_id,id,kind)=(o,w,e,j,'discovery');
 SELECT * INTO a FROM public.zasp_discovery_job_authorities WHERE(organization_id,workspace_id,environment_id,job_id,sync_id)=(o,w,e,j,job.authority_id);
 IF job.id IS NULL OR a.job_id IS NULL OR a.request_digest IS DISTINCT FROM job.request_digest OR EXISTS(SELECT 1 FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retained delivery ownership rejected';END IF;
 IF job.state IN('succeeded','failed','cancelled') AND EXISTS(SELECT 1 FROM zasp_temporal72.active_owners(o) owner WHERE(owner.workspace_id,owner.environment_id,owner.job_id)=(w,e,j)) THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='retained discovery awaits outcome evidence';END IF;
 IF job.state NOT IN('succeeded','failed','cancelled') AND(NOT locked OR NOT COALESCE(zasp_temporal72.retained_retry_safe(job),false) OR NOT zasp_temporal72.capacity_available(o,w,e,j,a.integration_id,a.provider)) THEN RETURN jsonb_build_object('id',j,'state',job.state,'attempt',job.attempt,'disposition','busy');END IF;
 IF NOT locked THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='retained delivery capacity contended';END IF;
 RETURN public.zasp_execution_claim_delivery(o,w,e,j,worker_value,token_value,seconds_value);
END $retained_claim$;

CREATE FUNCTION zasp_temporal72.prepare_page(o text,w text,e text,j text,i text,input_digest text,budget timestamptz,expected bigint,expected_digest text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $prepare$
DECLARE r zasp_temporal72.runs%ROWTYPE;p zasp_temporal72.page_effects%ROWTYPE;waiting zasp_temporal72.page_waits%ROWTYPE;reservation public.zasp_discovery_generation_reservations%ROWTYPE;sync_row public.zasp_discovery_syncs%ROWTYPE;effect_value text;generation_value bigint;wait_until timestamptz;wait_digest text;wait_result jsonb;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id,integration_id)=(o,w,e,j,i) FOR UPDATE;
 IF NOT FOUND OR input_digest IS DISTINCT FROM encode(r.request_digest,'hex') OR budget IS NULL OR budget IS DISTINCT FROM r.deadline OR expected IS NULL OR expected NOT BETWEEN 0 AND 9999 OR expected_digest IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery page intent rejected';END IF;
 SELECT * INTO waiting FROM zasp_temporal72.page_waits WHERE(organization_id,workspace_id,environment_id,job_id,expected_version)=(o,w,e,j,expected);
 IF FOUND THEN
  IF waiting.expected_digest IS DISTINCT FROM expected_digest OR EXISTS(SELECT 1 FROM zasp_temporal72.page_effects WHERE(organization_id,workspace_id,environment_id,job_id,expected_version)=(o,w,e,j,expected)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery wait replay conflict';END IF;
  RETURN jsonb_build_object('page',waiting.result);
 END IF;
 SELECT * INTO p FROM zasp_temporal72.page_effects WHERE(organization_id,workspace_id,environment_id,job_id,expected_version)=(o,w,e,j,expected);
 IF FOUND THEN
  IF p.expected_digest IS DISTINCT FROM expected_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery page replay conflict';END IF;
  RETURN jsonb_build_object('page',COALESCE(p.result,jsonb_build_object('outcome','outcome_unknown')));
 END IF;
 IF(r.checkpoint_version,r.checkpoint_digest) IS DISTINCT FROM(expected,expected_digest) OR r.state NOT IN('admitted','partial','retryable') OR r.retry_not_before>clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery page precondition rejected';END IF;
 PERFORM zasp_temporal72.require_current_run(r,budget);
 -- Retain narrow provider/generation serialization, including retained jobs.
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,i,r.provider),0));
 IF NOT zasp_temporal72.try_capacity_lock() OR NOT zasp_temporal72.capacity_available(o,w,e,j,i,r.provider) THEN
  wait_until:=clock_timestamp()+interval '5 seconds';
  wait_digest:=encode(digest(convert_to(jsonb_build_object('kind','discovery72-no-io-wait','organization_id',o,'workspace_id',w,'environment_id',e,'job_id',j,'expected_version',expected,'expected_digest',expected_digest,'not_before',wait_until)::text,'UTF8'),'sha256'),'hex');
  wait_result:=jsonb_build_object('outcome','retryable','checkpoint_version',expected+1,'receipt_digest',wait_digest,'retry_after_seconds',5);
  INSERT INTO zasp_temporal72.page_waits VALUES(o,w,e,j,expected,expected_digest,wait_result,wait_until);
  UPDATE zasp_temporal72.runs SET state='retryable',checkpoint_version=expected+1,checkpoint_digest=wait_digest,retry_not_before=wait_until WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
  UPDATE public.zasp_discovery_syncs SET state='queued',last_error='discovery retryable',last_error_code='retryable' WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,r.sync_id) AND state IN('queued','running');
  RETURN jsonb_build_object('page',wait_result);
 END IF;
 SELECT * INTO reservation FROM public.zasp_discovery_generation_reservations WHERE(organization_id,workspace_id,environment_id,sync_id)=(o,w,e,r.sync_id);
 IF NOT FOUND THEN
  SELECT greatest(COALESCE((SELECT max(generation) FROM public.zasp_discovery_snapshots WHERE(organization_id,workspace_id,environment_id,integration_id,source)=(o,w,e,i,r.provider)),0),COALESCE((SELECT max(generation) FROM public.zasp_discovery_generation_reservations WHERE(organization_id,workspace_id,environment_id,integration_id,source)=(o,w,e,i,r.provider)),0))+1 INTO generation_value;
  INSERT INTO public.zasp_discovery_generation_reservations(organization_id,workspace_id,environment_id,sync_id,integration_id,source,generation,snapshot_id) VALUES(o,w,e,r.sync_id,i,r.provider,generation_value,'pid_'||gen_random_uuid()::text) RETURNING * INTO reservation;
 END IF;
 effect_value:=encode(digest(convert_to(concat_ws(chr(31),'discovery72-page',o,w,e,j,reservation.generation,expected,expected_digest),'UTF8'),'sha256'),'hex');
 INSERT INTO zasp_temporal72.page_effects(organization_id,workspace_id,environment_id,job_id,expected_version,expected_digest,effect_id) VALUES(o,w,e,j,expected,expected_digest,effect_value);
 UPDATE zasp_temporal72.runs SET state='collecting' WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 UPDATE public.zasp_discovery_syncs SET state='running',attempt=1,started_at=COALESCE(started_at,clock_timestamp()),last_error=NULL,last_error_code=NULL WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,r.sync_id) RETURNING * INTO sync_row;
 RETURN jsonb_build_object('effect_id',effect_value,'input',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'job_id',j,'sync_id',r.sync_id,'integration_id',i,'connection_id',r.connection_id,'snapshot_id',reservation.snapshot_id,'generation',reservation.generation,'observation_time',date_trunc('second',reservation.reserved_at),'provider',r.provider,'collector_version','collector_v1','credential_class',CASE r.provider WHEN 'aws' THEN 'aws_assume_role' WHEN 'kubernetes' THEN 'kubernetes_cluster' WHEN 'github' THEN 'github_installation' ELSE 'okta_refresh' END,'credential_reference',r.credential_reference,'subject_kind',r.subject_kind,'subject_id',r.subject_id,'parser_version',sync_row.parser_version,'tool_version',sync_row.tool_version,'configuration',r.configuration,'checkpoint_version',0,'deadline',r.deadline,'effect_id',effect_value)||zasp_temporal72.resume_input(r));
END $prepare$;

CREATE FUNCTION zasp_temporal72.guard_page_effect(o text,w text,e text,j text,effect_value text,budget timestamptz) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
DECLARE r zasp_temporal72.runs%ROWTYPE;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j) FOR SHARE;
 IF NOT FOUND OR r.state<>'collecting' OR NOT EXISTS(SELECT 1 FROM zasp_temporal72.page_effects WHERE(organization_id,workspace_id,environment_id,job_id,effect_id)=(o,w,e,j,effect_value) AND result IS NULL) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery effect rejected';END IF;
 PERFORM zasp_temporal72.require_current_run(r,budget);
 IF NOT EXISTS(SELECT 1 FROM zasp_temporal72.active_owners(o) owner WHERE(owner.workspace_id,owner.environment_id,owner.job_id,owner.ownership)=(w,e,j,'temporal')) OR NOT zasp_temporal72.capacity_available(o,w,e,j,r.integration_id,r.provider) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery effect ownership rejected';END IF;
 RETURN true;
END $guard$;

-- Recording evidence may finish after the deadline or revocation. It grants no
-- fresh IO. A terminal/unknown result cannot be changed into a safe retry.
CREATE FUNCTION zasp_temporal72.record_page(o text,w text,e text,j text,effect_value text,details jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $record$
DECLARE r zasp_temporal72.runs%ROWTYPE;p zasp_temporal72.page_effects%ROWTYPE;outcome_value text;digest_value text;raw_digest text;result_value jsonb;next_version bigint;delay_value integer;cursor_value jsonb;manifest_value jsonb;scope_prefix text;sync_row public.zasp_discovery_syncs%ROWTYPE;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery receipt scope rejected';END IF;
 SELECT * INTO p FROM zasp_temporal72.page_effects WHERE(organization_id,workspace_id,environment_id,job_id,effect_id)=(o,w,e,j,effect_value) FOR UPDATE;
 IF NOT FOUND OR details IS NULL OR jsonb_typeof(details)<>'object' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery receipt rejected';END IF;
 outcome_value:=details->>'outcome';
 IF outcome_value IS NULL OR outcome_value NOT IN('partial','complete','incomplete','retryable','denied','revoked','malformed','terminal','cancelled','outcome_unknown') OR details-(CASE WHEN outcome_value='complete' THEN ARRAY['outcome','cursor','manifest','candidate'] WHEN outcome_value='partial' THEN ARRAY['outcome','cursor','manifest'] ELSE ARRAY['outcome','retry_after_seconds'] END)<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery page outcome rejected';END IF;
 delay_value:=COALESCE((details->>'retry_after_seconds')::integer,0);
 IF outcome_value='retryable' AND delay_value NOT BETWEEN 1 AND 900 OR outcome_value<>'retryable' AND delay_value<>0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery retry delay rejected';END IF;
 digest_value:=encode(digest(convert_to(jsonb_build_object('effect_id',effect_value,'details',details)::text,'UTF8'),'sha256'),'hex');
 raw_digest:=digest_value;
 IF p.result IS NOT NULL THEN
  IF p.record_digest IS DISTINCT FROM digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery receipt immutable';END IF;RETURN p.result;
 END IF;
 IF(r.checkpoint_version,r.checkpoint_digest) IS DISTINCT FROM(p.expected_version,p.expected_digest) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery receipt precondition conflict';END IF;
 IF outcome_value IN('partial','complete') THEN
  cursor_value:=details->'cursor';manifest_value:=details->'manifest';scope_prefix:='organizations/'||o||'/workspaces/'||w||'/environments/'||e||'/artifacts/';
  SELECT * INTO STRICT sync_row FROM public.zasp_discovery_syncs WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,r.sync_id);
  IF NOT COALESCE(jsonb_typeof(cursor_value)='object' AND cursor_value ?& ARRAY['provider','version','value'] AND cursor_value-ARRAY['provider','version','value']='{}'::jsonb AND cursor_value->>'provider'=r.provider AND cursor_value->>'version' ~ '^[a-z][a-z0-9_.-]{1,63}$' AND length(cursor_value->>'value') BETWEEN 1 AND 2048
  AND jsonb_typeof(manifest_value)='object' AND manifest_value ?& ARRAY['reference','key','version_id','checksum','size_bytes','media_type','schema_version','parser_version','tool_version'] AND manifest_value-ARRAY['reference','key','version_id','checksum','size_bytes','media_type','schema_version','parser_version','tool_version']='{}'::jsonb
  AND public.zasp_discovery_s3_object_reference(manifest_value->>'reference') AND substring(manifest_value->>'reference' FROM '^s3://[a-z0-9][a-z0-9.-]{2,62}/(.+)$')=manifest_value->>'key' AND starts_with(manifest_value->>'key',scope_prefix) AND public.zasp_valid_product_id(substring(manifest_value->>'key' FROM length(scope_prefix)+1))
  AND length(manifest_value->>'version_id') BETWEEN 1 AND 1024 AND manifest_value->>'version_id' !~ '[[:space:][:cntrl:]]' AND manifest_value->>'checksum' ~ '^[0-9a-f]{64}$' AND manifest_value->>'checksum'<>repeat('0',64) AND (manifest_value->>'size_bytes')::bigint BETWEEN 1 AND 536870912
  AND manifest_value->>'media_type'='application/json' AND manifest_value->>'schema_version' ~ '^[a-z][a-z0-9_.-]{1,63}$' AND(manifest_value->>'parser_version',manifest_value->>'tool_version')=(sync_row.parser_version,sync_row.tool_version),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery partial manifest rejected';END IF;
  IF outcome_value='complete' AND NOT COALESCE(jsonb_typeof(details->'candidate')='object' AND (details->'candidate') ?& ARRAY['entities','relationships','evidence'] AND (details->'candidate')-ARRAY['entities','relationships','evidence']='{}'::jsonb AND jsonb_typeof(details->'candidate'->'entities')='array' AND jsonb_typeof(details->'candidate'->'relationships')='array' AND jsonb_typeof(details->'candidate'->'evidence')='array' AND jsonb_array_length(details->'candidate'->'entities')<=1000 AND jsonb_array_length(details->'candidate'->'relationships')<=2000 AND jsonb_array_length(details->'candidate'->'evidence')<=1000,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery complete candidate rejected';END IF;
  IF outcome_value='complete' THEN
   details:=jsonb_set(details,'{candidate,relationships}',zasp_temporal72.normalize_relationships(o,w,e,r.integration_id,r.provider,details->'candidate'->'relationships'));
   digest_value:=encode(digest(convert_to(jsonb_build_object('effect_id',effect_value,'details',details)::text,'UTF8'),'sha256'),'hex');
  END IF;
  INSERT INTO zasp_temporal72.checkpoints(organization_id,workspace_id,environment_id,job_id,version,digest,effect_id,cursor,manifest,candidate) VALUES(o,w,e,j,1,digest_value,effect_value,cursor_value,manifest_value,details->'candidate')
  ON CONFLICT(organization_id,workspace_id,environment_id,job_id) DO UPDATE SET version=zasp_temporal72.checkpoints.version+1,digest=excluded.digest,effect_id=excluded.effect_id,cursor=excluded.cursor,manifest=excluded.manifest,candidate=excluded.candidate;
 END IF;
 next_version:=r.checkpoint_version+CASE WHEN outcome_value IN('partial','retryable') THEN 1 ELSE 0 END;
 result_value:=jsonb_build_object('outcome',outcome_value,'checkpoint_version',next_version,'receipt_digest',digest_value,'retry_after_seconds',delay_value);
 UPDATE zasp_temporal72.page_effects SET result=result_value,record_digest=raw_digest,recorded_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,job_id,effect_id)=(o,w,e,j,effect_value);
 UPDATE zasp_temporal72.runs SET state=outcome_value,checkpoint_version=next_version,checkpoint_digest=digest_value,retry_not_before=CASE WHEN outcome_value='retryable' THEN clock_timestamp()+make_interval(secs=>delay_value) END WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 IF outcome_value='retryable' THEN
  UPDATE public.zasp_discovery_syncs SET state='queued',last_error='discovery retryable',last_error_code='retryable' WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,r.sync_id) AND state='running';
 END IF;
 RETURN result_value;
END $record$;

-- Apply intent is non-reclaimable. Only the first caller receives a dispatch
-- identity; a retry reads existing evidence and never repeats an unknown send.
CREATE FUNCTION zasp_temporal72.prepare_apply(o text,w text,e text,j text,i text,input_digest text,budget timestamptz,complete_receipt text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $prepare_apply$
DECLARE r zasp_temporal72.runs%ROWTYPE;a zasp_temporal72.apply_effects%ROWTYPE;effect_value text;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id,integration_id)=(o,w,e,j,i) FOR UPDATE;
 IF NOT FOUND OR input_digest IS DISTINCT FROM encode(r.request_digest,'hex') OR budget IS NULL OR budget IS DISTINCT FROM r.deadline OR complete_receipt IS DISTINCT FROM r.checkpoint_digest THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery apply intent rejected';END IF;
 SELECT * INTO a FROM zasp_temporal72.apply_effects WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 IF FOUND THEN RETURN jsonb_build_object('result',COALESCE(a.result,jsonb_build_object('outcome','outcome_unknown')));END IF;
 IF r.state<>'complete' OR NOT EXISTS(SELECT 1 FROM zasp_temporal72.checkpoints WHERE(organization_id,workspace_id,environment_id,job_id,digest)=(o,w,e,j,complete_receipt) AND candidate IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery complete evidence missing';END IF;
 PERFORM zasp_temporal72.require_current_run(r,budget);
 effect_value:=encode(digest(convert_to(concat_ws(chr(31),'discovery72-apply',o,w,e,j,complete_receipt),'UTF8'),'sha256'),'hex');
 INSERT INTO zasp_temporal72.apply_effects(organization_id,workspace_id,environment_id,job_id,effect_id,complete_digest) VALUES(o,w,e,j,effect_value,complete_receipt);
 UPDATE zasp_temporal72.runs SET state='applying' WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 RETURN jsonb_build_object('effect_id',effect_value);
END $prepare_apply$;

-- Domain extraction from13 apply_complete_snapshot: snapshot-input and
-- projection-input writes, not its old job/lease authority. The retained14
-- typed writer performs the inventory/cursor/tombstone transaction itself.
CREATE FUNCTION zasp_temporal72.commit_apply(o text,w text,e text,j text,effect_value text,budget timestamptz) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $commit_apply$
DECLARE r zasp_temporal72.runs%ROWTYPE;a zasp_temporal72.apply_effects%ROWTYPE;c zasp_temporal72.checkpoints%ROWTYPE;g public.zasp_discovery_generation_reservations%ROWTYPE;m jsonb;candidate_value jsonb;digest_value bytea;result_value jsonb;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j) FOR UPDATE;
 IF NOT FOUND OR budget IS NULL OR budget IS DISTINCT FROM r.deadline THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery apply scope rejected';END IF;
 SELECT * INTO a FROM zasp_temporal72.apply_effects WHERE(organization_id,workspace_id,environment_id,job_id,effect_id)=(o,w,e,j,effect_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery apply effect rejected';END IF;
 IF a.result IS NOT NULL THEN RETURN a.result;END IF;
 IF r.state<>'applying' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery apply state rejected';END IF;
 PERFORM zasp_temporal72.require_current_run(r,budget);
 SELECT * INTO STRICT c FROM zasp_temporal72.checkpoints WHERE(organization_id,workspace_id,environment_id,job_id,digest)=(o,w,e,j,a.complete_digest) AND candidate IS NOT NULL;
 SELECT * INTO STRICT g FROM public.zasp_discovery_generation_reservations WHERE(organization_id,workspace_id,environment_id,sync_id,integration_id,source)=(o,w,e,r.sync_id,r.integration_id,r.provider);
 m:=c.manifest;candidate_value:=c.candidate;
 digest_value:=digest(convert_to(jsonb_build_object('integration_id',r.integration_id,'sync_id',r.sync_id,'snapshot_id',g.snapshot_id,'generation',g.generation,'source',r.provider,'manifest_reference',m->>'reference','manifest_key',m->>'key','manifest_version_id',m->>'version_id','manifest_checksum',m->>'checksum','manifest_size_bytes',(m->>'size_bytes')::bigint,'manifest_media_type',m->>'media_type','manifest_schema_version',m->>'schema_version','collected_at_epoch_us',floor(extract(epoch FROM date_trunc('second',g.reserved_at))*1000000)::bigint,'cursor',c.cursor->>'value','parser_version',m->>'parser_version','tool_version',m->>'tool_version','entities',candidate_value->'entities','relationships',candidate_value->'relationships','evidence',candidate_value->'evidence')::text,'UTF8'),'sha256');
 PERFORM public.zasp_discovery_apply_snapshot(o,w,e,r.integration_id,r.sync_id,g.snapshot_id,g.generation,r.provider,m->>'reference',decode(m->>'checksum','hex'),date_trunc('second',g.reserved_at),r.provider,c.cursor->>'value',candidate_value->'entities',candidate_value->'relationships',candidate_value->'evidence');
 INSERT INTO public.zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,generation,candidate_digest,manifest_reference,manifest_key,manifest_version_id,manifest_checksum,manifest_size_bytes,manifest_media_type,manifest_schema_version,parser_version,tool_version,entities,relationships,evidence)
 VALUES(o,w,e,g.snapshot_id,r.integration_id,r.provider,g.generation,digest_value,m->>'reference',m->>'key',m->>'version_id',decode(m->>'checksum','hex'),(m->>'size_bytes')::bigint,m->>'media_type',m->>'schema_version',m->>'parser_version',m->>'tool_version',candidate_value->'entities',candidate_value->'relationships',candidate_value->'evidence');
 INSERT INTO public.zasp_discovery_snapshot_projection_items(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,section,item_id,payload)
 SELECT o,w,e,g.snapshot_id,r.integration_id,r.provider,section,value->>'id',value FROM(SELECT 'entities'::text section,value FROM jsonb_array_elements(candidate_value->'entities') UNION ALL SELECT 'relationships',value FROM jsonb_array_elements(candidate_value->'relationships') UNION ALL SELECT 'evidence',value FROM jsonb_array_elements(candidate_value->'evidence')) items;
 UPDATE public.zasp_projection_work SET input_digest=digest_value WHERE(organization_id,workspace_id,environment_id,snapshot_id)=(o,w,e,g.snapshot_id) AND state='pending' AND attempt=0;
 PERFORM public.zasp_execution_bump_freshness(o,w,e,r.integration_id);
 -- Crossing the original budget rolls back the whole local transaction.
 PERFORM zasp_temporal72.require_current_run(r,budget);
 result_value:=jsonb_build_object('outcome','succeeded','receipt_digest',encode(digest_value,'hex'));
 UPDATE zasp_temporal72.apply_effects SET result=result_value,committed_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 UPDATE zasp_temporal72.runs SET state='succeeded' WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 RETURN result_value;
END $commit_apply$;

-- No current connector check or new application here. Cancellation/deadline
-- settlement may only report committed evidence or durable uncertainty.
CREATE FUNCTION zasp_temporal72.settle(o text,w text,e text,j text,i text,input_digest text,budget timestamptz,reason text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $settle$
DECLARE r zasp_temporal72.runs%ROWTYPE;a zasp_temporal72.apply_effects%ROWTYPE;result_value jsonb;outcome_value text;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id,integration_id)=(o,w,e,j,i) FOR UPDATE;
 IF NOT FOUND OR input_digest IS DISTINCT FROM encode(r.request_digest,'hex') OR budget IS NULL OR budget IS DISTINCT FROM r.deadline OR reason IS NULL OR reason NOT IN('succeeded','incomplete','retryable','denied','revoked','malformed','terminal','cancelled','outcome_unknown','deadline','activity_failed','apply_uncertain','settlement_uncertain') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery settlement rejected';END IF;
 SELECT * INTO a FROM zasp_temporal72.apply_effects WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 IF a.result IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_generation_reservations g JOIN public.zasp_discovery_snapshots s ON(s.organization_id,s.workspace_id,s.environment_id,s.id,s.integration_id,s.sync_id,s.source,s.generation)=(g.organization_id,g.workspace_id,g.environment_id,g.snapshot_id,g.integration_id,g.sync_id,g.source,g.generation) JOIN public.zasp_discovery_snapshot_inputs si ON(si.organization_id,si.workspace_id,si.environment_id,si.snapshot_id)=(s.organization_id,s.workspace_id,s.environment_id,s.id) JOIN public.zasp_discovery_syncs sy ON(sy.organization_id,sy.workspace_id,sy.environment_id,sy.id)=(s.organization_id,s.workspace_id,s.environment_id,s.sync_id) WHERE(g.organization_id,g.workspace_id,g.environment_id,g.sync_id)=(o,w,e,r.sync_id) AND s.complete AND s.state='complete' AND sy.state='succeeded' AND sy.snapshot_id=s.id AND encode(si.candidate_digest,'hex')=a.result->>'receipt_digest') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery committed evidence inconsistent';END IF;
  IF reason='succeeded' AND receipt_value IS DISTINCT FROM a.result->>'receipt_digest' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery completion receipt rejected';END IF;
  RETURN a.result;
 END IF;
 IF reason='succeeded' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery success evidence missing';END IF;
 IF a.effect_id IS NOT NULL OR EXISTS(SELECT 1 FROM zasp_temporal72.page_effects WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j) AND(result IS NULL OR result->>'outcome'='outcome_unknown')) THEN outcome_value:='outcome_unknown';
 ELSE outcome_value:=CASE WHEN reason IN('denied','revoked','malformed','terminal') THEN reason ELSE 'incomplete' END;END IF;
 UPDATE zasp_temporal72.runs SET state=outcome_value WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 UPDATE public.zasp_discovery_syncs SET state='failed',completed_at=COALESCE(completed_at,clock_timestamp()),last_error='discovery '||outcome_value,last_error_code=CASE WHEN outcome_value='incomplete' THEN 'partial' ELSE outcome_value END WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,r.sync_id) AND state IN('queued','running');
 PERFORM public.zasp_execution_bump_freshness(o,w,e,i);
 RETURN jsonb_build_object('outcome',outcome_value);
END $settle$;

CREATE FUNCTION zasp_temporal72.finish(o text,w text,e text,j text,i text,input_digest text,outcome_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $finish$
DECLARE budget timestamptz;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_worker');
 SELECT deadline INTO budget FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id,integration_id)=(o,w,e,j,i);
 RETURN zasp_temporal72.settle(o,w,e,j,i,input_digest,budget,outcome_value,receipt_value);
END $finish$;

CREATE FUNCTION zasp_temporal72.require_actor(o text,w text,e text,p text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $actor$
DECLARE scope_row public.zasp_authorized_scopes%ROWTYPE;membership public.zasp_identity_memberships%ROWTYPE;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_api');
 SELECT * INTO membership FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(o,p) AND active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery actor revoked';END IF;
 scope_row:=zasp_sa_multistep_prior.lock_scope(o,w,e,p);
 IF scope_row.principal_id IS NULL OR NOT(public.zasp_effective_scope_permissions(scope_row.permissions,membership.role)?'manage_workflows') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery scope denied';END IF;
END $actor$;

-- Public API shape/audit/idempotency is retained. Human authority is checked
-- before both fresh admission and receipt replay; scheduled authority never
-- calls require_actor and never borrows the creator's login session.
-- The existing wire has one product-run attempt:0 before first durable page
-- dispatch,1 afterwards. Receipt attempts, pages and continuation never alter it.
CREATE FUNCTION zasp_temporal72.sync_body(o text,w text,e text,i text,s text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $sync_body$
DECLARE r zasp_temporal72.runs%ROWTYPE;b jsonb;
BEGIN
 b:=public.zasp_execution_sync_body(o,w,e,i,s);
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,integration_id,sync_id)=(o,w,e,i,s);
 IF FOUND THEN
  IF (b->>'attempt')::integer NOT IN(0,1) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery run projection rejected';END IF;
  IF b->>'status'='queued' AND (b->>'attempt')::integer=0 AND r.state='retryable' AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.page_waits wait WHERE(wait.organization_id,wait.workspace_id,wait.environment_id,wait.job_id,wait.expected_version+1)=(o,w,e,r.job_id,r.checkpoint_version) AND wait.result->>'receipt_digest'=r.checkpoint_digest AND wait.not_before=r.retry_not_before) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery wait projection rejected';END IF;
  b:=b||jsonb_build_object('retry_at',CASE WHEN b->>'status'='queued' AND r.state='retryable' THEN to_char(r.retry_not_before AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ELSE NULL END);
 ELSIF (b->>'attempt')::integer=0 AND (b->>'status' IN('failed','cancelled') OR b->>'status'='queued' AND (b->>'last_error_code' IS NOT NULL OR b->>'retry_at' IS NOT NULL)) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='legacy terminal attempt rejected';
 END IF;
 RETURN b;
END $sync_body$;
CREATE FUNCTION zasp_temporal72.sync_detail(o text,w text,e text,i text,s text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $detail$
DECLARE b jsonb;v bigint;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_api');
 b:=zasp_temporal72.sync_body(o,w,e,i,s);
 SELECT version INTO STRICT v FROM public.zasp_discovery_syncs WHERE(organization_id,workspace_id,environment_id,integration_id,id)=(o,w,e,i,s);
 RETURN jsonb_build_object('body',b,'version',v);
END $detail$;
CREATE FUNCTION zasp_temporal72.sync_history(o text,w text,e text,i text,before_time timestamptz,before_id text,lim integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $history$
DECLARE b jsonb;items jsonb;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_api');
 b:=public.zasp_execution_sync_history(o,w,e,i,before_time,before_id,lim);
 SELECT COALESCE(jsonb_agg(zasp_temporal72.sync_body(o,w,e,i,item->>'id') ORDER BY ordinal),'[]'::jsonb) INTO items FROM jsonb_array_elements(b->'items') WITH ORDINALITY x(item,ordinal);
 RETURN b||jsonb_build_object('items',items);
END $history$;
CREATE FUNCTION zasp_temporal72.last_good_freshness(o text,w text,e text,i text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $freshness$
DECLARE b jsonb;
BEGIN
 PERFORM zasp_temporal72.require_principal('zasp_discovery_api');
 b:=public.zasp_execution_last_good_freshness(o,w,e,i);
 IF b->'latest_sync'<>'null'::jsonb THEN b:=b||jsonb_build_object('latest_sync',zasp_temporal72.sync_body(o,w,e,i,b->'latest_sync'->>'id'));END IF;
 RETURN b;
END $freshness$;

CREATE FUNCTION zasp_temporal72.public_request_sync(o text,w text,e text,p text,i text,k text,expected bigint,s text,j text,b text,d bytea,parser_value text,tool_value text,a text,c text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $manual$
DECLARE intent_value jsonb;replay_value jsonb;body_value jsonb;version_value bigint;
BEGIN
 PERFORM zasp_temporal72.require_actor(o,w,e,p);
 intent_value:=jsonb_build_object('scope',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e),'integration_id',i,'expected_version',expected,'idempotency_key',k,'body','{}'::jsonb);
 replay_value:=public.zasp_workflow_replay(o,w,e,p,'syncIntegration',k,intent_value);
 IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result';END IF;
 PERFORM 1 FROM public.zasp_integrations WHERE (organization_id,workspace_id,environment_id,id,version)=(o,w,e,i,expected) AND state IN('active','degraded') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery integration version rejected';END IF;
 PERFORM zasp_temporal72.admit(o,w,e,p,i,s,j,b,k,d,'manual',parser_value,tool_value,NULL,NULL);
 body_value:=zasp_temporal72.sync_body(o,w,e,i,s);
 SELECT version INTO STRICT version_value FROM public.zasp_discovery_syncs WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,s);
 RETURN public.zasp_execution_record_public_mutation(o,w,e,p,'syncIntegration',k,intent_value,body_value,'integration_sync',s,version_value,a,c,receipt_value);
END $manual$;

CREATE FUNCTION zasp_temporal72.schedule_body(o text,w text,e text,i text,include_deleted boolean) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$
DECLARE s zasp_temporal72.schedules%ROWTYPE;
BEGIN
 SELECT * INTO s FROM zasp_temporal72.schedules WHERE (organization_id,workspace_id,environment_id,integration_id)=(o,w,e,i) AND (include_deleted OR state<>'deleted');
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='discovery schedule missing';END IF;
 RETURN jsonb_build_object('integration_id',i,'cadence_seconds',s.cadence_seconds,'state',s.state,'time_zone','UTC','next_run_at',CASE WHEN s.state='enabled' THEN to_char(s.next_run_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ELSE NULL END,'version',s.version,'created_at',to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'updated_at',to_char(s.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $body$;

CREATE FUNCTION zasp_temporal72.schedule_detail(o text,w text,e text,i text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $detail$
BEGIN PERFORM zasp_temporal72.require_principal('zasp_discovery_api');RETURN zasp_temporal72.schedule_body(o,w,e,i,false);END $detail$;

-- A configuration change and its undelivered revision are one row/transaction.
-- No RPC occurs here. WithCurrentSchedule rereads after session serialization.
CREATE FUNCTION zasp_temporal72.public_put_schedule(o text,w text,e text,p text,i text,k text,expected bigint,cadence integer,state_value text,a text,c text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $put$
DECLARE intent_value jsonb;replay_value jsonb;s zasp_temporal72.schedules%ROWTYPE;body_value jsonb;now_value timestamptz;
BEGIN
 PERFORM zasp_temporal72.require_actor(o,w,e,p);
 IF expected IS NULL OR expected<0 OR cadence IS NULL OR cadence NOT BETWEEN 300 AND 2678400 OR state_value IS NULL OR state_value NOT IN('enabled','disabled') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery schedule request rejected';END IF;
 intent_value:=jsonb_build_object('scope',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e),'integration_id',i,'expected_version',expected,'idempotency_key',k,'body',jsonb_build_object('cadence_seconds',cadence,'state',state_value));
 replay_value:=public.zasp_workflow_replay(o,w,e,p,'putIntegrationSchedule',k,intent_value);
 IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result';END IF;
 PERFORM 1 FROM public.zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,i) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='discovery integration missing';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'discovery72-config',o,w,e,i),0));
 SELECT * INTO s FROM zasp_temporal72.schedules WHERE (organization_id,workspace_id,environment_id,integration_id)=(o,w,e,i) FOR UPDATE;
 now_value:=clock_timestamp();
 IF expected=0 THEN
  IF FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery schedule exists';END IF;
  INSERT INTO zasp_temporal72.schedules(organization_id,workspace_id,environment_id,id,integration_id,cadence_seconds,state,next_run_at,anchor,version,created_at,updated_at)
  VALUES(o,w,e,'pid_'||gen_random_uuid()::text,i,cadence,state_value,now_value+make_interval(secs=>cadence),now_value+make_interval(secs=>cadence),1,now_value,now_value) RETURNING * INTO s;
 ELSE
  IF NOT FOUND OR s.version<>expected OR s.state='deleted' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery schedule version rejected';END IF;
  UPDATE zasp_temporal72.schedules SET cadence_seconds=cadence,state=state_value,next_run_at=now_value+make_interval(secs=>cadence),anchor=now_value+make_interval(secs=>cadence),version=version+1,updated_at=now_value WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,s.id) RETURNING * INTO s;
 END IF;
 body_value:=zasp_temporal72.schedule_body(o,w,e,i,true);
 RETURN public.zasp_execution_record_public_mutation(o,w,e,p,'putIntegrationSchedule',k,intent_value,body_value,'integration_schedule',i,s.version,a,c,receipt_value);
END $put$;

CREATE FUNCTION zasp_temporal72.public_delete_schedule(o text,w text,e text,p text,i text,k text,expected bigint,a text,c text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $delete$
DECLARE intent_value jsonb;replay_value jsonb;s zasp_temporal72.schedules%ROWTYPE;body_value jsonb;
BEGIN
 PERFORM zasp_temporal72.require_actor(o,w,e,p);
 IF expected IS NULL OR expected NOT BETWEEN 1 AND 999999 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery schedule delete rejected';END IF;
 intent_value:=jsonb_build_object('scope',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e),'integration_id',i,'expected_version',expected,'idempotency_key',k,'body','{}'::jsonb);
 replay_value:=public.zasp_workflow_replay(o,w,e,p,'deleteIntegrationSchedule',k,intent_value);
 IF (replay_value->>'found')::boolean THEN RETURN replay_value->'result';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'discovery72-config',o,w,e,i),0));
 SELECT * INTO s FROM zasp_temporal72.schedules WHERE(organization_id,workspace_id,environment_id,integration_id)=(o,w,e,i) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='discovery schedule missing';END IF;
 IF s.version<>expected OR s.state='deleted' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery schedule version rejected';END IF;
 UPDATE zasp_temporal72.schedules SET state='deleted',version=version+1,updated_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,s.id) RETURNING * INTO s;
 body_value:=zasp_temporal72.schedule_body(o,w,e,i,true);
 RETURN public.zasp_execution_record_public_mutation(o,w,e,p,'deleteIntegrationSchedule',k,intent_value,body_value,'integration_schedule',i,s.version,a,c,receipt_value);
END $delete$;

-- Concrete retained domain catalog used by admission, generation, checkpoints,
-- typed application and projection-input writes. Pin live RLS/ACL/trigger and
-- constraint shape too, not just the stored procedure text. No grants change.
CREATE FUNCTION zasp_temporal72.domain_catalog() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $domain_catalog$
 WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])), identities(value) AS(
 SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM selected c
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM selected c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM selected c JOIN pg_constraint k ON k.conrelid=c.oid
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM selected c JOIN pg_index i ON i.indrelid=c.oid
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM selected c JOIN pg_policy p ON p.polrelid=c.oid
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,'')) FROM selected c JOIN pg_trigger t ON t.tgrelid=c.oid JOIN pg_proc p ON p.oid=t.tgfoid WHERE NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','foreign-key-trigger',k.conrelid::regclass::text,k.conname,k.confrelid::regclass::text,t.tgrelid::regclass::text,t.tgconstrrelid::regclass::text,t.tgfoid::regprocedure::text,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,t.tgnargs,encode(t.tgargs,'hex'),t.tgattr::text,COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')) FROM selected c JOIN pg_constraint k ON k.conrelid=c.oid JOIN pg_trigger t ON t.tgconstraint=k.oid WHERE t.tgisinternal AND k.contype='f'
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$domain_catalog$;

-- The51 catalog includes every user trigger on the shared outbox and its own
-- function definition. Preserve all live categories while projecting exactly
-- these two authorized deltas. Both actual replacements and the saved original
-- are checked by the independent72 pin; no predecessor pin is refreshed.
DO $precision_handoff$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_production_runtime_precision_live_fingerprint()';
 d:=replace(d,'FUNCTION public.zasp_production_runtime_precision_live_fingerprint()', 'FUNCTION zasp_temporal72.retained_precision_fingerprint()');
 needle:='pg_get_functiondef(p.oid)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery precision self entry rejected';END IF;
 d:=replace(d,needle,$replacement$CASE WHEN p.oid='public.zasp_production_runtime_precision_live_fingerprint()'::regprocedure THEN (SELECT definition FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_production_runtime_precision_live_fingerprint()') ELSE pg_get_functiondef(p.oid) END$replacement$);
 needle:='AND NOT t.tgisinternal';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery precision trigger entry rejected';END IF;
 EXECUTE replace(d,needle,needle||' AND NOT(t.tgrelid=''public.zasp_discovery_outbox''::regclass AND t.tgname=''zasp_temporal72_outbox_guard'')');
END $precision_handoff$;

--13 excludes its own fingerprint definition.60 independently includes that
-- definition and its identity helper. Project these exact saved definitions
-- only; all other catalog rows and all live security attributes stay visible.
DO $bulk_catalog_handoff$ DECLARE d text;needle text;original text;checking text:=current_setting('check_function_bodies');BEGIN
 PERFORM set_config('check_function_bodies','off',true);
 SELECT definition INTO STRICT d FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_execution_live_fingerprint()';
 d:=replace(d,'FUNCTION public.zasp_execution_live_fingerprint()', 'FUNCTION zasp_temporal72.retained_execution_fingerprint()');
 needle:='btrim(p.prosrc)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery execution catalog shape rejected';END IF;
 EXECUTE replace(d,needle,$projection$btrim(CASE WHEN p.oid='public.zasp_execution_claim_jobs(text,text,integer,integer)'::regprocedure THEN (SELECT split_part(definition,chr(36)||'function'||chr(36),2) FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_execution_claim_jobs(text,text,integer,integer)') ELSE p.prosrc END)$projection$);
 SELECT definition INTO STRICT d FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_execution_live_fingerprint()';
 original:=split_part(d,'$function$',2);
 IF original='' OR array_length(string_to_array(d,'$function$'),1)<>3 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery execution fingerprint body rejected';END IF;
 EXECUTE replace(d,original,$body$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM zasp_temporal72.registration WHERE checksum='-- discovery72 checksum' AND fingerprint='-- discovery72 fingerprint') AND zasp_temporal72.fingerprint()='-- discovery72 fingerprint' THEN zasp_temporal72.retained_execution_fingerprint() ELSE NULL END
$body$);
 SELECT definition INTO STRICT d FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_discovery_schedule_replay_function_identity(oid)';
 needle:='pg_get_functiondef(value)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery schedule identity shape rejected';END IF;
 EXECUTE replace(d,needle,$projection$CASE WHEN value IN('public.zasp_execution_live_fingerprint()'::regprocedure,'public.zasp_discovery_schedule_replay_function_identity(oid)'::regprocedure) THEN CASE WHEN EXISTS(SELECT 1 FROM zasp_temporal72.registration WHERE checksum='-- discovery72 checksum' AND fingerprint='-- discovery72 fingerprint') AND zasp_temporal72.fingerprint()='-- discovery72 fingerprint' THEN (SELECT definition FROM zasp_temporal72.predecessor_functions WHERE to_regprocedure(signature)=value) ELSE NULL END ELSE pg_get_functiondef(value) END$projection$);
 PERFORM set_config('check_function_bodies',checking,true);
END $bulk_catalog_handoff$;

CREATE FUNCTION zasp_temporal72.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_temporal72'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(pg_get_functiondef(p.oid),'-- discovery72 checksum','<checksum>'),'-- discovery72 fingerprint','<fingerprint>')) FROM pg_proc p WHERE p.pronamespace='zasp_temporal72'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='zasp_temporal72'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal72'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal72'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal72'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal72'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal72'::regnamespace
 UNION ALL SELECT concat_ws('|','foreign-key-trigger',k.conrelid::regclass::text,k.conname,k.confrelid::regclass::text,t.tgrelid::regclass::text,t.tgconstrrelid::regclass::text,t.tgfoid::regprocedure::text,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,t.tgnargs,encode(t.tgargs,'hex'),t.tgattr::text,COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal72'::regnamespace
 UNION ALL SELECT CASE WHEN signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)') THEN concat_ws('|','saved',signature,definition,COALESCE(zasp_temporal72.migration_helper_identity(signature,owner_name,acl),'<invalid-migration-helper>')) ELSE concat_ws('|','saved',signature,definition,owner_name,acl) END FROM zasp_temporal72.predecessor_functions
 UNION ALL SELECT 'domain-catalog|'||zasp_temporal72.domain_catalog()
 UNION ALL SELECT 'inventory-catalog|'||public.zasp_inventory_live_fingerprint()
 UNION ALL SELECT concat_ws('|','precision-handoff',p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(pg_get_functiondef(p.oid),'-- discovery72 checksum','<checksum>'),'-- discovery72 fingerprint','<fingerprint>')) FROM pg_proc p WHERE p.oid='public.zasp_production_runtime_precision_live_fingerprint()'::regprocedure
 UNION ALL SELECT concat_ws('|','bulk-handoff',p.oid::regprocedure::text,p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(pg_get_functiondef(p.oid),'-- discovery72 checksum','<checksum>'),'-- discovery72 fingerprint','<fingerprint>')) FROM pg_proc p WHERE p.oid IN('public.zasp_execution_claim_jobs(text,text,integer,integer)'::regprocedure,'public.zasp_execution_live_fingerprint()'::regprocedure,'public.zasp_discovery_schedule_replay_function_identity(oid)'::regprocedure)
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE OR REPLACE FUNCTION public.zasp_production_runtime_precision_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $precision$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM zasp_temporal72.registration WHERE checksum='-- discovery72 checksum' AND fingerprint='-- discovery72 fingerprint') AND zasp_temporal72.fingerprint()='-- discovery72 fingerprint' THEN zasp_temporal72.retained_precision_fingerprint() ELSE NULL END
$precision$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal72'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
GRANT USAGE ON SCHEMA zasp_temporal72 TO zasp_discovery_api,zasp_discovery_worker,zasp_discovery_scheduler,zasp_outbox_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.ready(text,text),zasp_temporal72.current_ready() TO zasp_discovery_api,zasp_discovery_worker,zasp_discovery_scheduler,zasp_outbox_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.principal_ready(text) TO zasp_discovery_api,zasp_discovery_worker,zasp_discovery_scheduler,zasp_outbox_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.claim_outbox(text,text,text,integer,integer),zasp_temporal72.heartbeat_outbox(text,text,text,integer,integer),zasp_temporal72.ack_outbox(text,text,text,text,text,text,text,text),zasp_temporal72.retry_outbox(text,text,text,text,text,text,text,integer,text) TO zasp_outbox_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.scheduled_admit(text,text,text,text,text,bigint,timestamptz) TO zasp_discovery_scheduler,zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.prepare_page(text,text,text,text,text,text,timestamptz,bigint,text),zasp_temporal72.record_page(text,text,text,text,text,jsonb),zasp_temporal72.guard_page_effect(text,text,text,text,text,timestamptz) TO zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.prepare_apply(text,text,text,text,text,text,timestamptz,text),zasp_temporal72.commit_apply(text,text,text,text,text,timestamptz),zasp_temporal72.settle(text,text,text,text,text,text,timestamptz,text,text) TO zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.finish(text,text,text,text,text,text,text,text) TO zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.start_delivery(text,text,text,text,jsonb) TO zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.delivery_route(text,text,text,text,jsonb) TO zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.claim_retained_delivery(text,text,text,text,text,text,integer) TO zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.apply_retained_snapshot(text,text,text,text,text,text,text,text,text,bigint,text,text,text,text,bytea,bigint,text,text,timestamptz,text,text,text,jsonb,jsonb,jsonb) TO zasp_discovery_worker;
GRANT USAGE ON SCHEMA zasp_temporal72 TO zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.retained_principal_ready(text) TO zasp_discovery_worker,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal72.schedule_current(text,text,text,text,text),zasp_temporal72.schedule_ack(text,text,text,text,text,bigint),zasp_temporal72.reconcile_due(text,text,text,text,text),zasp_temporal72.pending_schedules(text,boolean,integer) TO zasp_discovery_scheduler;
GRANT EXECUTE ON FUNCTION zasp_temporal72.public_request_sync(text,text,text,text,text,text,bigint,text,text,text,bytea,text,text,text,text,text),zasp_temporal72.public_put_schedule(text,text,text,text,text,text,bigint,integer,text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_temporal72.sync_detail(text,text,text,text,text),zasp_temporal72.sync_history(text,text,text,text,timestamptz,text,integer),zasp_temporal72.schedule_detail(text,text,text,text),zasp_temporal72.last_good_freshness(text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_temporal72.public_delete_schedule(text,text,text,text,text,text,bigint,text,text,text) TO zasp_discovery_api;
