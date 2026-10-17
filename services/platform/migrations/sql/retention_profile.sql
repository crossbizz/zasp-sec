-- Additive M7-19 authority. Historical catalogs and source files stay immutable.
-- PREPARED alone never admits expiry. ACTIVE needs the separately sealed exact
-- catalog/writer successor and explicit operator cutover activation.
CREATE SCHEMA zasp_retention_v1 AUTHORIZATION zasp_discovery_authority;
SET LOCAL ROLE zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_retention_v1 FROM PUBLIC;
DO $source_schema_access$ BEGIN
 EXECUTE format('GRANT USAGE,CREATE ON SCHEMA zasp_retention_v1 TO %I',session_user);
END $source_schema_access$;
SET LOCAL ROLE NONE;

-- These two narrow functions retain source7's actual registered table owner.
CREATE FUNCTION zasp_retention_v1.policy_lock(o text,w text,e text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $policy$
DECLARE result jsonb;BEGIN
 PERFORM zasp_retention_v1.require_maintenance();
 SELECT to_jsonb(p) INTO result FROM public.zasp_data_controls p
 WHERE(p.organization_id,p.workspace_id,p.environment_id)=(o,w,e) FOR UPDATE;
 RETURN result;
END $policy$;
CREATE FUNCTION zasp_retention_v1.delete_product_event(o text,w text,e text,parent text,id text,expected_digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $delete$
DECLARE item jsonb;BEGIN
 PERFORM zasp_retention_v1.require_sweep();
 SELECT to_jsonb(v) INTO item FROM public.zasp_session_events v
 WHERE(v.organization_id,v.session_id,v.id)=(o,parent,id)
 AND EXISTS(SELECT 1 FROM zasp_retention_v1.event_origins origin WHERE(origin.organization_id,origin.workspace_id,origin.environment_id,origin.session_id,origin.event_id)=(o,w,e,parent,id) AND origin.source_digest=zasp_retention_v1.source_digest('product_session_event',to_jsonb(v))) FOR UPDATE;
 IF NOT FOUND THEN RETURN false;END IF;
 IF zasp_retention_v1.source_digest('product_session_event',item) IS DISTINCT FROM expected_digest
 OR NOT EXISTS(SELECT 1 FROM zasp_retention_v1.tombstones t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.class,t.parent_id,t.source_id,t.source_digest)=(o,w,e,'product_session_event',parent,id,expected_digest))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention product source changed';END IF;
 DELETE FROM public.zasp_session_events v WHERE(v.organization_id,v.session_id,v.id)=(o,parent,id);
 RETURN FOUND;
END $delete$;
REVOKE ALL ON FUNCTION zasp_retention_v1.policy_lock(text,text,text),zasp_retention_v1.delete_product_event(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_retention_v1.policy_lock(text,text,text),zasp_retention_v1.delete_product_event(text,text,text,text,text,text) TO zasp_discovery_authority;
CREATE FUNCTION zasp_retention_v1.capture_product_event_origin() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $origin$
DECLARE origin record;session_value jsonb;digest_value text;BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'zasp_session_events' OR TG_OP NOT IN('INSERT','UPDATE') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention origin source rejected';END IF;
 IF NOT zasp_retention_v1.effective_catalog_ready('-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='active retention origin authority required';END IF;
 digest_value:=zasp_retention_v1.source_digest('product_session_event',to_jsonb(NEW));
 SELECT * INTO origin FROM zasp_retention_v1.event_origins WHERE(organization_id,session_id,event_id)=(NEW.organization_id,NEW.session_id,NEW.id);
 IF FOUND THEN
  IF origin.source_digest IS DISTINCT FROM digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='retention event identity changed';END IF;
 ELSE
  IF TG_OP<>'INSERT' OR EXISTS(SELECT 1 FROM public.zasp_session_events v WHERE(v.organization_id,v.session_id,v.id)=(NEW.organization_id,NEW.session_id,NEW.id)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy event origin unavailable';END IF;
  SELECT to_jsonb(s) INTO session_value FROM public.zasp_product_sessions s WHERE(s.organization_id,s.session_id)=(NEW.organization_id,NEW.session_id) FOR SHARE;
  IF NOT FOUND OR session_value->>'revoked_at' IS NOT NULL OR(session_value->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current event origin required';END IF;
  INSERT INTO zasp_retention_v1.event_origins VALUES(NEW.organization_id,session_value->>'workspace_id',session_value->>'environment_id',NEW.session_id,NEW.id,digest_value,clock_timestamp()) ON CONFLICT DO NOTHING;
  SELECT * INTO STRICT origin FROM zasp_retention_v1.event_origins WHERE(organization_id,session_id,event_id)=(NEW.organization_id,NEW.session_id,NEW.id);
 END IF;
 IF origin.source_digest IS DISTINCT FROM digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='retention event origin conflict';END IF;
 IF EXISTS(SELECT 1 FROM zasp_retention_v1.tombstones t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.class,t.parent_id,t.source_id)=(origin.organization_id,origin.workspace_id,origin.environment_id,'product_session_event',origin.session_id,origin.event_id)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='expired product event cannot be restored';END IF;
 RETURN NEW;
END $origin$;
REVOKE ALL ON FUNCTION zasp_retention_v1.capture_product_event_origin() FROM PUBLIC;
CREATE TABLE zasp_retention_v1.scopes(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,PRIMARY KEY(organization_id,workspace_id,environment_id),FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id));
CREATE TABLE zasp_retention_v1.event_origins(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,session_id text NOT NULL,event_id text NOT NULL,source_digest text NOT NULL CHECK(source_digest~'^[0-9a-f]{64}$'),recorded_at timestamptz NOT NULL,PRIMARY KEY(organization_id,session_id,event_id),FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id));
CREATE FUNCTION zasp_retention_v1.install_product_guard() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $install_guard$
BEGIN
 IF NOT zasp_retention_v1.registered_operator() OR NOT zasp_retention_v1.prepared_ready('-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention original-owner activation required';END IF;
 CREATE TRIGGER zasp_000_retention_v1_product_event BEFORE INSERT OR UPDATE ON public.zasp_session_events FOR EACH ROW EXECUTE FUNCTION zasp_retention_v1.capture_product_event_origin();
 CREATE TRIGGER zasp_000_retention_v1_policy_scope AFTER INSERT OR UPDATE OF deletion_enabled ON public.zasp_data_controls FOR EACH ROW EXECUTE FUNCTION zasp_retention_v1.enroll_policy_scope();
 INSERT INTO zasp_retention_v1.scopes SELECT organization_id,workspace_id,environment_id FROM public.zasp_data_controls WHERE deletion_enabled ON CONFLICT DO NOTHING;
 INSERT INTO zasp_retention_v1.scope_schedule SELECT organization_id,workspace_id,environment_id,0 FROM zasp_retention_v1.scopes ON CONFLICT DO NOTHING;
END $install_guard$;
CREATE FUNCTION zasp_retention_v1.enroll_policy_scope() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $enroll$
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'zasp_data_controls' OR TG_OP NOT IN('INSERT','UPDATE') OR NOT zasp_retention_v1.effective_catalog_ready('-- retention checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='active retention policy source required';END IF;
 IF NEW.deletion_enabled THEN
  INSERT INTO zasp_retention_v1.scopes VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id) ON CONFLICT DO NOTHING;
  INSERT INTO zasp_retention_v1.scope_schedule VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,0) ON CONFLICT DO NOTHING;
 END IF;
 RETURN NEW;
END $enroll$;
REVOKE ALL ON FUNCTION zasp_retention_v1.install_product_guard(),zasp_retention_v1.enroll_policy_scope() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_retention_v1.install_product_guard() TO zasp_discovery_authority;
ALTER TABLE zasp_retention_v1.scopes OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_retention_v1.event_origins OWNER TO zasp_discovery_authority;

SET LOCAL ROLE zasp_discovery_authority;
DO $close_schema_create$ BEGIN
 EXECUTE format('REVOKE CREATE ON SCHEMA zasp_retention_v1 FROM %I',session_user);
END $close_schema_create$;
-- retention authority definitions
CREATE TABLE zasp_retention_v1.preimages(signature text PRIMARY KEY,target_oid oid NOT NULL UNIQUE,kind text NOT NULL CHECK(kind IN('catalog','writer')),definition text NOT NULL,source text NOT NULL,owner_oid oid NOT NULL,acl text);
CREATE TABLE zasp_retention_v1.successors(signature text PRIMARY KEY REFERENCES zasp_retention_v1.preimages,definition text NOT NULL);
CREATE TABLE zasp_retention_v1.cutover_receipts(receipt_digest text PRIMARY KEY CHECK(receipt_digest~'^[0-9a-f]{64}$'),profile_checksum text NOT NULL,database_name text NOT NULL,database_oid oid NOT NULL,parent_worker text NOT NULL,parent_runtime text NOT NULL,operator_oid oid NOT NULL,artifact jsonb NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE zasp_retention_v1.registration(singleton boolean PRIMARY KEY CHECK(singleton),checksum text NOT NULL,parent_worker text NOT NULL,parent_runtime text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_retention_v1.activation(singleton boolean PRIMARY KEY CHECK(singleton),checksum text NOT NULL,successor_fingerprint text NOT NULL,cutover_digest text NOT NULL);
CREATE TABLE zasp_retention_v1.principals(purpose text PRIMARY KEY CHECK(purpose IN('human-read','runtime-index','runtime-coordinator','sweep')),login_oid oid NOT NULL UNIQUE,login_name text NOT NULL,authority_role text NOT NULL);
CREATE TABLE zasp_retention_v1.scheduler(singleton boolean PRIMARY KEY CHECK(singleton),sequence bigint NOT NULL CHECK(sequence>=0));
INSERT INTO zasp_retention_v1.scheduler VALUES(true,0);
CREATE TABLE zasp_retention_v1.scope_schedule(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,last_served bigint NOT NULL DEFAULT 0,PRIMARY KEY(organization_id,workspace_id,environment_id),FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES zasp_retention_v1.scopes);
CREATE TABLE zasp_retention_v1.cursors(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,class text NOT NULL CHECK(class IN('runtime_event','product_session_event','inventory_evidence')),parent_id text NOT NULL DEFAULT '',source_id text NOT NULL DEFAULT '',PRIMARY KEY(organization_id,workspace_id,environment_id,class),FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES zasp_retention_v1.scopes);
CREATE TABLE zasp_retention_v1.tombstones(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,class text NOT NULL CHECK(class IN('runtime_event','product_session_event','inventory_evidence')),parent_id text NOT NULL,source_id text NOT NULL,resource_id text NOT NULL,source_digest text NOT NULL CHECK(source_digest~'^[0-9a-f]{64}$'),policy_version bigint NOT NULL CHECK(policy_version>0),cutoff timestamptz NOT NULL,expired_at timestamptz NOT NULL,cycle_key text NOT NULL,PRIMARY KEY(organization_id,workspace_id,environment_id,class,parent_id,source_id));
CREATE TABLE zasp_retention_v1.pending_cleanup(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,class text NOT NULL DEFAULT 'runtime_event' CHECK(class='runtime_event'),parent_id text NOT NULL DEFAULT '' CHECK(parent_id=''),source_id text NOT NULL,source_digest text NOT NULL,kind text NOT NULL CHECK(kind IN('raw-index','session-index-v1','session-index-v2')),cycle_key text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,workspace_id,environment_id,source_id,kind),FOREIGN KEY(organization_id,workspace_id,environment_id,class,parent_id,source_id) REFERENCES zasp_retention_v1.tombstones);
CREATE TABLE zasp_retention_v1.actions(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,class text NOT NULL,parent_id text NOT NULL,source_id text NOT NULL,source_digest text NOT NULL,policy_version bigint NOT NULL,cutoff timestamptz NOT NULL,cycle_key text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,workspace_id,environment_id,class,parent_id,source_id),FOREIGN KEY(organization_id,workspace_id,environment_id,class,parent_id,source_id) REFERENCES zasp_retention_v1.tombstones);
CREATE TABLE zasp_retention_v1.cycles(cycle_key text PRIMARY KEY CHECK(cycle_key~'^[0-9a-f]{64}$'),login_oid oid NOT NULL,receipt jsonb NOT NULL,completed_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE FUNCTION zasp_retention_v1.registered_operator() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $operator$ SELECT zasp_authorization79.operator() $operator$;
CREATE FUNCTION zasp_retention_v1.source_digest(class_value text,item jsonb) RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public SET timezone='UTC' AS $digest$
 SELECT encode(digest(convert_to(jsonb_build_array(class_value,CASE WHEN class_value='runtime_event' THEN item-'projected_at' ELSE item END)::text,'UTF8'),'sha256'),'hex')
$digest$;
CREATE FUNCTION zasp_retention_v1.principal(purpose_value text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $principal$
 SELECT coalesce(EXISTS(SELECT 1 FROM zasp_retention_v1.principals p JOIN pg_roles r ON(r.oid,r.rolname)=(p.login_oid,p.login_name)
 WHERE p.purpose=purpose_value AND r.rolname=session_user AND r.rolcanlogin AND r.rolinherit
 AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND(m.roleid<>p.authority_role::regrole OR m.admin_option))
 AND CASE purpose_value WHEN 'sweep' THEN p.authority_role='zasp_temporal_executor' AND zasp_temporal68.principal_ready('zasp_temporal_executor')
 WHEN 'human-read' THEN p.authority_role='zasp_discovery_api' AND public.zasp_discovery_principal_ready('zasp_discovery_api')
 WHEN 'runtime-index' THEN p.authority_role='zasp_runtime_index_worker' AND public.zasp_runtime_principal_ready('zasp_runtime_index_worker') WHEN 'runtime-coordinator' THEN p.authority_role='zasp_runtime_coordinator' AND public.zasp_runtime_principal_ready('zasp_runtime_coordinator') ELSE false END),false)
$principal$;
CREATE FUNCTION zasp_retention_v1.caller_ready(purpose_value text,pin text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
DECLARE result boolean;BEGIN
 IF pin IS DISTINCT FROM '-- retention checksum' OR NOT zasp_retention_v1.principal(purpose_value)
 OR NOT EXISTS(SELECT 1 FROM zasp_retention_v1.activation WHERE singleton AND checksum=pin)
 OR to_regprocedure('zasp_retention_v1.effective_catalog_ready(text)') IS NULL THEN RETURN false;END IF;
 -- Closed target exists only in the complete independently reviewed successor.
 EXECUTE 'SELECT zasp_retention_v1.effective_catalog_ready($1)' INTO result USING pin;
 RETURN result IS TRUE;
END $ready$;
CREATE FUNCTION zasp_retention_v1.require_sweep() RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $require$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT zasp_retention_v1.caller_ready('sweep','-- retention checksum') THEN
 RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='active retention sweep authority required';END IF;
END $require$;
CREATE FUNCTION zasp_retention_v1.visibility(q jsonb) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $visibility$
DECLARE p jsonb;id_value text;result jsonb:='[]';visible_value boolean;BEGIN
 IF NOT zasp_retention_v1.caller_ready('human-read','-- retention checksum')
 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','class','event_ids'])
 OR q->>'class' IS DISTINCT FROM 'runtime_event' OR jsonb_typeof(q->'event_ids') IS DISTINCT FROM 'array'
 OR jsonb_array_length(q->'event_ids') NOT BETWEEN 1 AND 1000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(q->'event_ids') v WHERE jsonb_typeof(v)<>'string' OR NOT public.zasp_valid_product_id(v#>>'{}'))
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(q->'event_ids') v GROUP BY v HAVING count(*)>1)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention visibility request rejected';END IF;
 p:=zasp_authorization80.context();
 IF p->>'operation_id'='listSessions' THEN
  IF NOT zasp_authorization80.session_query_authorized(q->>'organization_id',q->>'workspace_id',q->>'environment_id',p->>'principal_id') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current session query required';END IF;
 ELSIF p->>'operation_id'='simulatePolicy' THEN
  PERFORM zasp_authorization80.require_read(q->>'organization_id',q->>'workspace_id',q->>'environment_id',ARRAY['simulatePolicy'],'manage_workflows',false,p->>'principal_id');
  IF NOT zasp_authorization80.allowed(q->>'organization_id',q->>'workspace_id',q->>'environment_id','policy',p#>>'{path_parameters,id}') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current policy query required';END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current retention read purpose required';END IF;
 FOR id_value IN SELECT value FROM jsonb_array_elements_text(q->'event_ids') LOOP
  IF EXISTS(SELECT 1 FROM zasp_retention_v1.tombstones t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.class,t.parent_id,t.source_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','runtime_event','',id_value)) THEN
   IF p->>'operation_id'='listSessions' AND NOT EXISTS(SELECT 1 FROM zasp_retention_v1.tombstones t WHERE(t.organization_id,t.workspace_id,t.environment_id,t.class,t.parent_id,t.source_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','runtime_event','',id_value) AND zasp_authorization80.allowed(t.organization_id,t.workspace_id,t.environment_id,'session',t.resource_id)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current expired session permission required';END IF;visible_value:=false;
  ELSIF EXISTS(SELECT 1 FROM public.zasp_runtime_session_events v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.event_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',id_value)) THEN
   IF p->>'operation_id'='listSessions' AND NOT EXISTS(SELECT 1 FROM public.zasp_runtime_session_events v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.event_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',id_value) AND zasp_authorization80.allowed(v.organization_id,v.workspace_id,v.environment_id,'session',coalesce(v.session_id,'unattributed'))) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current live session permission required';END IF;visible_value:=true;
  ELSE RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention event relation unavailable';END IF;
  result:=result||jsonb_build_array(jsonb_build_object('event_id',id_value,'visible',visible_value));
 END LOOP;
 RETURN jsonb_build_object('items',result);
END $visibility$;

CREATE FUNCTION zasp_retention_v1.product_session_event_page(o text,session_value text,w text,e text,after_value timestamptz,after_id text,page_limit integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $product_page$
DECLARE p jsonb;result jsonb;BEGIN
 IF NOT zasp_retention_v1.caller_ready('human-read','-- retention checksum') OR page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 101 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='active product event reader required';END IF;
 p:=zasp_authorization80.context();
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listSessionEvents'],'investigate_sessions',true,p->>'principal_id');
 IF p#>>'{path_parameters,id}' IS DISTINCT FROM session_value OR NOT zasp_authorization80.allowed(o,w,e,'product_session',session_value)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_product_sessions v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.session_id)=(o,w,e,session_value)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current product session permission required';END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_session_events v WHERE(v.organization_id,v.session_id)=(o,session_value) AND NOT EXISTS(SELECT 1 FROM zasp_retention_v1.event_origins origin WHERE(origin.organization_id,origin.session_id,origin.event_id)=(v.organization_id,v.session_id,v.id) AND origin.source_digest=zasp_retention_v1.source_digest('product_session_event',to_jsonb(v)))) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy product event origin unavailable';END IF;
 SELECT jsonb_build_object('items',coalesce(jsonb_agg(item ORDER BY at,id),'[]')) INTO result FROM(
 SELECT v.id,v.at,jsonb_build_object('id',v.id,'session_id',v.session_id,'class',v.class,'label',v.label,'evidence_id',v.evidence_id,'source',v.source,'confidence',v.confidence,'at',v.at) item
 FROM public.zasp_session_events v JOIN zasp_retention_v1.event_origins origin ON(origin.organization_id,origin.session_id,origin.event_id)=(v.organization_id,v.session_id,v.id)
 WHERE(origin.organization_id,origin.workspace_id,origin.environment_id,origin.session_id)=(o,w,e,session_value) AND(after_value IS NULL OR(v.at,v.id)>(after_value,after_id)) ORDER BY v.at,v.id LIMIT page_limit
 ) page;
 RETURN result;
END $product_page$;
CREATE FUNCTION zasp_retention_v1.sweep(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $sweep$
DECLARE scope_value record;cursor_value zasp_retention_v1.cursors;candidate record;policy jsonb;item jsonb;digest_value text;cutoff_value timestamptz;class_value text;sequence_value bigint;scopes_value integer:=0;scanned_value integer:=0;expired_value integer:=0;receipt_value jsonb;deleted_value boolean;
BEGIN
 PERFORM zasp_retention_v1.require_sweep();
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['cycle_key']) OR jsonb_typeof(q->'cycle_key') IS DISTINCT FROM 'string' OR q->>'cycle_key'!~'^[0-9a-f]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='retention cycle rejected';END IF;
 SELECT sequence INTO STRICT sequence_value FROM zasp_retention_v1.scheduler WHERE singleton FOR UPDATE;
 PERFORM zasp_retention_v1.require_sweep();
 SELECT receipt INTO receipt_value FROM zasp_retention_v1.cycles WHERE cycle_key=q->>'cycle_key' AND login_oid=session_user::regrole;
 IF FOUND THEN RETURN receipt_value;END IF;
 IF EXISTS(SELECT 1 FROM zasp_retention_v1.cycles WHERE cycle_key=q->>'cycle_key') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention cycle identity changed';END IF;
 FOR scope_value IN SELECT s.* FROM zasp_retention_v1.scope_schedule s ORDER BY last_served,organization_id,workspace_id,environment_id LIMIT 16 FOR UPDATE LOOP
  IF sequence_value>=9223372036854775807 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention scheduler exhausted';END IF;
  sequence_value:=sequence_value+1;scopes_value:=scopes_value+1;
  UPDATE zasp_retention_v1.scope_schedule SET last_served=sequence_value WHERE(organization_id,workspace_id,environment_id)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id);
  PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||scope_value.organization_id,0));
  PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=scope_value.organization_id FOR UPDATE;
  IF NOT FOUND THEN CONTINUE;END IF;
  policy:=zasp_retention_v1.policy_lock(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id);
  PERFORM zasp_retention_v1.require_sweep();
  IF policy IS NULL OR policy->>'deletion_enabled' IS DISTINCT FROM 'true' THEN CONTINUE;END IF;
  cutoff_value:=transaction_timestamp()-make_interval(days=>(policy->>'retention_days')::integer);
  FOREACH class_value IN ARRAY ARRAY['runtime_event','product_session_event','inventory_evidence'] LOOP
   INSERT INTO zasp_retention_v1.cursors(organization_id,workspace_id,environment_id,class) VALUES(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,class_value) ON CONFLICT DO NOTHING;
   SELECT * INTO STRICT cursor_value FROM zasp_retention_v1.cursors WHERE(organization_id,workspace_id,environment_id,class)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,class_value) FOR UPDATE;
   deleted_value:=false;
   FOR candidate IN
    SELECT * FROM(
     SELECT ''::text parent_id,v.event_id source_id,v.event_time created_at,to_jsonb(v) body FROM public.zasp_runtime_session_events v WHERE class_value='runtime_event' AND(v.organization_id,v.workspace_id,v.environment_id)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id)
     UNION ALL SELECT v.session_id,v.id,v.at,to_jsonb(v) FROM public.zasp_session_events v WHERE class_value='product_session_event' AND v.organization_id=scope_value.organization_id AND EXISTS(SELECT 1 FROM zasp_retention_v1.event_origins origin WHERE(origin.organization_id,origin.workspace_id,origin.environment_id,origin.session_id,origin.event_id)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,v.session_id,v.id) AND origin.source_digest=zasp_retention_v1.source_digest('product_session_event',to_jsonb(v)))
     UNION ALL SELECT '',v.id,v.collected_at,to_jsonb(v) FROM public.zasp_inventory_evidence v WHERE class_value='inventory_evidence' AND(v.organization_id,v.workspace_id,v.environment_id)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id)
    ) candidates WHERE(parent_id,source_id)>(cursor_value.parent_id,cursor_value.source_id) ORDER BY parent_id,source_id LIMIT 33
   LOOP
    deleted_value:=true;scanned_value:=scanned_value+1;
    UPDATE zasp_retention_v1.cursors SET parent_id=candidate.parent_id,source_id=candidate.source_id WHERE(organization_id,workspace_id,environment_id,class)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,class_value);
    IF candidate.created_at>=cutoff_value THEN CONTINUE;END IF;
    IF class_value='runtime_event' THEN SELECT to_jsonb(v) INTO item FROM public.zasp_runtime_session_events v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.event_id)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,candidate.source_id) FOR UPDATE;
    ELSIF class_value='inventory_evidence' THEN SELECT to_jsonb(v) INTO item FROM public.zasp_inventory_evidence v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.id)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,candidate.source_id) FOR UPDATE;
    ELSE item:=candidate.body;END IF;
    PERFORM zasp_retention_v1.require_sweep();
    IF item IS DISTINCT FROM candidate.body THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='retention source changed';END IF;
    digest_value:=zasp_retention_v1.source_digest(class_value,item);
    INSERT INTO zasp_retention_v1.tombstones VALUES(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,class_value,candidate.parent_id,candidate.source_id,CASE WHEN class_value='runtime_event' THEN coalesce(item->>'session_id','unattributed') WHEN class_value='product_session_event' THEN candidate.parent_id ELSE coalesce(item->>'finding_id',item->>'entity_id','') END,digest_value,(policy->>'version')::bigint,cutoff_value,clock_timestamp(),q->>'cycle_key');
    IF class_value='runtime_event' THEN DELETE FROM public.zasp_runtime_session_events WHERE(organization_id,workspace_id,environment_id,event_id)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,candidate.source_id);deleted_value:=FOUND;
    ELSIF class_value='inventory_evidence' THEN DELETE FROM public.zasp_inventory_evidence WHERE(organization_id,workspace_id,environment_id,id)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,candidate.source_id);deleted_value:=FOUND;
    ELSE deleted_value:=zasp_retention_v1.delete_product_event(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,candidate.parent_id,candidate.source_id,digest_value);END IF;
    IF NOT deleted_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='retention source disappearance';END IF;
    INSERT INTO zasp_retention_v1.actions(organization_id,workspace_id,environment_id,class,parent_id,source_id,source_digest,policy_version,cutoff,cycle_key) VALUES(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,class_value,candidate.parent_id,candidate.source_id,digest_value,(policy->>'version')::bigint,cutoff_value,q->>'cycle_key');
    IF class_value='runtime_event' THEN
     INSERT INTO zasp_retention_v1.pending_cleanup(organization_id,workspace_id,environment_id,source_id,source_digest,kind,cycle_key) SELECT scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,candidate.source_id,digest_value,kind,q->>'cycle_key' FROM unnest(ARRAY['raw-index','session-index-v1','session-index-v2']) kind;
     INSERT INTO zasp_retention_v1.cleanup_queue(organization_id,workspace_id,environment_id,source_id,kind) SELECT scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,candidate.source_id,kind FROM unnest(ARRAY['raw-index','session-index-v1','session-index-v2']) kind;
    END IF;
    expired_value:=expired_value+1;
   END LOOP;
   IF NOT deleted_value THEN UPDATE zasp_retention_v1.cursors SET parent_id='',source_id='' WHERE(organization_id,workspace_id,environment_id,class)=(scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,class_value);END IF;
  END LOOP;
 END LOOP;
 UPDATE zasp_retention_v1.scheduler SET sequence=sequence_value WHERE singleton;
 PERFORM zasp_retention_v1.require_sweep();
 receipt_value:=jsonb_build_object('scopes',scopes_value,'scanned',scanned_value,'expired',expired_value);
 INSERT INTO zasp_retention_v1.cycles VALUES(q->>'cycle_key',session_user::regrole,receipt_value,clock_timestamp());
 RETURN receipt_value;
END $sweep$;

CREATE FUNCTION zasp_retention_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fingerprint$
 WITH facts(v) AS(
 SELECT concat_ws('|','namespace',nspowner::regrole::text,nspacl::text) FROM pg_namespace WHERE nspname='zasp_retention_v1'
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_proc p WHERE pronamespace='zasp_retention_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_retention_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attacl::text) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_retention_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_retention_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_retention_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_retention_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_retention_v1'::regnamespace AND NOT t.tgisinternal

 UNION ALL SELECT concat_ws('|','preimage',signature,target_oid,kind,definition,source,owner_oid,acl) FROM zasp_retention_v1.preimages
 UNION ALL SELECT concat_ws('|','successor',signature,definition) FROM zasp_retention_v1.successors
 UNION ALL SELECT concat_ws('|','effective-parent',p.oid::regprocedure::text,pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_proc p WHERE p.oid IN(SELECT target_oid FROM zasp_retention_v1.preimages)
 UNION ALL SELECT concat_ws('|','source-table',c.oid::regclass::text,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.oid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_session_events'::regclass,'public.zasp_data_controls'::regclass)
 UNION ALL SELECT concat_ws('|','source-column',a.attrelid::regclass::text,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attacl::text) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_session_events'::regclass,'public.zasp_data_controls'::regclass) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','source-constraint',conrelid::regclass::text,conname,pg_get_constraintdef(oid),convalidated) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_session_events'::regclass,'public.zasp_data_controls'::regclass)
 UNION ALL SELECT concat_ws('|','source-policy',polrelid::regclass::text,polname,polcmd,polpermissive,polroles::text,pg_get_expr(polqual,polrelid),pg_get_expr(polwithcheck,polrelid)) FROM pg_policy WHERE polrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_session_events'::regclass,'public.zasp_data_controls'::regclass)
 UNION ALL SELECT concat_ws('|','source-index',indrelid::regclass::text,pg_get_indexdef(indexrelid),indisvalid,indisready) FROM pg_index WHERE indrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_session_events'::regclass,'public.zasp_data_controls'::regclass)
 UNION ALL SELECT concat_ws('|','source-trigger',tgrelid::regclass::text,tgname,tgenabled,pg_get_triggerdef(oid)) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_session_events'::regclass,'public.zasp_data_controls'::regclass)

 UNION ALL SELECT concat_ws('|','source-owner',r.oid,r.rolname,r.rolcanlogin,b.authority_role) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner LEFT JOIN public.zasp_discovery_principal_bindings b ON b.principal_name=r.rolname WHERE p.oid='zasp_retention_v1.policy_lock(text,text,text)'::regprocedure
 ) SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$fingerprint$;
CREATE FUNCTION zasp_retention_v1.prepared_ready(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $prepared$
 SELECT coalesce(pin='-- retention checksum' AND(SELECT count(*)=1 FROM zasp_retention_v1.registration) AND EXISTS(SELECT 1 FROM zasp_retention_v1.registration WHERE singleton AND checksum=pin AND parent_worker='-- retention worker checksum' AND parent_runtime='-- retention runtime checksum' AND fingerprint=zasp_retention_v1.fingerprint()),false)
$prepared$;
CREATE FUNCTION zasp_retention_v1.register_principal(login_value text,purpose_value text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $register$
DECLARE role_value text;BEGIN
 IF NOT zasp_authorization79.operator() OR NOT(zasp_retention_v1.prepared_ready('-- retention checksum') OR zasp_retention_v1.effective_catalog_ready('-- retention checksum')) OR purpose_value NOT IN('human-read','runtime-index','runtime-coordinator','sweep') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention registration rejected';END IF;
 role_value:=CASE purpose_value WHEN 'human-read' THEN 'zasp_discovery_api' WHEN 'runtime-index' THEN 'zasp_runtime_index_worker' WHEN 'runtime-coordinator' THEN 'zasp_runtime_coordinator' WHEN 'sweep' THEN 'zasp_temporal_executor' END;
 INSERT INTO zasp_retention_v1.principals SELECT purpose_value,r.oid,r.rolname,role_value FROM pg_roles r WHERE r.rolname=login_value AND r.rolcanlogin AND r.rolinherit AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND(m.roleid<>role_value::regrole OR m.admin_option))
 AND pg_has_role(r.oid,role_value,'MEMBER')
 AND (CASE purpose_value WHEN 'sweep' THEN EXISTS(SELECT 1 FROM zasp_temporal68.principals WHERE principal=login_value AND authority=role_value) WHEN 'runtime-index' THEN EXISTS(SELECT 1 FROM public.zasp_runtime_principal_bindings WHERE principal_name=login_value AND authority_role=role_value) WHEN 'runtime-coordinator' THEN EXISTS(SELECT 1 FROM public.zasp_runtime_principal_bindings WHERE principal_name=login_value AND authority_role=role_value) ELSE EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=login_value AND authority_role=role_value) END) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_retention_v1.principals WHERE(purpose,login_name,authority_role)=(purpose_value,login_value,role_value)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention original principal required';END IF;
 RETURN true;
END $register$;
CREATE FUNCTION zasp_retention_v1.register_scope(o text,w text,e text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $scope$
BEGIN
 IF NOT zasp_authorization79.operator() OR NOT(zasp_retention_v1.prepared_ready('-- retention checksum') OR zasp_retention_v1.effective_catalog_ready('-- retention checksum')) OR NOT EXISTS(SELECT 1 FROM public.zasp_environments WHERE(organization_id,workspace_id,id)=(o,w,e)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='retention scope registration rejected';END IF;
 INSERT INTO zasp_retention_v1.scopes VALUES(o,w,e) ON CONFLICT DO NOTHING;
 INSERT INTO zasp_retention_v1.scope_schedule VALUES(o,w,e,0) ON CONFLICT DO NOTHING;
 RETURN true;
END $scope$;
-- retention successor definitions
DO $seal$ DECLARE n record;BEGIN
 FOR n IN SELECT tablename FROM pg_tables WHERE schemaname='zasp_retention_v1' LOOP
  EXECUTE format('ALTER TABLE zasp_retention_v1.%I OWNER TO zasp_discovery_authority',n.tablename);
  EXECUTE format('ALTER TABLE zasp_retention_v1.%I ENABLE ROW LEVEL SECURITY',n.tablename);
  EXECUTE format('ALTER TABLE zasp_retention_v1.%I FORCE ROW LEVEL SECURITY',n.tablename);
  EXECUTE format('CREATE POLICY authority ON zasp_retention_v1.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n.tablename);
  EXECUTE format('REVOKE ALL ON TABLE zasp_retention_v1.%I FROM PUBLIC',n.tablename);
  IF n.tablename IN('cleanup_claims','cleanup_authorizations','cleanup_observations','index_admissions','admission_settlements','index_partitions','partition_completions','preimages','successors','cutover_receipts','registration','activation','principals','scopes','event_origins','tombstones','pending_cleanup','actions','cycles') THEN EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_retention_v1.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n.tablename);END IF;
 END LOOP;
 FOR n IN SELECT p.oid::regprocedure signature FROM pg_proc p WHERE p.pronamespace='zasp_retention_v1'::regnamespace AND p.proname NOT IN('policy_lock','delete_product_event','capture_product_event_origin','install_product_guard','enroll_policy_scope') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',n.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',n.signature);
 END LOOP;
END $seal$;
GRANT USAGE ON SCHEMA zasp_retention_v1 TO zasp_discovery_api,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_retention_v1.caller_ready(text,text) TO zasp_discovery_api,zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_retention_v1.sweep(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_retention_v1.visibility(jsonb),zasp_retention_v1.product_session_event_page(text,text,text,text,timestamptz,text,integer) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_retention_v1.index_visibility(jsonb),zasp_retention_v1.session_index_visibility(jsonb) TO zasp_runtime_index_worker;
GRANT EXECUTE ON FUNCTION zasp_retention_v1.record_index_partition(jsonb),zasp_retention_v1.record_session_index_partition(jsonb),zasp_retention_v1.current_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer),zasp_retention_v1.current_session_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer),zasp_retention_v1.current_sandbox_search_finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer) TO zasp_runtime_index_worker;

-- Preserve the original registered source7 owner's NOINHERIT contract. Only
-- new supplementary metadata and fixed helper entrypoints are granted; parent
-- roles/ACLs are untouched. Exact ACLs and policies are part of fingerprint().
DO $bridge_access$ DECLARE owner_value text;n text;BEGIN
 SELECT p.proowner::regrole::text INTO STRICT owner_value FROM pg_proc p WHERE p.oid='zasp_retention_v1.policy_lock(text,text,text)'::regprocedure;
 IF NOT EXISTS(SELECT 1 FROM pg_roles r JOIN public.zasp_discovery_principal_bindings b ON b.principal_name=r.rolname WHERE r.rolname=owner_value AND r.rolcanlogin AND b.authority_role='zasp_discovery_authority') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='retention original source owner required';END IF;
 EXECUTE format('GRANT USAGE ON SCHEMA zasp_retention_v1 TO %I',owner_value);
 EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_retention_v1.registered_operator(),zasp_retention_v1.require_maintenance(),zasp_retention_v1.require_sweep(),zasp_retention_v1.source_digest(text,jsonb),zasp_retention_v1.effective_catalog_ready(text),zasp_retention_v1.prepared_ready(text) TO %I',owner_value);
 EXECUTE format('GRANT SELECT,INSERT ON zasp_retention_v1.event_origins,zasp_retention_v1.scopes TO %I',owner_value);
 EXECUTE format('GRANT SELECT ON zasp_retention_v1.tombstones TO %I',owner_value);
 EXECUTE format('GRANT INSERT ON zasp_retention_v1.scope_schedule TO %I',owner_value);
 FOREACH n IN ARRAY ARRAY['event_origins','scopes','tombstones','scope_schedule'] LOOP
  EXECUTE format('CREATE POLICY bridge_owner ON zasp_retention_v1.%I TO %I USING(current_user=%L) WITH CHECK(current_user=%L)',n,owner_value,owner_value,owner_value);
 END LOOP;
END $bridge_access$;
GRANT EXECUTE ON FUNCTION zasp_retention_v1.cleanup_claim(jsonb),zasp_retention_v1.cleanup_authorize(jsonb),zasp_retention_v1.cleanup_settle(jsonb) TO zasp_runtime_index_worker;
