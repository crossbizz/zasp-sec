-- Additive versioned settlement audit. Original maintenance and activation
-- definitions, privileges, registrations and immutable receipts are untouched.
CREATE SCHEMA zasp_approval_settlement_v1 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_approval_settlement_v1 FROM PUBLIC;
CREATE TABLE zasp_approval_settlement_v1.registration(singleton boolean PRIMARY KEY CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE FUNCTION zasp_approval_settlement_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT encode(digest(convert_to(jsonb_build_object('namespace',(SELECT jsonb_build_array(nspowner::regrole::text,coalesce(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_approval_settlement_v1'),'indexes',(SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) ORDER BY c.relname) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid WHERE t.relnamespace='zasp_approval_settlement_v1'::regnamespace),'defaults',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attname,pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attname) FROM pg_attrdef d JOIN pg_class c ON c.oid=d.adrelid JOIN pg_attribute a ON(a.attrelid,a.attnum)=(d.adrelid,d.adnum) WHERE c.relnamespace='zasp_approval_settlement_v1'::regnamespace),'views',(SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_viewdef(c.oid),c.relowner::regrole::text,coalesce(c.relacl::text,'')) ORDER BY c.relname) FROM pg_class c WHERE c.relnamespace='zasp_approval_settlement_v1'::regnamespace AND c.relkind='v'),'functions',(SELECT jsonb_agg(jsonb_build_array(p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,coalesce(p.proacl::text,'')) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_approval_settlement_v1'::regnamespace),'columns',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,c.relrowsecurity,c.relforcerowsecurity,c.relowner::regrole::text,coalesce(c.relacl::text,'')) ORDER BY c.relname,a.attnum) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped WHERE c.relnamespace='zasp_approval_settlement_v1'::regnamespace AND c.relkind='r'),'policies',(SELECT jsonb_agg(jsonb_build_array(c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY c.relname,p.polname) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_approval_settlement_v1'::regnamespace),'triggers',(SELECT jsonb_agg(jsonb_build_array(c.relname,t.tgname,pg_get_triggerdef(t.oid),t.tgenabled) ORDER BY c.relname,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_approval_settlement_v1'::regnamespace AND NOT t.tgisinternal),'constraints',(SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,pg_get_constraintdef(k.oid)) ORDER BY c.relname,k.conname) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_approval_settlement_v1'::regnamespace))::text,'UTF8'),'sha256'),'hex')
$f$;
CREATE FUNCTION zasp_approval_settlement_v1.catalog_ready(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $catalog$
 SELECT pin IS NOT DISTINCT FROM '-- settlement checksum'
 AND coalesce((SELECT count(*)=1 AND bool_and(singleton AND checksum='-- settlement checksum' AND fingerprint=zasp_approval_settlement_v1.fingerprint()) FROM zasp_approval_settlement_v1.registration),false)
 AND zasp_approval_activation_v1.catalog_ready('-- activation checksum') IS TRUE
$catalog$;
CREATE FUNCTION zasp_approval_settlement_v1.settle(q jsonb,envelope_value json,successful boolean,pin text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $settle$
DECLARE r zasp_approval_maintenance.reservations;n public.zasp_security_agent_approval_notifications;o zasp_approval_maintenance.origins;a public.zasp_security_agent_approvals;
 result_value jsonb;transition_value text;event_value text;audit_value text;correlation_value text;identity_value text;body_value jsonb;digest_value bytea;actor_value text;
BEGIN
 IF zasp_approval_settlement_v1.catalog_ready(pin) IS NOT TRUE OR successful IS NULL OR zasp_approval_maintenance.worker() IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval audited settlement unavailable';END IF;
 -- Original organization lock first, then original notification/reservation
 -- locks. No FGA or current membership is required for captured settlement.
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||(q->>'organization_id'),0));
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval audit organization unavailable';END IF;
 r:=zasp_approval_maintenance.reserved(q);
 SELECT x.* INTO STRICT n FROM public.zasp_security_agent_approval_notifications x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.delivery_id)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id);
 SELECT x.* INTO STRICT o FROM zasp_approval_maintenance.origins x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.delivery_id)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id) FOR SHARE;
 SELECT x.* INTO STRICT a FROM public.zasp_security_agent_approvals x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.approval_id,x.run_id)=(n.organization_id,n.workspace_id,n.environment_id,n.approval_id,n.run_id) FOR SHARE;
 actor_value:=o.delegation->>'principal_id';
 IF r.state IS DISTINCT FROM 'attempted' OR r.attempt IS NULL OR r.attempt NOT BETWEEN 1 AND 10 OR r.kind IS NULL OR r.kind NOT IN('delivery','secret_failure')
 OR(r.attempt,r.payload_digest) IS DISTINCT FROM(n.attempt,n.payload_digest)
 OR digest(convert_to(n.payload::text,'UTF8'),'sha256') IS DISTINCT FROM n.payload_digest
 OR(o.facts->>'organization_id',o.facts->>'workspace_id',o.facts->>'environment_id',o.facts->>'run_id') IS DISTINCT FROM(n.organization_id,n.workspace_id,n.environment_id,n.run_id)
 OR zasp_sa_multistep_prior.closed(o.delegation,ARRAY['task_id','purpose','principal_id','grantor_id']) IS NOT TRUE
 OR(o.approval_id,o.run_id,o.payload_digest,o.destination_url,o.secret_reference) IS DISTINCT FROM(n.approval_id,n.run_id,n.payload_digest,n.destination_url,n.secret_reference)
 OR public.zasp_valid_product_id(actor_value) IS NOT TRUE OR o.delegation->>'purpose' IS DISTINCT FROM 'approval_notification_delivery'
 OR actor_value IS DISTINCT FROM o.facts->>'principal_id' OR o.source_digest IS NULL OR o.source_digest!~'^[a-f0-9]{64}$' OR o.source_digest IS DISTINCT FROM o.facts->>'source_digest'
 OR o.delegation->>'task_id' IS DISTINCT FROM public.zasp_discovery_canonical_id(n.organization_id,n.workspace_id,n.environment_id,'approval_delivery_task',n.delivery_id||chr(31)||encode(n.payload_digest,'hex'))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval audit native source unavailable';END IF;
 -- Original native receipt/HMAC/purpose/lease/attempt validation and mutation
 -- remain authoritative. Any subsequent audit error rolls this entire call back.
 result_value:=zasp_approval_maintenance.settle(q,envelope_value,successful);
 IF zasp_sa_multistep_prior.closed(result_value,ARRAY['transition']) IS NOT TRUE OR jsonb_typeof(result_value->'transition') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval audit transition unavailable';END IF;
 transition_value:=result_value->>'transition';
 IF transition_value IS DISTINCT FROM (CASE WHEN successful THEN 'delivered' WHEN r.attempt>=10 THEN 'exhausted' ELSE 'retryable' END) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval audit transition changed';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approval_notifications x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.delivery_id,x.approval_id,x.run_id,x.payload_digest,x.attempt,x.state)=(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id,n.approval_id,n.run_id,n.payload_digest,r.attempt,transition_value) AND x.lease_owner IS NULL AND x.lease_token IS NULL AND x.lease_expires_at IS NULL AND(successful AND x.completed_at IS NOT NULL OR NOT successful AND x.completed_at IS NULL))
 OR NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.reservations x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.delivery_id,x.lease_token,x.state,x.attempt,x.kind,x.receipt) IS NOT DISTINCT FROM(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id,r.lease_token,'settled',r.attempt,r.kind,r.receipt))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval audit settlement changed';END IF;
 event_value:=CASE transition_value WHEN 'delivered' THEN 'approval_notification_delivered' WHEN 'retryable' THEN 'approval_notification_retryable' WHEN 'exhausted' THEN 'approval_notification_exhausted' END;
 identity_value:=n.delivery_id||chr(31)||r.attempt::text||chr(31)||r.kind;
 audit_value:=public.zasp_discovery_canonical_id(n.organization_id,n.workspace_id,n.environment_id,'approval_delivery_audit',identity_value||chr(31)||transition_value);
 correlation_value:=public.zasp_discovery_canonical_id(n.organization_id,n.workspace_id,n.environment_id,'approval_delivery_attempt',identity_value);
 body_value:=jsonb_build_object('delivery_id',n.delivery_id,'run_id',n.run_id,'approval_id',n.approval_id,'step_id',a.step_id,'attempt',r.attempt,'kind',r.kind,'transition',transition_value,'payload_digest','sha256:'||encode(n.payload_digest,'hex'),'source_digest','sha256:'||o.source_digest,'receipt_digest','sha256:'||encode(digest(convert_to(r.receipt::text,'UTF8'),'sha256'),'hex'));
 digest_value:=digest(convert_to(jsonb_build_object('organization_id',n.organization_id,'workspace_id',n.workspace_id,'environment_id',n.environment_id,'audit_id',audit_value,'correlation_id',correlation_value,'actor_id',actor_value,'event_kind',event_value,'body',body_value)::text,'UTF8'),'sha256');
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body)
 VALUES(n.organization_id,n.workspace_id,n.environment_id,audit_value,correlation_value,n.run_id,a.step_id,n.approval_id,actor_value,event_value,digest_value,body_value) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.audit_id,x.correlation_id,x.run_id,x.step_id,x.approval_id,x.actor_id,x.event_kind,x.event_digest,x.body) IS NOT DISTINCT FROM(n.organization_id,n.workspace_id,n.environment_id,audit_value,correlation_value,n.run_id,a.step_id,n.approval_id,actor_value,event_value,digest_value,body_value)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval audit evidence changed';END IF;
 RETURN result_value;
END $settle$;
DO $seal$ DECLARE n record;BEGIN
 FOR n IN SELECT tablename FROM pg_tables WHERE schemaname='zasp_approval_settlement_v1' LOOP
 EXECUTE format('ALTER TABLE zasp_approval_settlement_v1.%I OWNER TO zasp_discovery_authority',n.tablename);
 EXECUTE format('ALTER TABLE zasp_approval_settlement_v1.%I ENABLE ROW LEVEL SECURITY',n.tablename);
 EXECUTE format('ALTER TABLE zasp_approval_settlement_v1.%I FORCE ROW LEVEL SECURITY',n.tablename);
 EXECUTE format('CREATE POLICY authority ON zasp_approval_settlement_v1.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n.tablename);
 EXECUTE format('REVOKE ALL ON TABLE zasp_approval_settlement_v1.%I FROM PUBLIC',n.tablename);
 END LOOP;
 FOR n IN SELECT p.oid::regprocedure signature FROM pg_proc p WHERE p.pronamespace='zasp_approval_settlement_v1'::regnamespace LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',n.signature);
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',n.signature);
 END LOOP;
END $seal$;
GRANT USAGE ON SCHEMA zasp_approval_settlement_v1 TO zasp_approval_maintenance_worker;
GRANT EXECUTE ON FUNCTION zasp_approval_settlement_v1.catalog_ready(text),zasp_approval_settlement_v1.settle(jsonb,json,boolean,text) TO zasp_approval_maintenance_worker;
