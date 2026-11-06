-- Supplementary activation; predecessor source, fingerprints and ACLs remain immutable.
CREATE SCHEMA zasp_approval_activation_v1 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_approval_activation_v1 FROM PUBLIC;
CREATE TABLE zasp_approval_activation_v1.registration(singleton boolean PRIMARY KEY CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_approval_activation_v1.organizations(organization_id text PRIMARY KEY,connector_checksum text NOT NULL,approval_checksum text NOT NULL,store_id text NOT NULL,model_id text NOT NULL,withdrawal_reference text NOT NULL CHECK(withdrawal_reference~'^[a-f0-9]{64}$'));
CREATE FUNCTION zasp_approval_activation_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT encode(digest(convert_to(jsonb_build_object('namespace',(SELECT jsonb_build_array(nspowner::regrole::text,coalesce(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_approval_activation_v1'),'indexes',(SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) ORDER BY c.relname) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid WHERE t.relnamespace='zasp_approval_activation_v1'::regnamespace),'defaults',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attname,pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attname) FROM pg_attrdef d JOIN pg_class c ON c.oid=d.adrelid JOIN pg_attribute a ON(a.attrelid,a.attnum)=(d.adrelid,d.adnum) WHERE c.relnamespace='zasp_approval_activation_v1'::regnamespace),'views',(SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_viewdef(c.oid),c.relowner::regrole::text,coalesce(c.relacl::text,'')) ORDER BY c.relname) FROM pg_class c WHERE c.relnamespace='zasp_approval_activation_v1'::regnamespace AND c.relkind='v'),'functions',(SELECT jsonb_agg(jsonb_build_array(p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,coalesce(p.proacl::text,'')) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_approval_activation_v1'::regnamespace),'columns',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,c.relrowsecurity,c.relforcerowsecurity,c.relowner::regrole::text,coalesce(c.relacl::text,'')) ORDER BY c.relname,a.attnum) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped WHERE c.relnamespace='zasp_approval_activation_v1'::regnamespace AND c.relkind='r'),'policies',(SELECT jsonb_agg(jsonb_build_array(c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY c.relname,p.polname) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_approval_activation_v1'::regnamespace),'triggers',(SELECT jsonb_agg(jsonb_build_array(c.relname,t.tgname,pg_get_triggerdef(t.oid),t.tgenabled) ORDER BY c.relname,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_approval_activation_v1'::regnamespace AND NOT t.tgisinternal),'constraints',(SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,pg_get_constraintdef(k.oid)) ORDER BY c.relname,k.conname) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_approval_activation_v1'::regnamespace))::text,'UTF8'),'sha256'),'hex')
$f$;
CREATE FUNCTION zasp_approval_activation_v1.ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
 SELECT coalesce((SELECT count(*)=1 AND bool_and(singleton AND checksum='-- activation checksum' AND fingerprint=zasp_approval_activation_v1.fingerprint()) FROM zasp_approval_activation_v1.registration),false)
 AND zasp_authorization79.ready('-- authorization79 checksum') AND zasp_authorization80.ready('-- authorization80 checksum')
 AND zasp_connector_maintenance.catalog_ready('-- connector checksum') AND zasp_approval_maintenance.catalog_ready()
 AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE singleton AND checksum='-- approval checksum')
$ready$;
CREATE FUNCTION zasp_approval_activation_v1.catalog_ready(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $catalog$
 SELECT pin IS NOT DISTINCT FROM '-- activation checksum' AND zasp_approval_activation_v1.ready() IS TRUE
$catalog$;
-- Only validate a pre-existing authentic native delegation. Never reissue one.
CREATE FUNCTION zasp_approval_activation_v1.eligible(o zasp_approval_maintenance.origins) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $eligible$
DECLARE n public.zasp_security_agent_approval_notifications;checks_count integer;BEGIN
 IF o.status<>'captured_inactive' OR o.delegation IS NULL OR o.family IS NULL OR o.family NOT IN('finding78','test74','ordered68','ordered68_progress')
 OR o.source_digest IS NULL OR o.source_digest!~'^[a-f0-9]{64}$' OR o.source_digest IS DISTINCT FROM o.facts->>'source_digest'
 OR (o.facts->>'organization_id',o.facts->>'workspace_id',o.facts->>'environment_id',o.facts->>'run_id') IS DISTINCT FROM(o.organization_id,o.workspace_id,o.environment_id,o.run_id)
 OR public.zasp_valid_product_id(o.facts->>'principal_id') IS NOT TRUE OR public.zasp_valid_product_id(o.facts->>'grantor_id') IS NOT TRUE
 OR zasp_sa_multistep_prior.closed(o.delegation,ARRAY['task_id','purpose','principal_id','grantor_id']) IS NOT TRUE
 OR o.delegation IS DISTINCT FROM jsonb_build_object('task_id',public.zasp_discovery_canonical_id(o.organization_id,o.workspace_id,o.environment_id,'approval_delivery_task',o.delivery_id||chr(31)||encode(o.payload_digest,'hex')),'purpose','approval_notification_delivery','principal_id',o.facts->>'principal_id','grantor_id',o.facts->>'grantor_id')
 OR jsonb_typeof(o.facts->'checks') IS DISTINCT FROM 'array' THEN RETURN false;END IF;
 checks_count:=jsonb_array_length(o.facts->'checks');
 IF checks_count NOT BETWEEN 2 AND 128 OR(o.family='ordered68_progress' AND(o.facts->>'execution_phase' IS DISTINCT FROM 'progress' OR checks_count<>2)) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(o.facts->'checks') c WHERE jsonb_typeof(c) IS DISTINCT FROM 'object') THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(o.facts->'checks') c WHERE zasp_sa_multistep_prior.closed(c,ARRAY['kind','id','permission']) IS NOT TRUE OR EXISTS(SELECT 1 FROM jsonb_each(c) WHERE jsonb_typeof(value) IS DISTINCT FROM 'string') OR public.zasp_valid_product_id(c->>'id') IS NOT TRUE OR c->>'kind'!~'^[a-z][a-z0-9_]{0,62}$' OR c->>'permission' NOT IN('investigate_sessions','manage_api_tokens','manage_data_controls','manage_findings','manage_identity','manage_workflows','revoke_sessions','run_tests','view','view_audit','view_compliance'))
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(o.facts->'checks') c WHERE(c->>'kind',c->>'id',c->>'permission')=('security_agent',o.facts->>'definition_id','manage_workflows'))
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(o.facts->'checks') c WHERE(c->>'kind',c->>'id',c->>'permission')=('security_agent_run',o.run_id,'manage_workflows'))
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(o.facts->'checks') c GROUP BY c->>'kind',c->>'id',c->>'permission' HAVING count(*)>1)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_memberships m WHERE(m.organization_id,m.principal_id,m.active)=(o.organization_id,o.facts->>'grantor_id',true))
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(o.facts->'checks') c WHERE NOT EXISTS(SELECT 1 FROM zasp_authorization79.resources r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=(o.organization_id,o.workspace_id,o.environment_id,c->>'kind',c->>'id')))
 THEN RETURN false;END IF;
 SELECT x.* INTO n FROM public.zasp_security_agent_approval_notifications x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.delivery_id)=(o.organization_id,o.workspace_id,o.environment_id,o.delivery_id);
 IF NOT FOUND OR n.state NOT IN('pending','retryable') OR n.attempt<>0 OR n.lease_token IS NOT NULL
 OR(n.approval_id,n.run_id,n.payload_digest,n.destination_url,n.secret_reference) IS DISTINCT FROM(o.approval_id,o.run_id,o.payload_digest,o.destination_url,o.secret_reference)
 OR digest(convert_to(n.payload::text,'UTF8'),'sha256') IS DISTINCT FROM o.payload_digest
 OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.approval_id,a.run_id)=(o.organization_id,o.workspace_id,o.environment_id,o.approval_id,o.run_id))
 THEN RETURN false;END IF;
 RETURN EXISTS(SELECT 1 FROM zasp_approval_maintenance.origin_intents i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.run_id,i.family,i.source_digest,i.facts) IS NOT DISTINCT FROM(o.organization_id,o.workspace_id,o.environment_id,o.run_id,o.family,o.source_digest,o.facts));
END $eligible$;
CREATE FUNCTION zasp_approval_activation_v1.activate_controlled_organization(o text,activation_pin text,connector_pin text,approval_pin text,store_value text,model_value text,withdrawal_value text,desired_value bigint,applied_value bigint,generation_value bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $activate$
DECLARE v zasp_authorization79.organizations;prior zasp_approval_activation_v1.organizations;result_value jsonb;eligible integer;promoted integer;BEGIN
 -- Lock precedes all source capture, admission and activation work.
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||o,0));
 IF zasp_authorization79.operator() IS NOT TRUE OR zasp_approval_activation_v1.ready() IS NOT TRUE OR activation_pin IS DISTINCT FROM '-- activation checksum' OR connector_pin IS DISTINCT FROM '-- connector checksum' OR approval_pin IS DISTINCT FROM '-- approval checksum'
 OR public.zasp_valid_product_id(o) IS NOT TRUE OR withdrawal_value IS NULL OR withdrawal_value!~'^[a-f0-9]{64}$'
 OR NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.principals p JOIN pg_roles r ON r.rolname=p.principal_name JOIN pg_roles a ON a.rolname=p.authority_role WHERE r.rolcanlogin AND NOT(r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls) AND NOT(a.rolcanlogin OR a.rolinherit OR a.rolsuper OR a.rolcreatedb OR a.rolcreaterole OR a.rolreplication OR a.rolbypassrls) AND pg_has_role(r.oid,a.oid,'MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=a.oid OR(m.member=r.oid AND(m.roleid<>a.oid OR m.admin_option))))
 OR NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.verifiers f CROSS JOIN zasp_approval_maintenance.verifiers c WHERE f.purpose='approval-forward' AND c.purpose='approval-captured' AND octet_length(f.key)=32 AND octet_length(c.key)=32 AND f.key<>c.key AND f.version=encode(digest(f.key,'sha256'),'hex') AND c.version=encode(digest(c.key,'sha256'),'hex'))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='combined activation rejected';END IF;
 SELECT x.* INTO v FROM zasp_authorization79.organizations x WHERE x.organization_id=o FOR UPDATE;
 IF NOT FOUND OR desired_value IS NULL OR applied_value IS NULL OR generation_value IS NULL OR desired_value<1 OR desired_value<>applied_value OR generation_value<1 OR(v.desired,v.applied,v.generation,v.store_id,v.model_id) IS DISTINCT FROM(desired_value,applied_value,generation_value,store_value,model_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='combined activation revision changed';END IF;
 SELECT x.* INTO prior FROM zasp_approval_activation_v1.organizations x WHERE x.organization_id=o FOR UPDATE;
 IF FOUND AND(prior.connector_checksum,prior.approval_checksum,prior.store_id,prior.model_id,prior.withdrawal_reference) IS DISTINCT FROM(connector_pin,approval_pin,store_value,model_value,withdrawal_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='combined activation already bound';END IF;
 PERFORM 1 FROM public.zasp_security_agent_approval_notifications n WHERE n.organization_id=o ORDER BY n.workspace_id,n.environment_id,n.delivery_id FOR UPDATE;
 PERFORM 1 FROM zasp_approval_maintenance.origins x WHERE x.organization_id=o ORDER BY x.workspace_id,x.environment_id,x.delivery_id FOR UPDATE;
 SELECT count(*) INTO eligible FROM zasp_approval_maintenance.origins x WHERE x.organization_id=o AND zasp_approval_activation_v1.eligible(x);
 IF eligible>20 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='combined activation bound exceeded';END IF;
 IF EXISTS(SELECT 1 FROM zasp_approval_maintenance.projection_activations a WHERE a.organization_id=o AND(a.source_checksum,a.store_id,a.model_id,a.withdrawal_reference) IS DISTINCT FROM(approval_pin,store_value,model_value,withdrawal_value)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval activation already bound';END IF;
 result_value:=zasp_connector_maintenance.activate_controlled_organization(o,connector_pin,approval_pin,store_value,model_value,withdrawal_value,desired_value,applied_value,generation_value);
 INSERT INTO zasp_approval_activation_v1.organizations VALUES(o,connector_pin,approval_pin,store_value,model_value,withdrawal_value) ON CONFLICT DO NOTHING;
 INSERT INTO zasp_approval_maintenance.projection_activations VALUES(o,approval_pin,store_value,model_value,withdrawal_value) ON CONFLICT DO NOTHING;
 UPDATE zasp_approval_maintenance.registration SET active=true WHERE singleton;
 UPDATE zasp_approval_maintenance.origins x SET status='active' WHERE x.organization_id=o AND zasp_approval_activation_v1.eligible(x);
 GET DIAGNOSTICS promoted=ROW_COUNT;
 IF promoted<>eligible THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval captures changed';END IF;
 SELECT x.* INTO STRICT v FROM zasp_authorization79.organizations x WHERE x.organization_id=o;
 IF v.desired=desired_value AND(promoted>0 OR prior.organization_id IS NULL) THEN PERFORM zasp_authorization79.touch(o);END IF;
 SELECT x.* INTO STRICT v FROM zasp_authorization79.organizations x WHERE x.organization_id=o;
 IF(v.applied,v.generation,v.store_id,v.model_id) IS DISTINCT FROM(applied_value,generation_value,store_value,model_value) OR v.desired NOT IN(desired_value,desired_value+1) OR zasp_approval_activation_v1.ready() IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='combined publication changed';END IF;
 RETURN jsonb_build_object('organization_id',o,'activated',true,'connector_origins',(result_value->>'origins')::integer,'approval_origins',promoted,'desired',v.desired,'applied',v.applied,'generation',v.generation,'store_id',v.store_id,'model_id',v.model_id);
END $activate$;
CREATE FUNCTION zasp_approval_activation_v1.admit_with_origin(family_value text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $admit$
DECLARE o text:=q->>'organization_id';result_value jsonb;changed integer;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||o,0));
 IF zasp_approval_activation_v1.ready() IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval activation unavailable';END IF;
 result_value:=zasp_approval_maintenance.admit_with_origin(family_value,q);
 IF EXISTS(SELECT 1 FROM zasp_approval_activation_v1.organizations a JOIN zasp_authorization79.organizations v ON(v.organization_id,v.store_id,v.model_id)=(a.organization_id,a.store_id,a.model_id) WHERE a.organization_id=o AND a.connector_checksum='-- connector checksum' AND a.approval_checksum='-- approval checksum') THEN
 UPDATE zasp_approval_maintenance.origins x SET status='active' WHERE x.organization_id=o AND x.workspace_id=q->>'workspace_id' AND x.environment_id=q->>'environment_id' AND x.run_id=q->>'run_id' AND x.family=family_value AND x.approval_id=result_value->>'approval_id' AND zasp_approval_activation_v1.eligible(x)
 AND EXISTS(SELECT 1 FROM public.zasp_security_agent_approval_notifications n WHERE(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id)=(x.organization_id,x.workspace_id,x.environment_id,x.delivery_id) AND n.created_at=transaction_timestamp() AND n.xmin::text::bigint=txid_current()%4294967296)
 AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.origin_intents i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.run_id,i.transaction_id,i.backend_id,i.principal_name,i.family)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,txid_current(),pg_backend_pid(),session_user,family_value));
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed>1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval admission multiplicity changed';END IF;
 IF changed=1 THEN PERFORM zasp_authorization79.touch(o);END IF;
 END IF;
 RETURN result_value;
END $admit$;
DO $seal$ DECLARE n record;BEGIN
 FOR n IN SELECT tablename FROM pg_tables WHERE schemaname='zasp_approval_activation_v1' LOOP
 EXECUTE format('ALTER TABLE zasp_approval_activation_v1.%I OWNER TO zasp_discovery_authority',n.tablename);
 EXECUTE format('ALTER TABLE zasp_approval_activation_v1.%I ENABLE ROW LEVEL SECURITY',n.tablename);
 EXECUTE format('ALTER TABLE zasp_approval_activation_v1.%I FORCE ROW LEVEL SECURITY',n.tablename);
 EXECUTE format('CREATE POLICY authority ON zasp_approval_activation_v1.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n.tablename);
 EXECUTE format('REVOKE ALL ON TABLE zasp_approval_activation_v1.%I FROM PUBLIC',n.tablename);
 END LOOP;
 FOR n IN SELECT p.oid::regprocedure signature FROM pg_proc p WHERE p.pronamespace='zasp_approval_activation_v1'::regnamespace LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',n.signature);
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',n.signature);
 END LOOP;
END $seal$;
GRANT USAGE ON SCHEMA zasp_approval_activation_v1 TO zasp_temporal_executor,zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_approval_activation_v1.admit_with_origin(text,jsonb),zasp_approval_activation_v1.catalog_ready(text) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_approval_activation_v1.activate_controlled_organization(text,text,text,text,text,text,text,bigint,bigint,bigint) TO zasp_discovery_authority;
