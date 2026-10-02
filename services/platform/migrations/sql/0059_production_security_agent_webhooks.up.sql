DO $guard$
BEGIN
 IF NOT public.zasp_sa_export_readiness('-- webhook predecessor checksum','-- webhook predecessor fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='webhook predecessor unavailable';END IF;
END $guard$;
CREATE SCHEMA zasp_sa_webhook_prior AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_sa_webhook_prior FROM PUBLIC;
CREATE TABLE zasp_sa_webhook_prior.functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl jsonb NOT NULL);
ALTER TABLE zasp_sa_webhook_prior.functions OWNER TO zasp_discovery_authority;
REVOKE ALL ON zasp_sa_webhook_prior.functions FROM PUBLIC;
CREATE FUNCTION public.zasp_sa_webhook_save(signature_value text) RETURNS void LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $save$
DECLARE p pg_proc%ROWTYPE;
BEGIN
 SELECT * INTO STRICT p FROM pg_proc WHERE oid=signature_value::regprocedure;
 INSERT INTO zasp_sa_webhook_prior.functions SELECT signature_value,pg_get_functiondef(p.oid),p.proowner::regrole::text,COALESCE((SELECT jsonb_agg(jsonb_build_object('grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'grantable',a.is_grantable) ORDER BY a.ordinality) FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) WITH ORDINALITY a WHERE a.privilege_type='EXECUTE'),'[]');
END $save$;
REVOKE ALL ON FUNCTION public.zasp_sa_webhook_save(text) FROM PUBLIC;

DO $ancestry$
DECLARE sig text;d text;needle text;n integer;
BEGIN
 PERFORM set_config('check_function_bodies','off',true);
 FOREACH sig IN ARRAY ARRAY[
 'public.zasp_compliance_readiness(text,text)',
 'public.zasp_production_security_agent_existing_tests_readiness(text,text)',
 'public.zasp_sa_attack_lab_readiness(text,text)',
 'zasp_sa_attack_lab_prior.predecessor_ready(text,text)',
 'zasp_sa_export_prior.predecessor_ready(text,text)',
 'public.zasp_sa_export_readiness(text,text)',
 'public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',
 'public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)',
 'public.zasp_production_security_agent_attack_path_security_ready()',
 'public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  PERFORM public.zasp_sa_webhook_save(sig);d:=pg_get_functiondef(sig::regprocedure);
  IF strpos(sig,'readiness(')>0 OR strpos(sig,'predecessor_ready(')>0 THEN
   IF strpos(d,'count(*)=58')=0 OR strpos(d,'version>58')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='webhook predecessor shape rejected';END IF;
   d:=replace(replace(d,'count(*)=58','count(*)=59'),'version>58','version>59');
   IF sig='public.zasp_sa_export_readiness(text,text)' THEN
    EXECUTE replace(replace(d,'FUNCTION public.zasp_sa_export_readiness(','FUNCTION zasp_sa_webhook_prior.predecessor_ready('),'public.zasp_sa_export_live_fingerprint()=expected_fingerprint','true');
    ALTER FUNCTION zasp_sa_webhook_prior.predecessor_ready(text,text) OWNER TO zasp_discovery_authority;
    REVOKE ALL ON FUNCTION zasp_sa_webhook_prior.predecessor_ready(text,text) FROM PUBLIC;
    d:=replace(d,'public.zasp_sa_export_live_fingerprint()=expected_fingerprint','public.zasp_sa_webhook_guard()');
   END IF;
  ELSE
   n:=0;
   FOREACH needle IN ARRAY ARRAY['later_release."version" > 58','later."version">58','later."version" > 58'] LOOP
    n:=n+(length(d)-length(replace(d,needle,'')))/length(needle);
    d:=replace(d,needle,replace(needle,'58','59'));
   END LOOP;
   IF n NOT IN(1,3) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='webhook compatibility rejected';END IF;
  END IF;
  EXECUTE d;
 END LOOP;
 sig:='zasp_sa_attack_lab_prior.audit_fingerprint()';PERFORM public.zasp_sa_webhook_save(sig);d:=pg_get_functiondef(sig::regprocedure);
 needle:='''production_security_agent_exports_checksum'',''production_security_agent_exports_fingerprint''';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='webhook ancestry rejected';END IF;
 EXECUTE replace(d,needle,needle||',''production_security_agent_webhooks_checksum'',''production_security_agent_webhooks_fingerprint''');
 PERFORM set_config('check_function_bodies','on',true);
END $ancestry$;

CREATE ROLE zasp_security_agent_webhook_worker NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT zasp_security_agent_webhook_worker TO zasp_discovery_authority WITH ADMIN OPTION;
CREATE TABLE public.zasp_sa_webhook_principals(principal_name text PRIMARY KEY CHECK(principal_name ~ '^[a-z][a-z0-9_]{2,62}$'));
ALTER TABLE public.zasp_sa_webhook_principals OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_sa_webhook_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_sa_webhook_principals FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_principal_authority ON public.zasp_sa_webhook_principals USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON public.zasp_sa_webhook_principals FROM PUBLIC;
CREATE FUNCTION public.zasp_sa_webhook_register_principal(migration_value text,principal_value text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $register$
BEGIN
 IF migration_value IS DISTINCT FROM session_user OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') OR NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook registration authority rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=principal_value AND rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls) OR EXISTS(SELECT 1 FROM pg_roles WHERE starts_with(rolname,'zasp_') AND rolname<>'zasp_security_agent_webhook_worker' AND pg_has_role(principal_value,oid,'MEMBER')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook unsafe principal rejected';END IF;
 EXECUTE format('GRANT zasp_security_agent_webhook_worker TO %I',principal_value);
 INSERT INTO public.zasp_sa_webhook_principals VALUES(principal_value) ON CONFLICT DO NOTHING;
 RETURN true;
END $register$;

CREATE TABLE public.zasp_security_agent_webhook_deliveries(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 delivery_id text NOT NULL CHECK(public.zasp_valid_product_id(delivery_id)),
 run_id text NOT NULL,step_id text NOT NULL,action_id text NOT NULL DEFAULT 'send_response_webhook' CHECK(action_id='send_response_webhook'),
 definition_id text NOT NULL,definition_version bigint NOT NULL CHECK(definition_version BETWEEN 1 AND 1000000),
 definition_digest bytea NOT NULL CHECK(octet_length(definition_digest)=32),control_digest bytea NOT NULL CHECK(octet_length(control_digest)=32),
 destination_id text NOT NULL,integration_version bigint NOT NULL CHECK(integration_version BETWEEN 1 AND 1000000),configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),
 destination_url text NOT NULL,secret_reference text NOT NULL,signing_version text NOT NULL CHECK(signing_version ~ '^[A-Za-z0-9-]{32,64}$'),
 payload text NOT NULL CHECK(octet_length(payload) BETWEEN 2 AND 16384),payload_digest text NOT NULL CHECK(payload_digest='sha256:'||encode(digest(convert_to(payload,'UTF8'),'sha256'),'hex')),
 selection jsonb NOT NULL CHECK(jsonb_typeof(selection)='array' AND jsonb_array_length(selection) BETWEEN 1 AND 8),selection_digest text NOT NULL CHECK(selection_digest ~ '^sha256:[a-f0-9]{64}$'),
 plan_hash bytea NOT NULL CHECK(octet_length(plan_hash)=32),approval_id text NOT NULL,
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
 audit_id text NOT NULL,correlation_id text NOT NULL,
 state text NOT NULL DEFAULT 'prepared' CHECK(state IN('prepared','leased','dispatching','acknowledged','failed','uncertain','cancelled')),
 error_code text NOT NULL DEFAULT '' CHECK(error_code IN('','invalid_request','response_rejected','delivery_uncertain','secret_unavailable','authority_changed','claim_exhausted')),
 lease_token text,lease_generation bigint NOT NULL DEFAULT 0 CHECK(lease_generation BETWEEN 0 AND 3),lease_expires_at timestamptz,attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 3),
 dispatch_started_at timestamptz,acknowledged_at timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 settlement_state text NOT NULL DEFAULT 'pending' CHECK(settlement_state IN('pending','leased','settled')),
 settlement_worker text,settlement_token text,settlement_generation bigint NOT NULL DEFAULT 0 CHECK(settlement_generation>=0),settlement_expires_at timestamptz,settlement_result jsonb,settlement_parent_version bigint,
 PRIMARY KEY(organization_id,workspace_id,environment_id,delivery_id),
 UNIQUE(organization_id,workspace_id,environment_id,run_id,step_id,action_id),
 UNIQUE(organization_id,workspace_id,environment_id,idempotency_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id),
 CHECK((state IN('leased','dispatching') AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL) OR state NOT IN('leased','dispatching')),
 CHECK((state='acknowledged')=(acknowledged_at IS NOT NULL)),
 CHECK((settlement_state='leased' AND settlement_worker IS NOT NULL AND settlement_token IS NOT NULL AND settlement_expires_at IS NOT NULL) OR settlement_state<>'leased'),
 CHECK((settlement_state='settled')=(settlement_result IS NOT NULL))
);
ALTER TABLE public.zasp_security_agent_webhook_deliveries OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_webhook_authority ON public.zasp_security_agent_webhook_deliveries TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TABLE public.zasp_sa_webhook_keys(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),delivery_id text NOT NULL,PRIMARY KEY(organization_id,workspace_id,environment_id,idempotency_key),FOREIGN KEY(organization_id,workspace_id,environment_id,delivery_id) REFERENCES public.zasp_security_agent_webhook_deliveries(organization_id,workspace_id,environment_id,delivery_id));
ALTER TABLE public.zasp_sa_webhook_keys OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_sa_webhook_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_sa_webhook_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_key_authority ON public.zasp_sa_webhook_keys USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON public.zasp_sa_webhook_keys FROM PUBLIC;
REVOKE ALL ON public.zasp_security_agent_webhook_deliveries FROM PUBLIC;
CREATE INDEX zasp_webhook_claim_due ON public.zasp_security_agent_webhook_deliveries(created_at,delivery_id) WHERE state IN('prepared','leased');
CREATE INDEX zasp_webhook_settle_due ON public.zasp_security_agent_webhook_deliveries(created_at,delivery_id) WHERE settlement_state<>'settled' AND state IN('acknowledged','failed','uncertain','cancelled');

CREATE FUNCTION public.zasp_sa_webhook_destination(o text,w text,e text,binding_value jsonb) RETURNS public.zasp_workflow_records LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $destination$
DECLARE i public.zasp_workflow_records%ROWTYPE;c jsonb;
BEGIN
 IF jsonb_typeof(binding_value) IS DISTINCT FROM 'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(binding_value) key) IS DISTINCT FROM ARRAY['integration_id','integration_version']::text[] OR NOT COALESCE(public.zasp_valid_product_id(binding_value->>'integration_id') AND jsonb_typeof(binding_value->'integration_version')='number' AND binding_value->>'integration_version' ~ '^[1-9][0-9]{0,6}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook destination binding rejected';END IF;
 SELECT * INTO i FROM public.zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id,version)=(o,w,e,'integration',binding_value->>'integration_id',(binding_value->>'integration_version')::bigint) FOR SHARE;
 IF NOT FOUND OR i.body->>'connector_key' IS DISTINCT FROM 'generic-webhook' OR i.body->>'status' IS DISTINCT FROM 'configured' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook destination unavailable';END IF;
 c:=i.body->'configuration';
 IF jsonb_typeof(c) IS DISTINCT FROM 'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(c) key) IS DISTINCT FROM ARRAY['destination_url','signing_secret_reference','signing_secret_version']::text[] OR NOT COALESCE(length(c->>'destination_url')<=2048 AND c->>'destination_url' ~ '^https://[a-z0-9][a-z0-9.-]*[a-z0-9](:443)?(/[^?#[:cntrl:] ]*)?$' AND position('..' IN c->>'destination_url')=0 AND c->>'signing_secret_reference' ~ '^secret_ref_[A-Za-z0-9][A-Za-z0-9._/-]{0,115}$' AND position('..' IN c->>'signing_secret_reference')=0 AND position('//' IN c->>'signing_secret_reference')=0 AND c->>'signing_secret_version' ~ '^[A-Za-z0-9-]{32,64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook destination configuration rejected';END IF;
 RETURN i;
END $destination$;

CREATE FUNCTION public.zasp_sa_webhook_controls_digest(o text,w text,e text) RETURNS bytea LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $controls$
DECLARE result_value bytea;
BEGIN
 PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,'send_response_webhook');
 SELECT digest(convert_to(jsonb_agg(to_jsonb(k) ORDER BY organization_id,workspace_id,environment_id,action_key)::text,'UTF8'),'sha256') INTO result_value FROM public.zasp_security_agent_kill_switches k WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*','send_response_webhook');
 RETURN result_value;
END $controls$;

CREATE FUNCTION public.zasp_sa_webhook_selection(o text,w text,e text,r text,selection_value jsonb) RETURNS text LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $selection$
DECLARE x jsonb;previous_value text:='';identity_value text;result_value text:='[';
BEGIN
 IF jsonb_typeof(selection_value) IS DISTINCT FROM 'array' OR jsonb_array_length(selection_value) NOT BETWEEN 1 AND 8 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook evidence rejected';END IF;
 FOR x IN SELECT value FROM jsonb_array_elements(selection_value) LOOP
  IF jsonb_typeof(x) IS DISTINCT FROM 'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(x) key) IS DISTINCT FROM ARRAY['association_digest','source_id','source_kind','source_version']::text[] OR NOT COALESCE(x->>'source_kind' IN('manual','run_audit') AND jsonb_typeof(x->'source_version')='number' AND x->>'source_version' ~ '^[1-9][0-9]{0,15}$' AND (x->>'source_version')::numeric<=9007199254740991 AND x->>'association_digest' ~ '^sha256:[a-f0-9]{64}$' AND x->>'association_digest'<>'sha256:'||repeat('0',64) AND CASE x->>'source_kind' WHEN 'manual' THEN x->>'source_id' ~ '^[a-f0-9]{64}$' AND x->>'source_id'<>repeat('0',64) ELSE public.zasp_valid_product_id(x->>'source_id') END,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook evidence descriptor rejected';END IF;
  identity_value:=(x->>'source_kind')||'/'||(x->>'source_id');
  IF identity_value COLLATE "C"<=previous_value COLLATE "C" THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook evidence order rejected';END IF;
  previous_value:=identity_value;
  IF result_value<>'[' THEN result_value:=result_value||',';END IF;
  result_value:=result_value||'{"source_kind":'||to_json(x->>'source_kind')::text||',"source_id":'||to_json(x->>'source_id')::text||',"source_version":'||(x->>'source_version')||',"association_digest":'||to_json(x->>'association_digest')::text||'}';
 END LOOP;
 PERFORM public.zasp_sa_export_planner_validate(o,w,e,r,selection_value);
 RETURN result_value||']';
END $selection$;

-- New admission uses the registered version/control/history implementation.
-- Private clones retain the predecessor's writer and CAS checks; the saved
-- destination check is action-specific and cannot be supplied by a model.
DO $definition_clones$
DECLARE p record;d text;
BEGIN
 PERFORM set_config('check_function_bodies','off',true);
 FOR p IN SELECT oid,proname FROM pg_proc WHERE pronamespace='zasp_sa_export_prior'::regnamespace AND starts_with(proname,'definition_') LOOP
  d:=replace(pg_get_functiondef(p.oid),'zasp_sa_export_prior.','zasp_sa_webhook_prior.');
  d:=replace(d,'''create_evidence_export''','''send_response_webhook''');
  EXECUTE d;
  EXECUTE format('ALTER FUNCTION zasp_sa_webhook_prior.%I(%s) OWNER TO zasp_discovery_authority',p.proname,pg_get_function_identity_arguments(p.oid));
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_sa_webhook_prior.%I(%s) FROM PUBLIC',p.proname,pg_get_function_identity_arguments(p.oid));
 END LOOP;
 FOR p IN SELECT oid,proname FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname IN('zasp_sa_export_definition_authority','zasp_sa_export_definition_shape','zasp_sa_export_workflow_readiness','zasp_sa_export_mutate_definition','zasp_sa_export_activate','zasp_sa_export_set_control') LOOP
  d:=replace(replace(replace(pg_get_functiondef(p.oid),'zasp_sa_export_','zasp_sa_webhook_'),'create_evidence_export','send_response_webhook'),'''export''','''signed_delivery''');
  d:=replace(d,'public.zasp_sa_webhook_principal_ready(','public.zasp_sa_export_principal_ready(');
  d:=replace(d,'''definition_version'',''enabled'']','''definition_version'',''enabled'',''response_webhook_destination'']');
  IF p.proname='zasp_sa_export_definition_shape' THEN d:=replace(d,E'\nEND',E'\n PERFORM public.zasp_sa_webhook_destination(o,w,e,b->''response_webhook_destination'');\nEND');END IF;
  EXECUTE d;
 END LOOP;
 PERFORM public.zasp_sa_webhook_save('public.zasp_sa_manual_authority(text,text,text,text,bigint,text)');
 d:=pg_get_functiondef('public.zasp_sa_manual_authority(text,text,text,text,bigint,text)'::regprocedure);
 d:=replace(d,'  ELSE RAISE EXCEPTION',E'  WHEN ''send_response_webhook'' THEN PERFORM public.zasp_sa_webhook_destination(o,w,e,current_row.body->''response_webhook_destination'');\n  ELSE RAISE EXCEPTION');
 EXECUTE d;
 PERFORM set_config('check_function_bodies','on',true);
END $definition_clones$;

CREATE TABLE public.zasp_sa_webhook_planner_inputs(LIKE public.zasp_sa_export_planner_inputs INCLUDING ALL);
ALTER TABLE public.zasp_sa_webhook_planner_inputs ADD FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id),ADD FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id,definition_version) REFERENCES public.zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version);
ALTER TABLE public.zasp_sa_webhook_planner_inputs OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_sa_webhook_planner_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_sa_webhook_planner_inputs FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_webhook_inputs_authority ON public.zasp_sa_webhook_planner_inputs TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_sa_webhook_planner_inputs FROM PUBLIC;

DO $planner_clones$
DECLARE p record;d text;name_value text;
BEGIN
 PERFORM set_config('check_function_bodies','off',true);
 FOR p IN SELECT oid,proname FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname IN('zasp_sa_export_planner_context_core','zasp_sa_export_planner_context','zasp_sa_export_recheck_context','zasp_sa_export_reserve_core','zasp_sa_export_reserve_planner','zasp_sa_export_finish_prepare','zasp_sa_export_planner_source_authority') LOOP
  d:=pg_get_functiondef(p.oid);
  FOREACH name_value IN ARRAY ARRAY['planner_context_core','planner_context','recheck_context','reserve_core','reserve_planner','finish_prepare','planner_source_authority','planner_inputs','guard'] LOOP d:=replace(d,'zasp_sa_export_'||name_value,'zasp_sa_webhook_'||name_value);END LOOP;
  d:=replace(replace(d,'create_evidence_export','send_response_webhook'),'''export''','''signed_delivery''');
  IF p.proname='zasp_sa_export_planner_context_core' THEN
   d:=replace(d,'selection_value:=public.zasp_sa_export_planner_selection(o,w,e,r,include_audit);','SELECT jsonb_agg(x ORDER BY x->>''source_kind'' COLLATE "C",x->>''source_id'' COLLATE "C") INTO selection_value FROM jsonb_array_elements(public.zasp_sa_export_planner_selection(o,w,e,r,include_audit)) x WHERE x->>''source_kind'' IN(''manual'',''run_audit'');');
   d:=replace(d,'''allowed_targets'',jsonb_build_array(r)','''allowed_targets'',jsonb_build_array(d.definition->''response_webhook_destination''->>''integration_id''),''response_webhook_destination'',d.definition->''response_webhook_destination''');
   d:=replace(d,'PERFORM public.zasp_sa_export_planner_validate(o,w,e,r,selection_value);','PERFORM public.zasp_sa_webhook_destination(o,w,e,d.definition->''response_webhook_destination''); PERFORM public.zasp_sa_webhook_selection(o,w,e,r,selection_value);');
  END IF;
  EXECUTE d;
 END LOOP;
 PERFORM set_config('check_function_bodies','on',true);
END $planner_clones$;

CREATE FUNCTION public.zasp_sa_webhook_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $immutable$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['state','error_code','lease_token','lease_generation','lease_expires_at','attempt_count','dispatch_started_at','acknowledged_at','settlement_state','settlement_worker','settlement_token','settlement_generation','settlement_expires_at','settlement_result','settlement_parent_version']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','error_code','lease_token','lease_generation','lease_expires_at','attempt_count','dispatch_started_at','acknowledged_at','settlement_state','settlement_worker','settlement_token','settlement_generation','settlement_expires_at','settlement_result','settlement_parent_version']) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='webhook immutable handoff changed';END IF;
 IF OLD.state IN('acknowledged','failed','uncertain','cancelled') AND (NEW.state,NEW.error_code,NEW.lease_token,NEW.lease_generation,NEW.lease_expires_at,NEW.attempt_count,NEW.dispatch_started_at,NEW.acknowledged_at) IS DISTINCT FROM (OLD.state,OLD.error_code,OLD.lease_token,OLD.lease_generation,OLD.lease_expires_at,OLD.attempt_count,OLD.dispatch_started_at,OLD.acknowledged_at) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='webhook terminal fact changed';END IF;
 IF OLD.settlement_state='settled' AND (NEW.settlement_state,NEW.settlement_worker,NEW.settlement_token,NEW.settlement_generation,NEW.settlement_expires_at,NEW.settlement_result) IS DISTINCT FROM (OLD.settlement_state,OLD.settlement_worker,OLD.settlement_token,OLD.settlement_generation,OLD.settlement_expires_at,OLD.settlement_result) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='webhook terminal settlement changed';END IF;
 RETURN NEW;
END $immutable$;
CREATE TRIGGER zasp_webhook_immutable BEFORE UPDATE ON public.zasp_security_agent_webhook_deliveries FOR EACH ROW EXECUTE FUNCTION public.zasp_sa_webhook_immutable();

CREATE FUNCTION public.zasp_sa_webhook_public(d public.zasp_security_agent_webhook_deliveries) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $status$
 SELECT jsonb_build_object('delivery_id',d.delivery_id,'run_id',d.run_id,'step_id',d.step_id,'destination_integration_id',d.destination_id,'destination_integration_version',d.integration_version,'payload_digest',d.payload_digest,'selection_digest',d.selection_digest,'signing_version',d.signing_version,'state',d.state,'error_code',d.error_code,'acknowledged_at',CASE WHEN d.acknowledged_at IS NULL THEN NULL ELSE to_char(d.acknowledged_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,'receiver_verification','unproven')
$status$;

CREATE FUNCTION public.zasp_get_security_agent_webhook(o text,w text,e text,actor text,session_value text,agent_value text,run_value text,delivery_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
DECLARE d public.zasp_security_agent_webhook_deliveries%ROWTYPE;
BEGIN
 IF NOT public.zasp_sa_export_principal_ready('zasp_security_agent_api') OR NOT public.zasp_sa_webhook_guard() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook read authority unavailable';END IF;
 PERFORM 1 FROM public.zasp_product_sessions WHERE token_digest=digest(session_value,'sha256') AND (organization_id,workspace_id,environment_id,principal_id)=(o,w,e,actor) AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='webhook session unavailable';END IF;
 PERFORM 1 FROM public.zasp_identity_memberships WHERE (organization_id,principal_id,active)=(o,actor,true) FOR SHARE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(actor,o) s WHERE (s.organization_id,s.workspace_id,s.environment_id)=(o,w,e) AND s.permissions ? 'view') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook read permission rejected';END IF;
 SELECT * INTO d FROM public.zasp_security_agent_webhook_deliveries WHERE (organization_id,workspace_id,environment_id,definition_id,run_id,delivery_id)=(o,w,e,agent_value,run_value,delivery_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='webhook unavailable';END IF;
 RETURN public.zasp_sa_webhook_public(d);
END $read$;

CREATE FUNCTION public.zasp_accept_security_agent_webhook_plan(o text,w text,e text,r text,worker_value text,lease_value text,attempt_value bigint,definition_value text,definition_version_value bigint,input_value bytea,output_value bytea,model_value text,policy_value text,summary_value text,action_value text,target_value text,approval_value text,expires_value timestamptz,audit_value text,correlation_value text,key_value text,destination_value text,evidence_value jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $accept$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;d public.zasp_security_agent_definition_versions%ROWTYPE;i public.zasp_workflow_records%ROWTYPE;prior public.zasp_security_agent_webhook_deliveries%ROWTYPE;reservation public.zasp_security_agent_provider_reservations%ROWTYPE;context_value jsonb;request_value bytea;selection_text text;selection_hash text;control_value bytea;step_value text;delivery_value text;plan_value jsonb;plan_digest bytea;payload_value text;response_value jsonb;prepared_value jsonb;trigger_digest_value bytea;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_worker') OR NOT public.zasp_sa_webhook_guard() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook planning authority unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(definition_value) AND public.zasp_valid_product_id(approval_value) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(destination_value) AND target_value=destination_value AND action_value='send_response_webhook' AND attempt_value>0 AND definition_version_value BETWEEN 1 AND 1000000 AND octet_length(input_value)=32 AND octet_length(output_value)=32 AND length(worker_value) BETWEEN 1 AND 128 AND length(lease_value) BETWEEN 16 AND 128 AND length(model_value) BETWEEN 1 AND 128 AND length(policy_value) BETWEEN 1 AND 64 AND length(summary_value) BETWEEN 1 AND 500 AND summary_value!~'[[:cntrl:]]' AND length(key_value) BETWEEN 16 AND 128 AND key_value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook candidate rejected';END IF;
 request_value:=digest(convert_to(jsonb_build_array(o,w,e,r,worker_value,digest(lease_value,'sha256'),attempt_value,definition_value,definition_version_value,encode(input_value,'hex'),encode(output_value,'hex'),model_value,policy_value,summary_value,action_value,target_value,approval_value,expires_value,audit_value,correlation_value,destination_value,evidence_value)::text,'UTF8'),'sha256');
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR (rr.definition_id,rr.definition_version,rr.attempt) IS DISTINCT FROM (definition_value,definition_version_value,attempt_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook planning claim changed';END IF;
 SELECT q.* INTO prior FROM public.zasp_security_agent_webhook_deliveries q WHERE (q.organization_id,q.workspace_id,q.environment_id)=(o,w,e) AND (q.run_id=r OR EXISTS(SELECT 1 FROM public.zasp_sa_webhook_keys k WHERE (k.organization_id,k.workspace_id,k.environment_id,k.delivery_id,k.idempotency_key)=(o,w,e,q.delivery_id,key_value)));
 IF FOUND THEN
  IF prior.run_id<>r OR prior.request_digest IS DISTINCT FROM request_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='webhook acceptance replay conflict';END IF;
  INSERT INTO public.zasp_sa_webhook_keys VALUES(o,w,e,key_value,prior.delivery_id) ON CONFLICT DO NOTHING;
  IF NOT EXISTS(SELECT 1 FROM public.zasp_sa_webhook_keys WHERE (organization_id,workspace_id,environment_id,idempotency_key,delivery_id)=(o,w,e,key_value,prior.delivery_id)) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='webhook key alias conflict';END IF;
  RETURN public.zasp_sa_webhook_public(prior);
 END IF;
 IF NOT COALESCE(expires_value>clock_timestamp() AND expires_value<=clock_timestamp()+interval '16 minutes',false) OR NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook planning lease expired';END IF;
 SELECT * INTO reservation FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,attempt_value) FOR SHARE;
 IF NOT FOUND OR reservation.settled_at IS NULL OR (reservation.input_digest,reservation.output_digest,reservation.model,reservation.worker_id,reservation.lease_token_digest) IS DISTINCT FROM (input_value,output_value,model_value,worker_value,digest(lease_value,'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook settled model receipt changed';END IF;
 context_value:=public.zasp_sa_webhook_planner_context(o,w,e,r,worker_value,lease_value);
 IF context_value->>'input_digest' IS DISTINCT FROM 'sha256:'||encode(input_value,'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook planner input changed';END IF;
 PERFORM public.zasp_sa_export_planner_subset(evidence_value,context_value->'context'->'export_selection');
 selection_text:=public.zasp_sa_webhook_selection(o,w,e,r,evidence_value);selection_hash:='sha256:'||encode(digest(convert_to(selection_text,'UTF8'),'sha256'),'hex');
 SELECT * INTO STRICT d FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,rr.definition_id,rr.definition_version) FOR SHARE;
 IF d.definition->'response_webhook_destination'->>'integration_id' IS DISTINCT FROM destination_value THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook saved binding changed';END IF;
 i:=public.zasp_sa_webhook_destination(o,w,e,d.definition->'response_webhook_destination');control_value:=public.zasp_sa_webhook_controls_digest(o,w,e);
 step_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0');
 delivery_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_webhook',r||chr(31)||step_value||chr(31)||action_value);
 SELECT trigger_digest INTO STRICT trigger_digest_value FROM public.zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 plan_value:=jsonb_build_object('definition_id',rr.definition_id,'definition_version',rr.definition_version,'catalog_version','security-agent-actions-v1','evidence_ids',public.zasp_sa_manual_evidence(o,w,e,r,rr.trigger_id),'steps',jsonb_build_array(jsonb_build_object('index',0,'step_id',step_value,'action',action_value,'target_id',destination_value,'integration_version',i.version,'signing_version',i.body->'configuration'->>'signing_secret_version','selection_digest',selection_hash,'evidence_selection',evidence_value,'authorization','approval_required')),'verification',jsonb_build_object('kind','signed_delivery'),'expires_at',to_char(expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 plan_digest:=digest(convert_to(plan_value::text,'UTF8'),'sha256');
 payload_value:='{"schema_version":1,"type":"security_agent.response","delivery_id":'||to_json(delivery_value)::text||',"organization_id":'||to_json(o)::text||',"workspace_id":'||to_json(w)::text||',"environment_id":'||to_json(e)::text||',"run_id":'||to_json(r)::text||',"step_id":'||to_json(step_value)::text||',"plan_hash":'||to_json('sha256:'||encode(plan_digest,'hex'))::text||',"evidence":'||selection_text||'}';
 INSERT INTO public.zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at) VALUES(o,w,e,r,rr.definition_id,rr.definition_version,trigger_digest_value,'security-agent-actions-v1',plan_value,plan_digest,expires_value);
 INSERT INTO public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) VALUES(o,w,e,r,step_value,0,action_value,digest(convert_to((plan_value->'steps'->0)::text,'UTF8'),'sha256'),'approval_required','waiting_approval');
 INSERT INTO public.zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at) VALUES(o,w,e,approval_value,r,step_value,plan_digest,'pending',rr.requested_by,expires_value);
 INSERT INTO public.zasp_security_agent_webhook_deliveries(organization_id,workspace_id,environment_id,delivery_id,run_id,step_id,definition_id,definition_version,definition_digest,control_digest,destination_id,integration_version,configuration_digest,destination_url,secret_reference,signing_version,payload,payload_digest,selection,selection_digest,plan_hash,approval_id,request_digest,idempotency_key,audit_id,correlation_id)
 VALUES(o,w,e,delivery_value,r,step_value,d.definition_id,d.version,d.definition_digest,control_value,i.id,i.version,digest(convert_to((i.body->'configuration')::text,'UTF8'),'sha256'),i.body->'configuration'->>'destination_url',i.body->'configuration'->>'signing_secret_reference',i.body->'configuration'->>'signing_secret_version',payload_value,'sha256:'||encode(digest(convert_to(payload_value,'UTF8'),'sha256'),'hex'),evidence_value,selection_hash,plan_digest,approval_value,request_value,key_value,audit_value,correlation_value) RETURNING * INTO prior;
 response_value:=jsonb_build_object('run_id',r,'state','waiting_approval','version',rr.version+1,'approval_id',approval_value,'step_id',step_value,'plan_hash','sha256:'||encode(plan_digest,'hex'),'planner_outcome','accepted','planner_summary',summary_value,'replayed',false);
 INSERT INTO public.zasp_security_agent_planner_receipts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,output_digest,outcome,model,policy_version,response) VALUES(o,w,e,r,rr.attempt,input_value,output_value,'accepted',model_value,policy_value,response_value);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,correlation_value,r,step_value,approval_value,worker_value,'approval_requested',plan_digest,jsonb_build_object('action',action_value,'delivery_id',delivery_value,'payload_digest',prior.payload_digest,'selection_digest',selection_hash));
 prepared_value:=jsonb_build_object('result',response_value,'input_digest','sha256:'||encode(input_value,'hex'));
 INSERT INTO public.zasp_sa_webhook_keys VALUES(o,w,e,key_value,prior.delivery_id);
 PERFORM public.zasp_sa_webhook_finish_prepare(o,w,e,r,worker_value,lease_value,prepared_value);
 RETURN public.zasp_sa_webhook_public(prior);
END $accept$;

CREATE FUNCTION public.zasp_sa_webhook_authorize(d public.zasp_security_agent_webhook_deliveries) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $authorize$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;def public.zasp_security_agent_definitions%ROWTYPE;i public.zasp_workflow_records%ROWTYPE;a public.zasp_security_agent_approvals%ROWTYPE;history public.zasp_security_agent_definition_versions%ROWTYPE;
BEGIN
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id) FOR SHARE;
 IF NOT FOUND OR rr.state NOT IN('queued','running','waiting_approval') OR (rr.definition_id,rr.definition_version,rr.plan_hash) IS DISTINCT FROM (d.definition_id,d.definition_version,d.plan_hash) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook parent unavailable';END IF;
 SELECT * INTO def FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.definition_version) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND OR def.activation NOT IN('supervised','autonomous') OR def.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR digest(convert_to(def.body::text,'UTF8'),'sha256') IS DISTINCT FROM d.definition_digest THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook definition changed';END IF;
 SELECT * INTO STRICT history FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.definition_version) FOR SHARE;
 IF history.definition_digest IS DISTINCT FROM d.definition_digest OR history.definition IS DISTINCT FROM def.body THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook definition history changed';END IF;
 PERFORM public.zasp_sa_export_principal(d.organization_id,d.workspace_id,d.environment_id,history.actor_id);
 PERFORM public.zasp_sa_export_source_permissions(d.organization_id,d.workspace_id,d.environment_id,history.actor_id,d.selection);
 IF public.zasp_valid_product_id(rr.requested_by) THEN PERFORM public.zasp_sa_export_principal(d.organization_id,d.workspace_id,d.environment_id,rr.requested_by);PERFORM public.zasp_sa_export_source_permissions(d.organization_id,d.workspace_id,d.environment_id,rr.requested_by,d.selection);END IF;
 IF public.zasp_sa_webhook_controls_digest(d.organization_id,d.workspace_id,d.environment_id) IS DISTINCT FROM d.control_digest THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook controls changed';END IF;
 i:=public.zasp_sa_webhook_destination(d.organization_id,d.workspace_id,d.environment_id,def.body->'response_webhook_destination');
 IF (i.id,i.version,digest(convert_to((i.body->'configuration')::text,'UTF8'),'sha256')) IS DISTINCT FROM (d.destination_id,d.integration_version,d.configuration_digest) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook destination changed';END IF;
 SELECT * INTO a FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,approval_id,run_id,step_id)=(d.organization_id,d.workspace_id,d.environment_id,d.approval_id,d.run_id,d.step_id) FOR SHARE;
 IF NOT FOUND OR a.state<>'approved' OR a.version<>2 OR a.requester_id IS DISTINCT FROM rr.requested_by OR a.approver_id IS NULL OR a.approver_id=a.requester_id OR a.fresh_auth_at IS NULL OR a.fresh_auth_at>clock_timestamp() OR a.plan_hash IS DISTINCT FROM d.plan_hash OR a.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook approval unavailable';END IF;
 PERFORM public.zasp_sa_export_principal(d.organization_id,d.workspace_id,d.environment_id,a.approver_id);
 PERFORM public.zasp_sa_webhook_approval_value(d.organization_id,d.workspace_id,d.environment_id,d.approval_id);
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id) AND stop_reason IS NULL AND deadline_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook budget unavailable';END IF;
 PERFORM 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id,plan_hash)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.plan_hash) AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook plan expired';END IF;
 PERFORM public.zasp_sa_webhook_selection(d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.selection);
END $authorize$;

CREATE FUNCTION public.zasp_sa_webhook_approval_value(o text,w text,e text,a text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $approval$
DECLARE approval public.zasp_security_agent_approvals%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;d public.zasp_security_agent_webhook_deliveries%ROWTYPE;item jsonb;
BEGIN
 SELECT * INTO STRICT approval FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,approval_id)=(o,w,e,a);
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,approval.run_id);
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,rr.run_id,approval.step_id,'send_response_webhook');
 SELECT * INTO STRICT p FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id,plan_hash,definition_id,definition_version)=(o,w,e,rr.run_id,approval.plan_hash,rr.definition_id,rr.definition_version);
 SELECT * INTO STRICT d FROM public.zasp_security_agent_webhook_deliveries WHERE (organization_id,workspace_id,environment_id,run_id,step_id,approval_id)=(o,w,e,rr.run_id,st.step_id,a);
 item:=p.plan->'steps'->st.step_index;
 IF rr.plan_hash IS DISTINCT FROM approval.plan_hash OR p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256') OR p.plan->'verification' IS DISTINCT FROM '{"kind":"signed_delivery"}'::jsonb OR st.authorization_result IS DISTINCT FROM 'approval_required'
 OR item IS DISTINCT FROM jsonb_build_object('index',st.step_index,'step_id',st.step_id,'action','send_response_webhook','target_id',d.destination_id,'integration_version',d.integration_version,'signing_version',d.signing_version,'selection_digest',d.selection_digest,'evidence_selection',d.selection,'authorization','approval_required')
 OR st.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256') OR approval.requester_id IS DISTINCT FROM rr.requested_by OR d.plan_hash IS DISTINCT FROM p.plan_hash
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='webhook approval plan changed';END IF;
 RETURN jsonb_build_object('id',a,'run_id',rr.run_id,'step_id',st.step_id,'state',approval.state,'expires_at',to_char(approval.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'version',approval.version,'expected_effect','Send approved response webhook; receiver verification unproven','reversible',false,'ttl_seconds',0,'evidence_summary',jsonb_build_array(rr.trigger_id));
END $approval$;

CREATE FUNCTION public.zasp_sa_webhook_approved(o text,w text,e text,a text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $approved$
DECLARE d public.zasp_security_agent_webhook_deliveries%ROWTYPE;
BEGIN
 SELECT * INTO STRICT d FROM public.zasp_security_agent_webhook_deliveries WHERE (organization_id,workspace_id,environment_id,approval_id)=(o,w,e,a);
 PERFORM public.zasp_sa_webhook_authorize(d);
END $approved$;

DO $approval_routes$
DECLARE sig text;d text;anchor text;
BEGIN
 sig:='public.zasp_production_security_agent_existing_tests_approval_value(text,text,text,text)';
 PERFORM public.zasp_sa_webhook_save(sig);d:=pg_get_functiondef(sig::regprocedure);anchor:=' IF step_row.action_key NOT IN(''run_test'',''rerun_test'') THEN';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='webhook approval predecessor changed';END IF;
 EXECUTE replace(d,anchor,' IF step_row.action_key=''send_response_webhook'' THEN RETURN public.zasp_sa_webhook_approval_value(o,w,e,a);END IF;'||chr(10)||anchor);
 sig:='public.zasp_production_security_agent_existing_tests_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text)';
 PERFORM public.zasp_sa_webhook_save(sig);d:=pg_get_functiondef(sig::regprocedure);anchor:='AND action_value IS DISTINCT FROM ''create_evidence_export'' THEN';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='webhook decision predecessor changed';END IF;
 d:=replace(d,anchor,'AND action_value IS DISTINCT FROM ''create_evidence_export'' AND action_value IS DISTINCT FROM ''send_response_webhook'' THEN');
 anchor:='IF response_value->>''replayed'' IS DISTINCT FROM ''true'' THEN';
 d:=replace(d,anchor,anchor||chr(10)||' IF action_value=''send_response_webhook'' AND decision_value=''approved'' THEN PERFORM public.zasp_sa_webhook_approved(o,w,e,a);END IF;');
 EXECUTE d;
 sig:='public.zasp_security_agent_claim_budgeted_runs(text,text,integer,integer)';
 PERFORM public.zasp_sa_webhook_save(sig);d:=pg_get_functiondef(sig::regprocedure);
 anchor:='WHERE r.organization_id=organization_value';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='webhook claim predecessor changed';END IF;
 EXECUTE replace(d,anchor,anchor||' AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_webhook_deliveries wh WHERE (wh.organization_id,wh.workspace_id,wh.environment_id,wh.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id))');
END $approval_routes$;

CREATE FUNCTION public.zasp_sa_webhook_dispatch_principal() RETURNS void LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $principal$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT EXISTS(SELECT 1 FROM public.zasp_sa_webhook_principals WHERE principal_name=session_user) OR NOT pg_has_role(session_user,'zasp_security_agent_webhook_worker','MEMBER') OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls) OR EXISTS(SELECT 1 FROM pg_roles WHERE starts_with(rolname,'zasp_') AND rolname<>'zasp_security_agent_webhook_worker' AND rolname<>session_user AND pg_has_role(session_user,oid,'MEMBER')) OR NOT public.zasp_sa_webhook_guard() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook worker unavailable';END IF;
END $principal$;

CREATE FUNCTION public.zasp_claim_security_agent_webhook() RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
DECLARE d public.zasp_security_agent_webhook_deliveries%ROWTYPE;
BEGIN
 PERFORM public.zasp_sa_webhook_dispatch_principal();
 FOR d IN SELECT q.* FROM public.zasp_security_agent_webhook_deliveries q JOIN public.zasp_security_agent_approvals a ON (a.organization_id,a.workspace_id,a.environment_id,a.approval_id)=(q.organization_id,q.workspace_id,q.environment_id,q.approval_id) WHERE (q.state='prepared' OR q.state='leased' AND q.lease_expires_at<=clock_timestamp()) AND a.state='approved' ORDER BY q.created_at,q.delivery_id LIMIT 25 FOR UPDATE OF q SKIP LOCKED LOOP
  BEGIN
   PERFORM public.zasp_sa_webhook_authorize(d);
  EXCEPTION WHEN SQLSTATE '42501' OR SQLSTATE '40001' OR SQLSTATE '22023' OR SQLSTATE '55000' THEN
   UPDATE public.zasp_security_agent_webhook_deliveries SET state='cancelled',error_code='authority_changed' WHERE (organization_id,workspace_id,environment_id,delivery_id)=(d.organization_id,d.workspace_id,d.environment_id,d.delivery_id);
   CONTINUE;
  END;
  IF d.attempt_count>=3 THEN
   UPDATE public.zasp_security_agent_webhook_deliveries SET state='failed',error_code='claim_exhausted' WHERE (organization_id,workspace_id,environment_id,delivery_id)=(d.organization_id,d.workspace_id,d.environment_id,d.delivery_id);CONTINUE;
  END IF;
  UPDATE public.zasp_security_agent_webhook_deliveries SET state='leased',lease_token=encode(gen_random_bytes(32),'hex'),lease_generation=lease_generation+1,attempt_count=attempt_count+1,lease_expires_at=clock_timestamp()+interval '30 seconds' WHERE (organization_id,workspace_id,environment_id,delivery_id)=(d.organization_id,d.workspace_id,d.environment_id,d.delivery_id) RETURNING * INTO d;
  RETURN jsonb_build_object('delivery_id',d.delivery_id,'organization_id',d.organization_id,'workspace_id',d.workspace_id,'environment_id',d.environment_id,'token',d.lease_token,'generation',d.lease_generation,'expires_at',to_char(d.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'destination_url',d.destination_url,'secret_reference',d.secret_reference,'signing_version',d.signing_version,'payload',d.payload,'payload_digest',d.payload_digest,'selection_digest',d.selection_digest,'run_id',d.run_id,'step_id',d.step_id);
 END LOOP;
 RETURN 'null'::jsonb;
END $claim$;

CREATE FUNCTION public.zasp_begin_security_agent_webhook_dispatch(p_organization_id text,p_workspace_id text,p_environment_id text,p_delivery_id text,p_lease_token text,p_generation bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $begin$
DECLARE d public.zasp_security_agent_webhook_deliveries%ROWTYPE;changed text;budget public.zasp_security_agent_run_budgets%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;
BEGIN
 PERFORM public.zasp_sa_webhook_dispatch_principal();
 SELECT * INTO d FROM public.zasp_security_agent_webhook_deliveries WHERE (organization_id,workspace_id,environment_id,delivery_id)=(p_organization_id,p_workspace_id,p_environment_id,p_delivery_id) FOR UPDATE;
 IF NOT FOUND OR d.state<>'leased' OR (d.lease_token,d.lease_generation) IS DISTINCT FROM (p_lease_token,p_generation) OR d.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook dispatch fence rejected';END IF;
 BEGIN
  PERFORM public.zasp_sa_webhook_authorize(d);
 EXCEPTION WHEN SQLSTATE '42501' OR SQLSTATE '40001' OR SQLSTATE '22023' OR SQLSTATE '55000' THEN
  UPDATE public.zasp_security_agent_webhook_deliveries SET state='cancelled',error_code='authority_changed' WHERE (organization_id,workspace_id,environment_id,delivery_id)=(p_organization_id,p_workspace_id,p_environment_id,p_delivery_id);
  RETURN jsonb_build_object('begun',false);
 END;
 SELECT * INTO STRICT budget FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id) FOR UPDATE;
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.step_id) FOR UPDATE;
 IF st.state<>'authorized' OR budget.stop_reason IS NOT NULL OR budget.deadline_at<=clock_timestamp() OR (SELECT count(*) FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id))>=budget.max_steps THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook step budget rejected';END IF;
 INSERT INTO public.zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest) VALUES(d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.step_id,'send_response_webhook',st.input_digest);
 UPDATE public.zasp_security_agent_webhook_deliveries SET state='dispatching',dispatch_started_at=clock_timestamp()
 WHERE organization_id=p_organization_id AND workspace_id=p_workspace_id AND environment_id=p_environment_id AND delivery_id=p_delivery_id AND state='leased' AND lease_token=p_lease_token AND lease_generation=p_generation AND lease_expires_at>clock_timestamp()
 AND EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.approval_id)=(d.organization_id,d.workspace_id,d.environment_id,d.approval_id) AND a.state='approved' AND a.expires_at>clock_timestamp())
 AND EXISTS(SELECT 1 FROM public.zasp_security_agent_plans p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id,p.plan_hash)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.plan_hash) AND p.expires_at>clock_timestamp())
 AND EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id) AND b.stop_reason IS NULL AND b.deadline_at>clock_timestamp()) RETURNING delivery_id INTO changed;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook dispatch fence rejected';END IF;
 UPDATE public.zasp_security_agent_runs SET state='running',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id);
 UPDATE public.zasp_security_agent_steps SET state='executing',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.step_id);
 RETURN jsonb_build_object('begun',true);
END $begin$;

CREATE FUNCTION public.zasp_complete_security_agent_webhook(o text,w text,e text,id_value text,token_value text,generation_value bigint,outcome_value text,error_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $complete$
DECLARE d public.zasp_security_agent_webhook_deliveries%ROWTYPE;
BEGIN
 PERFORM public.zasp_sa_webhook_dispatch_principal();
 IF NOT COALESCE(outcome_value='acknowledged' AND error_value='' OR outcome_value='failed' AND error_value IN('invalid_request','response_rejected','secret_unavailable') OR outcome_value='uncertain' AND error_value='delivery_uncertain',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook receipt rejected';END IF;
 SELECT * INTO d FROM public.zasp_security_agent_webhook_deliveries WHERE (organization_id,workspace_id,environment_id,delivery_id,lease_token,lease_generation)=(o,w,e,id_value,token_value,generation_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook receipt fence rejected';END IF;
 IF d.state IN('acknowledged','failed','uncertain','cancelled') THEN
  IF (d.state,d.error_code) IS DISTINCT FROM (outcome_value,error_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook terminal receipt conflict';END IF;
  RETURN public.zasp_sa_webhook_public(d);
 END IF;
 IF d.lease_expires_at<=clock_timestamp() OR NOT (d.state='dispatching' OR d.state='leased' AND outcome_value='failed' AND error_value IN('invalid_request','secret_unavailable')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook receipt expired';END IF;
 UPDATE public.zasp_security_agent_webhook_deliveries SET state=outcome_value,error_code=error_value,acknowledged_at=CASE outcome_value WHEN 'acknowledged' THEN clock_timestamp() ELSE NULL END WHERE (organization_id,workspace_id,environment_id,delivery_id)=(o,w,e,id_value) RETURNING * INTO d;
 RETURN public.zasp_sa_webhook_public(d);
END $complete$;

CREATE FUNCTION public.zasp_expire_security_agent_webhooks(limit_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $expire$
DECLARE count_value integer;
BEGIN
 PERFORM public.zasp_sa_webhook_dispatch_principal();
 IF limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook expiry bound rejected';END IF;
 WITH candidates AS (
  SELECT q.organization_id,q.workspace_id,q.environment_id,q.delivery_id,
   q.state IN('prepared','leased') AND (r.state NOT IN('queued','running','waiting_approval') OR a.state NOT IN('pending','approved') OR a.expires_at<=clock_timestamp() OR p.expires_at<=clock_timestamp() OR b.stop_reason IS NOT NULL OR b.deadline_at<=clock_timestamp()) AS invalidated
  FROM public.zasp_security_agent_webhook_deliveries q
  JOIN public.zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id)
  JOIN public.zasp_security_agent_approvals a ON (a.organization_id,a.workspace_id,a.environment_id,a.approval_id)=(q.organization_id,q.workspace_id,q.environment_id,q.approval_id)
  JOIN public.zasp_security_agent_plans p ON (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(q.organization_id,q.workspace_id,q.environment_id,q.run_id)
  JOIN public.zasp_security_agent_run_budgets b ON (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(q.organization_id,q.workspace_id,q.environment_id,q.run_id)
  WHERE q.state='dispatching' AND q.lease_expires_at<=clock_timestamp() OR q.state='leased' AND q.attempt_count=3 AND q.lease_expires_at<=clock_timestamp()
   OR q.state IN('prepared','leased') AND (r.state NOT IN('queued','running','waiting_approval') OR a.state NOT IN('pending','approved') OR a.expires_at<=clock_timestamp() OR p.expires_at<=clock_timestamp() OR b.stop_reason IS NOT NULL OR b.deadline_at<=clock_timestamp())
  ORDER BY q.created_at,q.delivery_id LIMIT limit_value FOR UPDATE OF q SKIP LOCKED
 ),changed AS (
  UPDATE public.zasp_security_agent_webhook_deliveries d SET state=CASE WHEN c.invalidated THEN 'cancelled' WHEN d.state='dispatching' THEN 'uncertain' ELSE 'failed' END,error_code=CASE WHEN c.invalidated THEN 'authority_changed' WHEN d.state='dispatching' THEN 'delivery_uncertain' ELSE 'claim_exhausted' END
  FROM candidates c WHERE (d.organization_id,d.workspace_id,d.environment_id,d.delivery_id)=(c.organization_id,c.workspace_id,c.environment_id,c.delivery_id) RETURNING d.delivery_id
 ) SELECT count(*) INTO count_value FROM changed;
 RETURN jsonb_build_object('expired',count_value);
END $expire$;

CREATE FUNCTION public.zasp_claim_security_agent_webhook_settlements(worker_value text,token_value text,seconds_value integer,limit_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
DECLARE d public.zasp_security_agent_webhook_deliveries%ROWTYPE;items jsonb:='[]';parent_version bigint;
BEGIN
 IF NOT public.zasp_sa_export_principal_ready('zasp_security_agent_worker') OR NOT public.zasp_sa_webhook_guard() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook settlement authority unavailable';END IF;
 IF NOT COALESCE(length(worker_value) BETWEEN 1 AND 128 AND length(token_value) BETWEEN 16 AND 128 AND seconds_value BETWEEN 1 AND 120 AND limit_value BETWEEN 1 AND 25,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook settlement claim rejected';END IF;
 FOR d IN SELECT * FROM public.zasp_security_agent_webhook_deliveries WHERE state IN('acknowledged','failed','uncertain','cancelled') AND (settlement_state='pending' OR settlement_state='leased' AND settlement_expires_at<=clock_timestamp()) ORDER BY created_at,delivery_id LIMIT limit_value FOR UPDATE SKIP LOCKED LOOP
  SELECT version INTO STRICT parent_version FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id) FOR SHARE;
  UPDATE public.zasp_security_agent_webhook_deliveries SET settlement_state='leased',settlement_worker=worker_value,settlement_token=token_value,settlement_generation=settlement_generation+1,settlement_expires_at=clock_timestamp()+make_interval(secs=>seconds_value),settlement_parent_version=parent_version WHERE (organization_id,workspace_id,environment_id,delivery_id)=(d.organization_id,d.workspace_id,d.environment_id,d.delivery_id) RETURNING * INTO d;
  items:=items||jsonb_build_array(jsonb_build_object('organization_id',d.organization_id,'workspace_id',d.workspace_id,'environment_id',d.environment_id,'delivery_id',d.delivery_id,'run_id',d.run_id,'step_id',d.step_id,'token',d.settlement_token,'generation',d.settlement_generation,'expires_at',to_char(d.settlement_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'state',d.state));
 END LOOP;
 RETURN jsonb_build_object('claims',items);
END $claim$;

CREATE FUNCTION public.zasp_settle_security_agent_webhook_parent(o text,w text,e text,id_value text,token_value text,generation_value bigint,worker_value text,audit_value text,correlation_value text,outcome_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $settle$
DECLARE d public.zasp_security_agent_webhook_deliveries%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;run_state text;step_state text;reason_value text;result_value jsonb;preserve_parent boolean:=false;
BEGIN
 IF NOT public.zasp_sa_export_principal_ready('zasp_security_agent_worker') OR NOT public.zasp_sa_webhook_guard() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='webhook settlement authority unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(outcome_value),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='webhook settlement identity rejected';END IF;
 SELECT * INTO d FROM public.zasp_security_agent_webhook_deliveries WHERE (organization_id,workspace_id,environment_id,delivery_id,settlement_worker,settlement_token,settlement_generation)=(o,w,e,id_value,worker_value,token_value,generation_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook settlement fence rejected';END IF;
 IF d.settlement_state='settled' THEN RETURN d.settlement_result;END IF;
 IF d.settlement_state<>'leased' OR d.settlement_expires_at<=clock_timestamp() OR d.state NOT IN('acknowledged','failed','uncertain','cancelled') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook settlement expired';END IF;
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,d.run_id) FOR UPDATE;
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,d.run_id,d.step_id) FOR UPDATE;
 IF rr.state='cancelled' THEN run_state:='cancelled';step_state:='cancelled';reason_value:='webhook_parent_cancelled';
 ELSIF d.state='cancelled' AND rr.state IN('contained','remediated','failed','inconclusive','needs_human','simulated') AND rr.version=d.settlement_parent_version AND rr.plan_hash=d.plan_hash THEN
  run_state:=rr.state;step_state:=st.state;reason_value:='webhook_parent_outcome_preserved';preserve_parent:=true;
 ELSIF rr.state IN('contained','remediated','failed','inconclusive','needs_human','simulated') OR st.state IN('succeeded','failed','inconclusive','cancelled') OR rr.version<>d.settlement_parent_version OR rr.plan_hash IS DISTINCT FROM d.plan_hash THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='webhook parent settlement changed';
 ELSE run_state:=CASE d.state WHEN 'acknowledged' THEN 'needs_human' WHEN 'uncertain' THEN 'needs_human' WHEN 'cancelled' THEN 'cancelled' ELSE 'failed' END;step_state:=CASE d.state WHEN 'acknowledged' THEN 'succeeded' WHEN 'uncertain' THEN 'inconclusive' WHEN 'cancelled' THEN 'cancelled' ELSE 'failed' END;reason_value:=CASE d.state WHEN 'acknowledged' THEN 'webhook_handoff_acknowledged' WHEN 'uncertain' THEN 'webhook_delivery_uncertain' WHEN 'cancelled' THEN 'webhook_delivery_cancelled' ELSE 'webhook_delivery_failed' END;
 END IF;
 IF NOT preserve_parent AND st.state NOT IN('succeeded','failed','inconclusive','cancelled') THEN UPDATE public.zasp_security_agent_steps SET state=step_state,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,d.run_id,d.step_id);END IF;
 IF NOT preserve_parent AND rr.state<>'cancelled' THEN UPDATE public.zasp_security_agent_runs SET state=run_state,last_error_code=reason_value,completed_at=clock_timestamp(),version=version+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,d.run_id);END IF;
 result_value:=jsonb_build_object('delivery_id',d.delivery_id,'run_id',d.run_id,'step_id',d.step_id,'state',run_state,'delivery_state',d.state,'outcome_id',outcome_value,'reason',reason_value);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,correlation_value,d.run_id,d.step_id,worker_value,'webhook_parent_settled',digest(convert_to(result_value::text,'UTF8'),'sha256'),result_value);
 UPDATE public.zasp_security_agent_webhook_deliveries SET settlement_state='settled',settlement_result=result_value WHERE (organization_id,workspace_id,environment_id,delivery_id)=(o,w,e,d.delivery_id);
 RETURN result_value;
END $settle$;

CREATE FUNCTION public.zasp_sa_webhook_function_identity(value oid) RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT replace(replace(pg_get_functiondef(value),'-- compiled webhook checksum','<compiled-checksum>'),'-- compiled webhook fingerprint','<compiled-fingerprint>')
$identity$;
CREATE FUNCTION public.zasp_sa_webhook_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',public.zasp_sa_export_live_fingerprint())
 UNION ALL SELECT concat_ws('|','saved',signature,definition,owner_name,acl::text) FROM zasp_sa_webhook_prior.functions
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_sa_webhook_prior'
 UNION ALL SELECT concat_ws('|','function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),public.zasp_sa_webhook_function_identity(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (starts_with(p.proname,'zasp_sa_webhook_') OR p.proname LIKE '%security_agent_webhook%')
 UNION ALL SELECT concat_ws('|','table',n.nspname,c.relname,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))) AND c.relkind='r'
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE (n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_')
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))
 UNION ALL SELECT concat_ws('|','role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls) FROM pg_roles WHERE rolname='zasp_security_agent_webhook_worker'
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_sa_webhook_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(expected_checksum='-- compiled webhook checksum' AND expected_fingerprint='-- compiled webhook fingerprint'
 AND (SELECT count(*)=59 FROM public.zasp_schema_versions) AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>59)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=59 AND name='production_security_agent_webhooks' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_webhooks_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_webhooks_fingerprint' AND value=expected_fingerprint)
 AND zasp_sa_webhook_prior.predecessor_ready('-- webhook predecessor checksum','-- webhook predecessor fingerprint')
 AND public.zasp_sa_webhook_live_fingerprint()=expected_fingerprint,false)
$ready$;
CREATE FUNCTION public.zasp_sa_webhook_guard() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
 SELECT public.zasp_sa_webhook_readiness('-- compiled webhook checksum','-- compiled webhook fingerprint')
$guard$;
DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='public'::regnamespace AND (starts_with(proname,'zasp_sa_webhook_') OR proname LIKE '%security_agent_webhook%') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p);
 END LOOP;
END $owners$;
GRANT EXECUTE ON FUNCTION public.zasp_sa_webhook_readiness(text,text) TO zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_webhook_worker;
GRANT EXECUTE ON FUNCTION public.zasp_get_security_agent_webhook(text,text,text,text,text,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_sa_webhook_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text),public.zasp_sa_webhook_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text),public.zasp_sa_webhook_set_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_sa_webhook_planner_context(text,text,text,text,text,text),public.zasp_sa_webhook_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint),public.zasp_accept_security_agent_webhook_plan(text,text,text,text,text,text,bigint,text,bigint,bytea,bytea,text,text,text,text,text,text,timestamptz,text,text,text,text,jsonb) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION public.zasp_claim_security_agent_webhook(),public.zasp_begin_security_agent_webhook_dispatch(text,text,text,text,text,bigint),public.zasp_complete_security_agent_webhook(text,text,text,text,text,bigint,text,text),public.zasp_expire_security_agent_webhooks(integer) TO zasp_security_agent_webhook_worker;
GRANT EXECUTE ON FUNCTION public.zasp_claim_security_agent_webhook_settlements(text,text,integer,integer),public.zasp_settle_security_agent_webhook_parent(text,text,text,text,text,bigint,text,text,text,text) TO zasp_security_agent_worker;
DROP FUNCTION public.zasp_sa_webhook_save(text);
