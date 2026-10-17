-- Additive optional egress authority; no historical source or fingerprint is rewritten.
-- In this new profile every *_nano_credits field is fixed usd_nano:
-- 1 USD = 1,000,000,000 units; rates are nano-USD per million tokens.
-- Existing planner credit/account conversions are independent and unchanged.
CREATE SCHEMA zasp_optional_egress_v1 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_optional_egress_v1 FROM PUBLIC;
CREATE TABLE zasp_optional_egress_v1.registration(singleton boolean PRIMARY KEY CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_optional_egress_v1.principals(login_oid oid PRIMARY KEY,login_name text UNIQUE NOT NULL,authority_role text NOT NULL,purpose text UNIQUE NOT NULL CHECK(purpose IN('human-forward','planner-forward','captured-settlement')));
CREATE TABLE zasp_optional_egress_v1.approved_profiles(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,profile_id text NOT NULL,profile_version bigint NOT NULL,profile_digest text NOT NULL UNIQUE,profile jsonb NOT NULL,PRIMARY KEY(organization_id,workspace_id,environment_id,profile_id,profile_version));
CREATE TABLE zasp_optional_egress_v1.policies(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,flow_id text NOT NULL CHECK(flow_id IN('posthog','openrouter','remote-otlp')),enabled boolean NOT NULL DEFAULT false,version bigint NOT NULL DEFAULT 1 CHECK(version>0),profile_id text,profile_version bigint,PRIMARY KEY(organization_id,workspace_id,environment_id,flow_id));
CREATE TABLE zasp_optional_egress_v1.requests(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,request_id text NOT NULL,actor_id text NOT NULL,purpose text NOT NULL CHECK(purpose='finding_explanation'),idempotency_key text NOT NULL,binding jsonb NOT NULL,state text NOT NULL CHECK(state IN('reserved','started','complete','unknown','failed')),nonce_digest text,started_at timestamptz,completed_at timestamptz,result_digest text NOT NULL DEFAULT '',failure_code text NOT NULL DEFAULT '',usage jsonb,PRIMARY KEY(organization_id,workspace_id,environment_id,request_id),UNIQUE(organization_id,workspace_id,environment_id,actor_id,purpose,idempotency_key));
CREATE TABLE zasp_optional_egress_v1.events(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,event_id bigint GENERATED ALWAYS AS IDENTITY,request_id text,actor_id text NOT NULL,action text NOT NULL,metadata jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,workspace_id,environment_id,event_id));
CREATE TABLE zasp_optional_egress_v1.mutations(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,actor_id text NOT NULL,idempotency_key text NOT NULL,intent jsonb NOT NULL,receipt jsonb NOT NULL,PRIMARY KEY(organization_id,workspace_id,environment_id,actor_id,idempotency_key));

CREATE FUNCTION zasp_optional_egress_v1.profile_digest(p jsonb) RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $digest$
 SELECT 'sha256:'||encode(digest(convert_to(array_to_string(ARRAY[p->>'profile_id',p->>'profile_version',p->>'provider',p->>'purpose',p->>'model',p->>'backend',p->>'account_id',p->>'credential_reference',p->>'credential_digest',p->>'capability_digest',p->>'pricing_digest',p->>'effective_at',p->>'expires_at',p->>'input_token_bound',p->>'output_token_cap',p->>'prompt_price_nano_credits_per_million',p->>'completion_price_nano_credits_per_million',p->>'cost_ceiling_nano_credits',p->>'maximum_outstanding_nano_credits',p->>'maximum_concurrency',p->>'timeout_milliseconds',p->>'policy_version'],chr(31)),'UTF8'),'sha256'),'hex')
$digest$;
CREATE FUNCTION zasp_optional_egress_v1.principal(p text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $principal$
 SELECT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.principals b JOIN pg_roles r ON(r.oid,r.rolname)=(b.login_oid,b.login_name) JOIN pg_roles a ON a.rolname=b.authority_role WHERE b.purpose=p AND r.rolname=session_user AND r.rolcanlogin AND r.rolinherit AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls) AND NOT(a.rolcanlogin OR a.rolsuper OR a.rolcreatedb OR a.rolcreaterole OR a.rolreplication OR a.rolbypassrls) AND a.rolinherit=(a.rolname IN('zasp_temporal_executor','zasp_temporal_compensation')) AND pg_has_role(r.oid,a.oid,'MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=a.oid OR m.member=r.oid AND(m.roleid<>a.oid OR m.admin_option)) AND b.authority_role=CASE p WHEN 'human-forward' THEN 'zasp_security_agent_api' WHEN 'planner-forward' THEN 'zasp_temporal_executor' WHEN 'captured-settlement' THEN 'zasp_temporal_compensation' END
 AND CASE p WHEN 'human-forward' THEN public.zasp_security_agent_principal_ready('zasp_security_agent_api') WHEN 'planner-forward' THEN zasp_temporal68.principal_ready('zasp_temporal_executor') WHEN 'captured-settlement' THEN zasp_temporal68.principal_ready('zasp_temporal_compensation') ELSE false END)
$principal$;
CREATE FUNCTION zasp_optional_egress_v1.register_principal(login_value text,purpose_value text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $register$
DECLARE role_value text;oid_value oid;BEGIN
 IF NOT zasp_authorization79.operator() OR NOT zasp_optional_egress_v1.ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional egress registration rejected';END IF;
 role_value:=CASE purpose_value WHEN 'human-forward' THEN 'zasp_security_agent_api' WHEN 'planner-forward' THEN 'zasp_temporal_executor' WHEN 'captured-settlement' THEN 'zasp_temporal_compensation' END;
 SELECT oid INTO oid_value FROM pg_roles WHERE rolname=login_value;
 IF oid_value IS NULL OR role_value IS NULL
 OR CASE WHEN purpose_value='human-forward' THEN NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_principal_bindings WHERE principal_name=login_value AND authority_role=role_value) ELSE NOT EXISTS(SELECT 1 FROM zasp_temporal68.principals WHERE principal=login_value AND authority=role_value) END
 OR NOT EXISTS(SELECT 1 FROM pg_roles r JOIN pg_roles a ON a.rolname=role_value WHERE r.oid=oid_value AND r.rolcanlogin AND r.rolinherit AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls) AND NOT(a.rolcanlogin OR a.rolsuper OR a.rolcreatedb OR a.rolcreaterole OR a.rolreplication OR a.rolbypassrls) AND a.rolinherit=(a.rolname IN('zasp_temporal_executor','zasp_temporal_compensation')) AND pg_has_role(r.oid,a.oid,'MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=a.oid OR m.member=r.oid AND(m.roleid<>a.oid OR m.admin_option))) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional egress registration rejected';END IF;
 INSERT INTO zasp_optional_egress_v1.principals VALUES(oid_value,login_value,role_value,purpose_value) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.principals WHERE(login_oid,login_name,authority_role,purpose)=(oid_value,login_value,role_value,purpose_value)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional principal already bound';END IF;
 -- Runtime rechecks exact login OID and all role restrictions on every call.
 RETURN true;
END $register$;
CREATE FUNCTION zasp_optional_egress_v1.require_human(q jsonb,operations text[],permission_value text,finding_required boolean) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $human$
DECLARE p jsonb;r jsonb;o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||o,0));
 IF current_setting('transaction_isolation')<>'read committed' OR zasp_optional_egress_v1.ready() IS NOT TRUE OR zasp_optional_egress_v1.principal('human-forward') IS NOT TRUE OR NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(q->>'actor_id'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional egress identity rejected';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,operations,permission_value,true,q->>'actor_id');
 p:=zasp_authorization80.context();r:=p->'revision';
 PERFORM zasp_authorization79.revalidate(o,(r->>'desired')::bigint,(r->>'generation')::bigint,r->>'store_id',r->>'model_id');
 PERFORM zasp_authorization80.identity_fence(p);
 IF p->>'principal_kind' IS NOT NULL AND p->>'principal_kind' NOT IN('human','user') OR permission_value='manage_data_controls' AND NOT EXISTS(SELECT 1 FROM public.zasp_product_sessions s WHERE s.token_digest=decode(p->>'credential_digest','hex') AND s.authenticated_at>clock_timestamp()-interval '5 minutes') OR NOT zasp_authorization80.allowed(o,w,e,CASE WHEN finding_required THEN 'finding' ELSE 'environment' END,CASE WHEN finding_required THEN q->>'finding_id' ELSE e END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional egress current permission rejected';END IF;
END $human$;
CREATE FUNCTION zasp_optional_egress_v1.valid_profile(p jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $valid$
DECLARE k text;v text;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(p,ARRAY['profile_id','profile_version','profile_digest','provider','purpose','model','backend','account_id','credential_reference','credential_digest','capability_digest','pricing_digest','effective_at','expires_at','input_token_bound','output_token_cap','prompt_price_nano_credits_per_million','completion_price_nano_credits_per_million','cost_ceiling_nano_credits','maximum_outstanding_nano_credits','maximum_concurrency','timeout_milliseconds','policy_version']) OR octet_length(p::text)>8192 THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['profile_id','profile_digest','provider','purpose','model','backend','account_id','credential_reference','credential_digest','capability_digest','pricing_digest','effective_at','expires_at','policy_version'] LOOP IF jsonb_typeof(p->k)<>'string' THEN RETURN false;END IF;END LOOP;
 FOR k,v IN SELECT key,value#>>'{}' FROM jsonb_each(p) LOOP IF v IS NULL OR v~'[[:cntrl:]]' OR length(v)>256 THEN RETURN false;END IF;END LOOP;
 IF public.zasp_valid_product_id(p->>'profile_id') IS NOT TRUE OR p->>'provider'<>'openrouter' OR p->>'purpose'<>'finding_explanation' OR p->>'profile_digest' IS DISTINCT FROM zasp_optional_egress_v1.profile_digest(p) OR p->>'model'!~'^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$' OR p->>'backend'!~'^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,127}$' OR p->>'backend' IS DISTINCT FROM btrim(p->>'backend') OR p->>'policy_version'!~'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$' OR p->>'account_id'!~'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' OR length(p->>'credential_reference') NOT BETWEEN 1 AND 256 THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['credential_digest','capability_digest','pricing_digest'] LOOP IF p->>k!~'^sha256:[a-f0-9]{64}$' THEN RETURN false;END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['profile_version','input_token_bound','output_token_cap','prompt_price_nano_credits_per_million','completion_price_nano_credits_per_million','cost_ceiling_nano_credits','maximum_outstanding_nano_credits','maximum_concurrency','timeout_milliseconds'] LOOP IF jsonb_typeof(p->k)<>'number' OR p->>k!~'^[1-9][0-9]{0,15}$' THEN RETURN false;END IF;END LOOP;
 IF (p->>'profile_version')::bigint>1000000 OR (p->>'input_token_bound')::bigint>1000000 OR (p->>'output_token_cap')::bigint>8192 OR (p->>'prompt_price_nano_credits_per_million')::bigint>1000000000000 OR (p->>'completion_price_nano_credits_per_million')::bigint>1000000000000 OR (p->>'cost_ceiling_nano_credits')::bigint>1000000000000 OR (p->>'maximum_outstanding_nano_credits')::bigint>1000000000000000 OR (p->>'maximum_concurrency')::bigint>100 OR (p->>'timeout_milliseconds')::bigint NOT BETWEEN 1000 AND 30000 THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['effective_at','expires_at'] LOOP IF p->>k IS DISTINCT FROM to_char((p->>k)::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') THEN RETURN false;END IF;END LOOP;
 RETURN (p->>'effective_at')::timestamptz<(p->>'expires_at')::timestamptz AND (p->>'expires_at')::timestamptz-(p->>'effective_at')::timestamptz<=interval '720 hours' AND (p->>'maximum_outstanding_nano_credits')::numeric>=(p->>'cost_ceiling_nano_credits')::numeric;
EXCEPTION WHEN data_exception THEN RETURN false;END $valid$;
CREATE FUNCTION zasp_optional_egress_v1.register_profile(q jsonb) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $profile$
DECLARE p jsonb:=q->'profile';BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||(q->>'organization_id'),0));
 IF NOT zasp_authorization79.operator() OR NOT zasp_optional_egress_v1.ready() OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','profile']) OR zasp_optional_egress_v1.valid_profile(p) IS NOT TRUE OR NOT EXISTS(SELECT 1 FROM public.zasp_environments e WHERE(e.organization_id,e.workspace_id,e.id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional profile registration rejected';END IF;
 INSERT INTO zasp_optional_egress_v1.approved_profiles VALUES(q->>'organization_id',q->>'workspace_id',q->>'environment_id',p->>'profile_id',(p->>'profile_version')::bigint,p->>'profile_digest',p) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.approved_profiles x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.profile_id,x.profile_version,x.profile)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',p->>'profile_id',(p->>'profile_version')::bigint,p)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional profile already bound';END IF;
 IF p->>'credential_reference' !~ ('^'||'secret_ref_ai/'||(q->>'organization_id')||'/'||(q->>'workspace_id')||'/'||(q->>'environment_id')||'/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional credential scope rejected';END IF;
 INSERT INTO zasp_optional_egress_v1.policies VALUES(q->>'organization_id',q->>'workspace_id',q->>'environment_id','openrouter',false,1,p->>'profile_id',(p->>'profile_version')::bigint) ON CONFLICT DO NOTHING;
 RETURN true;
END $profile$;
-- New approved versions do not silently replace current dispatch authority.
-- Only the registered operator can activate a version, under the same switch
-- fence; captured requests retain their immutable old version for settlement.
CREATE FUNCTION zasp_optional_egress_v1.activate_profile(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $activate_profile$
DECLARE p zasp_optional_egress_v1.policies;a zasp_optional_egress_v1.approved_profiles;receipt jsonb;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||(q->>'organization_id'),0));
 IF zasp_authorization79.operator() IS NOT TRUE OR zasp_optional_egress_v1.ready() IS NOT TRUE OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','profile_id','profile_version','expected_version']) OR q->>'profile_version'!~'^[1-9][0-9]{0,6}$' OR q->>'expected_version'!~'^[1-9][0-9]{0,14}$' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional profile activation rejected';END IF;
 SELECT * INTO p FROM zasp_optional_egress_v1.policies WHERE(organization_id,workspace_id,environment_id,flow_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','openrouter') FOR UPDATE;
 IF NOT FOUND OR p.version<>(q->>'expected_version')::bigint OR p.version>=9223372036854775807 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='optional profile policy changed';END IF;
 IF p.enabled THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='disable optional egress before profile rotation';END IF;
 SELECT * INTO a FROM zasp_optional_egress_v1.approved_profiles WHERE(organization_id,workspace_id,environment_id,profile_id,profile_version)=(p.organization_id,p.workspace_id,p.environment_id,q->>'profile_id',(q->>'profile_version')::bigint);
 IF NOT FOUND OR zasp_optional_egress_v1.valid_profile(a.profile) IS NOT TRUE OR(a.profile->>'effective_at')::timestamptz>clock_timestamp() OR(a.profile->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional approved version unavailable';END IF;
 IF(p.profile_id,p.profile_version) IS NOT DISTINCT FROM(a.profile_id,a.profile_version) THEN RETURN jsonb_build_object('profile_id',p.profile_id,'profile_version',p.profile_version,'version',p.version);END IF;
 UPDATE zasp_optional_egress_v1.policies SET profile_id=a.profile_id,profile_version=a.profile_version,version=version+1 WHERE(organization_id,workspace_id,environment_id,flow_id)=(p.organization_id,p.workspace_id,p.environment_id,'openrouter') RETURNING * INTO STRICT p;
 receipt:=jsonb_build_object('profile_id',p.profile_id,'profile_version',p.profile_version,'profile_digest',a.profile_digest,'version',p.version);
 INSERT INTO zasp_optional_egress_v1.events(organization_id,workspace_id,environment_id,actor_id,action,metadata) VALUES(p.organization_id,p.workspace_id,p.environment_id,session_user,'profile_activated',receipt);
 RETURN receipt;
END $activate_profile$;
CREATE FUNCTION zasp_optional_egress_v1.current_profile(o text,w text,e text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $current_profile$
 SELECT a.profile FROM zasp_optional_egress_v1.policies p JOIN zasp_optional_egress_v1.approved_profiles a ON(a.organization_id,a.workspace_id,a.environment_id,a.profile_id,a.profile_version)=(p.organization_id,p.workspace_id,p.environment_id,p.profile_id,p.profile_version) WHERE(p.organization_id,p.workspace_id,p.environment_id,p.flow_id)=(o,w,e,'openrouter') AND p.enabled AND (a.profile->>'effective_at')::timestamptz<=clock_timestamp() AND(a.profile->>'expires_at')::timestamptz>clock_timestamp() AND zasp_optional_egress_v1.valid_profile(a.profile)
$current_profile$;
CREATE FUNCTION zasp_optional_egress_v1.catalog(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $catalog$
DECLARE result_value jsonb;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','actor_id']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='optional catalog request rejected';END IF;
 PERFORM zasp_optional_egress_v1.require_human(q,ARRAY['getExternalDataFlows'],'view',false);
 SELECT jsonb_build_object('items',jsonb_agg(jsonb_build_object('id',c.id,'name',c.name,'categories',CASE c.id WHEN 'stytch' THEN jsonb_build_array('identity_metadata') WHEN 'neon' THEN jsonb_build_array('product_metadata','security_metadata') WHEN 'posthog' THEN jsonb_build_array('product_usage') WHEN 'openrouter' THEN jsonb_build_array('redacted_summary') WHEN 'remote-otlp' THEN jsonb_build_array('remote_telemetry') END,'required',c.required,'enabled',CASE WHEN c.required THEN true ELSE coalesce(p.enabled,false) END,'version',coalesce(p.version,1),'available',c.required OR(c.id='openrouter' AND EXISTS(SELECT 1 FROM zasp_optional_egress_v1.approved_profiles a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.profile_id,a.profile_version)=(p.organization_id,p.workspace_id,p.environment_id,p.profile_id,p.profile_version) AND(a.profile->>'effective_at')::timestamptz<=clock_timestamp() AND(a.profile->>'expires_at')::timestamptz>clock_timestamp() AND zasp_optional_egress_v1.valid_profile(a.profile))),'health','unknown') ORDER BY c.ordinal)) INTO result_value FROM(VALUES(1,'stytch','Stytch',true),(2,'neon','Neon PostgreSQL',true),(3,'posthog','PostHog',false),(4,'openrouter','OpenRouter',false),(5,'remote-otlp','Remote OTLP',false)) c(ordinal,id,name,required) LEFT JOIN zasp_optional_egress_v1.policies p ON(p.organization_id,p.workspace_id,p.environment_id,p.flow_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',c.id);
 RETURN result_value;
END $catalog$;
CREATE FUNCTION zasp_optional_egress_v1.update_enabled(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $update$
DECLARE p zasp_optional_egress_v1.policies;prior zasp_optional_egress_v1.mutations;intent jsonb;receipt jsonb;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','actor_id','flow_id','enabled','expected_version','idempotency_key']) OR q->>'flow_id' NOT IN('posthog','openrouter','remote-otlp') OR jsonb_typeof(q->'enabled')<>'boolean' OR jsonb_typeof(q->'expected_version')<>'number' OR q->>'expected_version'!~'^[1-9][0-9]{0,14}$' OR q->>'idempotency_key'!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='optional update rejected';END IF;
 PERFORM zasp_optional_egress_v1.require_human(q,ARRAY['updateExternalDataFlows'],'manage_data_controls',false);
 INSERT INTO zasp_optional_egress_v1.policies(organization_id,workspace_id,environment_id,flow_id) VALUES(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'flow_id') ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT p FROM zasp_optional_egress_v1.policies WHERE(organization_id,workspace_id,environment_id,flow_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'flow_id') FOR UPDATE;
 intent:=q-'actor_id';SELECT * INTO prior FROM zasp_optional_egress_v1.mutations WHERE(organization_id,workspace_id,environment_id,actor_id,idempotency_key)=(p.organization_id,p.workspace_id,p.environment_id,q->>'actor_id',q->>'idempotency_key');
 IF FOUND THEN IF prior.intent IS DISTINCT FROM intent THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='optional update intent changed';END IF;RETURN prior.receipt;END IF;
 IF p.version<>(q->>'expected_version')::bigint OR p.version>=9223372036854775807 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='optional policy changed';END IF;
 IF (q->>'enabled')::boolean AND(p.flow_id<>'openrouter' OR p.profile_id IS NULL OR NOT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.approved_profiles a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.profile_id,a.profile_version)=(p.organization_id,p.workspace_id,p.environment_id,p.profile_id,p.profile_version) AND(a.profile->>'effective_at')::timestamptz<=clock_timestamp() AND(a.profile->>'expires_at')::timestamptz>clock_timestamp() AND zasp_optional_egress_v1.valid_profile(a.profile))) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional adapter unavailable';END IF;
 PERFORM zasp_authorization80.require_read(q->>'organization_id',q->>'workspace_id',q->>'environment_id',ARRAY['updateExternalDataFlows'],'manage_data_controls',true,q->>'actor_id');
 UPDATE zasp_optional_egress_v1.policies SET enabled=(q->>'enabled')::boolean,version=version+1 WHERE(organization_id,workspace_id,environment_id,flow_id)=(p.organization_id,p.workspace_id,p.environment_id,p.flow_id) RETURNING * INTO p;
 receipt:=jsonb_build_object('flow_id',p.flow_id,'enabled',p.enabled,'version',p.version,'idempotency_key',q->>'idempotency_key');
 INSERT INTO zasp_optional_egress_v1.mutations VALUES(p.organization_id,p.workspace_id,p.environment_id,q->>'actor_id',q->>'idempotency_key',intent,receipt);
 INSERT INTO zasp_optional_egress_v1.events(organization_id,workspace_id,environment_id,actor_id,action,metadata) VALUES(p.organization_id,p.workspace_id,p.environment_id,q->>'actor_id','policy_updated',receipt);
 RETURN receipt;
END $update$;
CREATE FUNCTION zasp_optional_egress_v1.valid_intent(q jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $intent$
 SELECT coalesce(q->>'purpose'='finding_explanation' AND public.zasp_valid_product_id(q->>'finding_id') AND jsonb_typeof(q->'finding_version')='number' AND q->>'finding_version'~'^[1-9][0-9]{0,6}$' AND(q->>'finding_version')::bigint<=1000000 AND q->>'idempotency_key'~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$',false)
$intent$;
CREATE FUNCTION zasp_optional_egress_v1.finding_summary(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $summary$
DECLARE f public.zasp_risk_findings;n bigint;d text;BEGIN
 SELECT * INTO f FROM public.zasp_risk_findings WHERE(organization_id,workspace_id,environment_id,id,version)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'finding_id',(q->>'finding_version')::bigint) FOR SHARE;
 IF NOT FOUND OR NOT public.zasp_risk_finding_visible(f) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='explanation finding changed';END IF;
 SELECT count(*) INTO n FROM public.zasp_risk_finding_evidence WHERE(organization_id,workspace_id,environment_id,finding_id)=(f.organization_id,f.workspace_id,f.environment_id,f.id);
 d:='sha256:'||encode(digest(convert_to(array_to_string(ARRAY[f.id,f.version::text,coalesce(f.rule,f.source),f.severity,n::text],chr(31)),'UTF8'),'sha256'),'hex');
 RETURN jsonb_build_object('finding_id',f.id,'version',f.version,'rule',coalesce(f.rule,f.source),'severity',f.severity,'evidence_count',n,'source_digest',d);
END $summary$;
CREATE FUNCTION zasp_optional_egress_v1.source(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $source$
DECLARE p jsonb;s jsonb;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','actor_id','finding_id','finding_version','idempotency_key','purpose']) OR NOT zasp_optional_egress_v1.valid_intent(q) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='explanation intent rejected';END IF;
 PERFORM zasp_optional_egress_v1.require_human(q,ARRAY['getFinding'],'view',true);
 PERFORM 1 FROM zasp_optional_egress_v1.policies WHERE(organization_id,workspace_id,environment_id,flow_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','openrouter') FOR UPDATE;
 p:=zasp_optional_egress_v1.current_profile(q->>'organization_id',q->>'workspace_id',q->>'environment_id');
 IF p IS NULL OR p->>'purpose'<>'finding_explanation' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='explanation profile unavailable';END IF;
 s:=zasp_optional_egress_v1.finding_summary(q);RETURN jsonb_build_object('summary',s,'profile',p);
END $source$;
CREATE FUNCTION zasp_optional_egress_v1.receipt(r zasp_optional_egress_v1.requests) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $receipt$
 SELECT jsonb_build_object('binding',r.binding,'state',r.state,'result_digest',r.result_digest,'failure_code',r.failure_code,'usage',r.usage)
$receipt$;
-- Mounted reads converge abandoned attempts without a background worker.
-- The caller holds the organization, policy and exact request locks already.
CREATE FUNCTION zasp_optional_egress_v1.expire_request(r zasp_optional_egress_v1.requests) RETURNS zasp_optional_egress_v1.requests LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $expire$
DECLARE prior_state text:=r.state;BEGIN
 IF r.state IN('reserved','started') AND(r.binding->>'deadline')::timestamptz<=clock_timestamp() THEN
  UPDATE zasp_optional_egress_v1.requests SET state=CASE WHEN prior_state='reserved' THEN 'failed' ELSE 'unknown' END,failure_code=CASE WHEN prior_state='reserved' THEN 'expired_no_send' ELSE 'deadline' END,completed_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,request_id,binding,state)=(r.organization_id,r.workspace_id,r.environment_id,r.request_id,r.binding,prior_state) RETURNING * INTO STRICT r;
  INSERT INTO zasp_optional_egress_v1.events(organization_id,workspace_id,environment_id,request_id,actor_id,action,metadata) VALUES(r.organization_id,r.workspace_id,r.environment_id,r.request_id,r.actor_id,'expired',jsonb_build_object('prior_state',prior_state,'deadline',r.binding->>'deadline','cost_ceiling_nano_credits',r.binding->'cost_ceiling_nano_credits'));
 END IF;RETURN r;
END $expire$;
CREATE FUNCTION zasp_optional_egress_v1.replay(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $replay$
DECLARE r zasp_optional_egress_v1.requests;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','actor_id','finding_id','finding_version','idempotency_key','purpose']) OR NOT zasp_optional_egress_v1.valid_intent(q) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='explanation replay rejected';END IF;
 PERFORM zasp_optional_egress_v1.require_human(q,ARRAY['getFinding'],'view',true);
 PERFORM 1 FROM zasp_optional_egress_v1.policies WHERE(organization_id,workspace_id,environment_id,flow_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','openrouter') FOR UPDATE;
 SELECT * INTO r FROM zasp_optional_egress_v1.requests WHERE(organization_id,workspace_id,environment_id,actor_id,purpose,idempotency_key)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'actor_id',q->>'purpose',q->>'idempotency_key') FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('found',false,'receipt',NULL);END IF;
 IF (r.binding->>'finding_id',r.binding->'finding_version') IS DISTINCT FROM(q->>'finding_id',q->'finding_version') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='explanation intent changed';END IF;
 PERFORM zasp_optional_egress_v1.finding_summary(q);
 r:=zasp_optional_egress_v1.expire_request(r);
 RETURN jsonb_build_object('found',true,'receipt',zasp_optional_egress_v1.receipt(r));
END $replay$;
CREATE FUNCTION zasp_optional_egress_v1.validate_binding(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $binding$
DECLARE p jsonb;s jsonb;k text;expected_cost numeric;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','actor_id','finding_id','finding_version','idempotency_key','purpose','request_id','source_digest','profile_id','profile_version','profile_digest','body_digest','pricing_digest','credential_digest','input_token_bound','output_token_cap','cost_ceiling_nano_credits','deadline']) OR NOT zasp_optional_egress_v1.valid_intent(q) OR public.zasp_valid_product_id(q->>'request_id') IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='explanation binding rejected';END IF;
 FOREACH k IN ARRAY ARRAY['source_digest','profile_digest','body_digest','pricing_digest','credential_digest'] LOOP IF coalesce(q->>k,'')!~'^sha256:[a-f0-9]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='explanation digest rejected';END IF;END LOOP;
 p:=zasp_optional_egress_v1.current_profile(q->>'organization_id',q->>'workspace_id',q->>'environment_id');
 s:=zasp_optional_egress_v1.finding_summary(q);
 IF p IS NULL OR p->>'purpose'<>'finding_explanation' OR q->>'source_digest' IS DISTINCT FROM s->>'source_digest' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='explanation source unavailable';END IF;
 FOREACH k IN ARRAY ARRAY['profile_id','profile_version','profile_digest','pricing_digest','credential_digest','input_token_bound','output_token_cap'] LOOP IF q->k IS DISTINCT FROM p->k THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='explanation approved binding changed';END IF;END LOOP;
 -- NUMERIC arithmetic cannot overflow before validating the bounded bigint result.
 expected_cost:=ceil(((p->>'input_token_bound')::numeric*(p->>'prompt_price_nano_credits_per_million')::numeric+(p->>'output_token_cap')::numeric*(p->>'completion_price_nano_credits_per_million')::numeric)/1000000);
 IF jsonb_typeof(q->'cost_ceiling_nano_credits')<>'number' OR q->>'cost_ceiling_nano_credits'!~'^[1-9][0-9]{0,12}$' OR (q->>'cost_ceiling_nano_credits')::numeric<>expected_cost OR expected_cost>(p->>'cost_ceiling_nano_credits')::numeric OR q->>'deadline' IS DISTINCT FROM to_char((q->>'deadline')::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') OR (q->>'deadline')::timestamptz<=clock_timestamp() OR (q->>'deadline')::timestamptz>(p->>'expires_at')::timestamptz OR (q->>'deadline')::timestamptz>clock_timestamp()+((p->>'timeout_milliseconds')::bigint*interval '1 millisecond') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='explanation bounds rejected';END IF;
 RETURN p;
END $binding$;
CREATE FUNCTION zasp_optional_egress_v1.reserve(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $reserve$
DECLARE r zasp_optional_egress_v1.requests;p jsonb;outstanding numeric;BEGIN
 PERFORM zasp_optional_egress_v1.require_human(q,ARRAY['getFinding'],'view',true);
 PERFORM zasp_optional_egress_v1.finding_summary(q);
 PERFORM 1 FROM zasp_optional_egress_v1.policies WHERE(organization_id,workspace_id,environment_id,flow_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','openrouter') FOR UPDATE;
 -- Same-key replay precedes fresh profile selection; it cannot adopt a new body.
 SELECT * INTO r FROM zasp_optional_egress_v1.requests WHERE(organization_id,workspace_id,environment_id,actor_id,purpose,idempotency_key)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'actor_id',q->>'purpose',q->>'idempotency_key') FOR UPDATE;
 IF FOUND THEN IF r.binding IS DISTINCT FROM q THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='explanation immutable binding changed';END IF;r:=zasp_optional_egress_v1.expire_request(r);RETURN zasp_optional_egress_v1.receipt(r)||jsonb_build_object('newly_reserved',false);END IF;
 p:=zasp_optional_egress_v1.validate_binding(q);
 SELECT coalesce(sum((binding->>'cost_ceiling_nano_credits')::numeric),0) INTO outstanding FROM zasp_optional_egress_v1.requests WHERE(organization_id,workspace_id,environment_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id') AND binding->>'profile_digest'=q->>'profile_digest' AND state IN('reserved','started','unknown') AND(state<>'reserved' OR(binding->>'deadline')::timestamptz>clock_timestamp());
 IF outstanding+(q->>'cost_ceiling_nano_credits')::numeric>(p->>'maximum_outstanding_nano_credits')::numeric THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='explanation reservation limit';END IF;
 PERFORM zasp_authorization80.require_read(q->>'organization_id',q->>'workspace_id',q->>'environment_id',ARRAY['getFinding'],'view',true,q->>'actor_id');
 INSERT INTO zasp_optional_egress_v1.requests(organization_id,workspace_id,environment_id,request_id,actor_id,purpose,idempotency_key,binding,state) VALUES(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'request_id',q->>'actor_id',q->>'purpose',q->>'idempotency_key',q,'reserved') RETURNING * INTO r;
 INSERT INTO zasp_optional_egress_v1.events(organization_id,workspace_id,environment_id,request_id,actor_id,action,metadata) VALUES(r.organization_id,r.workspace_id,r.environment_id,r.request_id,r.actor_id,'reserved',jsonb_build_object('body_digest',q->>'body_digest','profile_digest',q->>'profile_digest','source_digest',q->>'source_digest','cost_ceiling_nano_credits',q->'cost_ceiling_nano_credits'));
 RETURN zasp_optional_egress_v1.receipt(r)||jsonb_build_object('newly_reserved',true);
END $reserve$;
CREATE FUNCTION zasp_optional_egress_v1.dispatch(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $dispatch$
DECLARE r zasp_optional_egress_v1.requests;p jsonb;n text;active_count bigint;BEGIN
 PERFORM zasp_optional_egress_v1.require_human(q,ARRAY['getFinding'],'view',true);
 PERFORM zasp_optional_egress_v1.finding_summary(q);
 PERFORM 1 FROM zasp_optional_egress_v1.policies WHERE(organization_id,workspace_id,environment_id,flow_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','openrouter') FOR UPDATE;
 SELECT * INTO r FROM zasp_optional_egress_v1.requests WHERE(organization_id,workspace_id,environment_id,request_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'request_id') FOR UPDATE;
 IF NOT FOUND OR r.binding IS DISTINCT FROM q THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='explanation reservation changed';END IF;
 r:=zasp_optional_egress_v1.expire_request(r);
 IF r.state<>'reserved' THEN RETURN zasp_optional_egress_v1.receipt(r)||jsonb_build_object('newly_started',false,'nonce','','started_at',coalesce(to_char(r.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),''));END IF;
 p:=zasp_optional_egress_v1.validate_binding(q);
 SELECT count(*) INTO active_count FROM zasp_optional_egress_v1.requests WHERE(organization_id,workspace_id,environment_id)=(r.organization_id,r.workspace_id,r.environment_id) AND binding->>'profile_digest'=q->>'profile_digest' AND state='started' AND(binding->>'deadline')::timestamptz>clock_timestamp();
 IF active_count>=(p->>'maximum_concurrency')::bigint THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='explanation concurrency limit';END IF;
 PERFORM zasp_authorization80.require_read(q->>'organization_id',q->>'workspace_id',q->>'environment_id',ARRAY['getFinding'],'view',true,q->>'actor_id');
 n:=encode(gen_random_bytes(32),'hex');
 UPDATE zasp_optional_egress_v1.requests SET state='started',nonce_digest=encode(digest(n,'sha256'),'hex'),started_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,request_id)=(r.organization_id,r.workspace_id,r.environment_id,r.request_id) AND state='reserved' RETURNING * INTO STRICT r;
 INSERT INTO zasp_optional_egress_v1.events(organization_id,workspace_id,environment_id,request_id,actor_id,action,metadata) VALUES(r.organization_id,r.workspace_id,r.environment_id,r.request_id,r.actor_id,'started',jsonb_build_object('body_digest',q->>'body_digest','profile_digest',q->>'profile_digest'));
 RETURN zasp_optional_egress_v1.receipt(r)||jsonb_build_object('newly_started',true,'nonce',n,'started_at',to_char(r.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $dispatch$;
CREATE FUNCTION zasp_optional_egress_v1.settle(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $settle$
DECLARE r zasp_optional_egress_v1.requests;b jsonb:=q-ARRAY['nonce','state','result_digest','failure_code','usage'];u jsonb:=q->'usage';k text;p jsonb;expected_cost numeric;BEGIN
 IF zasp_optional_egress_v1.ready() IS NOT TRUE OR zasp_optional_egress_v1.principal('captured-settlement') IS NOT TRUE OR octet_length(q::text)>16384 OR NOT(q ? 'usage') OR NOT zasp_sa_multistep_prior.closed(q-'usage',ARRAY['organization_id','workspace_id','environment_id','actor_id','finding_id','finding_version','idempotency_key','purpose','request_id','source_digest','profile_id','profile_version','profile_digest','body_digest','pricing_digest','credential_digest','input_token_bound','output_token_cap','cost_ceiling_nano_credits','deadline','nonce','state','result_digest','failure_code']) OR coalesce(q->>'nonce','')!~'^[a-f0-9]{64}$' OR q->>'state' NOT IN('complete','unknown') OR q->>'failure_code' NOT IN('','provider_transport','provider_status','provider_contract','credential_unavailable','deadline','dispatch_uncertain','expired_no_send') OR coalesce(q->>'result_digest','')<>'' AND q->>'result_digest'!~'^sha256:[a-f0-9]{64}$' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='captured explanation settlement rejected';END IF;
 SELECT * INTO r FROM zasp_optional_egress_v1.requests WHERE(organization_id,workspace_id,environment_id,request_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'request_id') FOR UPDATE;
 IF NOT FOUND OR r.binding IS DISTINCT FROM b OR r.nonce_digest IS DISTINCT FROM encode(digest(q->>'nonce','sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='captured explanation binding changed';END IF;
 IF q->>'state'='complete' AND(q->>'result_digest'='' OR q->>'failure_code'<>'' OR u IS NULL OR u='null'::jsonb) OR q->>'state'='unknown' AND(q->>'failure_code'='' OR u IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='captured explanation outcome rejected';END IF;
 IF u IS NOT NULL AND u<>'null'::jsonb THEN
  IF NOT zasp_sa_multistep_prior.closed(u,ARRAY['input_tokens','output_tokens','cost_nano_credits']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='captured usage rejected';END IF;
  FOREACH k IN ARRAY ARRAY['input_tokens','output_tokens','cost_nano_credits'] LOOP IF jsonb_typeof(u->k)<>'number' OR u->>k!~'^(0|[1-9][0-9]{0,14})$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='captured usage rejected';END IF;END LOOP;
  SELECT profile INTO STRICT p FROM zasp_optional_egress_v1.approved_profiles WHERE(organization_id,workspace_id,environment_id,profile_id,profile_version,profile_digest)=(r.organization_id,r.workspace_id,r.environment_id,b->>'profile_id',(b->>'profile_version')::bigint,b->>'profile_digest');
  expected_cost:=ceil(((u->>'input_tokens')::numeric*(p->>'prompt_price_nano_credits_per_million')::numeric+(u->>'output_tokens')::numeric*(p->>'completion_price_nano_credits_per_million')::numeric)/1000000);
  IF (u->>'input_tokens')::bigint>(b->>'input_token_bound')::bigint OR(u->>'output_tokens')::bigint>(b->>'output_token_cap')::bigint OR(u->>'cost_nano_credits')::numeric>expected_cost OR expected_cost>(b->>'cost_ceiling_nano_credits')::numeric THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='captured usage over bound';END IF;
 END IF;
 IF r.state IN('complete','unknown','failed') THEN
  IF(r.state,r.result_digest,r.failure_code,coalesce(r.usage,'null'::jsonb)) IS DISTINCT FROM(q->>'state',q->>'result_digest',q->>'failure_code',u) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='captured first outcome already recorded';END IF;
  RETURN zasp_optional_egress_v1.receipt(r);
 END IF;
 IF r.state<>'started' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='captured request not started';END IF;
 UPDATE zasp_optional_egress_v1.requests SET state=q->>'state',result_digest=q->>'result_digest',failure_code=q->>'failure_code',usage=nullif(u,'null'::jsonb),completed_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,request_id)=(r.organization_id,r.workspace_id,r.environment_id,r.request_id) RETURNING * INTO STRICT r;
 INSERT INTO zasp_optional_egress_v1.events(organization_id,workspace_id,environment_id,request_id,actor_id,action,metadata) VALUES(r.organization_id,r.workspace_id,r.environment_id,r.request_id,r.actor_id,'settled',jsonb_build_object('state',r.state,'result_digest',r.result_digest,'failure_code',r.failure_code,'usage',r.usage));
 RETURN zasp_optional_egress_v1.receipt(r);
END $settle$;
CREATE FUNCTION zasp_optional_egress_v1.read(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $read$
BEGIN RETURN zasp_optional_egress_v1.replay(q);END $read$;
CREATE FUNCTION zasp_optional_egress_v1.sweep(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $sweep$
DECLARE r zasp_optional_egress_v1.requests;n integer:=0;BEGIN
 IF zasp_optional_egress_v1.ready() IS NOT TRUE OR zasp_optional_egress_v1.principal('captured-settlement') IS NOT TRUE OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','limit']) OR jsonb_typeof(q->'limit')<>'number' OR q->>'limit'!~'^[1-9][0-9]{0,2}$' OR(q->>'limit')::integer>100 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional sweep rejected';END IF;
 FOR r IN SELECT * FROM zasp_optional_egress_v1.requests WHERE(organization_id,workspace_id,environment_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id') AND state IN('reserved','started') AND(binding->>'deadline')::timestamptz<=clock_timestamp() ORDER BY request_id LIMIT(q->>'limit')::integer FOR UPDATE SKIP LOCKED LOOP
  UPDATE zasp_optional_egress_v1.requests SET state=CASE WHEN r.state='reserved' THEN 'failed' ELSE 'unknown' END,failure_code=CASE WHEN r.state='reserved' THEN 'expired_no_send' ELSE 'deadline' END,completed_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,request_id)=(r.organization_id,r.workspace_id,r.environment_id,r.request_id);
  INSERT INTO zasp_optional_egress_v1.events(organization_id,workspace_id,environment_id,request_id,actor_id,action,metadata) VALUES(r.organization_id,r.workspace_id,r.environment_id,r.request_id,r.actor_id,'expired',jsonb_build_object('prior_state',r.state,'deadline',r.binding->>'deadline','cost_ceiling_nano_credits',r.binding->'cost_ceiling_nano_credits'));
  n:=n+1;
 END LOOP;RETURN jsonb_build_object('swept',n);
END $sweep$;
-- Both optional switches and planner dispatch lock this exact policy row after
-- the current organization fence. Existing worker proof owns run/body/pricing.
CREATE FUNCTION zasp_optional_egress_v1.admit_planner_dispatch(family_value text,q jsonb) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $planner$
DECLARE enabled_value boolean;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||(q->>'organization_id'),0));
 IF family_value IS NULL OR family_value NOT IN('ordered68','test74','finding78') OR zasp_optional_egress_v1.ready() IS NOT TRUE OR zasp_optional_egress_v1.principal('planner-forward') IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional planner principal rejected';END IF;
 -- This proof retains the sealed planner's exact run/body/pricing/credential
 -- authority. An explanation profile grants no planner model/backend authority.
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional planner organization unavailable';END IF;
 SELECT enabled INTO enabled_value FROM zasp_optional_egress_v1.policies WHERE(organization_id,workspace_id,environment_id,flow_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id','openrouter') FOR UPDATE;
 IF enabled_value IS DISTINCT FROM true THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional planner policy disabled';END IF;
 -- Policy waits cannot preserve an expired proof or a changed runtime login.
 CASE family_value
 WHEN 'ordered68' THEN PERFORM zasp_authorization80_worker.require_planning68('start',q);
 WHEN 'test74' THEN PERFORM zasp_authorization80_worker.require_planning74('start',q);
 WHEN 'finding78' THEN PERFORM zasp_authorization80_worker.require_planning78('start',q);
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional planner family rejected';
 END CASE;
 IF zasp_optional_egress_v1.principal('planner-forward') IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='optional planner authority changed';END IF;
 RETURN true;
END $planner$;
CREATE FUNCTION zasp_optional_egress_v1.request_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $guard$
BEGIN
 IF TG_OP<>'UPDATE' OR (NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.request_id,NEW.actor_id,NEW.purpose,NEW.idempotency_key,NEW.binding) IS DISTINCT FROM(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.request_id,OLD.actor_id,OLD.purpose,OLD.idempotency_key,OLD.binding) OR OLD.state IN('complete','unknown','failed') OR OLD.state='reserved' AND NEW.state NOT IN('started','failed') OR OLD.state='started' AND NEW.state NOT IN('complete','unknown') OR OLD.nonce_digest IS NOT NULL AND NEW.nonce_digest IS DISTINCT FROM OLD.nonce_digest OR OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='immutable optional request rejected';END IF;RETURN NEW;
END $guard$;
CREATE TRIGGER binding_immutable BEFORE UPDATE OR DELETE ON zasp_optional_egress_v1.requests FOR EACH ROW EXECUTE FUNCTION zasp_optional_egress_v1.request_guard();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON zasp_optional_egress_v1.requests FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
-- Fingerprint covers definitions, role ACLs, FORCE RLS, defaults, constraints,
-- indexes and trigger bindings. Data registrations are immutable below.
CREATE FUNCTION zasp_optional_egress_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT encode(digest(convert_to(jsonb_build_object('namespace',(SELECT jsonb_build_array(nspowner::regrole::text,coalesce(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_optional_egress_v1'),'indexes',(SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) ORDER BY c.relname) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid WHERE t.relnamespace='zasp_optional_egress_v1'::regnamespace),'defaults',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attname,pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attname) FROM pg_attrdef d JOIN pg_class c ON c.oid=d.adrelid JOIN pg_attribute a ON(a.attrelid,a.attnum)=(d.adrelid,d.adnum) WHERE c.relnamespace='zasp_optional_egress_v1'::regnamespace),'views',(SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_viewdef(c.oid),c.relowner::regrole::text,coalesce(c.relacl::text,'')) ORDER BY c.relname) FROM pg_class c WHERE c.relnamespace='zasp_optional_egress_v1'::regnamespace AND c.relkind='v'),'functions',(SELECT jsonb_agg(jsonb_build_array(p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,coalesce(p.proacl::text,'')) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_optional_egress_v1'::regnamespace),'columns',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,c.relrowsecurity,c.relforcerowsecurity,c.relowner::regrole::text,coalesce(c.relacl::text,'')) ORDER BY c.relname,a.attnum) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped WHERE c.relnamespace='zasp_optional_egress_v1'::regnamespace AND c.relkind='r'),'policies',(SELECT jsonb_agg(jsonb_build_array(c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY c.relname,p.polname) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_optional_egress_v1'::regnamespace),'triggers',(SELECT jsonb_agg(jsonb_build_array(c.relname,t.tgname,pg_get_triggerdef(t.oid),t.tgenabled) ORDER BY c.relname,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_optional_egress_v1'::regnamespace AND NOT t.tgisinternal),'constraints',(SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,pg_get_constraintdef(k.oid)) ORDER BY c.relname,k.conname) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_optional_egress_v1'::regnamespace))::text,'UTF8'),'sha256'),'hex')
$f$;
CREATE FUNCTION zasp_optional_egress_v1.ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
 SELECT coalesce((SELECT count(*)=1 AND bool_and(singleton AND checksum='-- optional egress checksum' AND fingerprint=zasp_optional_egress_v1.fingerprint()) FROM zasp_optional_egress_v1.registration),false)
 AND zasp_authorization79.ready('-- authorization79 checksum') AND zasp_authorization80.ready('-- authorization80 checksum') AND zasp_temporal78.ready('-- optional temporal78 checksum','-- optional temporal78 fingerprint')
 AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum='-- optional worker checksum')
 AND zasp_authorization80_runtime.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum='-- optional runtime checksum')
$ready$;
CREATE FUNCTION zasp_optional_egress_v1.planner_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $planner_ready$
 SELECT zasp_optional_egress_v1.ready() IS TRUE AND zasp_optional_egress_v1.principal('planner-forward') IS TRUE
$planner_ready$;
CREATE FUNCTION zasp_optional_egress_v1.catalog_ready(pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
 SELECT pin IS NOT DISTINCT FROM '-- optional egress checksum' AND zasp_optional_egress_v1.ready() IS TRUE
$ready$;
CREATE FUNCTION zasp_optional_egress_v1.caller_ready(purpose_value text,pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $caller_ready$
 SELECT coalesce(purpose_value IN('human-forward','planner-forward','captured-settlement') AND zasp_optional_egress_v1.catalog_ready(pin) AND zasp_optional_egress_v1.principal(purpose_value),false)
$caller_ready$;
DO $seal$ DECLARE n record;BEGIN
 FOR n IN SELECT tablename FROM pg_tables WHERE schemaname='zasp_optional_egress_v1' LOOP
  EXECUTE format('ALTER TABLE zasp_optional_egress_v1.%I OWNER TO zasp_discovery_authority',n.tablename);
  EXECUTE format('ALTER TABLE zasp_optional_egress_v1.%I ENABLE ROW LEVEL SECURITY',n.tablename);
  EXECUTE format('ALTER TABLE zasp_optional_egress_v1.%I FORCE ROW LEVEL SECURITY',n.tablename);
  EXECUTE format('CREATE POLICY authority ON zasp_optional_egress_v1.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n.tablename);
  EXECUTE format('REVOKE ALL ON TABLE zasp_optional_egress_v1.%I FROM PUBLIC',n.tablename);
  IF n.tablename IN('registration','principals','approved_profiles','events','mutations') THEN EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_optional_egress_v1.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n.tablename);END IF;
 END LOOP;
 FOR n IN SELECT p.oid::regprocedure signature FROM pg_proc p WHERE p.pronamespace='zasp_optional_egress_v1'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',n.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',n.signature);
 END LOOP;
END $seal$;
GRANT USAGE ON SCHEMA zasp_optional_egress_v1 TO zasp_security_agent_api,zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_optional_egress_v1.catalog_ready(text),zasp_optional_egress_v1.caller_ready(text,text) TO zasp_security_agent_api,zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_optional_egress_v1.catalog(jsonb),zasp_optional_egress_v1.update_enabled(jsonb),zasp_optional_egress_v1.source(jsonb),zasp_optional_egress_v1.replay(jsonb),zasp_optional_egress_v1.reserve(jsonb),zasp_optional_egress_v1.dispatch(jsonb),zasp_optional_egress_v1.read(jsonb) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_optional_egress_v1.settle(jsonb),zasp_optional_egress_v1.sweep(jsonb) TO zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_optional_egress_v1.admit_planner_dispatch(text,jsonb),zasp_optional_egress_v1.planner_ready() TO zasp_temporal_executor;
