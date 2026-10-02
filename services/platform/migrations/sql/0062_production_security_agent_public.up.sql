-- Separately registered public facade. No canonical migration row is added.
SET LOCAL lock_timeout='3s';
SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));
DO $predecessor$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT COALESCE(public.zasp_sa_multistep_readiness('-- release61 checksum','-- release61 fingerprint'),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public ordered predecessor unavailable';END IF;
END $predecessor$;
CREATE SCHEMA zasp_ordered_public62 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_ordered_public62 FROM PUBLIC;
CREATE TABLE zasp_ordered_public62.registration (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),
 fingerprint text NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$')
);
ALTER TABLE zasp_ordered_public62.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_ordered_public62.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_ordered_public62.registration FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_ordered_public62.registration USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON zasp_ordered_public62.registration FROM PUBLIC;
CREATE FUNCTION zasp_ordered_public62.fingerprint() RETURNS text
 LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_ordered_public62'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(pg_get_functiondef(p.oid),'-- public62 checksum','<extension-checksum>'),'-- public62 fingerprint','<extension-fingerprint>')) FROM pg_proc p WHERE p.pronamespace='zasp_ordered_public62'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_ordered_public62'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_ordered_public62'::regnamespace
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION zasp_ordered_public62.ready(c text,f text) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- public62 checksum' AND f='-- public62 fingerprint'
 AND public.zasp_sa_multistep_readiness('-- release61 checksum','-- release61 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_ordered_public62.registration)
 AND EXISTS(SELECT 1 FROM zasp_ordered_public62.registration WHERE singleton AND checksum=c AND fingerprint=f)
 AND zasp_ordered_public62.fingerprint()=f,false)
$ready$;
CREATE FUNCTION zasp_ordered_public62.authorize(o text,w text,e text,actor text,write_value boolean) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $authorize$
DECLARE membership public.zasp_identity_memberships%ROWTYPE;scope_row public.zasp_authorized_scopes%ROWTYPE;
BEGIN
 SELECT * INTO membership FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(o,actor) FOR SHARE NOWAIT;
 scope_row:=zasp_sa_multistep_prior.lock_scope(o,w,e,actor);
 IF membership.principal_id IS NULL OR NOT membership.active OR scope_row.principal_id IS NULL
  OR NOT COALESCE(public.zasp_effective_scope_permissions(scope_row.permissions,membership.role) ?& CASE WHEN write_value THEN ARRAY['view','manage_workflows','run_tests'] ELSE ARRAY['view'] END,false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
END $authorize$;

-- Persisted family shape is independent of permission to start new execution.
CREATE FUNCTION zasp_ordered_public62.definition_shape(d public.zasp_security_agent_definitions,e text,enabled_value boolean) RETURNS void
 LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $shape$
DECLARE b jsonb;reference jsonb;k text;
BEGIN
 b:=d.body;
 IF d.definition_id IS NULL OR octet_length(b::text)>16384 OR d.activation IS DISTINCT FROM (CASE WHEN enabled_value THEN 'supervised' ELSE 'draft' END)
  OR d.plan_catalog_version IS DISTINCT FROM 'security-agent-actions-v1'
  OR NOT zasp_sa_multistep_prior.closed(b,ARRAY['id','name','trigger_kind','trigger_source','environment_ids','autonomy','max_steps','max_duration_seconds','temporary_policy_seconds','ai_token_budget','max_ai_cost_nano_credits','concurrency_limit','allowed_actions','verification_kind','definition_version','enabled','existing_test'])
  OR b->>'id' IS DISTINCT FROM d.definition_id OR b->'enabled' IS DISTINCT FROM to_jsonb(enabled_value)
  OR b->'allowed_actions' IS DISTINCT FROM '["create_temporary_policy","run_test"]'::jsonb
  OR b->'environment_ids' IS DISTINCT FROM jsonb_build_array(e) OR b->>'autonomy' IS DISTINCT FROM 'supervised'
  OR b->'max_steps' IS DISTINCT FROM '2'::jsonb OR b->>'verification_kind' IS DISTINCT FROM 'test_run'
  OR b->'definition_version' IS DISTINCT FROM to_jsonb(d.definition_version)
  OR b->>'trigger_kind' NOT IN('finding','attack_path') OR b->>'trigger_kind'='attack_path' AND b->>'trigger_source' NOT IN('observed','verified') THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
 FOREACH k IN ARRAY ARRAY['name','trigger_kind','trigger_source'] LOOP
  IF jsonb_typeof(b->k) IS DISTINCT FROM 'string' OR length(btrim(b->>k)) NOT BETWEEN 1 AND 128 OR (b->>k)~'[[:cntrl:]]' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered definition rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['max_duration_seconds','temporary_policy_seconds','ai_token_budget','max_ai_cost_nano_credits','concurrency_limit'] LOOP
  IF jsonb_typeof(b->k) IS DISTINCT FROM 'number' OR (b->>k)!~'^[1-9][0-9]{0,12}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered limit rejected';END IF;
 END LOOP;
 IF (b->>'max_duration_seconds')::bigint NOT BETWEEN 1 AND 86400 OR (b->>'temporary_policy_seconds')::bigint NOT BETWEEN 60 AND 3600
  OR (b->>'ai_token_budget')::bigint NOT BETWEEN 1 AND 12000 OR (b->>'max_ai_cost_nano_credits')::bigint NOT BETWEEN 1 AND 1000000000000
  OR (b->>'concurrency_limit')::bigint NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered limit rejected';END IF;
 reference:=b->'existing_test';
 IF NOT zasp_sa_multistep_prior.closed(reference,ARRAY['definition_id','definition_version'])
  OR jsonb_typeof(reference->'definition_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(reference->>'definition_id'),false)
  OR reference->>'definition_id' IN(e,d.definition_id) OR jsonb_typeof(reference->'definition_version') IS DISTINCT FROM 'number'
  OR (reference->>'definition_version')!~'^([1-9][0-9]{0,5}|1000000)$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered reference rejected';END IF;
END $shape$;

CREATE FUNCTION zasp_ordered_public62.definition(o text,w text,e text,did text,v bigint,enabled_value boolean) RETURNS public.zasp_security_agent_definitions
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $definition$
DECLARE d public.zasp_security_agent_definitions%ROWTYPE;t public.zasp_red_team_definitions%ROWTYPE;c public.zasp_attack_lab_credential_bindings%ROWTYPE;
 b jsonb;reference jsonb;target jsonb;class_value text;
BEGIN
 SELECT * INTO d FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,did,v) AND deleted_at IS NULL FOR SHARE;
 PERFORM zasp_ordered_public62.definition_shape(d,e,enabled_value);
 b:=d.body;reference:=b->'existing_test';
 PERFORM 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*','create_temporary_policy','run_test') ORDER BY organization_id,workspace_id,environment_id,action_key FOR SHARE;
 IF (SELECT count(*)<>4 OR NOT COALESCE(bool_and(execution_enabled),false) FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*','create_temporary_policy','run_test')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public ordered execution disabled';END IF;
 SELECT * INTO t FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,enabled)=(o,w,e,reference->>'definition_id',(reference->>'definition_version')::bigint,true) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
 class_value:=public.zasp_production_security_agent_run_context_lock_env(o,w,e);
 target:=public.zasp_production_security_agent_run_context_lock_target(o,w,e,t.target_id);
 SELECT * INTO c FROM public.zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id,target_id,credential_reference,state)=(o,w,e,t.target_id,target->'attributes'->'red_team'->>'credential_reference','active') AND credential_class=t.safety->>'credential_class' FOR SHARE;
 IF NOT FOUND OR NOT COALESCE(class_value IN('development','test','staging') AND class_value=t.safety->>'environment' AND target->>'state'='active'
  AND (target->>'fresh_until')::timestamptz>clock_timestamp() AND c.valid_until>clock_timestamp()
  AND public.zasp_red_team_safety_authorized(o,w,e,t.target_id,t.target_kind,t.safety),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
 RETURN d;
END $definition$;

-- Historical reads never substitute the mutable current definition or planner
-- state for the exact immutable version and public trigger authority.
CREATE FUNCTION zasp_ordered_public62.history(o text,w text,e text,r text) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $history$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;
 tr public.zasp_security_agent_trigger_receipts%ROWTYPE;a public.zasp_security_agent_audit%ROWTYPE;b jsonb;ref jsonb;k text;
BEGIN
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,rr.definition_id,rr.definition_version) FOR SHARE;
 b:=h.definition;ref:=b->'existing_test';
 IF h.definition_id IS NULL OR h.activation IS DISTINCT FROM 'supervised' OR h.definition_digest IS DISTINCT FROM digest(convert_to(b::text,'UTF8'),'sha256') OR octet_length(b::text)>16384
  OR NOT zasp_sa_multistep_prior.closed(b,ARRAY['id','name','trigger_kind','trigger_source','environment_ids','autonomy','max_steps','max_duration_seconds','temporary_policy_seconds','ai_token_budget','max_ai_cost_nano_credits','concurrency_limit','allowed_actions','verification_kind','definition_version','enabled','existing_test'])
  OR b->>'id' IS DISTINCT FROM rr.definition_id OR b->'enabled' IS DISTINCT FROM 'true'::jsonb OR b->'allowed_actions' IS DISTINCT FROM '["create_temporary_policy","run_test"]'::jsonb
  OR b->'environment_ids' IS DISTINCT FROM jsonb_build_array(e) OR b->>'autonomy' IS DISTINCT FROM 'supervised' OR b->'max_steps' IS DISTINCT FROM '2'::jsonb OR b->>'verification_kind' IS DISTINCT FROM 'test_run'
  OR jsonb_typeof(b->'definition_version') IS DISTINCT FROM 'number' OR NOT COALESCE(b->>'definition_version'~'^([1-9][0-9]{0,5}|1000000)$',false)
  OR b->>'trigger_kind' NOT IN('finding','attack_path') OR b->>'trigger_kind'='attack_path' AND b->>'trigger_source' NOT IN('observed','verified')
  OR NOT zasp_sa_multistep_prior.closed(ref,ARRAY['definition_id','definition_version']) OR jsonb_typeof(ref->'definition_id') IS DISTINCT FROM 'string'
  OR NOT COALESCE(public.zasp_valid_product_id(ref->>'definition_id'),false) OR ref->>'definition_id' IN(e,rr.definition_id)
  OR jsonb_typeof(ref->'definition_version') IS DISTINCT FROM 'number' OR NOT COALESCE(ref->>'definition_version'~'^([1-9][0-9]{0,5}|1000000)$',false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered history unavailable';END IF;
 FOREACH k IN ARRAY ARRAY['name','trigger_kind','trigger_source'] LOOP
  IF jsonb_typeof(b->k) IS DISTINCT FROM 'string' OR length(btrim(b->>k)) NOT BETWEEN 1 AND 128 OR (b->>k)~'[[:cntrl:]]' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered historical text unavailable';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['max_duration_seconds','temporary_policy_seconds','ai_token_budget','max_ai_cost_nano_credits','concurrency_limit'] LOOP
  IF jsonb_typeof(b->k) IS DISTINCT FROM 'number' OR (b->>k)!~'^[1-9][0-9]{0,12}$' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered historical limits unavailable';END IF;
 END LOOP;
 IF (b->>'max_duration_seconds')::bigint NOT BETWEEN 1 AND 86400 OR (b->>'temporary_policy_seconds')::bigint NOT BETWEEN 60 AND 3600 OR (b->>'ai_token_budget')::bigint NOT BETWEEN 1 AND 12000
  OR (b->>'max_ai_cost_nano_credits')::bigint NOT BETWEEN 1 AND 1000000000000 OR (b->>'concurrency_limit')::bigint NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered historical limits unavailable';END IF;
 SELECT * INTO tr FROM public.zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,trigger_id)=(o,w,e,r,rr.definition_id,rr.trigger_id) FOR SHARE;
 SELECT * INTO a FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'ordered_public_triggered');
 IF tr.run_id IS NULL OR tr.trigger_kind IS DISTINCT FROM b->>'trigger_kind' OR r IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',rr.definition_id||chr(31)||rr.trigger_id||chr(31)||tr.trigger_version::text)
  OR (SELECT count(*) FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'ordered_public_triggered'))<>1
  OR a.audit_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'public62_trigger',r) OR a.actor_id IS DISTINCT FROM rr.requested_by OR a.event_digest IS DISTINCT FROM digest(convert_to(a.body::text,'UTF8'),'sha256')
  OR a.body->>'definition_digest' IS DISTINCT FROM encode(h.definition_digest,'hex') OR a.body->'existing_test' IS DISTINCT FROM ref OR a.body->>'trigger_digest' IS DISTINCT FROM encode(tr.trigger_digest,'hex')
  OR a.body->'request'->>'organization_id' IS DISTINCT FROM o OR a.body->'request'->>'workspace_id' IS DISTINCT FROM w OR a.body->'request'->>'environment_id' IS DISTINCT FROM e OR a.body->'request'->>'actor_id' IS DISTINCT FROM rr.requested_by
  OR a.body->'request'->>'definition_id' IS DISTINCT FROM rr.definition_id OR a.body->'request'->'definition_version' IS DISTINCT FROM to_jsonb(rr.definition_version)
  OR a.body->'request'->>'trigger_id' IS DISTINCT FROM rr.trigger_id OR a.body->'request'->'trigger_version' IS DISTINCT FROM to_jsonb(tr.trigger_version)
  OR a.body->'response' IS DISTINCT FROM jsonb_build_object('contract_version',62,'run_id',r,'definition_id',rr.definition_id,'definition_version',rr.definition_version,'state','queued','version',1)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.principal_id,x.operation,x.resource_id,x.expected_version,x.audit_id)=(o,w,e,rr.requested_by,'runSecurityAgent',r,rr.definition_version,a.audit_id)
   AND x.intent=a.body->'request' AND x.intent_digest=digest(convert_to(x.intent::text,'UTF8'),'sha256') AND x.response=a.body->'response' AND x.idempotency_key=x.intent->>'idempotency_key') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered historical evidence unavailable';END IF;
END $history$;

-- Retained application proof for product reads only. This is the application
-- portion of the reviewed cleanup snapshot contract, without its terminal-test
-- requirement. Current credentials/targets/expiry grant no read authority.
CREATE FUNCTION zasp_ordered_public62.retained_application(o text,w text,e text,r text) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $retained_application$
DECLARE receipt public.zasp_sa_multistep_receipts%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;c public.zasp_security_agent_controls%ROWTYPE;
 result_hash bytea;deployment_hash bytea;expires timestamptz;applied timestamptz;s text;
BEGIN
 s:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0');
 SELECT * INTO receipt FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id,receipt_kind)=(o,w,e,r,s,'temporary_policy_applied.v1');
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
 SELECT * INTO c FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id,step_id,control_id)=(o,w,e,r,s,receipt.body->>'control_id');
 SELECT digest(fx.input_digest||decode(string_agg(encode(envelope_digest,'hex'),'' ORDER BY device_id),'hex'),'sha256'),digest(convert_to(jsonb_agg(jsonb_build_array(device_id,credential_id,sequence,policy_version,desired_generation,encode(envelope_digest,'hex')) ORDER BY device_id)::text,'UTF8'),'sha256'),min(expires_at),max(verified_at)
  INTO result_hash,deployment_hash,expires,applied FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply');
 IF receipt.run_id IS NULL OR fx.state IS DISTINCT FROM 'cleanup_pending' OR result_hash IS NULL
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,state)=(o,w,e,r,s,0,'create_temporary_policy','succeeded') AND input_digest=receipt.input_digest)
  OR fx.input_digest IS DISTINCT FROM receipt.input_digest OR receipt.result_digest IS DISTINCT FROM result_hash OR fx.result_digest IS DISTINCT FROM result_hash OR receipt.body->>'outcome_id' IS DISTINCT FROM fx.outcome_id
  OR receipt.body->>'control_id' IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_control',r||chr(31)||s)
  OR receipt.body->>'deployment_id' IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_deployment',r||chr(31)||s||chr(31)||encode(deployment_hash,'hex'))
  OR receipt.body->>'applied_at' IS DISTINCT FROM to_char(applied AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') OR receipt.body->>'expires_at' IS DISTINCT FROM to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  OR c.control_id IS NULL OR c.state NOT IN('active','disabled') OR c.target_id IS DISTINCT FROM e OR c.action_key IS DISTINCT FROM 'create_temporary_policy' OR c.expires_at IS DISTINCT FROM expires OR c.version IS DISTINCT FROM ((receipt.body->>'control_version')::bigint+CASE WHEN c.state='disabled' THEN 1 ELSE 0 END)
  OR (SELECT count(*) FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))<>1
  OR (SELECT count(*) FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply')) NOT BETWEEN 1 AND 100
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,phase)=(o,w,e,r,'apply') AND (step_id<>s OR state<>'verified' OR verified_at IS NULL OR desired_generation IS NULL OR policies IS DISTINCT FROM zasp_sa_multistep_prior.application_policies()))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state,version)=(o,w,e,r,s,'approved',2) AND approver_id IS NOT NULL AND approver_id<>requester_id AND fresh_auth_at IS NOT NULL AND decided_at IS NOT NULL AND fresh_auth_at>=decided_at-interval '5 minutes' AND fresh_auth_at<=decided_at+interval '5 seconds')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,s,'create_temporary_policy',receipt.input_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered retained application unavailable';END IF;
 RETURN c.state='active' AND expires>clock_timestamp();
END $retained_application$;

CREATE FUNCTION zasp_ordered_public62.project_core(o text,w text,e text,r text,retained_value boolean) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $project$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;s public.zasp_security_agent_steps%ROWTYPE;a public.zasp_security_agent_approvals%ROWTYPE;
 receipt public.zasp_sa_multistep_receipts%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;
 cleanup zasp_sa_multistep_prior.cleanups%ROWTYPE;cleaned zasp_sa_multistep_prior.cleanup_receipts%ROWTYPE;
 completion public.zasp_security_agent_audit%ROWTYPE;control_row public.zasp_security_agent_controls%ROWTYPE;completed_body jsonb;
 result_value jsonb;steps jsonb:='[]';receipt_value jsonb;cleanup_value jsonb;snapshot_value jsonb;predecessor text;settlement text;
 admitted boolean;application boolean;live_value boolean;terminal boolean;dependency_ready boolean;retained_live boolean:=true;
BEGIN
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
 admitted:=EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r));
 IF admitted THEN
  PERFORM zasp_sa_multistep_prior.cleanup_lock(o,w,e,r);
  PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,false);
 ELSE
  PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
  PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
  PERFORM 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 END IF;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 PERFORM zasp_ordered_public62.history(o,w,e,r);
 terminal:=rr.state IN('contained','remediated','needs_human','failed','inconclusive','cancelled');
 IF (terminal AND rr.completed_at IS NULL) OR (NOT terminal AND rr.completed_at IS NOT NULL) OR rr.version NOT BETWEEN 1 AND 1000000 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered aggregate unavailable';END IF;
 IF NOT admitted THEN
  IF rr.plan_hash IS NOT NULL OR rr.state NOT IN('queued','planning','needs_human','cancelled','failed','inconclusive') OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
   OR rr.state='queued' AND (rr.version<>1 OR rr.attempt<>0)
   OR rr.state='planning' AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered state unavailable';END IF;
  IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts tr WHERE (tr.organization_id,tr.workspace_id,tr.environment_id,tr.run_id,tr.definition_id,tr.trigger_id)=(o,w,e,r,rr.definition_id,rr.trigger_id) AND r=public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',rr.definition_id||chr(31)||rr.trigger_id||chr(31)||tr.trigger_version::text)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered trigger unavailable';END IF;
 ELSE
  application:=EXISTS(SELECT 1 FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,receipt_kind)=(o,w,e,r,'temporary_policy_applied.v1'));
  SELECT step_id INTO predecessor FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index)=(o,w,e,r,0);
  SELECT * INTO cleanup FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  SELECT * INTO cleaned FROM zasp_sa_multistep_prior.cleanup_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  IF (SELECT count(*) FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))>1
   OR (SELECT count(*) FROM zasp_sa_multistep_prior.cleanup_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))>1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered cleanup multiplicity';END IF;
  IF terminal AND (application OR cleanup.run_id IS NOT NULL) THEN snapshot_value:=zasp_sa_multistep_prior.cleanup_snapshot(o,w,e,r,predecessor);END IF;
  IF NOT terminal AND application THEN
   IF retained_value THEN retained_live:=zasp_ordered_public62.retained_application(o,w,e,r);
   ELSIF NOT zasp_sa_multistep_prior.application_ready(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered application unavailable';END IF;
  END IF;
  IF cleanup.run_id IS NOT NULL AND (cleanup.step_id<>predecessor OR cleanup.snapshot IS DISTINCT FROM snapshot_value)
   OR (cleanup.state='cleaned') IS DISTINCT FROM (cleaned.run_id IS NOT NULL) AND cleanup.run_id IS NOT NULL
   OR cleanup.run_id IS NULL AND cleaned.run_id IS NOT NULL
   OR cleaned.run_id IS NOT NULL AND (cleaned.digest IS DISTINCT FROM digest(convert_to(zasp_sa_multistep_prior.deployment_json(cleaned.body),'UTF8'),'sha256') OR cleaned.receipt_kind IS DISTINCT FROM (CASE WHEN cleanup.snapshot->>'kind'='partial' THEN 'temporary_policy_partial_cleaned.v1' ELSE 'temporary_policy_cleaned.v1' END)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered cleanup unavailable';END IF;
  IF cleanup.state='cleaned' THEN
   SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,predecessor,'create_temporary_policy');
   SELECT * INTO completion FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,predecessor,'ordered_cleanup_complete');
   IF (SELECT count(*) FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'ordered_cleanup_complete'))<>1
    OR completion.audit_id IS NULL OR completion.audit_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_cleanup_operation',r||chr(31)||predecessor||chr(31)||encode(completion.event_digest,'hex'))
    OR completion.correlation_id IS DISTINCT FROM completion.audit_id OR completion.body->'owner' IS DISTINCT FROM to_jsonb(cleanup)-'lease_token'
    OR fx.state IS DISTINCT FROM 'cleaned' OR fx.lease_owner IS NOT NULL OR fx.lease_token IS NOT NULL OR fx.lease_expires_at IS NOT NULL
    OR cleanup.lease_owner IS NOT NULL OR cleanup.lease_token IS NOT NULL OR cleanup.lease_expires_at IS NOT NULL OR cleanup.completed_at IS NULL
    OR cleaned.step_id IS DISTINCT FROM predecessor
    OR completion.body->'request'->>'operation' IS DISTINCT FROM 'complete' OR completion.body->'request'->>'run_id' IS DISTINCT FROM r OR completion.body->'request'->>'step_id' IS DISTINCT FROM predecessor
    OR completion.body->'request'->'effect_version' IS DISTINCT FROM to_jsonb(fx.version-1) OR completion.body->'request'->'version' IS DISTINCT FROM to_jsonb(cleanup.version-1)
    OR completion.body->'request'->'run_version' IS DISTINCT FROM to_jsonb(rr.version-1)
    OR completion.body->'response'->'effect_version' IS DISTINCT FROM to_jsonb(fx.version) OR completion.body->'response'->>'effect_state' IS DISTINCT FROM fx.state
    OR completion.body->'response'->'run_version' IS DISTINCT FROM to_jsonb(rr.version) OR completion.body->'response'->>'run_state' IS DISTINCT FROM rr.state
    OR completion.body->'response'->'version' IS DISTINCT FROM to_jsonb(cleanup.version) OR completion.body->'response'->>'state' IS DISTINCT FROM 'cleaned'
    OR completion.body->'response'->'receipt' IS DISTINCT FROM cleaned.body OR completion.body->'response'->>'receipt_kind' IS DISTINCT FROM cleaned.receipt_kind
    OR completion.body->'response'->>'receipt_digest' IS DISTINCT FROM 'sha256:'||encode(cleaned.digest,'hex')
    OR completion.body->'response'->'targets' IS DISTINCT FROM zasp_sa_multistep_prior.cleanup_targets(o,w,e,r,predecessor) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered completion unavailable';END IF;
   completed_body:=jsonb_build_object('cleanup_id',cleanup.cleanup_id,'removed_source_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'targets'),'UTF8'),'sha256'),'hex'),
    'cleanup_deployment_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(cleaned.body->'targets'),'UTF8'),'sha256'),'hex'),'targets',cleaned.body->'targets',
    'started_at',to_char(cleanup.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'completed_at',to_char(cleanup.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'attempts',cleanup.attempt,'outcome','cleaned');
   IF snapshot_value->>'kind'='partial' THEN
    IF rr.state NOT IN('cancelled','needs_human') OR EXISTS(SELECT 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) OR fx.outcome_id IS NOT NULL OR fx.result_digest IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered partial completion unavailable';END IF;
    completed_body:=completed_body||jsonb_build_object('partial_application_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'application'),'UTF8'),'sha256'),'hex'),'cancellation_evidence_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'test'),'UTF8'),'sha256'),'hex'));
   ELSE
    SELECT * INTO control_row FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id,step_id,control_id)=(o,w,e,r,predecessor,cleanup.control_id);
    IF control_row.state IS DISTINCT FROM 'disabled' OR control_row.version IS DISTINCT FROM (snapshot_value->'control'->>'version')::bigint+1
     OR control_row.lease_owner IS NOT NULL OR control_row.lease_token IS NOT NULL OR control_row.lease_expires_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered completed control unavailable';END IF;
    completed_body:=completed_body||jsonb_build_object('control_id',control_row.control_id,'control_version',control_row.version,'effect_id',fx.outcome_id,
     'application_receipt_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'application'),'UTF8'),'sha256'),'hex'),'test_evidence_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'test'),'UTF8'),'sha256'),'hex'));
   END IF;
   IF cleaned.body IS DISTINCT FROM completed_body THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered completed receipt unavailable';END IF;
  ELSIF EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'ordered_cleanup_complete')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered premature completion';END IF;
  live_value:=NOT terminal AND retained_live AND NOT zasp_sa_multistep_prior.orchestration_stop_required(o,w,e,r);
  FOR s IN SELECT * FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_index LOOP
   SELECT * INTO a FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s.step_id);
   SELECT * INTO receipt FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s.step_id);
   SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s.step_id);
   dependency_ready:=s.step_index=0 OR application;
   IF s.version NOT BETWEEN 1 AND 1000000 OR s.state NOT IN('queued','waiting_approval','authorized','executing','verifying','succeeded','failed','inconclusive','cancelled')
    OR s.step_index=0 AND s.state='queued' OR s.step_index=1 AND NOT application AND s.state NOT IN('queued','cancelled')
    OR s.state='queued' AND a.approval_id IS NOT NULL
    OR s.state='waiting_approval' AND (a.approval_id IS NULL OR a.state<>'pending')
    OR s.state IN('authorized','executing','verifying','succeeded') AND (a.approval_id IS NULL OR a.state<>'approved')
    OR s.state='succeeded' AND receipt.run_id IS NULL
    OR receipt.run_id IS NOT NULL AND (s.state<>'succeeded' OR receipt.action_key IS DISTINCT FROM s.action_key OR receipt.input_digest IS DISTINCT FROM s.input_digest OR receipt.plan_hash IS DISTINCT FROM rr.plan_hash OR receipt.result_digest IS DISTINCT FROM fx.result_digest OR NOT public.zasp_sa_multistep_body_valid(receipt.receipt_kind,receipt.body)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered step unavailable';END IF;
   receipt_value:=CASE WHEN receipt.run_id IS NULL THEN 'null'::jsonb ELSE jsonb_build_object('kind',receipt.receipt_kind,'version',receipt.receipt_version,'digest','sha256:'||encode(receipt.result_digest,'hex'),'reference',public.zasp_discovery_canonical_id(o,w,e,'public62_evidence',r||chr(31)||s.step_id||chr(31)||receipt.receipt_kind)) END;
   settlement:=CASE WHEN s.step_index=0 THEN 'not_applicable' WHEN receipt.run_id IS NULL THEN 'pending' ELSE receipt.body->>'outcome' END;
   cleanup_value:=CASE WHEN s.step_index=1 THEN jsonb_build_object('state','not_applicable','version',0,'attempt',0,'partial',false,'cleaned',false)
    ELSE jsonb_build_object('state',COALESCE(cleanup.state,CASE WHEN application THEN 'pending' ELSE 'not_started' END),'version',COALESCE(cleanup.version,0),'attempt',COALESCE(cleanup.attempt,0),'partial',COALESCE(cleanup.snapshot->>'kind'='partial' OR cleanup.reason='partial_acknowledgement',false),'cleaned',COALESCE(cleanup.state='cleaned',false)) END;
   steps:=steps||jsonb_build_array(jsonb_build_object('step_id',s.step_id,'index',s.step_index,'action',s.action_key,'state',CASE WHEN s.step_index=1 AND s.state='queued' THEN 'blocked' ELSE s.state END,'version',s.version,
    'dependency',jsonb_build_object('predecessor_step_id',CASE WHEN s.step_index=1 THEN predecessor END,'required_receipt_kind',CASE WHEN s.step_index=1 THEN 'temporary_policy_applied.v1' END,'satisfied',dependency_ready,'blocked',s.state='queued','ready',live_value AND dependency_ready AND s.state IN('authorized','waiting_approval')),
    'authorization',s.authorization_result,'approval',jsonb_build_object('state',COALESCE(a.state,'absent'),'version',COALESCE(a.version,0),'approval_id',a.approval_id),'receipt',receipt_value,'settlement',settlement,'cleanup',cleanup_value));
  END LOOP;
  IF jsonb_array_length(steps)<>2 OR rr.state IN('contained','remediated') AND steps->1->>'settlement'<>'not_reproduced' OR rr.state='remediated' AND cleanup.state IS DISTINCT FROM 'cleaned' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered verification unavailable';END IF;
 END IF;
 result_value:=jsonb_build_object('contract_version',62,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_id',rr.definition_id,'definition_version',rr.definition_version,'state',rr.state,'version',rr.version,'admitted',admitted,'steps',steps,'verification',CASE WHEN terminal THEN rr.state ELSE 'pending' END);
 IF octet_length(result_value::text)>8192 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered projection bound exceeded';END IF;
 RETURN result_value;
END $project$;

CREATE FUNCTION zasp_ordered_public62.project(o text,w text,e text,r text) RETURNS jsonb
 LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public AS $project$
 SELECT zasp_ordered_public62.project_core(o,w,e,r,false)
$project$;

-- The public mutation receipt is immutable history, not a caller-controlled
-- transition payload. Replay checks its closed projection and retained private
-- transition audit without repeating the transition after workers advance.
CREATE FUNCTION zasp_ordered_public62.mutate(c text,f text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $mutate$
DECLARE o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';actor text:=q->>'actor_id';r text:=q->>'run_id';op text:=q->>'operation';
 operation_value text;fresh timestamptz;rr public.zasp_security_agent_runs%ROWTYPE;s public.zasp_security_agent_steps%ROWTYPE;approval public.zasp_security_agent_approvals%ROWTYPE;
 prior public.zasp_security_agent_request_receipts%ROWTYPE;audit_row public.zasp_security_agent_audit%ROWTYPE;transition_row public.zasp_security_agent_audit%ROWTYPE;decision_row public.zasp_security_agent_audit%ROWTYPE;
 audit_id_value text;receipt_id_value text;transition_id text;transition_q jsonb;transition_result jsonb;result_value jsonb;body_value jsonb;projection jsonb;
 admitted boolean;cleanup_value boolean;replayed boolean:=false;keys text[];expected_step_version bigint;phase_value text;expected_phase text;decision_id text;
BEGIN
 IF jsonb_typeof(q->'idempotency_key') IS DISTINCT FROM 'string' OR length(q->>'idempotency_key') NOT BETWEEN 16 AND 128 OR q->>'idempotency_key'!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$'
  OR (q->>'run_version')::bigint>=1000000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered mutation rejected';END IF;
 IF op='decide' THEN
  IF jsonb_typeof(q->'decision') IS DISTINCT FROM 'string' OR q->>'decision' NOT IN('approved','rejected') OR jsonb_typeof(q->'fresh_auth_at') IS DISTINCT FROM 'string'
   OR length(q->>'fresh_auth_at') NOT BETWEEN 20 AND 35 OR q->>'fresh_auth_at'!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$' OR (q->>'approval_version')::bigint>=1000000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered decision rejected';END IF;
  fresh:=(q->>'fresh_auth_at')::timestamptz;
  IF fresh<clock_timestamp()-interval '5 minutes' OR fresh>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered decision unavailable';END IF;
 END IF;
 operation_value:=CASE op WHEN 'decide' THEN 'decideSecurityAgentApproval' ELSE 'cancelSecurityAgentRun' END;
 -- Organization admission precedes budget/run, exactly as the private worker.
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
 admitted:=EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r));
 IF admitted THEN PERFORM zasp_sa_multistep_prior.cleanup_lock(o,w,e,r);END IF;
 IF admitted AND op='cancel' THEN
  -- Cancellation must remain possible after gateway revocation or expiry.
  -- Validate retained authority here; validate terminal cleanup evidence after
  -- the reviewed transition creates its blocking audit, never live permission.
  PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,false);
  PERFORM zasp_ordered_public62.history(o,w,e,r);
 ELSE projection:=zasp_ordered_public62.project(o,w,e,r);END IF;
 audit_id_value:=public.zasp_discovery_canonical_id(o,w,e,'public62_mutation_audit',actor||chr(31)||op||chr(31)||(q->>'idempotency_key'));
 receipt_id_value:=public.zasp_discovery_canonical_id(o,w,e,'public62_mutation_receipt',actor||chr(31)||op||chr(31)||(q->>'idempotency_key'));
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,operation_value,q->>'idempotency_key') FOR SHARE;
 IF FOUND THEN
  IF prior.intent IS DISTINCT FROM q OR prior.intent_digest IS DISTINCT FROM digest(convert_to(q::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='public ordered replay conflict';END IF;
  SELECT * INTO audit_row FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,audit_id_value) FOR SHARE;
  result_value:=prior.response;body_value:=audit_row.body;transition_id:=body_value->>'transition_audit_id';
  IF (prior.resource_id,prior.expected_version,prior.audit_id,prior.correlation_id,prior.receipt_id) IS DISTINCT FROM (r,(q->>'run_version')::bigint,audit_id_value,audit_id_value,receipt_id_value)
   OR (audit_row.run_id,audit_row.actor_id,audit_row.event_kind,audit_row.correlation_id) IS DISTINCT FROM (r,actor,'ordered_public_'||op,audit_id_value)
   OR NOT zasp_sa_multistep_prior.closed(body_value||jsonb_build_object('transition_audit_id',COALESCE(transition_id,''),'transition_digest',COALESCE(body_value->>'transition_digest','')),ARRAY['request','response','transition_audit_id','transition_digest']) OR NOT body_value ?& ARRAY['transition_audit_id','transition_digest'] OR body_value->'request' IS DISTINCT FROM q OR body_value->'response' IS DISTINCT FROM result_value
   OR audit_row.event_digest IS DISTINCT FROM digest(convert_to(body_value::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation history unavailable';END IF;
  replayed:=true;
 ELSE
  IF rr.version<>(q->>'run_version')::bigint OR rr.completed_at IS NOT NULL OR rr.state NOT IN('queued','planning','waiting_approval','running','verifying') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation state changed';END IF;
  IF op='decide' THEN
   IF NOT admitted OR rr.state<>'waiting_approval' OR actor=rr.requested_by THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered approval unavailable';END IF;
   SELECT * INTO s FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,state)=(o,w,e,r,'waiting_approval') ORDER BY step_index LIMIT 1;
   SELECT * INTO approval FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s.step_id);
   IF approval.approval_id IS DISTINCT FROM q->>'approval_id' OR approval.state IS DISTINCT FROM 'pending' OR approval.version IS DISTINCT FROM (q->>'approval_version')::bigint OR s.version>=1000000
    OR approval.approver_id IS NOT NULL OR approval.decided_at IS NOT NULL OR approval.fresh_auth_at IS NOT NULL OR approval.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered approval unavailable';END IF;
  ELSIF admitted THEN
   -- Before the application receipt step zero owns cancellation. Once it is
   -- complete the canonical successor owns it, including the between-step gap.
   SELECT * INTO s FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND step_index=CASE WHEN EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index,state)=(o,w,e,r,0,'succeeded')) THEN 1 ELSE 0 END;
  END IF;
  PERFORM zasp_ordered_public62.history(o,w,e,r);
  IF NOT zasp_ordered_public62.ready(c,f) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation authority changed';END IF;
  IF admitted THEN
   IF s.step_id IS NULL OR s.version>=1000000 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered current step unavailable';END IF;
   IF op='cancel' THEN SELECT * INTO approval FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s.step_id);END IF;
   phase_value:=CASE s.state WHEN 'queued' THEN 'queued' WHEN 'waiting_approval' THEN 'pending-approval' WHEN 'authorized' THEN 'authorized' WHEN 'executing' THEN 'executing' END;
   -- The immutable cancel request retains positive pre-transition approval
   -- authority: pending=1, previously approved=2, no approval=1. Never infer
   -- a pending phase merely from missing prior decision evidence.
   transition_q:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'actor_id',actor,'run_id',r,'step_id',s.step_id,'operation',CASE WHEN op='cancel' THEN 'cancel' WHEN q->>'decision'='approved' THEN 'approve' ELSE 'reject' END,'run_version',rr.version,'approval_version',COALESCE(approval.version,1),'fresh_auth_at',CASE WHEN op='decide' THEN q->>'fresh_auth_at' ELSE to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END);
   transition_result:=zasp_sa_multistep_prior.transition('-- release61 checksum','-- release61 fingerprint',transition_q);
   transition_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_transition',r||chr(31)||s.step_id||chr(31)||CASE WHEN op='cancel' THEN 'ordered_run_cancelled' ELSE 'ordered_approval_decided' END);
   SELECT * INTO s FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s.step_id);
  ELSE
   IF op<>'cancel' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered admission absent';END IF;
   phase_value:='before-admission';
   -- Preserve all planner/provider accounting evidence. needs_human remains
   -- eligible for release61 expired-lease recovery; cancelled would strand it.
   PERFORM 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
   UPDATE public.zasp_security_agent_runs SET state=CASE WHEN state='queued' THEN 'cancelled' ELSE 'needs_human' END,version=version+1,completed_at=clock_timestamp(),updated_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error_code='public_cancel_requested' WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  END IF;
  SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  cleanup_value:=EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,action_key)=(o,w,e,r,'create_temporary_policy') AND state<>'cleaned');
  result_value:=jsonb_build_object('contract_version',62,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'run_state',rr.state,'run_version',rr.version,'step_id',s.step_id,'step_state',s.state,'step_version',COALESCE(s.version,0),'audit_id',audit_id_value,'receipt_id',receipt_id_value,'replayed',false);
  IF op='decide' THEN result_value:=result_value||jsonb_build_object('approval_id',approval.approval_id,'approval_version',approval.version+1,'decision',q->>'decision','outcome',CASE WHEN q->>'decision'='approved' THEN 'approved' ELSE 'blocked' END);
  ELSE result_value:=result_value||jsonb_build_object('cleanup_required',cleanup_value,'cancellation_phase',phase_value,'outcome','cancelled-request');END IF;
  SELECT * INTO transition_row FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,transition_id);
  body_value:=jsonb_build_object('request',q,'response',result_value,'transition_audit_id',transition_id,'transition_digest',CASE WHEN transition_id IS NOT NULL THEN encode(digest(convert_to(transition_row.body::text,'UTF8'),'sha256'),'hex') END);
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_id_value,audit_id_value,r,s.step_id,approval.approval_id,actor,'ordered_public_'||op,digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
  INSERT INTO public.zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id) VALUES(o,w,e,actor,operation_value,q->>'idempotency_key',r,(q->>'run_version')::bigint,q,digest(convert_to(q::text,'UTF8'),'sha256'),result_value,audit_id_value,audit_id_value,receipt_id_value);
 END IF;
 keys:=ARRAY['contract_version','organization_id','workspace_id','environment_id','run_id','run_state','run_version','step_id','step_state','step_version','audit_id','receipt_id','replayed','outcome'];
 IF op='decide' THEN keys:=keys||ARRAY['approval_id','approval_version','decision'];ELSE keys:=keys||ARRAY['cleanup_required','cancellation_phase'];END IF;
 IF NOT zasp_sa_multistep_prior.closed(CASE WHEN admitted THEN result_value ELSE result_value||jsonb_build_object('step_id','','step_state','') END,keys) OR NOT result_value ?& keys OR octet_length(result_value::text)>4096
  OR result_value->'contract_version' IS DISTINCT FROM '62'::jsonb OR result_value->>'organization_id' IS DISTINCT FROM o OR result_value->>'workspace_id' IS DISTINCT FROM w OR result_value->>'environment_id' IS DISTINCT FROM e OR result_value->>'run_id' IS DISTINCT FROM r
  OR result_value->'run_version' IS DISTINCT FROM to_jsonb((q->>'run_version')::bigint+1) OR result_value->>'audit_id' IS DISTINCT FROM audit_id_value OR result_value->>'receipt_id' IS DISTINCT FROM receipt_id_value OR result_value->'replayed' IS DISTINCT FROM 'false'::jsonb
  OR op='decide' AND (result_value->>'decision' IS DISTINCT FROM q->>'decision' OR result_value->>'approval_id' IS DISTINCT FROM q->>'approval_id' OR result_value->'approval_version' IS DISTINCT FROM to_jsonb((q->>'approval_version')::bigint+1)
   OR result_value->>'run_state' IS DISTINCT FROM CASE WHEN q->>'decision'='approved' THEN 'running' ELSE 'needs_human' END OR result_value->>'step_state' IS DISTINCT FROM CASE WHEN q->>'decision'='approved' THEN 'authorized' ELSE 'cancelled' END OR result_value->>'outcome' IS DISTINCT FROM CASE WHEN q->>'decision'='approved' THEN 'approved' ELSE 'blocked' END)
  OR op='cancel' AND (result_value->>'outcome' IS DISTINCT FROM 'cancelled-request' OR result_value->>'run_state' NOT IN('cancelled','needs_human') OR jsonb_typeof(result_value->'cleanup_required') IS DISTINCT FROM 'boolean'
   OR result_value->'cleanup_required' IS DISTINCT FROM to_jsonb(EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,action_key)=(o,w,e,r,'create_temporary_policy')))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation result unavailable';END IF;
 IF transition_id IS NOT NULL THEN
  SELECT * INTO transition_row FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,transition_id) FOR SHARE;
  SELECT * INTO s FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,result_value->>'step_id');
  -- Derive cancellation phase from immutable private transition evidence.
  -- Approval state alone cannot distinguish pending from prior authorization.
  SELECT * INTO approval FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s.step_id);
  IF op='decide' THEN expected_step_version:=s.step_index+2;
  ELSE
   decision_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_transition',r||chr(31)||s.step_id||chr(31)||'ordered_approval_decided');
   SELECT * INTO decision_row FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,decision_id) FOR SHARE;
   IF FOUND THEN
    IF (decision_row.run_id,decision_row.step_id,decision_row.event_kind,decision_row.correlation_id) IS DISTINCT FROM (r,s.step_id,'ordered_approval_decided',decision_id)
     OR NOT zasp_sa_multistep_prior.closed(decision_row.body,ARRAY['contract_version','request','response']) OR decision_row.body->'contract_version' IS DISTINCT FROM '61'::jsonb
     OR NOT zasp_sa_multistep_prior.closed(decision_row.body->'request',ARRAY['organization_id','workspace_id','environment_id','actor_id','run_id','step_id','operation','run_version','approval_version','fresh_auth_at'])
     OR NOT zasp_sa_multistep_prior.closed(decision_row.body->'response',ARRAY['contract_version','organization_id','workspace_id','environment_id','run_id','step_id','outcome','run_state','run_version','step_state','approval_id','approval_version'])
     OR decision_row.event_digest IS DISTINCT FROM digest(convert_to((decision_row.body->'request')::text,'UTF8'),'sha256')
     OR (decision_row.body->'request'->>'organization_id',decision_row.body->'request'->>'workspace_id',decision_row.body->'request'->>'environment_id',decision_row.body->'request'->>'run_id',decision_row.body->'request'->>'step_id',decision_row.body->'request'->>'actor_id',decision_row.body->'request'->>'operation') IS DISTINCT FROM (o,w,e,r,s.step_id,decision_row.actor_id,'approve')
     OR decision_row.body->'request'->'approval_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(decision_row.body->'request'->'run_version') IS DISTINCT FROM 'number' OR decision_row.body->'request'->>'run_version'!~'^[1-9][0-9]{0,5}$'
     OR (decision_row.body->'response'->>'organization_id',decision_row.body->'response'->>'workspace_id',decision_row.body->'response'->>'environment_id',decision_row.body->'response'->>'run_id',decision_row.body->'response'->>'step_id',decision_row.body->'response'->>'outcome',decision_row.body->'response'->>'run_state',decision_row.body->'response'->>'step_state') IS DISTINCT FROM (o,w,e,r,s.step_id,'approved','running','authorized')
     OR decision_row.body->'response'->'contract_version' IS DISTINCT FROM '61'::jsonb OR decision_row.body->'response'->'run_version' IS DISTINCT FROM to_jsonb((decision_row.body->'request'->>'run_version')::bigint+1)
     OR decision_row.body->'response'->>'approval_id' IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_approval',r||chr(31)||s.step_id) OR decision_row.body->'response'->'approval_version' IS DISTINCT FROM '2'::jsonb
     OR decision_row.body->'response'->'approval_id' IS DISTINCT FROM transition_row.body->'response'->'approval_id' OR decision_row.body->'response'->'approval_version' IS DISTINCT FROM transition_row.body->'response'->'approval_version'
     OR approval.approval_id IS DISTINCT FROM decision_row.body->'response'->>'approval_id' OR approval.state IS DISTINCT FROM 'approved' OR approval.version IS DISTINCT FROM 2 OR approval.approver_id IS DISTINCT FROM decision_row.actor_id OR approval.fresh_auth_at IS DISTINCT FROM (decision_row.body->'request'->>'fresh_auth_at')::timestamptz
     OR approval.decided_at IS NULL OR approval.approver_id=rr.requested_by OR NOT COALESCE(public.zasp_valid_product_id(decision_row.actor_id),false)
     OR (decision_row.body->'response'->>'run_version')::bigint>(q->>'run_version')::bigint THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered cancellation decision evidence unavailable';END IF;
   END IF;
   IF transition_row.body->'response'->>'step_state'='executing' AND transition_row.body->'request'->'approval_version'='2'::jsonb AND decision_row.audit_id IS NOT NULL THEN expected_phase:='executing';expected_step_version:=s.step_index+3;
   ELSIF transition_row.body->'response'->>'step_state'='cancelled' THEN
    IF s.step_index=1 AND transition_row.body->'request'->'approval_version'='1'::jsonb AND decision_row.audit_id IS NULL AND approval.approval_id IS NULL AND transition_row.body->'response'->>'approval_id'='' AND transition_row.body->'response'->'approval_version'='0'::jsonb THEN expected_phase:='queued';expected_step_version:=2;
    ELSIF transition_row.body->'response'->>'approval_id'=approval.approval_id AND approval.version=2 AND transition_row.body->'response'->'approval_version'='2'::jsonb THEN
     IF transition_row.body->'request'->'approval_version'='2'::jsonb AND decision_row.audit_id IS NOT NULL THEN expected_phase:='authorized';expected_step_version:=s.step_index+3;
     ELSIF transition_row.body->'request'->'approval_version'='1'::jsonb AND decision_row.audit_id IS NULL AND approval.state='cancelled' THEN expected_phase:='pending-approval';expected_step_version:=s.step_index+2;END IF;
    END IF;
   END IF;
   IF expected_phase IS NULL OR result_value->'cancellation_phase' IS DISTINCT FROM to_jsonb(expected_phase) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered cancellation phase unavailable';END IF;
  END IF;
  IF s.step_id IS NULL OR jsonb_typeof(result_value->'step_version') IS DISTINCT FROM 'number' OR result_value->>'step_version'!~'^([1-9][0-9]{0,5}|1000000)$' OR (result_value->>'step_version')::bigint>s.version
   OR expected_step_version IS NULL OR result_value->'step_version' IS DISTINCT FROM to_jsonb(expected_step_version)
   OR transition_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_transition',r||chr(31)||s.step_id||chr(31)||CASE WHEN op='cancel' THEN 'ordered_run_cancelled' ELSE 'ordered_approval_decided' END)
   OR body_value->>'transition_digest' IS DISTINCT FROM encode(digest(convert_to(transition_row.body::text,'UTF8'),'sha256'),'hex')
   OR transition_row.event_digest IS DISTINCT FROM digest(convert_to((transition_row.body->'request')::text,'UTF8'),'sha256')
   OR transition_row.body->'request'->>'actor_id' IS DISTINCT FROM actor OR transition_row.body->'request'->>'run_id' IS DISTINCT FROM r OR transition_row.body->'request'->>'step_id' IS DISTINCT FROM s.step_id
   OR transition_row.body->'request'->>'operation' IS DISTINCT FROM (CASE WHEN op='cancel' THEN 'cancel' WHEN q->>'decision'='approved' THEN 'approve' ELSE 'reject' END)
   OR transition_row.body->'request'->'run_version' IS DISTINCT FROM q->'run_version'
   OR transition_row.body->'response'->'run_version' IS DISTINCT FROM result_value->'run_version' OR transition_row.body->'response'->'run_state' IS DISTINCT FROM result_value->'run_state' OR transition_row.body->'response'->'step_state' IS DISTINCT FROM result_value->'step_state'
   OR op='decide' AND (transition_row.body->'request'->'approval_version' IS DISTINCT FROM q->'approval_version' OR transition_row.body->'request'->'fresh_auth_at' IS DISTINCT FROM q->'fresh_auth_at' OR transition_row.body->'response'->'approval_id' IS DISTINCT FROM q->'approval_id' OR transition_row.body->'response'->'approval_version' IS DISTINCT FROM result_value->'approval_version') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered transition history unavailable';END IF;
 ELSE
  IF result_value->>'run_state' IS DISTINCT FROM (CASE WHEN (q->>'run_version')::bigint=1 THEN 'cancelled' ELSE 'needs_human' END) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered pre-admission state unavailable';END IF;
  IF admitted OR op<>'cancel' OR result_value->>'cancellation_phase' IS DISTINCT FROM 'before-admission' OR result_value->'step_id' IS DISTINCT FROM 'null'::jsonb OR result_value->'step_state' IS DISTINCT FROM 'null'::jsonb OR result_value->'step_version' IS DISTINCT FROM '0'::jsonb OR result_value->'cleanup_required' IS DISTINCT FROM 'false'::jsonb OR body_value->'transition_digest' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered cancellation history unavailable';END IF;
 END IF;
 IF op='decide' THEN
  SELECT * INTO approval FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id,approval_id)=(o,w,e,r,result_value->>'step_id',q->>'approval_id');
  IF (approval.state,approval.version,approval.approver_id,approval.fresh_auth_at) IS DISTINCT FROM (q->>'decision',(q->>'approval_version')::bigint+1,actor,fresh)
   OR approval.requester_id=actor OR approval.decided_at IS NULL OR approval.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered decision evidence changed';END IF;
 END IF;
 PERFORM zasp_ordered_public62.history(o,w,e,r);
 IF op='cancel' THEN PERFORM zasp_ordered_public62.project(o,w,e,r);END IF;
 IF NOT zasp_ordered_public62.ready(c,f) OR op='decide' AND (fresh<clock_timestamp()-interval '5 minutes' OR fresh>clock_timestamp()+interval '5 seconds') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation expired';END IF;
 RETURN result_value||jsonb_build_object('replayed',replayed);
END $mutate$;

-- Classification has no lifecycle effects and never turns contradictory ordered
-- authority into a legacy result. Helpers remain owner-only behind api.
CREATE FUNCTION zasp_ordered_public62.classify(o text,w text,e text,kind text,rid text) RETURNS text
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $classify$
DECLARE d public.zasp_security_agent_definitions%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;
 rr public.zasp_security_agent_runs%ROWTYPE;a public.zasp_security_agent_approvals%ROWTYPE;
 trigger_audit public.zasp_security_agent_audit%ROWTYPE;did text;r text;claimed boolean;approval_claimed boolean:=false;proof record;
BEGIN
 IF kind='definition' THEN did:=rid;
 ELSE
  IF kind='approval' THEN
   SELECT * INTO a FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,approval_id)=(o,w,e,rid);
   -- Retained evidence belongs to the requested ID, not its mutable row links.
   FOR proof IN SELECT run_id,step_id FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND (
     approval_id=rid AND event_kind='approval_requested' AND body->'contract_version'='61'::jsonb
     OR event_kind IN('ordered_step_ready','ordered_approval_decided','ordered_run_cancelled') AND body->'contract_version'='61'::jsonb AND body->'response'->>'approval_id'=rid
     OR event_kind IN('ordered_public_decide','ordered_public_cancel') AND body->'response'->'contract_version'='62'::jsonb AND body->'response'->>'approval_id'=rid) LOOP
    approval_claimed:=true;
    IF a.approval_id IS NULL OR (a.run_id,a.step_id) IS DISTINCT FROM (proof.run_id,proof.step_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered approval unavailable';END IF;
   END LOOP;
   IF a.approval_id IS NULL THEN RETURN 'legacy_or_missing';END IF;
   r:=a.run_id;
  ELSE r:=rid;END IF;
  SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  did:=rr.definition_id;
 END IF;
 SELECT * INTO d FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,did) FOR SHARE;
 -- Definition-wide evidence cannot claim an unrelated historical run version.
 claimed:=approval_claimed OR kind='definition' AND (COALESCE(d.body->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb,false)
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,did) AND definition->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb)
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND (event_kind='ordered_public_activated' AND body->>'definition_id'=did OR event_kind IN('ordered_public_triggered','ordered_public_activation_receipted') AND body->'request'->>'definition_id'=did))
  OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,did)))
  OR kind<>'definition' AND EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,did,rr.definition_version) AND definition->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb)
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'ordered_public_triggered'))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,operation,resource_id)=(o,w,e,'runSecurityAgent',r) AND response->'contract_version'='62'::jsonb)
  OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR kind='approval' AND EXISTS(SELECT 1 FROM public.zasp_security_agent_steps s JOIN public.zasp_sa_multistep_runs m USING(organization_id,workspace_id,environment_id,run_id) WHERE (s.organization_id,s.workspace_id,s.environment_id,s.step_id)=(o,w,e,a.step_id));
 IF NOT claimed THEN RETURN 'legacy_or_missing';END IF;
 IF kind='definition' THEN
 IF d.definition_id IS NULL OR d.deleted_at IS NOT NULL OR d.activation NOT IN('draft','supervised') OR d.version NOT BETWEEN 1 AND 1000000 OR d.definition_version NOT BETWEEN 1 AND 1000000 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered definition unavailable';END IF;
 -- Ownership persists after execution revocation; activation/trigger alone
 -- require the stricter live control, target and credential checks.
 BEGIN
  PERFORM zasp_ordered_public62.definition_shape(d,e,d.activation='supervised');
 EXCEPTION WHEN SQLSTATE '22023' OR SQLSTATE '42501' THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered persisted definition unavailable';
 END;
 SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,did,d.version) FOR SHARE;
 IF (d.activation='supervised' AND h.definition_id IS NULL) OR (h.definition_id IS NOT NULL AND (h.activation IS DISTINCT FROM d.activation OR h.definition IS DISTINCT FROM d.body OR h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256'))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered definition history unavailable';END IF;
 ELSE
  -- Runs and approvals retain the immutable version pinned at public trigger;
  -- later current-definition revisions or deletion cannot erase ownership.
  IF rr.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered run unavailable';END IF;
  IF EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN
   PERFORM zasp_sa_multistep_prior.cleanup_lock(o,w,e,r);
   PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,false);
   PERFORM zasp_ordered_public62.history(o,w,e,r);
   IF EXISTS(SELECT 1 FROM public.zasp_security_agent_steps s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id)=(o,w,e,r)
    AND (s.step_index=0 OR s.state IN('waiting_approval','authorized','executing','verifying','succeeded')
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id)=(o,w,e,r,s.step_id) AND x.body->'response'->>'approval_id'=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_approval',r||chr(31)||s.step_id)))
    AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id)=(o,w,e,r,s.step_id))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered required approval unavailable';END IF;
  ELSE PERFORM zasp_ordered_public62.project(o,w,e,r);END IF;
  SELECT * INTO trigger_audit FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'ordered_public_triggered');
  IF NOT zasp_sa_multistep_prior.closed(trigger_audit.body,ARRAY['request','response','trigger_digest','existing_test','definition_digest'])
   OR NOT zasp_sa_multistep_prior.closed(trigger_audit.body->'request',ARRAY['organization_id','workspace_id','environment_id','actor_id','operation','definition_id','definition_version','trigger_id','trigger_version','idempotency_key'])
   OR trigger_audit.body->'request'->>'operation' IS DISTINCT FROM 'trigger' OR trigger_audit.correlation_id IS DISTINCT FROM trigger_audit.audit_id
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.principal_id,x.operation,x.resource_id,x.audit_id,x.correlation_id)=(o,w,e,rr.requested_by,'runSecurityAgent',r,trigger_audit.audit_id,trigger_audit.audit_id)
    AND x.intent=trigger_audit.body->'request' AND x.idempotency_key=x.intent->>'idempotency_key'
    AND x.receipt_id=public.zasp_discovery_canonical_id(o,w,e,'public62_receipt',rr.requested_by||chr(31)||x.idempotency_key)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered trigger identity unavailable';END IF;
  IF kind='approval' AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id)=(o,w,e,r,a.step_id)
   AND s.step_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||s.step_index::text)
   AND a.approval_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_approval',r||chr(31)||s.step_id)
   AND s.step_index IN(0,1)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered approval unavailable';END IF;
 END IF;
 RETURN 'ordered_release61';
END $classify$;

-- Receipt classification is read-only and independent of today's definition.
-- It binds retained intent, not the caller's new intent; only the mutation may
-- compare intents and return replay/conflict. No receipt means current shape.
CREATE FUNCTION zasp_ordered_public62.classify_mutation(o text,w text,e text,actor text,kind text,did text,key_value text,tid text,tv bigint) RETURNS text
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $mutation_classify$
DECLARE prior public.zasp_security_agent_request_receipts%ROWTYPE;proof public.zasp_security_agent_audit%ROWTYPE;
 h public.zasp_security_agent_definition_versions%ROWTYPE;d public.zasp_security_agent_definitions%ROWTYPE;
 stored_op text;intent_op text;event_value text;a text;receipt text;v bigint;claimed boolean;keys text[];requested_run text;
BEGIN
 IF kind NOT IN('activate','trigger') OR key_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered mutation classification rejected';END IF;
 IF kind='activate' AND (tid IS NOT NULL OR tv IS NOT NULL) OR kind='trigger' AND NOT COALESCE(public.zasp_valid_product_id(did) AND public.zasp_valid_product_id(tid) AND tv BETWEEN 1 AND 1000000,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered mutation trigger identity rejected';END IF;
 stored_op:=CASE WHEN kind='activate' THEN 'activateSecurityAgent' ELSE 'runSecurityAgent' END;
 intent_op:=CASE WHEN kind='activate' THEN 'activate_resource' ELSE 'trigger' END;
 event_value:=CASE WHEN kind='activate' THEN 'ordered_public_activation_receipted' ELSE 'ordered_public_triggered' END;
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,stored_op,key_value) FOR SHARE;
 claimed:=EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,event_kind)=(o,w,e,event_value) AND (actor_id=actor OR body->'request'->>'actor_id'=actor) AND body->'request'->>'idempotency_key'=key_value);
 -- A missing receipt cannot erase an independently retained canonical claim.
 -- Activation's ID binds actor/key directly; trigger's does not, so its
 -- retained proof must still link this actor AND this exact key.
 IF kind='activate' THEN
  a:=public.zasp_discovery_canonical_id(o,w,e,'public62_mutation_audit',actor||chr(31)||'activate_resource'||chr(31)||key_value);
  SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,a) FOR SHARE;
  claimed:=claimed OR proof.audit_id IS NOT NULL;
 ELSE
  requested_run:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',did||chr(31)||tid||chr(31)||tv::text);
  a:=public.zasp_discovery_canonical_id(o,w,e,'public62_trigger',requested_run);
  claimed:=claimed OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit marker WHERE (marker.organization_id,marker.workspace_id,marker.environment_id)=(o,w,e)
   AND jsonb_typeof(marker.body->'request'->'idempotency_key')='string' AND marker.body->'request'->>'idempotency_key'=key_value
   AND (marker.actor_id=actor OR marker.body->'request'->>'actor_id'=actor OR EXISTS(SELECT 1 FROM public.zasp_security_agent_runs rr WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,rr.requested_by)=(o,w,e,requested_run,actor)))
   AND (marker.audit_id=a OR marker.run_id=requested_run AND (EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,requested_run))
    OR EXISTS(SELECT 1 FROM public.zasp_security_agent_runs rr JOIN public.zasp_security_agent_definition_versions history_row ON (history_row.organization_id,history_row.workspace_id,history_row.environment_id,history_row.definition_id,history_row.version)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.definition_id,rr.definition_version) WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id)=(o,w,e,requested_run) AND history_row.definition->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb))));
 END IF;
 IF prior.receipt_id IS NULL THEN
  IF claimed THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation receipt unavailable';END IF;
  RETURN zasp_ordered_public62.classify(o,w,e,'definition',did);
 END IF;
 -- Canonical persisted identities are claims even when all descriptive tags
 -- have been damaged. Recognizing a claim only forces validation below.
 IF NOT COALESCE(public.zasp_valid_product_id(prior.resource_id) AND public.zasp_valid_product_id(prior.receipt_id) AND public.zasp_valid_product_id(prior.audit_id) AND public.zasp_valid_product_id(prior.correlation_id),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation identities unavailable';END IF;
 IF kind='activate' THEN
  a:=public.zasp_discovery_canonical_id(o,w,e,'public62_mutation_audit',actor||chr(31)||'activate_resource'||chr(31)||key_value);
  receipt:=public.zasp_discovery_canonical_id(o,w,e,'public62_mutation_receipt',actor||chr(31)||'activate_resource'||chr(31)||key_value);
  claimed:=claimed OR COALESCE(prior.response->>'audit_id'=a OR prior.response->>'correlation_id'=a OR prior.response->>'receipt_id'=receipt,false);
 ELSE
  -- The ordered trigger wire retains run_id, not legacy's id field. A
  -- malformed retained claim refuses; it cannot erase ordered provenance.
  IF prior.response ? 'run_id' THEN
   IF jsonb_typeof(prior.response->'run_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(prior.response->>'run_id'),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation response identity unavailable';END IF;
   claimed:=true;
  END IF;
  a:=public.zasp_discovery_canonical_id(o,w,e,'public62_trigger',prior.resource_id);
  receipt:=public.zasp_discovery_canonical_id(o,w,e,'public62_receipt',actor||chr(31)||key_value);
  claimed:=claimed
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_runs rr JOIN public.zasp_security_agent_definition_versions history_row ON (history_row.organization_id,history_row.workspace_id,history_row.environment_id,history_row.definition_id,history_row.version)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.definition_id,rr.definition_version) WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id)=(o,w,e,prior.resource_id) AND history_row.definition->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb)
   OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,prior.resource_id))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,prior.resource_id,event_value));
 END IF;
 SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,a) FOR SHARE;
 claimed:=claimed OR prior.audit_id=a OR prior.correlation_id=a OR prior.receipt_id=receipt OR proof.audit_id IS NOT NULL;
 IF NOT claimed AND prior.response->'contract_version' IS DISTINCT FROM '62'::jsonb AND prior.intent->>'operation' IS DISTINCT FROM intent_op THEN RETURN zasp_ordered_public62.classify(o,w,e,'definition',did);END IF;
 keys:=ARRAY['organization_id','workspace_id','environment_id','actor_id','operation','definition_id','definition_version','idempotency_key'];
 keys:=keys||CASE WHEN kind='activate' THEN ARRAY['activation'] ELSE ARRAY['trigger_id','trigger_version'] END;
 IF NOT zasp_sa_multistep_prior.closed(prior.intent,keys)
  OR jsonb_typeof(prior.intent->'idempotency_key') IS DISTINCT FROM 'string'
  OR (prior.intent->>'organization_id',prior.intent->>'workspace_id',prior.intent->>'environment_id',prior.intent->>'actor_id',prior.intent->>'operation',prior.intent->>'idempotency_key') IS DISTINCT FROM (o,w,e,actor,intent_op,key_value)
  OR jsonb_typeof(prior.intent->'definition_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(prior.intent->>'definition_id'),false)
  OR jsonb_typeof(prior.intent->'definition_version') IS DISTINCT FROM 'number' OR NOT COALESCE(prior.intent->>'definition_version'~'^([1-9][0-9]{0,5}|1000000)$',false)
  OR prior.intent_digest IS DISTINCT FROM digest(convert_to(prior.intent::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation intent unavailable';END IF;
 v:=(prior.intent->>'definition_version')::bigint;
 IF prior.expected_version IS DISTINCT FROM v THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered mutation version unavailable';END IF;
 IF kind='activate' THEN
  SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,prior.intent->>'definition_id',v+1) FOR SHARE;
  IF v>=1000000 OR prior.intent->>'activation' IS DISTINCT FROM 'supervised' OR prior.resource_id IS DISTINCT FROM prior.intent->>'definition_id'
   OR (prior.audit_id,prior.correlation_id,prior.receipt_id) IS DISTINCT FROM (a,a,receipt)
   OR prior.response IS DISTINCT FROM jsonb_build_object('contract_version',62,'id',prior.resource_id,'activation','supervised','enabled',true,'version',v+1,'audit_id',a,'correlation_id',a,'receipt_id',receipt,'replayed',false)
   OR (proof.event_kind,proof.actor_id,proof.correlation_id) IS DISTINCT FROM (event_value,actor,a) OR proof.run_id IS NOT NULL OR proof.step_id IS NOT NULL
   OR proof.body IS DISTINCT FROM jsonb_build_object('request',prior.intent,'response',prior.response,'definition_digest',encode(h.definition_digest,'hex')) OR proof.event_digest IS DISTINCT FROM digest(convert_to(proof.body::text,'UTF8'),'sha256')
   OR h.definition_id IS NULL OR h.activation IS DISTINCT FROM 'supervised' OR h.actor_id IS DISTINCT FROM actor OR h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256')
   OR jsonb_typeof(h.definition->'definition_version') IS DISTINCT FROM 'number' OR NOT COALESCE(h.definition->>'definition_version'~'^([1-9][0-9]{0,5}|1000000)$',false)
   THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered activation ownership unavailable';END IF;
  d.definition_id:=h.definition_id;d.activation:=h.activation;d.body:=h.definition;d.definition_version:=(h.definition->>'definition_version')::bigint;d.plan_catalog_version:='security-agent-actions-v1';
  BEGIN PERFORM zasp_ordered_public62.definition_shape(d,e,true);
  EXCEPTION WHEN SQLSTATE '22023' OR SQLSTATE '42501' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered activation snapshot unavailable';END;
 ELSE
  IF (prior.audit_id,prior.correlation_id,prior.receipt_id) IS DISTINCT FROM (a,a,receipt)
   OR NOT zasp_sa_multistep_prior.closed(proof.body,ARRAY['request','response','trigger_digest','existing_test','definition_digest'])
   OR (proof.event_kind,proof.actor_id,proof.correlation_id,proof.run_id) IS DISTINCT FROM (event_value,actor,a,prior.resource_id)
   OR proof.body->'request' IS DISTINCT FROM prior.intent OR proof.body->'response' IS DISTINCT FROM prior.response
   OR jsonb_typeof(prior.intent->'trigger_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(prior.intent->>'trigger_id'),false)
   OR jsonb_typeof(prior.intent->'trigger_version') IS DISTINCT FROM 'number' OR NOT COALESCE(prior.intent->>'trigger_version'~'^([1-9][0-9]{0,5}|1000000)$',false)
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by)=(o,w,e,prior.resource_id,prior.intent->>'definition_id',v,actor)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered trigger ownership unavailable';END IF;
  PERFORM zasp_ordered_public62.history(o,w,e,prior.resource_id);
 END IF;
 RETURN 'ordered_release61';
END $mutation_classify$;

-- Ownership preflight for the legacy wire, which has no trigger version.
-- Retained ordered intent supplies identity only after a positive claim; all
-- ordered historical proof validation remains in classify_mutation.
CREATE FUNCTION zasp_ordered_public62.classify_trigger_key(o text,w text,e text,actor text,did text,key_value text) RETURNS text
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $trigger_key$
DECLARE prior public.zasp_security_agent_request_receipts%ROWTYPE;proof public.zasp_security_agent_audit%ROWTYPE;
 claimed boolean;receipt text;a text;family text;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(did),false) OR key_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered trigger classification rejected';END IF;
 receipt:=public.zasp_discovery_canonical_id(o,w,e,'public62_receipt',actor||chr(31)||key_value);
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,'runSecurityAgent',key_value) FOR SHARE;
 claimed:=EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.principal_id,x.receipt_id)=(o,w,e,actor,receipt))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit x WHERE (x.organization_id,x.workspace_id,x.environment_id)=(o,w,e)
   AND x.body->'request'->>'idempotency_key'=key_value
   AND ((x.actor_id=actor OR x.body->'request'->>'actor_id'=actor)
    AND (x.event_kind='ordered_public_triggered' OR x.body->'request'->>'operation'='trigger'
     AND zasp_sa_multistep_prior.closed(x.body->'request',ARRAY['organization_id','workspace_id','environment_id','actor_id','operation','definition_id','definition_version','trigger_id','trigger_version','idempotency_key']))
    OR CASE WHEN public.zasp_valid_product_id(x.run_id) THEN x.audit_id=public.zasp_discovery_canonical_id(o,w,e,'public62_trigger',x.run_id) ELSE false END
     AND EXISTS(SELECT 1 FROM public.zasp_security_agent_runs rr WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,rr.requested_by)=(o,w,e,x.run_id,actor))));
 IF prior.receipt_id IS NULL THEN
  IF claimed THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered trigger receipt unavailable';END IF;
  RETURN zasp_ordered_public62.classify(o,w,e,'definition',did);
 END IF;
 IF octet_length(prior.intent::text)>16384 OR octet_length(prior.response::text)>16384
  OR NOT COALESCE(public.zasp_valid_product_id(prior.resource_id) AND public.zasp_valid_product_id(prior.audit_id) AND public.zasp_valid_product_id(prior.correlation_id) AND public.zasp_valid_product_id(prior.receipt_id),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered trigger identities unavailable';END IF;
 a:=public.zasp_discovery_canonical_id(o,w,e,'public62_trigger',prior.resource_id);
 claimed:=claimed OR prior.audit_id=a OR prior.correlation_id=a OR prior.receipt_id=receipt OR prior.response ? 'run_id' OR prior.response ? 'contract_version' OR prior.intent ? 'operation'
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.audit_id)=(o,w,e,a))
  OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,prior.resource_id));
 IF claimed THEN
  IF NOT zasp_sa_multistep_prior.closed(prior.intent,ARRAY['organization_id','workspace_id','environment_id','actor_id','operation','definition_id','definition_version','trigger_id','trigger_version','idempotency_key'])
   OR jsonb_typeof(prior.intent->'trigger_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(prior.intent->>'trigger_id'),false)
   OR jsonb_typeof(prior.intent->'trigger_version') IS DISTINCT FROM 'number' OR NOT COALESCE(prior.intent->>'trigger_version'~'^([1-9][0-9]{0,5}|1000000)$',false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered trigger intent unavailable';END IF;
  family:=zasp_ordered_public62.classify_mutation(o,w,e,actor,'trigger',did,key_value,prior.intent->>'trigger_id',(prior.intent->>'trigger_version')::bigint);
  IF family IS DISTINCT FROM 'ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered trigger ownership unavailable';END IF;
  RETURN family;
 END IF;
 -- Only the authentic legacy contract can select legacy. Partial erasure is
 -- not a negative ownership proof, even when current definition is legacy.
 IF NOT zasp_sa_multistep_prior.closed(prior.intent,ARRAY['definition_id','expected_version','trigger_kind','trigger_id'])
  OR prior.resource_id IS DISTINCT FROM did OR prior.intent->'definition_id' IS DISTINCT FROM to_jsonb(did)
  OR prior.intent->'expected_version' IS DISTINCT FROM to_jsonb(prior.expected_version) OR prior.expected_version NOT BETWEEN 1 AND 1000000
  OR prior.intent->>'trigger_kind' NOT IN('finding','session') OR jsonb_typeof(prior.intent->'trigger_kind') IS DISTINCT FROM 'string'
  OR jsonb_typeof(prior.intent->'trigger_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(prior.intent->>'trigger_id'),false)
  OR prior.intent_digest IS DISTINCT FROM digest(convert_to(prior.intent::text,'UTF8'),'sha256') OR NOT isfinite(prior.expires_at) OR prior.expires_at<=clock_timestamp()
  OR NOT zasp_sa_multistep_prior.closed(prior.response,ARRAY['id','agent_id','state','evidence_ids','definition_version','version','audit_id','correlation_id','receipt_id','replayed'])
  OR jsonb_typeof(prior.response->'id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(prior.response->>'id'),false)
  OR jsonb_typeof(prior.response->'version') IS DISTINCT FROM 'number' OR NOT COALESCE(prior.response->>'version'~'^([1-9][0-9]{0,5}|1000000)$',false)
  OR jsonb_typeof(prior.response->'replayed') IS DISTINCT FROM 'boolean' OR prior.response->>'state' NOT IN('queued','planning','waiting_approval','running','verifying','contained','remediated','needs_human','failed','inconclusive','cancelled')
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered legacy intent unavailable';END IF;
 IF prior.response IS DISTINCT FROM jsonb_build_object('id',prior.response->>'id','agent_id',did,'state',prior.response->>'state','evidence_ids',jsonb_build_array(prior.intent->>'trigger_id'),'definition_version',prior.expected_version,'version',(prior.response->>'version')::bigint,'audit_id',prior.audit_id,'correlation_id',prior.correlation_id,'receipt_id',prior.receipt_id,'replayed',prior.response->'replayed')
  OR prior.audit_id=prior.correlation_id OR prior.audit_id=prior.receipt_id OR prior.correlation_id=prior.receipt_id THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered legacy response unavailable';END IF;
 SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,prior.audit_id) FOR SHARE;
 IF prior.intent->>'trigger_kind'='session' AND (
  jsonb_typeof(proof.body->'trigger_version') IS DISTINCT FROM 'number' OR NOT COALESCE(proof.body->>'trigger_version'~'^[1-9][0-9]{0,18}$',false)
  OR proof.body->'trigger_version'>'9223372036854775807'::jsonb
  OR jsonb_typeof(proof.body->'device_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(proof.body->>'device_id'),false)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered legacy session proof unavailable';END IF;
 IF proof.event_kind NOT IN('run_queued','run_deduplicated') OR proof.audit_id IS NULL
  OR NOT zasp_sa_multistep_prior.closed(proof.body,ARRAY['run_id','definition_id','definition_version','trigger_kind','trigger_id']||CASE WHEN prior.intent->>'trigger_kind'='session' THEN ARRAY['trigger_version','device_id'] ELSE ARRAY[]::text[] END)
  OR (proof.actor_id,proof.correlation_id,proof.run_id) IS DISTINCT FROM (actor,prior.correlation_id,prior.response->>'id')
  OR proof.body->'run_id' IS DISTINCT FROM prior.response->'id' OR proof.body->'definition_id' IS DISTINCT FROM to_jsonb(did) OR proof.body->'definition_version' IS DISTINCT FROM to_jsonb(prior.expected_version)
  OR proof.body->'trigger_id' IS DISTINCT FROM prior.intent->'trigger_id' OR proof.body->>'trigger_kind' IS DISTINCT FROM (CASE WHEN prior.intent->>'trigger_kind'='session' THEN 'runtime_decision' ELSE 'finding' END)
  OR prior.response->'replayed' IS DISTINCT FROM to_jsonb(proof.event_kind='run_deduplicated')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs rr JOIN public.zasp_security_agent_trigger_receipts tr ON (tr.organization_id,tr.workspace_id,tr.environment_id,tr.run_id,tr.definition_id,tr.trigger_id)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,rr.definition_id,rr.trigger_id)
   WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,rr.definition_id,rr.trigger_id)=(o,w,e,prior.response->>'id',did,prior.intent->>'trigger_id')
    AND (proof.event_kind='run_deduplicated' OR rr.definition_version=prior.expected_version) AND tr.trigger_digest=proof.event_digest AND tr.trigger_kind=proof.body->>'trigger_kind'
    AND (prior.intent->>'trigger_kind'<>'session' OR proof.body->'trigger_version'=to_jsonb(tr.trigger_version)
     AND EXISTS(SELECT 1 FROM public.zasp_runtime_gateway_events event WHERE (event.organization_id,event.workspace_id,event.environment_id,event.classification->>'session_id',event.device_id,event.sequence)=(o,w,e,tr.trigger_id,proof.body->>'device_id',tr.trigger_version)
      AND tr.trigger_digest=digest(convert_to(jsonb_build_object('kind','runtime_decision','session_id',tr.trigger_id,'device_id',event.device_id,'event_id',event.event_id,'sequence',event.sequence,'request_digest','sha256:'||encode(event.request_digest,'hex'))::text,'UTF8'),'sha256'))))
  OR zasp_ordered_public62.classify(o,w,e,'run',prior.response->>'id') IS DISTINCT FROM 'legacy_or_missing' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered legacy proof unavailable';END IF;
 RETURN 'legacy_or_missing';
END $trigger_key$;

-- Additional product metadata stays separate from the original closed detail
-- contract. It contains no actor, provider, lease, or raw receipt information.
CREATE FUNCTION zasp_ordered_public62.resource_run(o text,w text,e text,r text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $resource_run$
DECLARE base jsonb;rr public.zasp_security_agent_runs%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;
 a public.zasp_security_agent_approvals%ROWTYPE;s public.zasp_security_agent_steps%ROWTYPE;proof public.zasp_security_agent_audit%ROWTYPE;approvals jsonb:='[]';plan_value jsonb;
BEGIN
 IF zasp_ordered_public62.classify(o,w,e,'run',r)<>'ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
 base:=zasp_ordered_public62.project_core(o,w,e,r,true);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF NOT isfinite(rr.created_at) OR rr.created_at<'2000-01-01'::timestamptz OR rr.created_at>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered timestamp unavailable';END IF;
 IF (base->>'admitted')::boolean THEN
  SELECT * INTO p FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  IF NOT isfinite(p.expires_at) OR p.expires_at<=rr.created_at OR p.catalog_version<>'security-agent-actions-v1' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered plan unavailable';END IF;
  plan_value:=jsonb_build_object('plan_hash','sha256:'||encode(p.plan_hash,'hex'),'catalog_version',p.catalog_version,'expires_at',to_char(p.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  FOR s IN SELECT * FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_index LOOP
   SELECT * INTO a FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s.step_id);
   IF a.approval_id IS NULL THEN CONTINUE;END IF;
   IF a.plan_hash IS DISTINCT FROM p.plan_hash OR a.expires_at IS DISTINCT FROM p.expires_at OR a.requester_id IS DISTINCT FROM rr.requested_by OR NOT isfinite(a.created_at) OR a.created_at<rr.created_at OR a.created_at>clock_timestamp()+interval '5 seconds'
    OR a.version IS DISTINCT FROM (CASE WHEN a.state='pending' THEN 1::bigint ELSE 2::bigint END)
    OR a.state='pending' AND (a.approver_id IS NOT NULL OR a.decided_at IS NOT NULL OR a.fresh_auth_at IS NOT NULL)
    OR a.state IN('approved','rejected') AND (a.approver_id IS NULL OR a.approver_id=a.requester_id OR a.decided_at IS NULL OR a.fresh_auth_at IS NULL)
    THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered approval metadata unavailable';END IF;
   IF a.state IN('approved','rejected') THEN
    SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_transition',r||chr(31)||s.step_id||chr(31)||'ordered_approval_decided'));
    IF proof.audit_id IS NULL OR (proof.run_id,proof.step_id,proof.actor_id,proof.event_kind,proof.correlation_id) IS DISTINCT FROM (r,s.step_id,a.approver_id,'ordered_approval_decided',proof.audit_id)
     OR NOT zasp_sa_multistep_prior.closed(proof.body,ARRAY['contract_version','request','response']) OR proof.body->'contract_version' IS DISTINCT FROM '61'::jsonb
     OR proof.event_digest IS DISTINCT FROM digest(convert_to((proof.body->'request')::text,'UTF8'),'sha256')
     OR (proof.body->'request'->>'organization_id',proof.body->'request'->>'workspace_id',proof.body->'request'->>'environment_id',proof.body->'request'->>'run_id',proof.body->'request'->>'step_id',proof.body->'request'->>'actor_id',proof.body->'request'->>'operation') IS DISTINCT FROM (o,w,e,r,s.step_id,a.approver_id,CASE WHEN a.state='approved' THEN 'approve' ELSE 'reject' END)
     OR proof.body->'request'->'approval_version' IS DISTINCT FROM '1'::jsonb OR (proof.body->'request'->>'fresh_auth_at')::timestamptz IS DISTINCT FROM a.fresh_auth_at
     OR a.fresh_auth_at<a.decided_at-interval '5 minutes' OR a.fresh_auth_at>a.decided_at+interval '5 seconds'
     OR proof.body->'response'->>'approval_id' IS DISTINCT FROM a.approval_id OR proof.body->'response'->'approval_version' IS DISTINCT FROM to_jsonb(a.version)
     OR proof.body->'response'->>'step_state' IS DISTINCT FROM (CASE WHEN a.state='approved' THEN 'authorized' ELSE 'cancelled' END)
     OR proof.body->'response'->>'outcome' IS DISTINCT FROM (CASE WHEN a.state='approved' THEN 'approved' ELSE 'blocked' END)
     THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered approval decision proof unavailable';END IF;
   END IF;
   approvals:=approvals||jsonb_build_array(jsonb_build_object('id',a.approval_id,'run_id',r,'step_id',s.step_id,'state',a.state,'version',a.version,
    'expires_at',to_char(a.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'created_at',to_char(a.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'expected_effect',CASE WHEN s.step_index=0 THEN 'Apply temporary containment policy' ELSE 'Run existing test' END,'reversible',s.step_index=0,'ttl_seconds',CASE WHEN s.step_index=0 THEN (p.plan->'steps'->0->>'ttl_seconds')::integer ELSE 0 END));
  END LOOP;
 END IF;
 RETURN jsonb_build_object('contract_version',62,'ordered',base,'trigger_id',rr.trigger_id,'created_at',to_char(rr.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'plan',plan_value,'approvals',approvals);
END $resource_run$;

CREATE FUNCTION zasp_ordered_public62.activate_resource(c text,f text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $activate_resource$
DECLARE o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';actor text:=q->>'actor_id';
 d public.zasp_security_agent_definitions%ROWTYPE;prior public.zasp_security_agent_request_receipts%ROWTYPE;proof public.zasp_security_agent_audit%ROWTYPE;
 result_value jsonb;body_value jsonb;a text;receipt text;snapshot_digest text;v bigint:=(q->>'definition_version')::bigint;
BEGIN
 IF jsonb_typeof(q->'idempotency_key') IS DISTINCT FROM 'string' OR q->>'idempotency_key'!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered idempotency rejected';END IF;
 PERFORM 1 FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,q->>'definition_id') FOR UPDATE;
 a:=public.zasp_discovery_canonical_id(o,w,e,'public62_mutation_audit',actor||chr(31)||'activate_resource'||chr(31)||(q->>'idempotency_key'));
 receipt:=public.zasp_discovery_canonical_id(o,w,e,'public62_mutation_receipt',actor||chr(31)||'activate_resource'||chr(31)||(q->>'idempotency_key'));
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,'activateSecurityAgent',q->>'idempotency_key') FOR SHARE;
 IF FOUND THEN
  IF prior.intent IS DISTINCT FROM q OR prior.intent_digest IS DISTINCT FROM digest(convert_to(q::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='public ordered replay conflict';END IF;
  result_value:=prior.response;
  SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,a) FOR SHARE;
  snapshot_digest:=proof.body->>'definition_digest';
  IF (prior.resource_id,prior.expected_version,prior.audit_id,prior.correlation_id,prior.receipt_id) IS DISTINCT FROM (q->>'definition_id',v,a,a,receipt)
   OR (proof.event_kind,proof.actor_id,proof.correlation_id) IS DISTINCT FROM ('ordered_public_activation_receipted',actor,a)
   OR snapshot_digest IS NULL OR snapshot_digest!~'^[a-f0-9]{64}$'
   OR proof.body IS DISTINCT FROM jsonb_build_object('request',q,'response',result_value,'definition_digest',snapshot_digest) OR proof.event_digest IS DISTINCT FROM digest(convert_to(proof.body::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered activation history unavailable';END IF;
 ELSE
  IF q->>'activation' IS DISTINCT FROM 'supervised' OR v>=1000000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered activation rejected';END IF;
  d:=zasp_ordered_public62.definition(o,w,e,q->>'definition_id',v,false);
  IF NOT zasp_ordered_public62.ready(c,f) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered activation unavailable';END IF;
  UPDATE public.zasp_security_agent_definitions SET activation='supervised',version=version+1,body=body||jsonb_build_object('enabled',true),updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d.definition_id) RETURNING * INTO d;
  INSERT INTO public.zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) VALUES(o,w,e,d.definition_id,d.version,'supervised',d.body,digest(convert_to(d.body::text,'UTF8'),'sha256'),actor);
  result_value:=jsonb_build_object('contract_version',62,'id',d.definition_id,'activation','supervised','enabled',true,'version',d.version,'audit_id',a,'correlation_id',a,'receipt_id',receipt,'replayed',false);
  snapshot_digest:=encode(digest(convert_to(d.body::text,'UTF8'),'sha256'),'hex');
  body_value:=jsonb_build_object('request',q,'response',result_value,'definition_digest',snapshot_digest);
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,a,a,actor,'ordered_public_activation_receipted',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
  INSERT INTO public.zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id) VALUES(o,w,e,actor,'activateSecurityAgent',q->>'idempotency_key',d.definition_id,v,q,digest(convert_to(q::text,'UTF8'),'sha256'),result_value,a,a,receipt);
 END IF;
 IF q->>'activation' IS DISTINCT FROM 'supervised' OR v>=1000000 OR result_value IS DISTINCT FROM jsonb_build_object('contract_version',62,'id',q->>'definition_id','activation','supervised','enabled',true,'version',v+1,'audit_id',a,'correlation_id',a,'receipt_id',receipt,'replayed',false)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions h WHERE (h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version,h.activation,h.actor_id)=(o,w,e,q->>'definition_id',v+1,'supervised',actor) AND h.definition_digest=digest(convert_to(h.definition::text,'UTF8'),'sha256') AND encode(h.definition_digest,'hex')=snapshot_digest AND h.definition->'enabled'='true'::jsonb AND h.definition->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb)
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered activation evidence unavailable';END IF;
 RETURN result_value||jsonb_build_object('replayed',prior.receipt_id IS NOT NULL);
END $activate_resource$;

-- A single descending keyset across the shared tables. This authority exposes
-- identities only: classification and semantic reads remain separate gates.
CREATE FUNCTION zasp_ordered_public62.candidates(q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $candidates$
DECLARE o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';op text:=q->>'operation';
 filter_value text:=q->>'resource_filter';state_value text:=q->>'state_filter';before_value timestamptz;limit_value integer;items_value jsonb;next_time text:='';next_id text:='';k text;
BEGIN
 FOREACH k IN ARRAY ARRAY['resource_filter','state_filter','before_created_at','before_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public candidate page rejected';END IF;
 END LOOP;
 IF jsonb_typeof(q->'limit') IS DISTINCT FROM 'number' OR NOT COALESCE(q->>'limit'~'^([1-9][0-9]?|100)$',false)
  OR filter_value<>'' AND NOT COALESCE(public.zasp_valid_product_id(filter_value),false)
  OR (q->>'before_created_at'='')<>(q->>'before_id'='')
  OR q->>'before_id'<>'' AND NOT COALESCE(public.zasp_valid_product_id(q->>'before_id'),false)
  OR state_value<>'' AND (op='run_candidates' AND state_value NOT IN('queued','planning','waiting_approval','running','verifying','contained','remediated','needs_human','failed','inconclusive','cancelled')
   OR op='approval_candidates' AND state_value NOT IN('pending','approved','rejected','cancelled','expired')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public candidate page rejected';END IF;
 limit_value:=(q->>'limit')::integer;
 IF q->>'before_created_at'<>'' THEN
  IF q->>'before_created_at'!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public candidate cursor rejected';END IF;
  BEGIN before_value:=(q->>'before_created_at')::timestamptz;EXCEPTION WHEN datetime_field_overflow OR invalid_datetime_format THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public candidate cursor rejected';END;
  IF to_char(before_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')<>q->>'before_created_at' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public candidate cursor rejected';END IF;
 END IF;
 WITH candidates AS MATERIALIZED (
  SELECT x.run_id AS id,x.created_at FROM public.zasp_security_agent_runs x
   WHERE op='run_candidates' AND (x.organization_id,x.workspace_id,x.environment_id)=(o,w,e) AND x.state<>'simulated'
   AND (filter_value='' OR x.definition_id=filter_value) AND (state_value='' OR x.state=state_value)
   AND (before_value IS NULL OR (x.created_at,x.run_id)<(before_value,q->>'before_id'))
  UNION ALL
  SELECT x.approval_id AS id,x.created_at FROM public.zasp_security_agent_approvals x
   JOIN public.zasp_security_agent_runs r ON (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)
   WHERE op='approval_candidates' AND (x.organization_id,x.workspace_id,x.environment_id)=(o,w,e)
   AND (filter_value='' OR x.run_id=filter_value) AND (state_value='' OR x.state=state_value)
   AND (before_value IS NULL OR (x.created_at,x.approval_id)<(before_value,q->>'before_id'))
  ORDER BY created_at DESC,id DESC LIMIT limit_value+1
 ), numbered AS (SELECT *,row_number() OVER(ORDER BY created_at DESC,id DESC) AS ordinal FROM candidates)
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY created_at DESC,id DESC) FILTER(WHERE ordinal<=limit_value),'[]'::jsonb),
  COALESCE(max(to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FILTER(WHERE ordinal=limit_value AND (SELECT count(*) FROM candidates)>limit_value),''),
  COALESCE(max(id) FILTER(WHERE ordinal=limit_value AND (SELECT count(*) FROM candidates)>limit_value),'')
 INTO items_value,next_time,next_id FROM numbered;
 RETURN jsonb_build_object('contract_version',62,'organization_id',o,'workspace_id',w,'environment_id',e,'operation',op,'items',items_value,'next_created_at',next_time,'next_id',next_id);
END $candidates$;

CREATE FUNCTION zasp_ordered_public62.api(c text,f text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $api$
DECLARE o text;w text;e text;actor text;op text;k text;keys text[];d public.zasp_security_agent_definitions%ROWTYPE;
 prior public.zasp_security_agent_request_receipts%ROWTYPE;r text;a text;receipt_id text;evidence jsonb;result_value jsonb;audit_body jsonb;items jsonb:='[]';item record;next_value text;
 inner_q jsonb;inner_result jsonb;resource_value jsonb;was_replay boolean;approval_row public.zasp_security_agent_approvals%ROWTYPE;run_row public.zasp_security_agent_runs%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='public ordered requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 PERFORM 1 FROM zasp_ordered_public62.registration FOR SHARE;
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered principal rejected';END IF;
 IF NOT COALESCE(zasp_ordered_public62.ready(c,f),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public ordered release unavailable';END IF;
 IF q IS NULL OR octet_length(q::text)>16384 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered request rejected';END IF;
 IF q->>'operation'='deployment_ready' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['operation']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered deployment request rejected';END IF;
  IF NOT COALESCE(zasp_ordered_public62.ready(c,f),false) OR NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public ordered deployment unavailable';END IF;
  RETURN jsonb_build_object('contract_version',62,'ready',true);
 END IF;
 op:=q->>'operation';keys:=ARRAY['organization_id','workspace_id','environment_id','actor_id','operation'];
 CASE op WHEN 'ready' THEN NULL; WHEN 'activate' THEN keys:=keys||ARRAY['definition_id','definition_version'];
 WHEN 'resource_activation' THEN keys:=keys||ARRAY['definition_id'];
 WHEN 'classify_mutation' THEN keys:=keys||ARRAY['mutation_kind','definition_id','idempotency_key'];IF q->>'mutation_kind'='trigger' THEN keys:=keys||ARRAY['trigger'];END IF;
 WHEN 'classify_trigger_key' THEN keys:=keys||ARRAY['definition_id','idempotency_key'];
 WHEN 'activate_resource' THEN keys:=keys||ARRAY['definition_id','definition_version','activation','idempotency_key'];
 WHEN 'trigger_resource' THEN keys:=keys||ARRAY['definition_id','definition_version','trigger_id','trigger_version','trigger_kind','trigger_source','idempotency_key'];
 WHEN 'resource_run' THEN keys:=keys||ARRAY['run_id'];
 WHEN 'resource_approval' THEN keys:=keys||ARRAY['approval_id'];
 WHEN 'decide_resource' THEN keys:=keys||ARRAY['approval_id','approval_version','decision','fresh_auth_at','idempotency_key'];
 WHEN 'trigger' THEN keys:=keys||ARRAY['definition_id','definition_version','trigger_id','trigger_version','idempotency_key'];
 WHEN 'decide' THEN keys:=keys||ARRAY['run_id','run_version','approval_id','approval_version','decision','fresh_auth_at','idempotency_key'];
 WHEN 'cancel' THEN keys:=keys||ARRAY['run_id','run_version','idempotency_key'];
 WHEN 'detail' THEN keys:=keys||ARRAY['run_id'];
 WHEN 'classify' THEN keys:=keys||ARRAY['resource_kind','resource_id'];
 WHEN 'list' THEN keys:=keys||ARRAY['limit','after_run_id'];
 WHEN 'run_candidates','approval_candidates' THEN keys:=keys||ARRAY['resource_filter','state_filter','limit','before_created_at','before_id'];
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered operation rejected';END CASE;
 IF NOT zasp_sa_multistep_prior.closed(q,keys) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','actor_id','definition_id','trigger_id','run_id','approval_id','resource_id'] LOOP
  IF q ? k AND (jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered identity rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['definition_version','trigger_version','run_version','approval_version'] LOOP
  IF q ? k AND (jsonb_typeof(q->k) IS DISTINCT FROM 'number' OR (q->>k)!~'^([1-9][0-9]{0,5}|1000000)$') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered version rejected';END IF;
 END LOOP;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';actor:=q->>'actor_id';
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM zasp_ordered_public62.authorize(o,w,e,actor,op IN('activate','trigger','decide','cancel','activate_resource','trigger_resource','decide_resource'));
 IF op='ready' THEN result_value:=jsonb_build_object('contract_version',62,'ready',true);
 ELSIF op IN('run_candidates','approval_candidates') THEN result_value:=zasp_ordered_public62.candidates(q);
 ELSIF op='resource_activation' THEN
  IF zasp_ordered_public62.classify(o,w,e,'definition',q->>'definition_id')<>'ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
  SELECT * INTO d FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,q->>'definition_id');
  result_value:=jsonb_build_object('contract_version',62,'id',d.definition_id,'activation',d.activation,'enabled',d.body->'enabled','version',d.version);
 ELSIF op='classify_trigger_key' THEN
  IF jsonb_typeof(q->'idempotency_key') IS DISTINCT FROM 'string' OR q->>'idempotency_key'!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered trigger classification rejected';END IF;
  result_value:=jsonb_build_object('contract_version',62,'definition_id',q->>'definition_id','idempotency_key',q->>'idempotency_key','family',zasp_ordered_public62.classify_trigger_key(o,w,e,actor,q->>'definition_id',q->>'idempotency_key'));
 ELSIF op='classify_mutation' THEN
  IF jsonb_typeof(q->'mutation_kind') IS DISTINCT FROM 'string' OR q->>'mutation_kind' NOT IN('activate','trigger') OR jsonb_typeof(q->'idempotency_key') IS DISTINCT FROM 'string' OR q->>'idempotency_key'!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered mutation classification rejected';END IF;
  IF q->>'mutation_kind'='trigger' THEN
   IF NOT zasp_sa_multistep_prior.closed(q->'trigger',ARRAY['trigger_id','trigger_version']) OR jsonb_typeof(q->'trigger'->'trigger_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->'trigger'->>'trigger_id'),false) OR jsonb_typeof(q->'trigger'->'trigger_version') IS DISTINCT FROM 'number' OR NOT COALESCE(q->'trigger'->>'trigger_version'~'^([1-9][0-9]{0,5}|1000000)$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered mutation trigger identity rejected';END IF;
  END IF;
  result_value:=jsonb_build_object('contract_version',62,'mutation_kind',q->>'mutation_kind','definition_id',q->>'definition_id','idempotency_key',q->>'idempotency_key','trigger',q->'trigger','family',zasp_ordered_public62.classify_mutation(o,w,e,actor,q->>'mutation_kind',q->>'definition_id',q->>'idempotency_key',q->'trigger'->>'trigger_id',(q->'trigger'->>'trigger_version')::bigint));
 ELSIF op='activate_resource' THEN
  IF zasp_ordered_public62.classify_mutation(o,w,e,actor,'activate',q->>'definition_id',q->>'idempotency_key',NULL,NULL)<>'ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
  result_value:=zasp_ordered_public62.activate_resource(c,f,q);
 ELSIF op='resource_run' THEN result_value:=zasp_ordered_public62.resource_run(o,w,e,q->>'run_id');
 ELSIF op='resource_approval' THEN
  IF zasp_ordered_public62.classify(o,w,e,'approval',q->>'approval_id')<>'ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
  SELECT * INTO approval_row FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,approval_id)=(o,w,e,q->>'approval_id');
  result_value:=zasp_ordered_public62.resource_run(o,w,e,approval_row.run_id);
 ELSIF op='trigger_resource' THEN
  IF zasp_ordered_public62.classify_mutation(o,w,e,actor,'trigger',q->>'definition_id',q->>'idempotency_key',q->>'trigger_id',(q->>'trigger_version')::bigint)<>'ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
  SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,'runSecurityAgent',q->>'idempotency_key') FOR SHARE;
  was_replay:=FOUND;
  SELECT definition INTO evidence FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,q->>'definition_id',(q->>'definition_version')::bigint) FOR SHARE;
  IF jsonb_typeof(q->'trigger_kind') IS DISTINCT FROM 'string' OR jsonb_typeof(q->'trigger_source') IS DISTINCT FROM 'string' OR q->'trigger_kind' IS DISTINCT FROM evidence->'trigger_kind' OR q->'trigger_source' IS DISTINCT FROM evidence->'trigger_source' THEN
   IF was_replay THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='public ordered replay conflict';END IF;
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered trigger rejected';END IF;
  inner_q:=(q-'trigger_kind'-'trigger_source')||jsonb_build_object('operation','trigger');
  inner_result:=zasp_ordered_public62.api(c,f,inner_q);r:=inner_result->>'run_id';
  IF zasp_ordered_public62.classify(o,w,e,'run',r)<>'ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered trigger unavailable';END IF;
  SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,'runSecurityAgent',q->>'idempotency_key');
  result_value:=jsonb_build_object('contract_version',62,'id',r,'agent_id',inner_result->>'definition_id','definition_version',inner_result->'definition_version','state',inner_result->>'state','version',inner_result->'version','evidence_ids',jsonb_build_array(q->>'trigger_id'),'audit_id',prior.audit_id,'correlation_id',prior.correlation_id,'receipt_id',prior.receipt_id,'replayed',was_replay);
 ELSIF op='decide_resource' THEN
  IF zasp_ordered_public62.classify(o,w,e,'approval',q->>'approval_id')<>'ordered_release61' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
  SELECT * INTO approval_row FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,approval_id)=(o,w,e,q->>'approval_id');
  SELECT * INTO run_row FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,approval_row.run_id);
  SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,'decideSecurityAgentApproval',q->>'idempotency_key') FOR SHARE;
  inner_q:=q||jsonb_build_object('operation','decide','run_id',approval_row.run_id,'run_version',CASE WHEN prior.receipt_id IS NULL THEN run_row.version ELSE prior.expected_version END);
  inner_result:=zasp_ordered_public62.api(c,f,inner_q);
  result_value:=jsonb_build_object('mutation',inner_result,'resource',zasp_ordered_public62.resource_run(o,w,e,approval_row.run_id));
 ELSIF op='classify' THEN
  IF jsonb_typeof(q->'resource_kind') IS DISTINCT FROM 'string' OR q->>'resource_kind' NOT IN('definition','run','approval') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered resource kind rejected';END IF;
  result_value:=jsonb_build_object('contract_version',62,'resource_kind',q->>'resource_kind','resource_id',q->>'resource_id','family',zasp_ordered_public62.classify(o,w,e,q->>'resource_kind',q->>'resource_id'));
 ELSIF op IN('decide','cancel') THEN result_value:=zasp_ordered_public62.mutate(c,f,q);
 ELSIF op='detail' THEN result_value:=zasp_ordered_public62.project(o,w,e,q->>'run_id');
 ELSIF op='list' THEN
  IF jsonb_typeof(q->'limit') IS DISTINCT FROM 'number' OR (q->>'limit')!~'^([1-9]|10)$' OR jsonb_typeof(q->'after_run_id') IS DISTINCT FROM 'string'
   OR q->>'after_run_id'<>'' AND NOT COALESCE(public.zasp_valid_product_id(q->>'after_run_id'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered page rejected';END IF;
  FOR item IN SELECT x.run_id FROM public.zasp_security_agent_runs x JOIN public.zasp_security_agent_definitions definition_item USING(organization_id,workspace_id,environment_id,definition_id)
   LEFT JOIN public.zasp_security_agent_definition_versions historical ON (historical.organization_id,historical.workspace_id,historical.environment_id,historical.definition_id,historical.version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version)
   WHERE (x.organization_id,x.workspace_id,x.environment_id)=(o,w,e) AND x.run_id>q->>'after_run_id' AND (definition_item.body->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb OR historical.definition->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb
    OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.event_kind)=(o,w,e,x.run_id,'ordered_public_triggered'))) ORDER BY x.run_id LIMIT (q->>'limit')::integer+1 LOOP
   PERFORM zasp_ordered_public62.history(o,w,e,item.run_id);
   IF jsonb_array_length(items)=(q->>'limit')::integer THEN next_value:=items->-1->>'run_id';EXIT;END IF;
   items:=items||jsonb_build_array(zasp_ordered_public62.project(o,w,e,item.run_id));
  END LOOP;
  result_value:=jsonb_build_object('contract_version',62,'items',items,'next_after_run_id',next_value);
 ELSIF op='activate' THEN
  PERFORM 1 FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,q->>'definition_id') FOR UPDATE;
  d:=zasp_ordered_public62.definition(o,w,e,q->>'definition_id',(q->>'definition_version')::bigint,false);
  IF d.version>=1000000 OR NOT zasp_ordered_public62.ready(c,f) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered activation changed';END IF;
  UPDATE public.zasp_security_agent_definitions SET activation='supervised',version=version+1,body=body||jsonb_build_object('enabled',true),updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d.definition_id) RETURNING * INTO d;
  INSERT INTO public.zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) VALUES(o,w,e,d.definition_id,d.version,'supervised',d.body,digest(convert_to(d.body::text,'UTF8'),'sha256'),actor);
  result_value:=jsonb_build_object('contract_version',62,'definition_id',d.definition_id,'definition_version',d.version,'activation','supervised');
  a:=public.zasp_discovery_canonical_id(o,w,e,'public62_activation',d.definition_id||chr(31)||d.version::text);
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,a,a,actor,'ordered_public_activated',digest(convert_to(result_value::text,'UTF8'),'sha256'),result_value);
 ELSE
  IF jsonb_typeof(q->'idempotency_key') IS DISTINCT FROM 'string' OR length(q->>'idempotency_key') NOT BETWEEN 16 AND 128 OR (q->>'idempotency_key')!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public ordered idempotency rejected';END IF;
  SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,'runSecurityAgent',q->>'idempotency_key') FOR SHARE;
  IF FOUND THEN
   IF prior.intent IS DISTINCT FROM q OR prior.intent_digest IS DISTINCT FROM digest(convert_to(q::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='public ordered replay conflict';END IF;
   IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by)=(o,w,e,prior.resource_id,q->>'definition_id',(q->>'definition_version')::bigint,actor)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered replay unavailable';END IF;
   r:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',(q->>'definition_id')||chr(31)||(q->>'trigger_id')||chr(31)||(q->>'trigger_version'));
   result_value:=jsonb_build_object('contract_version',62,'run_id',r,'definition_id',q->>'definition_id','definition_version',(q->>'definition_version')::bigint,'state','queued','version',1);
   IF prior.resource_id IS DISTINCT FROM r OR prior.expected_version IS DISTINCT FROM (q->>'definition_version')::bigint OR prior.response IS DISTINCT FROM result_value
    OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit history JOIN public.zasp_security_agent_trigger_receipts tr USING(organization_id,workspace_id,environment_id,run_id)
     JOIN public.zasp_security_agent_definition_versions versioned ON (versioned.organization_id,versioned.workspace_id,versioned.environment_id,versioned.definition_id,versioned.version)=(o,w,e,q->>'definition_id',(q->>'definition_version')::bigint)
     WHERE (history.organization_id,history.workspace_id,history.environment_id,history.run_id,history.actor_id,history.event_kind)=(o,w,e,r,actor,'ordered_public_triggered')
      AND history.audit_id=prior.audit_id AND history.body->'request'=q AND history.body->'response'=result_value AND history.event_digest=digest(convert_to(history.body::text,'UTF8'),'sha256')
      AND history.body->'trigger_digest'=to_jsonb(encode(tr.trigger_digest,'hex')) AND tr.trigger_version=(q->>'trigger_version')::bigint AND tr.trigger_id=q->>'trigger_id'
      AND history.body->'existing_test'=versioned.definition->'existing_test' AND versioned.definition_digest=digest(convert_to(versioned.definition::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered replay authority changed';END IF;
  ELSE
   d:=zasp_ordered_public62.definition(o,w,e,q->>'definition_id',(q->>'definition_version')::bigint,true);
   IF d.body->>'trigger_kind'='finding' THEN SELECT to_jsonb(x) INTO evidence FROM public.zasp_risk_findings x WHERE (organization_id,workspace_id,environment_id,id,version,status,rule)=(o,w,e,q->>'trigger_id',(q->>'trigger_version')::bigint,'open',d.body->>'trigger_source') FOR SHARE;
   ELSE SELECT to_jsonb(x) INTO evidence FROM public.zasp_risk_attack_paths x WHERE (organization_id,workspace_id,environment_id,id,version,state)=(o,w,e,q->>'trigger_id',(q->>'trigger_version')::bigint,d.body->>'trigger_source') AND state IN('observed','verified') AND public.zasp_risk_attack_path_valid(x) FOR SHARE;END IF;
   IF evidence IS NULL OR octet_length(evidence::text)>65536 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='public ordered object unavailable';END IF;
   r:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',d.definition_id||chr(31)||(q->>'trigger_id')||chr(31)||(q->>'trigger_version'));
   a:=public.zasp_discovery_canonical_id(o,w,e,'public62_trigger',r);receipt_id:=public.zasp_discovery_canonical_id(o,w,e,'public62_receipt',actor||chr(31)||(q->>'idempotency_key'));
   IF NOT zasp_ordered_public62.ready(c,f) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered trigger changed';END IF;
   INSERT INTO public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES(o,w,e,r,d.definition_id,d.version,q->>'trigger_id',actor,'queued');
   INSERT INTO public.zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) VALUES(o,w,e,d.definition_id,q->>'trigger_id',d.body->>'trigger_kind',(q->>'trigger_version')::bigint,digest(convert_to(evidence::text,'UTF8'),'sha256'),r);
   PERFORM zasp_sa_multistep_prior.context(o,w,e,r);
   result_value:=jsonb_build_object('contract_version',62,'run_id',r,'definition_id',d.definition_id,'definition_version',d.version,'state','queued','version',1);
   audit_body:=jsonb_build_object('request',q,'response',result_value,'trigger_digest',encode(digest(convert_to(evidence::text,'UTF8'),'sha256'),'hex'),'existing_test',d.body->'existing_test','definition_digest',encode(digest(convert_to(d.body::text,'UTF8'),'sha256'),'hex'));
   INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,a,a,r,actor,'ordered_public_triggered',digest(convert_to(audit_body::text,'UTF8'),'sha256'),audit_body);
   INSERT INTO public.zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id) VALUES(o,w,e,actor,'runSecurityAgent',q->>'idempotency_key',r,d.version,q,digest(convert_to(q::text,'UTF8'),'sha256'),result_value,a,a,receipt_id);
  END IF;
 END IF;
 IF op='trigger' THEN PERFORM zasp_ordered_public62.history(o,w,e,r);END IF;
 IF result_value IS NULL OR octet_length(result_value::text)>65536 OR NOT zasp_ordered_public62.ready(c,f) OR NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public ordered authority changed';END IF;
 RETURN result_value;
END $api$;

DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_ordered_public62'::regnamespace LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);END LOOP;
END $owners$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zasp_ordered_public62 FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_ordered_public62 TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_ordered_public62.api(text,text,jsonb) TO zasp_security_agent_api;
