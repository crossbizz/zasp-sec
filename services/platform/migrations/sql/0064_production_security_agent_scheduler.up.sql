-- Separate successor authority. Predecessor source and registration stay intact.
SET LOCAL lock_timeout='3s';
SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));
DO $predecessor$
BEGIN
 IF NOT COALESCE(zasp_ordered_worker63.ready('-- worker63 checksum','-- worker63 fingerprint'),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler predecessor unavailable';END IF;
END $predecessor$;
CREATE SCHEMA zasp_ordered_scheduler64 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_ordered_scheduler64 FROM PUBLIC;
CREATE TABLE zasp_ordered_scheduler64.registration (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),
 fingerprint text NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$')
);
ALTER TABLE zasp_ordered_scheduler64.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_ordered_scheduler64.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_ordered_scheduler64.registration FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_ordered_scheduler64.registration USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_ordered_scheduler64.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_sa_multistep_prior.immutable_admission();
REVOKE ALL ON zasp_ordered_scheduler64.registration FROM PUBLIC;
CREATE TABLE zasp_ordered_scheduler64.schedule_leases (
 schedule_id text PRIMARY KEY CHECK(public.zasp_valid_product_id(schedule_id)),
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 worker_id text NOT NULL,token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
 action_worker_id text NOT NULL,action_token_digest bytea NOT NULL CHECK(octet_length(action_token_digest)=32),
 deployment_worker_id text NOT NULL,deployment_token_digest bytea NOT NULL CHECK(octet_length(deployment_token_digest)=32),
 version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 1000000),
 state text NOT NULL CHECK(state IN('active','recovery_deferred','expired','reconciled')),
 lease_expires_at timestamptz NOT NULL,
 request jsonb NOT NULL CHECK(octet_length(request::text)<=4096),
 item jsonb NOT NULL CHECK(octet_length(item::text)<=4096),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 evidence_digest bytea NOT NULL CHECK(octet_length(evidence_digest)=32),
 UNIQUE(worker_id,token_digest),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id)
);
CREATE UNIQUE INDEX schedule_owner ON zasp_ordered_scheduler64.schedule_leases(organization_id,workspace_id,environment_id,run_id) WHERE state IN('active','recovery_deferred');
ALTER TABLE zasp_ordered_scheduler64.schedule_leases OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_ordered_scheduler64.schedule_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_ordered_scheduler64.schedule_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_ordered_scheduler64.schedule_leases USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON zasp_ordered_scheduler64.schedule_leases FROM PUBLIC;
CREATE FUNCTION zasp_ordered_scheduler64.evidence_digest(d zasp_ordered_scheduler64.schedule_leases) RETURNS bytea
 LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $evidence$
 SELECT digest(convert_to(((to_jsonb(d)-ARRAY['state','evidence_digest','created_at','lease_expires_at'])||jsonb_build_object('created_at',to_char(d.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'lease_expires_at',to_char(d.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')))::text,'UTF8'),'sha256')
$evidence$;
CREATE FUNCTION zasp_ordered_scheduler64.retain_binding() RETURNS trigger
 LANGUAGE plpgsql SET search_path TO pg_catalog,public AS $binding$
BEGIN
 IF TG_OP='INSERT' THEN
  NEW.evidence_digest:=zasp_ordered_scheduler64.evidence_digest(NEW);
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' OR OLD.state='reconciled' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler evidence immutable';END IF;
 IF OLD.evidence_digest IS DISTINCT FROM zasp_ordered_scheduler64.evidence_digest(OLD) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler evidence changed';END IF;
 IF NEW.state='reconciled' THEN
  IF (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state') OR OLD.state IN('expired','recovery_deferred') AND NOT zasp_ordered_scheduler64.clean_terminal(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.run_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler reconciliation unavailable';END IF;
  RETURN NEW;
 END IF;
 IF OLD.state='expired' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler evidence immutable';END IF;
 IF (to_jsonb(NEW)-ARRAY['version','state','lease_expires_at','item']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','state','lease_expires_at','item'])
  OR NEW.version<>OLD.version+1
  OR (NEW.item-ARRAY['run_version','state','state_class','schedule_version','lease_expires_at']) IS DISTINCT FROM (OLD.item-ARRAY['run_version','state','state_class','schedule_version','lease_expires_at'])
  OR NEW.state='active' AND (OLD.state<>'active' OR NEW.item->'schedule_version' IS DISTINCT FROM to_jsonb(NEW.version) OR NEW.item->>'lease_expires_at' IS DISTINCT FROM to_char(NEW.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
  OR NEW.state='recovery_deferred' AND (OLD.state<>'active' OR NEW.item IS DISTINCT FROM OLD.item OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at)
  OR NEW.state='expired' AND (OLD.lease_expires_at>clock_timestamp() OR NEW.item IS DISTINCT FROM OLD.item OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler binding immutable';END IF;
 NEW.evidence_digest:=zasp_ordered_scheduler64.evidence_digest(NEW);
 RETURN NEW;
END $binding$;
CREATE TRIGGER retain_binding BEFORE INSERT OR UPDATE OR DELETE ON zasp_ordered_scheduler64.schedule_leases FOR EACH ROW EXECUTE FUNCTION zasp_ordered_scheduler64.retain_binding();
CREATE FUNCTION zasp_ordered_scheduler64.fingerprint() RETURNS text
 LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_ordered_scheduler64'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(pg_get_functiondef(p.oid),'-- scheduler64 checksum','<extension-checksum>'),'-- scheduler64 fingerprint','<extension-fingerprint>')) FROM pg_proc p WHERE p.pronamespace='zasp_ordered_scheduler64'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='zasp_ordered_scheduler64'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_ordered_scheduler64'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_ordered_scheduler64'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_ordered_scheduler64'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_ordered_scheduler64'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_ordered_scheduler64'::regnamespace
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION zasp_ordered_scheduler64.ready(c text,f text) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- scheduler64 checksum' AND f='-- scheduler64 fingerprint'
 AND zasp_ordered_worker63.ready('-- worker63 checksum','-- worker63 fingerprint')
 AND zasp_ordered_public62.ready('-- public62 checksum','-- public62 fingerprint')
 AND public.zasp_sa_multistep_readiness('-- release61 checksum','-- release61 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_ordered_scheduler64.registration)
 AND EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.registration WHERE singleton AND checksum=c AND fingerprint=f)
 AND zasp_ordered_scheduler64.fingerprint()=f,false)
$ready$;
-- Read and validate through the reviewed authorities, never reconstruct their
-- decision evidence. This result stays owner-private and is not a wire shape.
CREATE FUNCTION zasp_ordered_scheduler64.terminal_evidence(o text,w text,e text,r text,rr public.zasp_security_agent_runs,s jsonb) RETURNS boolean
 LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $terminal$
BEGIN
 RETURN EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id)=(o,w,e,r)
  AND a.body->'response'->>'run_state'=rr.state AND a.body->'response'->'run_version'=to_jsonb(rr.version)
  AND (a.event_kind='ordered_cleanup_complete' AND s->'cleanup'->>'state'='cleaned'
   OR a.event_kind IN('ordered_run_cancelled','ordered_approval_decided','ordered_step_ready') AND a.body->'contract_version'='61'::jsonb AND a.body->'response'->'contract_version'='61'::jsonb
    AND (a.body->'request'->>'organization_id',a.body->'request'->>'workspace_id',a.body->'request'->>'environment_id',a.body->'request'->>'run_id',a.body->'request'->>'step_id',a.body->'request'->>'actor_id')=(o,w,e,r,a.step_id,a.actor_id)
    AND (a.body->'response'->>'organization_id',a.body->'response'->>'workspace_id',a.body->'response'->>'environment_id',a.body->'response'->>'run_id',a.body->'response'->>'step_id',a.body->'response'->>'outcome')=(o,w,e,r,a.step_id,'blocked')
    AND (a.event_kind='ordered_run_cancelled' AND a.body->'request'->>'operation'='cancel' AND rr.state='cancelled' OR a.event_kind='ordered_approval_decided' AND a.body->'request'->>'operation'='reject' AND rr.state='needs_human' OR a.event_kind='ordered_step_ready' AND a.body->'request'->>'operation' IN('progress','stop') AND rr.state='needs_human')
    AND a.event_digest=digest(convert_to((a.body->'request')::text,'UTF8'),'sha256') AND a.correlation_id=a.audit_id
    AND a.audit_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_transition',r||chr(31)||a.step_id||chr(31)||a.event_kind||CASE WHEN a.event_kind='ordered_step_ready' THEN chr(31)||'blocked' ELSE '' END)
    AND to_jsonb((a.body->'request'->>'run_version')::bigint+1)=to_jsonb(rr.version)
    AND EXISTS(SELECT 1 FROM jsonb_array_elements(s->'steps') st WHERE st->>'step_id'=a.step_id AND st->'state'=a.body->'response'->'step_state')));
END $terminal$;
-- Demotion and historical reconciliation need no lost token or worker login.
-- Reuse owner-private reviewed retained proof under its organization-first
-- lock, never an execution/reclaim call or a reconstructed receipt.
CREATE FUNCTION zasp_ordered_scheduler64.clean_terminal(o text,w text,e text,r text) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $clean$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;state_value jsonb;projection jsonb;
BEGIN
 PERFORM zasp_sa_multistep_prior.transition_lock(o,w,e,r);
 PERFORM zasp_ordered_public62.history(o,w,e,r);
 PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,false);
 projection:=zasp_ordered_public62.project_core(o,w,e,r,true);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF rr.state NOT IN('contained','remediated','needs_human','cancelled') THEN RETURN false;END IF;
 state_value:=jsonb_build_object('steps',(SELECT jsonb_agg(jsonb_build_object('step_id',step_id,'state',state) ORDER BY step_index) FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)),'cleanup',COALESCE((SELECT jsonb_build_object('state',state) FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)),'{}'::jsonb));
 RETURN zasp_ordered_scheduler64.terminal_evidence(o,w,e,r,rr,state_value)
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state IN('leased','cleanup_pending','cleanup_failed'))
  AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state<>'cleaned')
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state='active')
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(o,w,e,r) AND t.state IN('stored','verified') AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanups c WHERE (c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.state)=(o,w,e,r,'cleaned')))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work d JOIN public.zasp_security_agent_temporary_policy_targets t USING(organization_id,workspace_id,environment_id,device_id) WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(o,w,e,r) AND d.state='leased')
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links l LEFT JOIN public.zasp_red_team_runs child ON (child.organization_id,child.workspace_id,child.environment_id,child.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id)=(o,w,e,r) AND (l.reconcile_state='leased' OR child.state IN('queued','leased')));
END $clean$;
CREATE FUNCTION zasp_ordered_scheduler64.inspect(o text,w text,e text,r text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $inspect$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;j zasp_sa_multistep_prior.planning_jobs%ROWTYPE;s jsonb;p jsonb;class_value text:='unavailable';owned_schedule boolean;
 retained_policy zasp_sa_multistep_prior.pricing_policies%ROWTYPE;retained_account zasp_sa_multistep_prior.pricing_accounts%ROWTYPE;bound_value jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,event_kind)=(o,w,e,r,'ordered_public_triggered'))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs x JOIN public.zasp_security_agent_definition_versions h ON (h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND (h.definition->'max_steps'='2'::jsonb OR h.definition->'allowed_actions'='["create_temporary_policy","run_test"]'::jsonb))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,resource_id)=(o,w,e,r) AND response->'contract_version'='62'::jsonb) THEN RETURN NULL;END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 PERFORM zasp_ordered_public62.history(o,w,e,r);
 IF rr.state IN('failed','inconclusive') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler aggregate contradictory';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.admissions WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN
  PERFORM zasp_ordered_public62.project_core(o,w,e,r,true);
  RETURN NULL;
 END IF;
 SELECT * INTO j FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 IF j.state IS DISTINCT FROM 'admitted' OR j.lookup_request IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler planning handoff unavailable';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.admissions a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt)=(o,w,e,r,j.attempt)
  AND a.lease_token_digest=j.lease_token_digest AND a.lease_expires_at=j.lease_expires_at AND a.response=j.receipt
  AND a.request=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_id',rr.definition_id,'definition_version',rr.definition_version,'trigger_id',rr.trigger_id,'attempt',j.attempt,'run_version',j.run_version,'worker_id',j.worker_id,'input_digest',j.input_digest,'output_digest',j.provider_digest,'model',j.lookup_request->>'model','policy_version',j.lookup_request->>'request_policy_version','candidate',j.result_value->'candidate')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler immutable admission changed';END IF;
 s:=zasp_sa_multistep_prior.orchestration_state('-- release61 checksum','-- release61 fingerprint',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'worker_id',q->>'action_worker_id','lease_token',q->>'action_lease_token','deployment_worker_id',q->>'deployment_worker_id','deployment_lease_token',q->>'deployment_lease_token'));
 PERFORM zasp_ordered_public62.project_core(o,w,e,r,true);
 SELECT EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.schedule_leases own WHERE (own.organization_id,own.workspace_id,own.environment_id,own.run_id,own.worker_id,own.action_worker_id,own.deployment_worker_id)=(o,w,e,r,q->>'worker_id',q->>'action_worker_id',q->>'deployment_worker_id') AND own.state='active' AND own.lease_expires_at>clock_timestamp() AND own.token_digest=digest(convert_to(q->>'schedule_token','UTF8'),'sha256') AND own.action_token_digest=digest(convert_to(q->>'action_lease_token','UTF8'),'sha256') AND own.deployment_token_digest=digest(convert_to(q->>'deployment_lease_token','UTF8'),'sha256')) INTO owned_schedule;
 IF EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work dw JOIN public.zasp_security_agent_temporary_policy_targets t USING(organization_id,workspace_id,environment_id,device_id) WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(o,w,e,r) AND dw.state='leased' AND dw.lease_expires_at>clock_timestamp() AND (NOT owned_schedule OR (dw.lease_owner,dw.lease_token) IS DISTINCT FROM (q->>'deployment_worker_id',q->>'deployment_lease_token')))
  OR EXISTS(SELECT 1 FROM public.zasp_red_team_runs child JOIN public.zasp_security_agent_test_links l ON (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)=(child.organization_id,child.workspace_id,child.environment_id,child.run_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id)=(o,w,e,r) AND child.state='leased' AND child.lease_expires_at>clock_timestamp() AND (NOT owned_schedule OR (child.worker_id,child.lease_token) IS DISTINCT FROM (q->>'action_worker_id',convert_to(q->>'action_lease_token','UTF8'))))
  OR EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanups cleanup WHERE (cleanup.organization_id,cleanup.workspace_id,cleanup.environment_id,cleanup.run_id)=(o,w,e,r) AND cleanup.state='leased' AND cleanup.lease_expires_at>clock_timestamp() AND (NOT owned_schedule OR (cleanup.lease_owner,cleanup.lease_token) IS DISTINCT FROM (q->>'action_worker_id',q->>'action_lease_token')))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id)=(o,w,e,r) AND l.reconcile_state='leased' AND l.reconcile_expires_at>clock_timestamp()) THEN RETURN NULL;END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_effects fx WHERE (fx.organization_id,fx.workspace_id,fx.environment_id,fx.run_id)=(o,w,e,r) AND fx.state='leased' AND fx.lease_expires_at>clock_timestamp()
  AND ((fx.lease_owner,fx.lease_token) IS DISTINCT FROM (q->>'action_worker_id',q->>'action_lease_token') OR NOT EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.schedule_leases own WHERE (own.organization_id,own.workspace_id,own.environment_id,own.run_id,own.worker_id)=(o,w,e,r,q->>'worker_id') AND own.state='active' AND own.lease_expires_at>clock_timestamp() AND own.token_digest=digest(convert_to(q->>'schedule_token','UTF8'),'sha256') AND own.action_token_digest=digest(convert_to(q->>'action_lease_token','UTF8'),'sha256')))) THEN RETURN NULL;END IF;
 -- Admission settled this exact immutable revision. A later planner disable,
 -- rotation or expiry must not strand execution or cleanup of admitted work.
 SELECT * INTO retained_policy FROM zasp_sa_multistep_prior.pricing_policies WHERE (organization_id,workspace_id,environment_id,policy_id,version)=(o,w,e,j.lookup_request->>'policy_id',(j.lookup_request->>'policy_version')::bigint) FOR SHARE;
 SELECT * INTO retained_account FROM zasp_sa_multistep_prior.pricing_accounts WHERE (organization_id,workspace_id,environment_id,account_id,version)=(o,w,e,retained_policy.account_id,retained_policy.account_version) FOR SHARE;
 p:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'provider',retained_policy.policy->'provider','model',retained_policy.policy->'model','account_profile',retained_policy.policy->'account_profile','cost_unit',retained_policy.policy->'cost_unit','credential_reference',retained_account.credential_reference,'credential_digest',retained_account.credential_digest,'request_policy_version',retained_policy.policy->'request_policy_version','request_token_limit',retained_policy.policy->'request_token_limit','policy_id',retained_policy.policy_id,'policy_version',retained_policy.version,'policy_digest',retained_policy.policy_digest,'account_id',retained_account.account_id,'account_version',retained_account.version);
 bound_value:=jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'policy_id',retained_policy.policy_id,'policy_version',retained_policy.version,'policy_digest',retained_policy.policy_digest,'account_id',retained_account.account_id,'account_version',retained_account.version,'body_digest',j.request_digest,'policy',retained_policy.policy,'maximum_tokens',retained_policy.policy->'maximum_tokens','maximum_cost_nano_credits',retained_policy.policy->'maximum_cost_nano_credits','cost_policy_version','pricing61-'||retained_policy.version::text||'-'||substring(retained_policy.policy_digest FROM 8 FOR 32));
 IF retained_policy.policy_id IS NULL OR retained_account.account_id IS NULL OR retained_policy.disabled OR retained_policy.policy_digest IS DISTINCT FROM zasp_sa_multistep_prior.pricing_digest(retained_policy)
  OR NOT zasp_sa_multistep_prior.pricing_policy_valid(retained_policy.policy) OR (retained_account.provider,retained_account.account_profile,retained_account.credential_reference,retained_account.credential_digest) IS DISTINCT FROM (retained_policy.policy->>'provider',retained_policy.policy->>'account_profile',retained_policy.policy->>'credential_reference',retained_policy.policy->>'credential_digest')
  OR j.lookup_request IS DISTINCT FROM p||jsonb_build_object('body',j.request_body,'body_digest',j.request_digest) OR j.request_body IS DISTINCT FROM zasp_sa_multistep_prior.planning_body(j.context_value,j.lookup_request) OR j.request_digest IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(j.request_body,'UTF8'),'sha256'),'hex') OR j.pricing_bound IS DISTINCT FROM bound_value
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations u WHERE (u.organization_id,u.workspace_id,u.environment_id,u.run_id,u.attempt,u.reservation_id,u.worker_id)=(o,w,e,r,j.attempt,j.reservation_id,j.worker_id) AND u.lease_token_digest=j.lease_token_digest AND u.settled_at IS NOT NULL AND u.input_digest=decode(substring(j.input_digest FROM 8),'hex') AND u.output_digest=decode(substring(j.provider_digest FROM 8),'hex') AND u.model=p->>'model' AND u.cost_policy_version=bound_value->>'cost_policy_version' AND u.cost_unit=p->>'cost_unit' AND u.maximum_tokens=(bound_value->>'maximum_tokens')::bigint AND u.maximum_cost_nano_credits=(bound_value->>'maximum_cost_nano_credits')::bigint) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler retained pricing changed';END IF;
 IF s->'stop_required'='true'::jsonb THEN class_value:='stop';
 ELSIF EXISTS(SELECT 1 FROM jsonb_array_elements(s->'steps') t WHERE t->>'effect_state'='leased' AND (t->>'lease_expires_at')::timestamptz<=clock_timestamp()) THEN class_value:='recovery';
 ELSIF s->>'run_state' IN('contained','remediated','needs_human','cancelled') THEN
  IF s->'cleanup'->>'state' IS DISTINCT FROM 'cleaned' AND EXISTS(SELECT 1 FROM jsonb_array_elements(s->'application'->'targets') t WHERE t->>'state' IN('stored','verified')) THEN class_value:='cleanup';
  ELSIF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s->'steps') t WHERE t->>'effect_state'='leased') AND s->'cleanup'->>'state' IS DISTINCT FROM 'leased' AND s->'cleanup'->>'state' IS DISTINCT FROM 'retryable' AND s->'test'->>'child_state' IS DISTINCT FROM 'leased' THEN class_value:='terminal';END IF;
 ELSIF s->'steps'->0->>'state' IN('authorized','executing') THEN class_value:='application';
 ELSIF s->'steps'->0->>'state'='succeeded' AND s->'steps'->1->>'state'='queued' THEN class_value:='successor';
 ELSIF s->'steps'->0->>'state'='succeeded' AND s->'steps'->1->>'state' IN('authorized','executing') THEN class_value:='test';
 ELSIF s->>'run_state'='waiting_approval' AND (s->'steps'->0->>'state'='waiting_approval' OR s->'steps'->0->>'state'='succeeded' AND s->'steps'->1->>'state'='waiting_approval') AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s->'steps') t WHERE t->>'effect_state'='leased') AND s->'test'->>'child_state' IS DISTINCT FROM 'leased' THEN class_value:='approval';END IF;
 -- A terminal label alone is not completion evidence. Cross-bind the fresh
 -- projection to the retained response emitted by the reviewed transition or
 -- cleanup authority; the readers above validate its predecessor evidence.
 IF class_value='terminal' AND NOT zasp_ordered_scheduler64.terminal_evidence(o,w,e,r,rr,s) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler terminal evidence unavailable';END IF;
 RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_id',rr.definition_id,'definition_version',rr.definition_version,'run_version',s->'run_version','state',s->'run_state','state_class',class_value,'pricing',p-ARRAY['organization_id','workspace_id','environment_id']);
END $inspect$;
CREATE FUNCTION zasp_ordered_scheduler64.claim(q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $claim$
DECLARE k text;token bytea;action_token bytea;deployment_token bytea;candidate record;v jsonb;item_value jsonb;request_value jsonb;id text;expires timestamptz;d zasp_ordered_scheduler64.schedule_leases%ROWTYPE;
BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['operation','worker_id','schedule_token','action_worker_id','action_lease_token','deployment_worker_id','deployment_lease_token','lease_seconds','executor_lease_seconds','limit']) OR q->'limit' IS DISTINCT FROM '1'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler claim rejected';END IF;
 FOREACH k IN ARRAY ARRAY['worker_id','action_worker_id','deployment_worker_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(q->>k~'^[a-z][a-z0-9.-]{2,127}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler worker rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['schedule_token','action_lease_token','deployment_lease_token'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(q->>k~'^[A-Za-z0-9_.-]{16,128}$',false) OR q->>k~'^0+$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler token rejected';END IF;
 END LOOP;
 IF q->>'action_lease_token'!~'^[a-f0-9]{32}$' OR q->>'schedule_token' IN(q->>'action_lease_token',q->>'deployment_lease_token') OR q->>'action_lease_token'=q->>'deployment_lease_token' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler token separation rejected';END IF;
 FOREACH k IN ARRAY ARRAY['lease_seconds','executor_lease_seconds'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'number' OR NOT COALESCE(q->>k~'^[1-9][0-9]{1,2}$',false) OR (q->>k)::integer NOT BETWEEN 30 AND 300 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler duration rejected';END IF;
 END LOOP;
 token:=digest(convert_to(q->>'schedule_token','UTF8'),'sha256');action_token:=digest(convert_to(q->>'action_lease_token','UTF8'),'sha256');deployment_token:=digest(convert_to(q->>'deployment_lease_token','UTF8'),'sha256');
 request_value:=q-ARRAY['schedule_token','action_lease_token','deployment_lease_token'];
 -- Both multi-organization scans share worker63's outer serialization order.
 -- Take it before selection, replay, maintenance, or any organization lock.
 PERFORM pg_advisory_xact_lock(hashtextextended('ordered-worker63-dispatch',0));
 PERFORM pg_advisory_xact_lock(hashtextextended('ordered-scheduler64-selection',0));
 SELECT * INTO d FROM zasp_ordered_scheduler64.schedule_leases WHERE worker_id=q->>'worker_id' AND token_digest=token;
 IF FOUND THEN
  IF d.state<>'active' OR d.lease_expires_at<=clock_timestamp() OR d.request IS DISTINCT FROM request_value OR d.action_token_digest<>action_token OR d.deployment_token_digest<>deployment_token THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler replay changed';END IF;
  v:=zasp_ordered_scheduler64.inspect(d.organization_id,d.workspace_id,d.environment_id,d.run_id,q);
  IF v IS NULL OR v IS DISTINCT FROM d.item-ARRAY['schedule_id','schedule_version','lease_expires_at'] OR d.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler replay authority changed';END IF;
  RETURN jsonb_build_object('contract_version',64,'outcome','claimed','item',d.item);
 END IF;
 -- A crash after reviewed completion must not strand non-runnable history.
 -- Fresh retained eligibility also precedes this deterministic bounded window.
 FOR candidate IN WITH retained AS MATERIALIZED (
  SELECT h.*,zasp_ordered_scheduler64.clean_terminal(h.organization_id,h.workspace_id,h.environment_id,h.run_id) AS clean
  FROM zasp_ordered_scheduler64.schedule_leases h WHERE h.state='expired' OR h.state IN('active','recovery_deferred') AND h.lease_expires_at<=clock_timestamp()
 ) SELECT * FROM retained WHERE clean ORDER BY created_at,organization_id,workspace_id,environment_id,run_id,schedule_id LIMIT 100 LOOP
  IF NOT zasp_ordered_scheduler64.clean_terminal(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.run_id) THEN CONTINUE;END IF;
  UPDATE zasp_ordered_scheduler64.schedule_leases SET state='expired',version=version+1 WHERE schedule_id=candidate.schedule_id AND state IN('active','recovery_deferred') AND lease_expires_at<=clock_timestamp();
  UPDATE zasp_ordered_scheduler64.schedule_leases SET state='reconciled' WHERE schedule_id=candidate.schedule_id AND state='expired';
 END LOOP;
 -- Eligibility precedes the bounded window. No persisted cursor or requeue.
 FOR candidate IN WITH classified AS MATERIALIZED (
  SELECT x.*,zasp_ordered_scheduler64.inspect(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q) AS authority FROM public.zasp_security_agent_runs x
 ) SELECT * FROM classified x WHERE authority->>'state_class' IN('application','successor','test','stop','cleanup','recovery')
  AND NOT EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.schedule_leases owned_schedule WHERE (owned_schedule.organization_id,owned_schedule.workspace_id,owned_schedule.environment_id,owned_schedule.run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) AND owned_schedule.state IN('active','recovery_deferred') AND owned_schedule.lease_expires_at>clock_timestamp())
  ORDER BY created_at,organization_id,workspace_id,environment_id,run_id LIMIT 100 LOOP
  v:=zasp_ordered_scheduler64.inspect(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.run_id,q);
  IF v IS NULL OR v->>'state_class' NOT IN('application','successor','test','stop','cleanup','recovery') THEN CONTINUE;END IF;
  -- The old identity and retained item survive. Reclaim never overwrites its
  -- binding or adopts a predecessor lease; release61 still owns reconciliation.
  UPDATE zasp_ordered_scheduler64.schedule_leases SET state='expired',version=version+1 WHERE (organization_id,workspace_id,environment_id,run_id)=(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.run_id) AND state IN('active','recovery_deferred') AND lease_expires_at<=clock_timestamp();
  id:=public.zasp_discovery_canonical_id(candidate.organization_id,candidate.workspace_id,candidate.environment_id,'ordered_scheduler64',candidate.run_id||chr(31)||(q->>'worker_id')||chr(31)||encode(token,'hex'));
  expires:=clock_timestamp()+make_interval(secs=>(q->>'lease_seconds')::integer);
  item_value:=v||jsonb_build_object('schedule_id',id,'schedule_version',1,'lease_expires_at',to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  INSERT INTO zasp_ordered_scheduler64.schedule_leases(schedule_id,organization_id,workspace_id,environment_id,run_id,worker_id,token_digest,action_worker_id,action_token_digest,deployment_worker_id,deployment_token_digest,state,lease_expires_at,request,item)
   VALUES(id,candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.run_id,q->>'worker_id',token,q->>'action_worker_id',action_token,q->>'deployment_worker_id',deployment_token,'active',expires,request_value,item_value);
  RETURN jsonb_build_object('contract_version',64,'outcome','claimed','item',item_value);
 END LOOP;
 RETURN jsonb_build_object('contract_version',64,'outcome','empty','item',NULL);
END $claim$;
CREATE FUNCTION zasp_ordered_scheduler64.mutate(q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $mutate$
DECLARE k text;keys text[];op text:=q->>'operation';d zasp_ordered_scheduler64.schedule_leases%ROWTYPE;v jsonb;item_value jsonb;expires timestamptz;outcome text;
BEGIN
 keys:=ARRAY['operation','worker_id','schedule_token','action_worker_id','action_lease_token','deployment_worker_id','deployment_lease_token','schedule_id','run_version','schedule_version'];
 IF op='heartbeat' THEN keys:=keys||'lease_seconds'::text;END IF;
 IF op NOT IN('heartbeat','finish','abandon') OR NOT zasp_sa_multistep_prior.closed(q,keys) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler mutation rejected';END IF;
 FOREACH k IN ARRAY ARRAY['worker_id','action_worker_id','deployment_worker_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(q->>k~'^[a-z][a-z0-9.-]{2,127}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler worker rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['schedule_token','action_lease_token','deployment_lease_token'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(q->>k~'^[A-Za-z0-9_.-]{16,128}$',false) OR q->>k~'^0+$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler token rejected';END IF;
 END LOOP;
 IF jsonb_typeof(q->'schedule_id') IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>'schedule_id'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler identity rejected';END IF;
 FOREACH k IN ARRAY ARRAY['run_version','schedule_version'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'number' OR NOT COALESCE(q->>k~'^([1-9][0-9]{0,5}|1000000)$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler version rejected';END IF;
 END LOOP;
 IF op='heartbeat' AND (jsonb_typeof(q->'lease_seconds') IS DISTINCT FROM 'number' OR NOT COALESCE(q->>'lease_seconds'~'^[1-9][0-9]{1,2}$',false) OR (q->>'lease_seconds')::integer NOT BETWEEN 30 AND 300) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler duration rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('ordered-scheduler64-selection',0));
 SELECT * INTO d FROM zasp_ordered_scheduler64.schedule_leases WHERE schedule_id=q->>'schedule_id';
 IF d.schedule_id IS NULL OR d.state<>'active' OR d.version<>(q->>'schedule_version')::bigint OR d.version>=1000000 OR d.lease_expires_at<=clock_timestamp()
  OR (d.worker_id,d.action_worker_id,d.deployment_worker_id) IS DISTINCT FROM (q->>'worker_id',q->>'action_worker_id',q->>'deployment_worker_id')
  OR d.token_digest<>digest(convert_to(q->>'schedule_token','UTF8'),'sha256') OR d.action_token_digest<>digest(convert_to(q->>'action_lease_token','UTF8'),'sha256') OR d.deployment_token_digest<>digest(convert_to(q->>'deployment_lease_token','UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler ownership changed';END IF;
 v:=zasp_ordered_scheduler64.inspect(d.organization_id,d.workspace_id,d.environment_id,d.run_id,q);
 IF v IS NULL OR v->'run_version' IS DISTINCT FROM q->'run_version' OR v->'pricing' IS DISTINCT FROM d.item->'pricing' OR d.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler current authority changed';END IF;
 IF op='heartbeat' THEN
  expires:=clock_timestamp()+make_interval(secs=>(q->>'lease_seconds')::integer);
  item_value:=v||jsonb_build_object('schedule_id',d.schedule_id,'schedule_version',d.version+1,'lease_expires_at',to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  UPDATE zasp_ordered_scheduler64.schedule_leases SET version=version+1,lease_expires_at=expires,item=item_value WHERE schedule_id=d.schedule_id;
  outcome:='extended';
 ELSIF op='finish' AND (v->>'state_class'='approval' OR v->>'state_class'='terminal' AND zasp_ordered_scheduler64.clean_terminal(d.organization_id,d.workspace_id,d.environment_id,d.run_id)) THEN
  UPDATE zasp_ordered_scheduler64.schedule_leases SET state='reconciled' WHERE schedule_id=d.schedule_id;
  IF v->>'state_class'='terminal' THEN
   UPDATE zasp_ordered_scheduler64.schedule_leases SET state='reconciled' WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id) AND state IN('expired','recovery_deferred');
  END IF;
  outcome:='finished';
 ELSIF op='abandon' AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id))
  AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id)=(d.organization_id,d.workspace_id,d.environment_id,d.run_id)) THEN
  UPDATE zasp_ordered_scheduler64.schedule_leases SET state='reconciled' WHERE schedule_id=d.schedule_id;
  outcome:='released';
 ELSIF op='abandon' THEN
  UPDATE zasp_ordered_scheduler64.schedule_leases SET state='recovery_deferred',version=version+1 WHERE schedule_id=d.schedule_id;
  outcome:='recovery_deferred';
 ELSE RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler work unresolved';
 END IF;
 RETURN jsonb_build_object('contract_version',64,'outcome',outcome,'item',item_value);
END $mutate$;
CREATE FUNCTION zasp_ordered_scheduler64.scheduler(c text,f text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $scheduler$
DECLARE result_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='scheduler requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 LOCK TABLE zasp_ordered_public62.registration,zasp_ordered_worker63.registration,zasp_ordered_scheduler64.registration IN SHARE MODE;
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='scheduler principal rejected';END IF;
 IF NOT zasp_ordered_scheduler64.ready(c,f) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler release unavailable';END IF;
 IF EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.schedule_leases d WHERE d.evidence_digest IS DISTINCT FROM zasp_ordered_scheduler64.evidence_digest(d)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='scheduler evidence changed';END IF;
 IF q IS NULL OR octet_length(q::text)>4096 OR jsonb_typeof(q) IS DISTINCT FROM 'object' OR jsonb_typeof(q->'operation') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler request rejected';END IF;
 IF q->>'operation'='ready' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['operation']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler ready rejected';END IF;
  result_value:=jsonb_build_object('contract_version',64,'ready',true);
 ELSIF q->>'operation'='claim' THEN result_value:=zasp_ordered_scheduler64.claim(q);
 ELSIF q->>'operation' IN('heartbeat','finish','abandon') THEN result_value:=zasp_ordered_scheduler64.mutate(q);
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='scheduler operation rejected';END IF;
 IF result_value IS NULL OR octet_length(result_value::text)>8192 OR NOT zasp_ordered_scheduler64.ready(c,f) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler authority changed';END IF;
 IF result_value->'item' IS NOT NULL AND result_value->'item'<>'null'::jsonb AND (result_value->'item'->>'lease_expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='scheduler lease expired';END IF;
 RETURN result_value;
END $scheduler$;
DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_ordered_scheduler64'::regnamespace LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);END LOOP;
END $owners$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zasp_ordered_scheduler64 FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_ordered_scheduler64 TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_ordered_scheduler64.scheduler(text,text,jsonb) TO zasp_security_agent_worker;
