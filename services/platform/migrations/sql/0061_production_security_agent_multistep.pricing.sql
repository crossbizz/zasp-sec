-- Private approval ceilings, not provider rates or a dispatch permit. No
-- secret bytes, provider call, reservation, or planning state belongs here.
CREATE FUNCTION zasp_sa_multistep_prior.pricing_policy_valid(p jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $valid$
DECLARE k text;effective timestamptz;expires timestamptz;
BEGIN
 IF NOT zasp_sa_multistep_prior.closed(p,ARRAY['provider','model','account_profile','cost_unit','maximum_tokens','maximum_cost_nano_credits','request_policy_version','request_token_limit','credential_reference','credential_digest','effective_at','expires_at']) OR octet_length(p::text)>4096 THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['provider','model','account_profile','cost_unit','request_policy_version','credential_reference','credential_digest','effective_at','expires_at'] LOOP
  IF jsonb_typeof(p->k) IS DISTINCT FROM 'string' THEN RETURN false;END IF;
 END LOOP;
 IF p->>'provider'<>'openrouter' OR p->>'cost_unit'<>'openrouter_credit'
  OR p->>'model'!~'^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' OR octet_length(p->>'model') NOT BETWEEN 1 AND 128
  OR p->>'account_profile'!~'^[A-Za-z0-9_.-]{1,128}$' OR p->>'request_policy_version'!~'^[A-Za-z0-9_.-]{1,63}$'
  OR p->>'credential_reference'!~'^secret_ref_planner/[A-Za-z0-9_/-]{1,220}$' OR position('..' in p->>'credential_reference')>0 OR position('//' in p->>'credential_reference')>0
  OR p->>'credential_digest'!~'^sha256:[a-f0-9]{64}$' THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['maximum_tokens','maximum_cost_nano_credits','request_token_limit'] LOOP
  IF jsonb_typeof(p->k) IS DISTINCT FROM 'number' OR p->>k!~'^[1-9][0-9]{0,12}$' THEN RETURN false;END IF;
 END LOOP;
 IF (p->>'maximum_tokens')::bigint>12000 OR (p->>'maximum_cost_nano_credits')::bigint>1000000000000
  OR (p->>'request_token_limit')::bigint>4096 OR (p->>'request_token_limit')::bigint>(p->>'maximum_tokens')::bigint THEN RETURN false;END IF;
 effective:=(p->>'effective_at')::timestamptz;expires:=(p->>'expires_at')::timestamptz;
 RETURN isfinite(effective) AND isfinite(expires) AND expires>effective AND expires<=effective+interval '720 hours'
  AND p->>'effective_at'=to_char(effective AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  AND p->>'expires_at'=to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN RETURN false;
END $valid$;

CREATE TABLE zasp_sa_multistep_prior.pricing_accounts (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 account_id text NOT NULL CHECK(public.zasp_valid_product_id(account_id)),version bigint NOT NULL CHECK(version BETWEEN 1 AND 1000000),
 provider text NOT NULL CHECK(provider='openrouter'),account_profile text NOT NULL CHECK(account_profile~'^[A-Za-z0-9_.-]{1,128}$'),
 credential_reference text NOT NULL,credential_digest text NOT NULL CHECK(credential_digest~'^sha256:[a-f0-9]{64}$'),
 actor_id text NOT NULL CHECK(public.zasp_valid_product_id(actor_id)),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,account_id,version),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id)
);
CREATE TABLE zasp_sa_multistep_prior.pricing_policies (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 policy_id text NOT NULL CHECK(public.zasp_valid_product_id(policy_id)),version bigint NOT NULL CHECK(version BETWEEN 1 AND 1000000),
 account_id text NOT NULL,account_version bigint NOT NULL,policy jsonb NOT NULL CHECK(zasp_sa_multistep_prior.pricing_policy_valid(policy)),
 policy_digest text NOT NULL CHECK(policy_digest~'^sha256:[a-f0-9]{64}$'),disabled boolean NOT NULL CHECK(disabled OR version<1000000),
 actor_id text NOT NULL CHECK(public.zasp_valid_product_id(actor_id)),fresh_auth_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,policy_id,version),
 FOREIGN KEY(organization_id,workspace_id,environment_id,account_id,account_version) REFERENCES zasp_sa_multistep_prior.pricing_accounts(organization_id,workspace_id,environment_id,account_id,version)
);
CREATE TABLE zasp_sa_multistep_prior.pricing_mutations (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 mutation_id text NOT NULL CHECK(public.zasp_valid_product_id(mutation_id)),actor_id text NOT NULL CHECK(public.zasp_valid_product_id(actor_id)),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object' AND octet_length(request::text)<=8192),response jsonb NOT NULL CHECK(jsonb_typeof(response)='object' AND octet_length(response::text)<=8192),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,workspace_id,environment_id,mutation_id)
);
DO $tables$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['pricing_accounts','pricing_policies','pricing_mutations'] LOOP
  EXECUTE format('ALTER TABLE zasp_sa_multistep_prior.%I OWNER TO zasp_discovery_authority',name);
  EXECUTE format('ALTER TABLE zasp_sa_multistep_prior.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE zasp_sa_multistep_prior.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY authority ON zasp_sa_multistep_prior.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',name);
  EXECUTE format('REVOKE ALL ON zasp_sa_multistep_prior.%I FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker',name);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_sa_multistep_prior.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_sa_multistep_prior.immutable_admission()',name);
 END LOOP;
END $tables$;

CREATE FUNCTION zasp_sa_multistep_prior.pricing_ready(checksum_value text,fingerprint_value text,kind text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 RETURN jsonb_build_object('release',public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),'principal',CASE kind WHEN 'admin' THEN public.zasp_discovery_principal_ready('zasp_discovery_api') WHEN 'worker' THEN public.zasp_security_agent_principal_ready('zasp_security_agent_worker') ELSE false END);
END $ready$;

CREATE FUNCTION zasp_sa_multistep_prior.pricing_admin_current(o text,w text,e text,actor text,fresh timestamptz) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $authorized$
DECLARE member public.zasp_identity_memberships%ROWTYPE;scope_value public.zasp_authorized_scopes%ROWTYPE;
BEGIN
 -- Safety writers can lock identity first. Never wait on those rows while
 -- holding Organization/policy locks; refuse so they can complete.
 SELECT * INTO member FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(o,actor) FOR SHARE NOWAIT;
 scope_value:=zasp_sa_multistep_prior.pricing_lock_scope(o,w,e,actor);
 IF member.principal_id IS NULL OR NOT member.active OR member.role NOT IN('organization_admin','security_admin')
  OR scope_value.principal_id IS NULL OR NOT COALESCE(scope_value.permissions?&ARRAY['view','manage_identity'],false)
  OR NOT isfinite(fresh) OR fresh<clock_timestamp()-interval '5 minutes' OR fresh>clock_timestamp()+interval '5 seconds' THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='pricing administrator unavailable';END IF;
END $authorized$;

-- Keep scope-table UPDATE rights with its original owner, as admission does.
CREATE FUNCTION zasp_sa_multistep_prior.pricing_lock_scope(o text,w text,e text,p text) RETURNS public.zasp_authorized_scopes LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $scope$
 SELECT s FROM public.zasp_authorized_scopes s WHERE (principal_id,organization_id,workspace_id,environment_id)=(p,o,w,e) FOR SHARE NOWAIT
$scope$;
DO $owner$
DECLARE value text;
BEGIN SELECT relowner::regrole::text INTO STRICT value FROM pg_class WHERE oid='public.zasp_authorized_scopes'::regclass;
 EXECUTE format('ALTER FUNCTION zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text) OWNER TO %I',value);
END $owner$;
REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text) TO zasp_discovery_authority;

CREATE FUNCTION zasp_sa_multistep_prior.pricing_digest(p zasp_sa_multistep_prior.pricing_policies) RETURNS text LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $digest$
 SELECT 'sha256:'||encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(jsonb_build_object('organization_id',p.organization_id,'workspace_id',p.workspace_id,'environment_id',p.environment_id,'policy_id',p.policy_id,'version',p.version,'account_id',p.account_id,'account_version',p.account_version,'disabled',p.disabled,'policy',p.policy)),'UTF8'),'sha256'),'hex')
$digest$;

-- jsonb erases duplicate keys. Inspect the original body before conversion;
-- a bounded depth prevents an untrusted prepared body from exhausting recursion.
CREATE FUNCTION zasp_sa_multistep_prior.pricing_unique_json(v json,depth integer) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $unique$
BEGIN
 IF depth>32 THEN RETURN false;END IF;
 IF json_typeof(v)='object' THEN
  RETURN (SELECT count(*)=count(DISTINCT key) AND COALESCE(bool_and(zasp_sa_multistep_prior.pricing_unique_json(value,depth+1)),true) FROM json_each(v));
 ELSIF json_typeof(v)='array' THEN
  RETURN (SELECT COALESCE(bool_and(zasp_sa_multistep_prior.pricing_unique_json(value,depth+1)),true) FROM json_array_elements(v));
 END IF;
 RETURN true;
END $unique$;

CREATE FUNCTION zasp_sa_multistep_prior.pricing_admin(checksum_value text,fingerprint_value text,q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $admin$
DECLARE o text;w text;e text;k text;op text;actor text;fresh timestamptz;pid text;aid text;mid text;credential_prefix text;v bigint;av bigint;p jsonb;response_value jsonb;
 previous zasp_sa_multistep_prior.pricing_policies%ROWTYPE;next_policy zasp_sa_multistep_prior.pricing_policies%ROWTYPE;account zasp_sa_multistep_prior.pricing_accounts%ROWTYPE;prior zasp_sa_multistep_prior.pricing_mutations%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='pricing requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='pricing admin principal rejected';END IF;
 IF NOT public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='pricing release unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','actor_id','fresh_auth_at','operation','idempotency_key','expected_version','expected_account_version','policy']) OR octet_length(q::text)>8192 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','actor_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT public.zasp_valid_product_id(q->>k) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing scope rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['expected_version','expected_account_version'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'number' OR (q->>k!~'^(0|[1-9][0-9]{0,5})$' AND NOT(k='expected_account_version' AND q->>k='1000000')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing version rejected';END IF;
 END LOOP;
 IF jsonb_typeof(q->'operation') IS DISTINCT FROM 'string' OR q->>'operation' NOT IN('create','version','disable') OR jsonb_typeof(q->'idempotency_key') IS DISTINCT FROM 'string' OR q->>'idempotency_key'!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
  OR jsonb_typeof(q->'fresh_auth_at') IS DISTINCT FROM 'string' OR NOT zasp_sa_multistep_prior.pricing_policy_valid(q->'policy') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing policy rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';actor:=q->>'actor_id';fresh:=(q->>'fresh_auth_at')::timestamptz;p:=q->'policy';op:=q->>'operation';
 credential_prefix:='secret_ref_planner/'||o||'/'||w||'/'||e||'/';
 IF q->>'fresh_auth_at'<>to_char(fresh AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') OR left(p->>'credential_reference',length(credential_prefix))<>credential_prefix OR length(p->>'credential_reference')<=length(credential_prefix) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing credential scope rejected';END IF;
 pid:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_pricing_policy',concat_ws(chr(31),p->>'provider',p->>'model',p->>'account_profile'));
 aid:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_pricing_account',concat_ws(chr(31),p->>'provider',p->>'account_profile'));
 mid:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_pricing_mutation',actor||chr(31)||(q->>'idempotency_key'));
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM zasp_sa_multistep_prior.pricing_policies WHERE (organization_id,workspace_id,environment_id,policy_id)=(o,w,e,pid) ORDER BY version FOR UPDATE;
 PERFORM 1 FROM zasp_sa_multistep_prior.pricing_accounts WHERE (organization_id,workspace_id,environment_id,account_id)=(o,w,e,aid) ORDER BY version FOR UPDATE;
 PERFORM zasp_sa_multistep_prior.pricing_admin_current(o,w,e,actor,fresh);
 SELECT * INTO previous FROM zasp_sa_multistep_prior.pricing_policies WHERE (organization_id,workspace_id,environment_id,policy_id)=(o,w,e,pid) ORDER BY version DESC LIMIT 1;
 SELECT * INTO account FROM zasp_sa_multistep_prior.pricing_accounts WHERE (organization_id,workspace_id,environment_id,account_id)=(o,w,e,aid) ORDER BY version DESC LIMIT 1;
 SELECT * INTO prior FROM zasp_sa_multistep_prior.pricing_mutations WHERE (organization_id,workspace_id,environment_id,mutation_id)=(o,w,e,mid);
 IF FOUND THEN
  IF prior.request<>q OR previous.version IS DISTINCT FROM (prior.response->>'version')::bigint OR previous.policy_digest IS DISTINCT FROM zasp_sa_multistep_prior.pricing_digest(previous) OR account.version IS DISTINCT FROM previous.account_version THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing replay changed';END IF;
  response_value:=prior.response;
 ELSE
  IF COALESCE(previous.version,0)<>(q->>'expected_version')::bigint OR COALESCE(account.version,0)<>(q->>'expected_account_version')::bigint
   OR (op='create')<>(previous.policy_id IS NULL) OR op='disable' AND (previous.disabled OR previous.policy IS DISTINCT FROM p OR previous.account_version IS DISTINCT FROM account.version)
   OR previous.policy_id IS NOT NULL AND previous.policy_digest IS DISTINCT FROM zasp_sa_multistep_prior.pricing_digest(previous) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing current version changed';END IF;
  IF op<>'disable' AND ((p->>'effective_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (p->>'expires_at')::timestamptz<=clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing validity expired';END IF;
  v:=COALESCE(previous.version,0)+1;av:=COALESCE(account.version,0);
  -- The final policy revision is reserved for a disable tombstone. An account
  -- at its own ceiling remains usable, but cannot rotate its credential again.
  IF op<>'disable' AND v>=1000000 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing policy revision exhausted';END IF;
  IF op<>'disable' AND (account.account_id IS NULL OR (account.credential_reference,account.credential_digest) IS DISTINCT FROM (p->>'credential_reference',p->>'credential_digest')) THEN
   IF av>=1000000 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing account revision exhausted';END IF;
   av:=av+1;
   INSERT INTO zasp_sa_multistep_prior.pricing_accounts(organization_id,workspace_id,environment_id,account_id,version,provider,account_profile,credential_reference,credential_digest,actor_id) VALUES(o,w,e,aid,av,p->>'provider',p->>'account_profile',p->>'credential_reference',p->>'credential_digest',actor);
  END IF;
  next_policy.organization_id:=o;next_policy.workspace_id:=w;next_policy.environment_id:=e;next_policy.policy_id:=pid;next_policy.version:=v;next_policy.account_id:=aid;next_policy.account_version:=av;next_policy.policy:=p;next_policy.disabled:=op='disable';next_policy.actor_id:=actor;next_policy.fresh_auth_at:=fresh;next_policy.created_at:=clock_timestamp();
  next_policy.policy_digest:=zasp_sa_multistep_prior.pricing_digest(next_policy);
  INSERT INTO zasp_sa_multistep_prior.pricing_policies SELECT next_policy.*;
  response_value:=jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'policy_id',pid,'version',v,'policy_digest',next_policy.policy_digest,'account_id',aid,'account_version',av,'disabled',next_policy.disabled,'policy',p,'mutation_id',mid);
  INSERT INTO zasp_sa_multistep_prior.pricing_mutations(organization_id,workspace_id,environment_id,mutation_id,actor_id,request,response) VALUES(o,w,e,mid,actor,q,response_value);
  INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES(o,w,e,mid,actor,'security_agent.pricing.'||op,pid,'succeeded',jsonb_build_object('policy_version',v,'policy_digest',next_policy.policy_digest,'account_id',aid,'account_version',av,'disabled',next_policy.disabled));
 END IF;
 -- The audit key can wait. No fresh-auth, policy-lifetime or readiness fact
 -- sampled before that wait is enough to commit or replay approval.
 PERFORM zasp_sa_multistep_prior.pricing_admin_current(o,w,e,actor,fresh);
 IF op<>'disable' AND (p->>'expires_at')::timestamptz<=clock_timestamp() OR NOT public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value) OR NOT public.zasp_discovery_principal_ready('zasp_discovery_api') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing authority changed after wait';END IF;
 RETURN response_value;
END $admin$;

CREATE FUNCTION zasp_sa_multistep_prior.pricing_lookup(checksum_value text,fingerprint_value text,q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $lookup$
DECLARE o text;w text;e text;k text;pid text;aid text;body jsonb;p zasp_sa_multistep_prior.pricing_policies%ROWTYPE;a zasp_sa_multistep_prior.pricing_accounts%ROWTYPE;response_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='pricing requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='pricing worker principal rejected';END IF;
 IF NOT public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='pricing release unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','provider','model','account_profile','cost_unit','credential_reference','credential_digest','request_policy_version','request_token_limit','body','body_digest','policy_id','policy_version','policy_digest','account_id','account_version']) OR octet_length(q::text)>524288 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing lookup rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','policy_id','account_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT public.zasp_valid_product_id(q->>k) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing lookup scope rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['policy_version','account_version','request_token_limit'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'number' OR q->>k!~'^([1-9][0-9]{0,5}|1000000)$' OR k='policy_version' AND q->>k='1000000' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing lookup version rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['provider','model','account_profile','cost_unit','credential_reference','credential_digest','request_policy_version','body','body_digest','policy_digest'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing lookup text rejected';END IF;
 END LOOP;
 IF octet_length(q->>'body') NOT BETWEEN 1 AND 65536 OR q->>'body_digest' IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(q->>'body','UTF8'),'sha256'),'hex') OR NOT zasp_sa_multistep_prior.pricing_unique_json((q->>'body')::json,0) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing request digest rejected';END IF;
 body:=(q->>'body')::jsonb;
 IF NOT zasp_sa_multistep_prior.closed(body,ARRAY['model','max_tokens','messages','provider','response_format']) OR body->'model' IS DISTINCT FROM q->'model' OR body->'max_tokens' IS DISTINCT FROM q->'request_token_limit'
  OR body->'provider' IS DISTINCT FROM '{"data_collection":"deny","require_parameters":true}'::jsonb
  OR jsonb_typeof(body->'messages') IS DISTINCT FROM 'array' OR jsonb_array_length(body->'messages')<>2
  OR NOT zasp_sa_multistep_prior.closed(body->'messages'->0,ARRAY['role','content']) OR NOT zasp_sa_multistep_prior.closed(body->'messages'->1,ARRAY['role','content'])
  OR body->'messages'->0->>'role'<>'system' OR body->'messages'->1->>'role'<>'user'
  OR jsonb_typeof(body->'messages'->0->'content') IS DISTINCT FROM 'string' OR jsonb_typeof(body->'messages'->1->'content') IS DISTINCT FROM 'string'
  OR octet_length(body->'messages'->0->>'content') NOT BETWEEN 1 AND 4096 OR octet_length(body->'messages'->1->>'content') NOT BETWEEN 1 AND 49152
  OR NOT zasp_sa_multistep_prior.closed(body->'response_format',ARRAY['type','json_schema']) OR body->'response_format'->>'type'<>'json_schema'
  OR NOT zasp_sa_multistep_prior.closed(body->'response_format'->'json_schema',ARRAY['name','strict','schema']) OR body->'response_format'->'json_schema'->>'name'<>'security_response_plan'
  OR body->'response_format'->'json_schema'->'strict' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(body->'response_format'->'json_schema'->'schema') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing prepared request rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';
 pid:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_pricing_policy',concat_ws(chr(31),q->>'provider',q->>'model',q->>'account_profile'));
 aid:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_pricing_account',concat_ws(chr(31),q->>'provider',q->>'account_profile'));
 IF pid<>q->>'policy_id' OR aid<>q->>'account_id' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='pricing canonical identity rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM zasp_sa_multistep_prior.pricing_policies WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND policy->>'provider'=q->>'provider' AND policy->>'model'=q->>'model' AND policy->>'account_profile'=q->>'account_profile' ORDER BY policy_id,version FOR SHARE;
 PERFORM 1 FROM zasp_sa_multistep_prior.pricing_accounts WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND provider=q->>'provider' AND account_profile=q->>'account_profile' ORDER BY account_id,version FOR SHARE;
 IF (SELECT count(DISTINCT policy_id) FROM zasp_sa_multistep_prior.pricing_policies WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND policy->>'provider'=q->>'provider' AND policy->>'model'=q->>'model' AND policy->>'account_profile'=q->>'account_profile')<>1
  OR (SELECT count(DISTINCT account_id) FROM zasp_sa_multistep_prior.pricing_accounts WHERE (organization_id,workspace_id,environment_id,provider,account_profile)=(o,w,e,q->>'provider',q->>'account_profile'))<>1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing policy absent or ambiguous';END IF;
 SELECT * INTO p FROM zasp_sa_multistep_prior.pricing_policies WHERE (organization_id,workspace_id,environment_id,policy_id)=(o,w,e,pid) ORDER BY version DESC LIMIT 1;
 SELECT * INTO a FROM zasp_sa_multistep_prior.pricing_accounts WHERE (organization_id,workspace_id,environment_id,account_id)=(o,w,e,aid) ORDER BY version DESC LIMIT 1;
 IF p.policy_id IS NULL OR a.account_id IS NULL OR p.disabled OR p.version<>(q->>'policy_version')::bigint OR p.policy_digest<>q->>'policy_digest' OR p.policy_digest<>zasp_sa_multistep_prior.pricing_digest(p)
  OR p.account_id<>aid OR p.account_version<>a.version OR a.version<>(q->>'account_version')::bigint
  OR a.credential_reference<>q->>'credential_reference' OR a.credential_digest<>q->>'credential_digest'
  OR p.policy->>'credential_reference'<>a.credential_reference OR p.policy->>'credential_digest'<>a.credential_digest
  OR (p.policy->>'effective_at')::timestamptz>clock_timestamp() OR (p.policy->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing current authority unavailable';END IF;
 FOREACH k IN ARRAY ARRAY['provider','model','account_profile','cost_unit','request_policy_version','request_token_limit'] LOOP
  IF p.policy->k IS DISTINCT FROM q->k THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing request authority mismatch';END IF;
 END LOOP;
 response_value:=jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'policy_id',pid,'policy_version',p.version,'policy_digest',p.policy_digest,'account_id',aid,'account_version',a.version,'body_digest',q->>'body_digest','policy',p.policy,'maximum_tokens',(p.policy->>'maximum_tokens')::bigint,'maximum_cost_nano_credits',(p.policy->>'maximum_cost_nano_credits')::bigint,'cost_policy_version','pricing61-'||p.version::text||'-'||substring(p.policy_digest FROM 8 FOR 32));
 IF NOT public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value) OR NOT public.zasp_security_agent_principal_ready('zasp_security_agent_worker') OR (p.policy->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='pricing lookup authority changed';END IF;
 RETURN response_value;
END $lookup$;

DO $functions$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace AND proname LIKE 'pricing_%' AND proname<>'pricing_lock_scope' LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker',p);
 END LOOP;
END $functions$;
GRANT USAGE ON SCHEMA zasp_sa_multistep_prior TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.pricing_ready(text,text,text) TO zasp_discovery_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.pricing_admin(text,text,jsonb) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.pricing_lookup(text,text,jsonb) TO zasp_security_agent_worker;
