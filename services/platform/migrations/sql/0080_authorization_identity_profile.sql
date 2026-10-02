CREATE SCHEMA zasp_authorization80_identity AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization80_identity FROM PUBLIC;
CREATE TABLE zasp_authorization80_identity.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),catalog jsonb NOT NULL);
CREATE TABLE zasp_authorization80_identity.verifiers(
 purpose text PRIMARY KEY CHECK(purpose IN('session','webhook')),version text NOT NULL CHECK(version~'^[a-f0-9]{64}$'),key bytea NOT NULL CHECK(octet_length(key)=32),epoch bigint NOT NULL CHECK(epoch>0),
 audience text NOT NULL CHECK(audience~'^[a-f0-9]{64}$'),project text NOT NULL CHECK(project~'^project-[A-Za-z0-9_-]+$'),api_principal text NOT NULL,organization_pin text NOT NULL DEFAULT ''
);
CREATE TABLE zasp_authorization80_identity.attempts(
 state_digest bytea PRIMARY KEY CHECK(octet_length(state_digest)=32),attempt_id text NOT NULL UNIQUE CHECK(attempt_id~'^[a-f0-9]{64}$'),return_path text NOT NULL,
 consumed_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,phase text NOT NULL CHECK(phase IN('consumed','resolved','issued')),
 proof_digest bytea,key_epoch bigint,snapshot jsonb,session_id text,token_digest bytea,csrf_digest bytea,
 CHECK((phase='consumed' AND proof_digest IS NULL AND snapshot IS NULL) OR(phase IN('resolved','issued') AND octet_length(proof_digest)=32 AND key_epoch>0 AND snapshot IS NOT NULL)),
 CHECK(phase<>'issued' OR(session_id IS NOT NULL AND octet_length(token_digest)=32 AND octet_length(csrf_digest)=32))
);
CREATE INDEX attempts_expiry ON zasp_authorization80_identity.attempts(expires_at,state_digest);
-- Only closed consuming functions write this transaction-local authority record.
-- It is removed before every successful function return and rolls back on error.
CREATE TABLE zasp_authorization80_identity.permits(pid integer NOT NULL,tx xid8 NOT NULL,principal text NOT NULL,body jsonb NOT NULL,PRIMARY KEY(pid,tx));
CREATE FUNCTION zasp_authorization80_identity.immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity catalog immutable';END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_identity.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80_identity.immutable();
-- identity deprovision wrapper
CREATE FUNCTION zasp_authorization80_identity.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $gate$-- identity catalog body$gate$;

CREATE FUNCTION zasp_authorization80_identity.structural_ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT c='-- identity checksum' AND EXISTS(SELECT 1 FROM zasp_authorization80_identity.registration WHERE checksum=c)
 AND zasp_authorization80_identity.catalog_ready() AND zasp_authorization80.ready('-- identity80 checksum')
 AND EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE identity_mode='source19-canonical61-identity-v1' AND audit_mode='source52-canonical61-audit-v1')
 AND EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE checksum='-- identity audit checksum')
$$;
CREATE FUNCTION zasp_authorization80_identity.api_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_authorization80_identity.structural_ready('-- identity checksum') AND public.zasp_discovery_principal_ready('zasp_discovery_api')
 AND(SELECT count(*)=2 AND bool_and(api_principal=session_user) FROM zasp_authorization80_identity.verifiers)
$$;
CREATE FUNCTION zasp_authorization80_identity.register(p text,v text,k bytea,a text,project_value text,api_value text,pin text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result bigint;
BEGIN
 IF NOT zasp_authorization80_identity.structural_ready('-- identity checksum') OR NOT zasp_authorization79.operator()
 OR NOT COALESCE(p IN('session','webhook') AND octet_length(k)=32 AND v=encode(public.digest(k,'sha256'),'hex') AND a~'^[a-f0-9]{64}$' AND project_value~'^project-[A-Za-z0-9_-]+$' AND length(project_value)<=128 AND(pin='' OR(pin~'^organization-[A-Za-z0-9_-]+$' AND length(pin)<=128)),false)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=api_value AND authority_role='zasp_discovery_api')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity registration rejected';END IF;
 -- Registration never takes an organization lock. Consumers take key SHARE first.
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-identity-registration-'||p,0));
 INSERT INTO zasp_authorization80_identity.verifiers(purpose,version,key,epoch,audience,project,api_principal,organization_pin) VALUES(p,v,k,1,a,project_value,api_value,pin)
 ON CONFLICT(purpose) DO UPDATE SET version=EXCLUDED.version,key=EXCLUDED.key,audience=EXCLUDED.audience,project=EXCLUDED.project,api_principal=EXCLUDED.api_principal,organization_pin=EXCLUDED.organization_pin,
 epoch=CASE WHEN(verifiers.version,verifiers.key,verifiers.audience,verifiers.project,verifiers.api_principal,verifiers.organization_pin) IS NOT DISTINCT FROM(EXCLUDED.version,EXCLUDED.key,EXCLUDED.audience,EXCLUDED.project,EXCLUDED.api_principal,EXCLUDED.organization_pin) THEN verifiers.epoch ELSE verifiers.epoch+1 END RETURNING epoch INTO result;
 RETURN result;
END $$;
CREATE FUNCTION zasp_authorization80_identity.register_session(v text,k bytea,a text,p text,u text,o text) RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT zasp_authorization80_identity.register('session',v,k,a,p,u,o) $$;
CREATE FUNCTION zasp_authorization80_identity.register_webhook(v text,k bytea,a text,p text,u text,o text) RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT zasp_authorization80_identity.register('webhook',v,k,a,p,u,o) $$;
CREATE FUNCTION zasp_authorization80_identity.metadata() RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT zasp_authorization80_identity.api_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity runtime unavailable';END IF;
 RETURN(SELECT jsonb_object_agg(purpose,jsonb_build_object('version',version,'epoch',epoch,'audience',audience,'project',project,'api_principal',api_principal,'organization_pin',organization_pin)) FROM zasp_authorization80_identity.verifiers);
END $$;

CREATE FUNCTION zasp_authorization80_identity.verify(envelope text,purpose_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE outer_value json;bytes bytea;body_json json;body jsonb;v zasp_authorization80_identity.verifiers%ROWTYPE;now_ms bigint:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;fields text[];field text;
BEGIN
 IF NOT zasp_authorization80_identity.api_ready() OR envelope IS NULL OR octet_length(envelope)>98304 OR purpose_value NOT IN('session','webhook') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
 outer_value:=envelope::json;
 IF json_typeof(outer_value)<>'object' OR NOT zasp_authorization80.unique_json(outer_value) OR(SELECT count(*) FROM json_each(outer_value))<>3
 OR EXISTS(SELECT 1 FROM json_each(outer_value) WHERE key NOT IN('body','version','mac') OR json_typeof(value)<>'string') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
 SELECT * INTO STRICT v FROM zasp_authorization80_identity.verifiers WHERE purpose=purpose_value AND api_principal=session_user FOR SHARE;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 bytes:=decode(outer_value->>'body','base64');
 IF NOT COALESCE(octet_length(bytes) BETWEEN 1 AND 65536 AND outer_value->>'version'=v.version AND outer_value->>'mac'=encode(public.hmac(convert_to('zasp-identity-'||purpose_value||'-attestation-v1','UTF8')||decode('00','hex')||bytes,v.key,'sha256'),'hex'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
 body_json:=convert_from(bytes,'UTF8')::json;
 IF json_typeof(body_json)<>'object' OR NOT zasp_authorization80.unique_json(body_json) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
 body:=body_json::jsonb;
 fields:=ARRAY['domain','version','epoch','audience','project','profile','issued_at','expires_at','organization','member'];
 IF purpose_value='session' THEN fields:=fields||ARRAY['state_digest','attempt_id','session','groups','authenticated_at','external_expires_at','verified_at','token_digest','csrf_digest'];
 ELSE fields:=fields||ARRAY['event_id','event_kind','body_digest','audit_id'];END IF;
 IF(SELECT count(*) FROM jsonb_object_keys(body))<>cardinality(fields) OR EXISTS(SELECT 1 FROM jsonb_object_keys(body) k WHERE NOT k=ANY(fields)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
 FOREACH field IN ARRAY fields LOOP
  IF field IN('epoch','issued_at','expires_at','authenticated_at','external_expires_at','verified_at') THEN
   IF jsonb_typeof(body->field)<>'number' OR body->>field!~'^[0-9]+$' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
  ELSIF field='groups' THEN
   IF jsonb_typeof(body->field)<>'array' OR jsonb_array_length(body->field)>100 OR EXISTS(SELECT 1 FROM jsonb_array_elements(body->field) g WHERE jsonb_typeof(g)<>'string' OR g#>>'{}'!~'^scim-group-(test|live)-[A-Za-z0-9_-]+$' OR length(g#>>'{}') NOT BETWEEN 17 AND 128) OR(body->field) IS DISTINCT FROM(SELECT COALESCE(jsonb_agg(DISTINCT g ORDER BY g),'[]') FROM jsonb_array_elements(body->field) g) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
  ELSE IF jsonb_typeof(body->field)<>'string' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;END IF;
 END LOOP;
 IF NOT COALESCE(body->>'domain'='zasp-identity-'||purpose_value||'-attestation-v1' AND body->>'version'=v.version AND(body->>'epoch')::bigint=v.epoch AND body->>'audience'=v.audience AND body->>'project'=v.project AND body->>'profile'='-- identity checksum'
 AND(body->>'issued_at')::bigint<=now_ms+5000 AND(body->>'expires_at')::bigint>now_ms AND(body->>'expires_at')::bigint-(body->>'issued_at')::bigint BETWEEN 1 AND 60000
 AND body->>'organization'~'^organization-[A-Za-z0-9_-]+$' AND length(body->>'organization') BETWEEN 14 AND 128 AND(v.organization_pin='' OR body->>'organization'=v.organization_pin)
 AND body->>'member'~'^member-[A-Za-z0-9_-]+$' AND length(body->>'member') BETWEEN 8 AND 128,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
 IF purpose_value='session' THEN
  IF NOT COALESCE(body->>'state_digest'~'^[a-f0-9]{64}$' AND body->>'attempt_id'~'^[a-f0-9]{64}$' AND body->>'token_digest'~'^[a-f0-9]{64}$' AND body->>'csrf_digest'~'^[a-f0-9]{64}$' AND body->>'session'~'^member-session-[A-Za-z0-9_-]+$' AND length(body->>'session')<=128
  AND(body->>'authenticated_at')::bigint<=(body->>'verified_at')::bigint AND(body->>'verified_at')::bigint<=now_ms+5000 AND(body->>'verified_at')::bigint>now_ms-60000 AND(body->>'external_expires_at')::bigint>now_ms AND(body->>'external_expires_at')::bigint<=now_ms+86400000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
 ELSE
  IF NOT COALESCE(body->>'event_kind'='scim.member.delete' AND body->>'event_id'~'^webhook-event-(test|live)-[A-Za-z0-9_-]+$' AND length(body->>'event_id') BETWEEN 24 AND 128 AND body->>'body_digest'~'^[a-f0-9]{64}$' AND public.zasp_valid_product_id(body->>'audit_id'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';END IF;
 END IF;
 RETURN body||jsonb_build_object('_proof_digest',encode(public.digest(bytes,'sha256'),'hex'));
EXCEPTION WHEN data_exception OR no_data_found THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof rejected';
END $$;

CREATE FUNCTION zasp_authorization80_identity.set_permit(value jsonb) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 INSERT INTO zasp_authorization80_identity.permits(pid,tx,principal,body) VALUES(pg_backend_pid(),pg_current_xact_id(),session_user,value)
$$;
CREATE FUNCTION zasp_authorization80_identity.clear_permit() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 DELETE FROM zasp_authorization80_identity.permits WHERE pid=pg_backend_pid() AND tx=pg_current_xact_id() AND principal=session_user
$$;

CREATE FUNCTION zasp_authorization80_identity.begin_login(raw_state text,path text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT zasp_authorization80_identity.api_ready() OR NOT COALESCE(raw_state~'^[A-Za-z0-9_-]{43}$' AND length(path) BETWEEN 1 AND 2048 AND left(path,1)='/' AND left(path,2)<>'//' AND strpos(path,E'\\')=0 AND strpos(path,E'\n')=0 AND strpos(path,E'\r')=0,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity state rejected';END IF;
 PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','begin','state_digest',encode(public.digest(raw_state,'sha256'),'hex'),'return_path',path));
 INSERT INTO public.zasp_identity_states(state_digest,return_path,expires_at) VALUES(public.digest(raw_state,'sha256'),path,clock_timestamp()+interval '10 minutes');
 PERFORM zasp_authorization80_identity.clear_permit();RETURN true;
END $$;
CREATE FUNCTION zasp_authorization80_identity.consume_login(raw_state text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE state_row public.zasp_identity_states%ROWTYPE;attempt text:=encode(public.gen_random_bytes(32),'hex');
BEGIN
 IF NOT zasp_authorization80_identity.api_ready() OR NOT COALESCE(raw_state~'^[A-Za-z0-9_-]{43}$',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity state rejected';END IF;
 PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','consume','state_digest',encode(public.digest(raw_state,'sha256'),'hex')));
 UPDATE public.zasp_identity_states SET consumed_at=clock_timestamp() WHERE state_digest=public.digest(raw_state,'sha256') AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING * INTO state_row;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity state rejected';END IF;
 INSERT INTO zasp_authorization80_identity.attempts(state_digest,attempt_id,return_path,consumed_at,expires_at,phase) VALUES(state_row.state_digest,attempt,state_row.return_path,state_row.consumed_at,state_row.expires_at,'consumed');
 PERFORM zasp_authorization80_identity.clear_permit();
 RETURN jsonb_build_object('attempt_id',attempt,'state_digest',encode(state_row.state_digest,'hex'),'return_path',state_row.return_path);
END $$;

CREATE FUNCTION zasp_authorization80_identity.snapshot(o text,p text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT jsonb_build_object('principal_id',m.principal_id,'organization_id',m.organization_id,'organization_reference',m.organization_reference,'member_reference',m.member_reference,'role',m.role,'active',m.active,'version',m.version,
 'workspace_id',s.workspace_id,'environment_id',s.environment_id,'permissions',s.permissions,'groups',(SELECT COALESCE(jsonb_agg(g.group_reference ORDER BY g.group_reference),'[]') FROM public.zasp_identity_member_groups g WHERE g.organization_id=o AND g.principal_id=p),'desired',r.desired,'generation',r.generation)
 FROM public.zasp_identity_memberships m JOIN zasp_authorization79.organizations r ON r.organization_id=m.organization_id
 CROSS JOIN LATERAL(SELECT * FROM public.zasp_identity_admin_effective_scopes(p,o) ORDER BY is_default DESC,workspace_id,environment_id LIMIT 1)s
 WHERE m.organization_id=o AND m.principal_id=p AND m.active
$$;
CREATE FUNCTION zasp_authorization80_identity.resolve_login(envelope text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE b jsonb:=zasp_authorization80_identity.verify(envelope,'session');a zasp_authorization80_identity.attempts%ROWTYPE;o text;p text;result jsonb;snap jsonb;
BEGIN
 SELECT organization_id,principal_id INTO o,p FROM public.zasp_identity_memberships WHERE organization_reference=b->>'organization' AND member_reference=b->>'member' AND active;
 IF o IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity resolution rejected';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity resolution rejected';END IF;
 SELECT * INTO a FROM zasp_authorization80_identity.attempts WHERE state_digest=decode(b->>'state_digest','hex') AND attempt_id=b->>'attempt_id' FOR UPDATE;
 IF NOT FOUND OR a.expires_at<=clock_timestamp() OR a.phase='issued' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity resolution rejected';END IF;
 PERFORM 1 FROM public.zasp_identity_memberships WHERE organization_id=o AND principal_id=p AND organization_reference=b->>'organization' AND member_reference=b->>'member' AND active FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity resolution rejected';END IF;
 PERFORM zasp_authorization80_identity.require_session_time(b,a.expires_at);
 IF a.phase='resolved' THEN
  IF a.proof_digest IS DISTINCT FROM decode(b->>'_proof_digest','hex') OR a.key_epoch IS DISTINCT FROM(b->>'epoch')::bigint OR a.snapshot IS DISTINCT FROM zasp_authorization80_identity.snapshot(o,p) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity resolution replay rejected';END IF;
  PERFORM zasp_authorization80_identity.require_session_time(b,a.expires_at);
  RETURN a.snapshot;
 END IF;
 PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','resolve','organization_id',o,'principal_id',p,'groups',b->'groups'));
 result:=public.zasp_identity_admin_resolve_session(b->>'organization',b->>'member',b->'groups');
 snap:=zasp_authorization80_identity.snapshot(o,p);
 IF result IS NULL OR snap IS NULL OR result IS DISTINCT FROM(snap-ARRAY['version','groups','desired','generation']) OR snap->'groups' IS DISTINCT FROM b->'groups' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity resolution output rejected';END IF;
 UPDATE zasp_authorization80_identity.attempts SET phase='resolved',proof_digest=decode(b->>'_proof_digest','hex'),key_epoch=(b->>'epoch')::bigint,snapshot=snap WHERE state_digest=a.state_digest;
 PERFORM zasp_authorization80_identity.clear_permit();
 PERFORM zasp_authorization80_identity.require_session_time(b,a.expires_at);
 RETURN snap;
END $$;

CREATE FUNCTION zasp_authorization80_identity.body_time(b jsonb,k text) RETURNS timestamptz LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $$ SELECT to_timestamp((b->>k)::bigint/1000.0) $$;

-- Re-evaluate wall time after blocking work and before every session result.
-- This is private and cannot grant a permit or replace cryptographic admission.
CREATE FUNCTION zasp_authorization80_identity.require_session_time(b jsonb,attempt_expiry timestamptz) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE at_time timestamptz:=clock_timestamp();
BEGIN
 IF NOT COALESCE(attempt_expiry>at_time AND zasp_authorization80_identity.body_time(b,'expires_at')>at_time AND zasp_authorization80_identity.body_time(b,'external_expires_at')>at_time AND zasp_authorization80_identity.body_time(b,'verified_at')>at_time-interval '60 seconds',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity proof expired';END IF;
END $$;

CREATE FUNCTION zasp_authorization80_identity.issue_login(envelope text,raw_token text,raw_csrf text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE b jsonb:=zasp_authorization80_identity.verify(envelope,'session');a zasp_authorization80_identity.attempts%ROWTYPE;o text;p text;snap jsonb;result jsonb;s public.zasp_product_sessions%ROWTYPE;expected_revision bigint;
BEGIN
 IF NOT COALESCE(length(raw_token)=43 AND length(raw_csrf)=43 AND encode(public.digest(raw_token,'sha256'),'hex')=b->>'token_digest' AND encode(public.digest(raw_csrf,'sha256'),'hex')=b->>'csrf_digest',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity credential rejected';END IF;
 SELECT organization_id,principal_id INTO o,p FROM public.zasp_identity_memberships WHERE organization_reference=b->>'organization' AND member_reference=b->>'member' AND active;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity issuance rejected';END IF;
 SELECT * INTO a FROM zasp_authorization80_identity.attempts WHERE state_digest=decode(b->>'state_digest','hex') AND attempt_id=b->>'attempt_id' FOR UPDATE;
 IF NOT FOUND OR a.phase<>'resolved' OR a.expires_at<=clock_timestamp() OR a.proof_digest IS DISTINCT FROM decode(b->>'_proof_digest','hex') OR a.key_epoch IS DISTINCT FROM(b->>'epoch')::bigint THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity issuance rejected';END IF;
 PERFORM 1 FROM public.zasp_identity_memberships WHERE organization_id=o AND principal_id=p AND active FOR UPDATE;
 snap:=zasp_authorization80_identity.snapshot(o,p);
 IF snap IS NULL OR snap IS DISTINCT FROM a.snapshot THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity snapshot changed';END IF;
 PERFORM zasp_authorization80_identity.require_session_time(b,a.expires_at);
 expected_revision:=(snap->>'desired')::bigint+1;
 PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','issue','organization_id',o,'principal_id',p,'token_digest',b->>'token_digest','csrf_digest',b->>'csrf_digest','snapshot',snap,'expires_at',b->'external_expires_at'));
 result:=public.zasp_create_product_session(raw_token,raw_csrf,p,o,snap->>'workspace_id',snap->>'environment_id',snap->'permissions',zasp_authorization80_identity.body_time(b,'external_expires_at'));
 SELECT * INTO s FROM public.zasp_product_sessions WHERE token_digest=public.digest(raw_token,'sha256');
 IF NOT FOUND OR result IS DISTINCT FROM jsonb_build_object('principal_id',p,'organization_id',o,'workspace_id',snap->>'workspace_id','environment_id',snap->>'environment_id','permissions',snap->'permissions','csrf_token',raw_csrf)
 OR s.principal_id IS DISTINCT FROM p OR s.organization_id IS DISTINCT FROM o OR s.workspace_id IS DISTINCT FROM snap->>'workspace_id' OR s.environment_id IS DISTINCT FROM snap->>'environment_id' OR s.permissions IS DISTINCT FROM snap->'permissions' OR s.csrf_token IS DISTINCT FROM raw_csrf OR s.expires_at IS DISTINCT FROM zasp_authorization80_identity.body_time(b,'external_expires_at') OR s.authenticated_at IS DISTINCT FROM transaction_timestamp() OR s.revoked_at IS NOT NULL
 OR(zasp_authorization80_identity.snapshot(o,p)-'desired') IS DISTINCT FROM(snap-'desired')
 OR NOT EXISTS(SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=o AND desired=expected_revision AND generation=(snap->>'generation')::bigint)
 OR NOT EXISTS(SELECT 1 FROM zasp_authorization79.outbox WHERE organization_id=o AND revision=expected_revision)
 OR zasp_authorization80_identity.body_time(b,'expires_at')<=clock_timestamp() OR s.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity issuance output rejected';END IF;
 UPDATE zasp_authorization80_identity.attempts SET phase='issued',session_id=s.session_id,token_digest=s.token_digest,csrf_digest=public.digest(raw_csrf,'sha256') WHERE state_digest=a.state_digest;
 PERFORM zasp_authorization80_identity.clear_permit();
 PERFORM zasp_authorization80_identity.require_session_time(b,a.expires_at);
 RETURN result||jsonb_build_object('fresh_authenticated',true,'fresh_auth_expires_at',s.authenticated_at+interval '5 minutes');
END $$;

CREATE FUNCTION zasp_authorization80_identity.apply_verified_deprovision(envelope text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE b jsonb:=zasp_authorization80_identity.verify(envelope,'webhook');o text;p text;result jsonb;
BEGIN
 SELECT organization_id,principal_id INTO o,p FROM public.zasp_identity_memberships WHERE organization_reference=b->>'organization' AND member_reference=b->>'member';
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity deprovision rejected';END IF;
 PERFORM zasp_authorization80_identity.set_permit(b||jsonb_build_object('purpose','deprovision','organization_id',o,'principal_id',p));
 result:=public.zasp_identity_admin_reconcile_deprovision(b->>'project',b->>'event_id',b->>'organization',b->>'member',decode(b->>'body_digest','hex'),b->>'audit_id');
 IF NOT COALESCE(jsonb_typeof(result)='object' AND(result->>'processed')::boolean<>(result->>'replayed')::boolean AND(result->>'revoked_sessions')::bigint>=0 AND(result->>'revoked_tokens')::bigint>=0,false) OR zasp_authorization80_identity.body_time(b,'expires_at')<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity deprovision output rejected';END IF;
 PERFORM zasp_authorization80_identity.clear_permit();RETURN result;
END $$;

CREATE FUNCTION zasp_authorization80_identity.authenticate_pat(raw_token text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE t public.zasp_product_api_tokens%ROWTYPE;result jsonb;o text;
BEGIN
 IF NOT zasp_authorization80_identity.api_ready() OR NOT COALESCE(length(raw_token) BETWEEN 32 AND 512,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity credential rejected';END IF;
 -- Match resolve, issue, administration and deprovision lock order. Look up
 -- only the fence key first, then re-read the credential after acquiring it.
 SELECT organization_id INTO o FROM public.zasp_product_api_tokens WHERE token_digest=public.digest(raw_token,'sha256');
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity credential rejected';END IF;
 SELECT * INTO t FROM public.zasp_product_api_tokens WHERE token_digest=public.digest(raw_token,'sha256') AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND OR t.expires_at<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_memberships WHERE organization_id=t.organization_id AND principal_id=t.principal_id AND active)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(t.principal_id,t.organization_id) WHERE workspace_id=t.workspace_id AND environment_id=t.environment_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity credential rejected';END IF;
 PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','pat_use','organization_id',t.organization_id,'principal_id',t.principal_id,'token_digest',encode(t.token_digest,'hex')));
 UPDATE public.zasp_product_api_tokens SET last_used_at=clock_timestamp() WHERE token_digest=t.token_digest;
 PERFORM zasp_authorization80_identity.clear_permit();
 IF t.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity credential expired';END IF;
 RETURN jsonb_build_object('credential_id',t.id,'principal_id',t.principal_id,'organization_id',t.organization_id,'workspace_id',t.workspace_id,'environment_id',t.environment_id,'permissions','[]'::jsonb,'pat_ceiling',t.permissions);
END $$;

CREATE FUNCTION zasp_authorization80_identity.self_session(raw_token text,csrf text,o text,p text,w text,e text,logout boolean) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE s public.zasp_product_sessions%ROWTYPE;scope_row record;
BEGIN
 IF NOT zasp_authorization80_identity.api_ready() OR NOT COALESCE(length(raw_token) BETWEEN 32 AND 512 AND length(csrf) BETWEEN 32 AND 512 AND public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(p),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity self credential rejected';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 SELECT * INTO s FROM public.zasp_product_sessions WHERE token_digest=public.digest(raw_token,'sha256') AND organization_id=o AND principal_id=p AND csrf_token=csrf AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND OR s.expires_at<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_memberships WHERE organization_id=o AND principal_id=p AND active)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(p,o) WHERE workspace_id=s.workspace_id AND environment_id=s.environment_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity self credential rejected';END IF;
 IF logout THEN
  IF w IS NOT NULL OR e IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity self credential rejected';END IF;
  PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','logout','organization_id',o,'principal_id',p,'token_digest',encode(s.token_digest,'hex')));
  UPDATE public.zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=s.token_digest;
  PERFORM zasp_authorization80_identity.clear_permit();
  IF s.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity self credential expired';END IF;
  RETURN jsonb_build_object('revoked',true);
 END IF;
 SELECT * INTO scope_row FROM public.zasp_identity_admin_effective_scopes(p,o) WHERE workspace_id=w AND environment_id=e;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity scope rejected';END IF;
 PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','switch','organization_id',o,'principal_id',p,'token_digest',encode(s.token_digest,'hex'),'workspace_id',w,'environment_id',e,'permissions',scope_row.permissions));
 UPDATE public.zasp_product_sessions SET workspace_id=w,environment_id=e,permissions=scope_row.permissions WHERE token_digest=s.token_digest;
 PERFORM zasp_authorization80_identity.clear_permit();
 IF s.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity self credential expired';END IF;
 RETURN jsonb_build_object('principal_id',p,'organization_id',o,'workspace_id',w,'environment_id',e,'permissions','[]'::jsonb,'csrf_token',csrf,'fresh_authenticated',s.authenticated_at>clock_timestamp()-interval '5 minutes','fresh_auth_expires_at',s.authenticated_at+interval '5 minutes');
END $$;
CREATE FUNCTION zasp_authorization80_identity.logout(raw_token text,csrf text,o text,p text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT zasp_authorization80_identity.self_session(raw_token,csrf,o,p,NULL,NULL,true) $$;
CREATE FUNCTION zasp_authorization80_identity.switch_scope(raw_token text,csrf text,o text,p text,w text,e text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT zasp_authorization80_identity.self_session(raw_token,csrf,o,p,w,e,false) $$;

CREATE FUNCTION zasp_authorization80_identity.cleanup_expired(n integer) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result integer;
BEGIN
 IF NOT zasp_authorization80_identity.structural_ready('-- identity checksum') OR NOT zasp_authorization79.operator() OR n IS NULL OR n NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity cleanup rejected';END IF;
 -- One day retains the short-lived resolution snapshot for operational diagnosis.
 -- State rows remain expired after attempt deletion. No audit/receipt is removed.
 WITH expired AS(SELECT state_digest FROM zasp_authorization80_identity.attempts WHERE expires_at<clock_timestamp()-interval '1 day' ORDER BY expires_at,state_digest FOR UPDATE SKIP LOCKED LIMIT n),deleted AS(DELETE FROM zasp_authorization80_identity.attempts a USING expired x WHERE a.state_digest=x.state_digest AND a.expires_at<clock_timestamp()-interval '1 day' RETURNING 1) SELECT count(*) INTO result FROM deleted;
 RETURN result;
END $$;

-- identity administration consumers
-- identity post-login reads
GRANT SELECT(state_digest,return_path,expires_at,consumed_at),INSERT(state_digest,return_path,expires_at),UPDATE(consumed_at) ON public.zasp_identity_states TO zasp_discovery_authority;
GRANT INSERT(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at) ON public.zasp_product_sessions TO zasp_discovery_authority;
DO $owners$ DECLARE value record;BEGIN
 FOR value IN SELECT oid::regclass name FROM pg_class WHERE relnamespace='zasp_authorization80_identity'::regnamespace AND relkind='r' LOOP
  EXECUTE format('ALTER TABLE %s OWNER TO zasp_discovery_authority',value.name);
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',value.name);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',value.name);
  EXECUTE format('CREATE POLICY authority ON %s TO zasp_discovery_authority USING(true) WITH CHECK(true)',value.name);
 END LOOP;
 FOR value IN SELECT oid::regprocedure name FROM pg_proc WHERE pronamespace='zasp_authorization80_identity'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',value.name);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',value.name);
 END LOOP;
END $owners$;
REVOKE ALL ON ALL TABLES IN SCHEMA zasp_authorization80_identity FROM PUBLIC,zasp_discovery_api;
GRANT USAGE ON SCHEMA zasp_authorization80_identity TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.post_login_snapshot(jsonb),zasp_authorization80_identity.post_login_read(jsonb,jsonb,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.structural_ready(text),zasp_authorization80_identity.metadata(),zasp_authorization80_identity.begin_login(text,text),zasp_authorization80_identity.consume_login(text),zasp_authorization80_identity.resolve_login(text),zasp_authorization80_identity.issue_login(text,text,text),zasp_authorization80_identity.apply_verified_deprovision(text),zasp_authorization80_identity.authenticate_pat(text),zasp_authorization80_identity.logout(text,text,text,text),zasp_authorization80_identity.switch_scope(text,text,text,text,text,text) TO zasp_discovery_api;
