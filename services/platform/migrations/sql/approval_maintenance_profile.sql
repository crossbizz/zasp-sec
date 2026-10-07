-- INACTIVE INTEGRATION CANDIDATE. Not a canonical numbered migration.
-- A reviewed installer must own/register/checksum/fingerprint this module,
-- provision a distinct restricted maintenance principal and verifier, and
-- establish composed projection + measured old external writer withdrawal.
-- This source never creates a task/grant or activates a delivery delegation.
CREATE SCHEMA zasp_approval_maintenance AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_approval_maintenance FROM PUBLIC;
CREATE TABLE zasp_approval_maintenance.registration(singleton boolean PRIMARY KEY CHECK(singleton), checksum text NOT NULL, fingerprint text NOT NULL, active boolean NOT NULL DEFAULT false);
CREATE TABLE zasp_approval_maintenance.principals(principal_name name PRIMARY KEY, authority_role name NOT NULL CHECK(authority_role='zasp_approval_maintenance_worker'));
CREATE TABLE zasp_approval_maintenance.verifiers(purpose text NOT NULL CHECK(purpose IN('approval-forward','approval-captured')),version text NOT NULL,key bytea NOT NULL CHECK(octet_length(key)=32),PRIMARY KEY(purpose,version));
-- An intent records only facts validated by the ORIGINAL native signed admit.
-- tx/backend/session equality is necessary: it is not an independently usable
-- admission receipt and cannot retroactively authorize an old notification.
CREATE TABLE zasp_approval_maintenance.origin_intents(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 family text NOT NULL CHECK(family IN('finding78','test74','ordered68')),facts jsonb NOT NULL,
 source_digest text NOT NULL CHECK(source_digest~'^[a-f0-9]{64}$'),
 transaction_id bigint NOT NULL,backend_id integer NOT NULL,principal_name name NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,transaction_id));
CREATE TABLE zasp_approval_maintenance.origins(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,delivery_id text NOT NULL,
 approval_id text NOT NULL,run_id text NOT NULL,family text,source_digest text,facts jsonb,
 payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32),destination_url text NOT NULL,secret_reference text NOT NULL,
 status text NOT NULL CHECK(status IN('paused_unsupported','captured_inactive','active','paused_denied','revoked')),
 delegation jsonb,PRIMARY KEY(organization_id,workspace_id,environment_id,delivery_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,delivery_id) REFERENCES public.zasp_security_agent_approval_notifications);
CREATE TABLE zasp_approval_maintenance.reservations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,delivery_id text NOT NULL,
 lease_owner text NOT NULL,lease_token text NOT NULL CHECK(lease_token~'^[a-f0-9]{64}$'),lease_expires_at timestamptz NOT NULL,
 payload_digest bytea NOT NULL,state text NOT NULL CHECK(state IN('reserved','paused','released','attempted','settled')),
 attempt integer,kind text CHECK(kind IN('delivery','secret_failure')),receipt jsonb,
 PRIMARY KEY(organization_id,workspace_id,environment_id,delivery_id,lease_token),
 FOREIGN KEY(organization_id,workspace_id,environment_id,delivery_id) REFERENCES zasp_approval_maintenance.origins);

CREATE FUNCTION zasp_approval_maintenance.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
 SELECT encode(digest(convert_to(jsonb_build_object('functions',(SELECT jsonb_agg(jsonb_build_array(p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,coalesce(p.proacl::text,'')) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_approval_maintenance'::regnamespace),'columns',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,c.relrowsecurity,c.relforcerowsecurity,c.relowner::regrole::text,coalesce(c.relacl::text,'')) ORDER BY c.relname,a.attnum) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped WHERE c.relnamespace='zasp_approval_maintenance'::regnamespace AND c.relkind='r'),'policies',(SELECT jsonb_agg(jsonb_build_array(c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY c.relname,p.polname) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_approval_maintenance'::regnamespace),'triggers',(SELECT jsonb_agg(jsonb_build_array(c.relname,t.tgname,pg_get_triggerdef(t.oid),t.tgenabled) ORDER BY c.relname,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_approval_maintenance'::regnamespace AND NOT t.tgisinternal),'constraints',(SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,pg_get_constraintdef(k.oid)) ORDER BY c.relname,k.conname) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_approval_maintenance'::regnamespace))::text,'UTF8'),'sha256'),'hex')
$f$;
CREATE FUNCTION zasp_approval_maintenance.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $r$
 SELECT coalesce((SELECT count(*)=1 AND bool_and(singleton AND checksum='-- approval maintenance checksum' AND fingerprint=zasp_approval_maintenance.fingerprint()) FROM zasp_approval_maintenance.registration),false) AND zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_temporal.ready()
$r$;
CREATE FUNCTION zasp_approval_maintenance.ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
 SELECT zasp_approval_maintenance.catalog_ready() IS TRUE AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE singleton AND active)
$ready$;
CREATE FUNCTION zasp_approval_maintenance.operator() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $op$
 SELECT zasp_authorization80_worker.operator() IS TRUE AND zasp_approval_maintenance.catalog_ready() IS TRUE
$op$;
CREATE FUNCTION zasp_approval_maintenance.register_principal(login_value name) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $register_principal$
BEGIN
 IF zasp_approval_maintenance.operator() IS NOT TRUE OR NOT EXISTS(SELECT 1 FROM pg_roles p JOIN pg_roles a ON a.rolname='zasp_approval_maintenance_worker' WHERE p.rolname=login_value AND p.rolcanlogin AND NOT(p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls OR p.rolinherit) AND NOT a.rolcanlogin AND NOT(a.rolsuper OR a.rolcreatedb OR a.rolcreaterole OR a.rolreplication OR a.rolbypassrls OR a.rolinherit) AND pg_has_role(p.oid,a.oid,'MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=a.oid) AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=p.oid AND(m.roleid<>a.oid OR m.admin_option))) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval principal registration rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-approval-maintenance-registration',0));
 IF EXISTS(SELECT 1 FROM zasp_approval_maintenance.principals WHERE principal_name<>login_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval principal registration changed';END IF;
 INSERT INTO zasp_approval_maintenance.principals VALUES(login_value,'zasp_approval_maintenance_worker') ON CONFLICT DO NOTHING;RETURN true;
END $register_principal$;
CREATE FUNCTION zasp_approval_maintenance.register_verifier(purpose_value text,version_value text,key_value bytea) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $register_verifier$
BEGIN
 IF zasp_approval_maintenance.operator() IS NOT TRUE OR purpose_value IS NULL OR purpose_value NOT IN('approval-forward','approval-captured') OR key_value IS NULL OR octet_length(key_value)<>32 OR version_value IS DISTINCT FROM encode(digest(key_value,'sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval verifier registration rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-approval-maintenance-key/'||purpose_value,0));
 IF EXISTS(SELECT 1 FROM zasp_approval_maintenance.verifiers WHERE purpose=purpose_value AND(version,key) IS DISTINCT FROM(version_value,key_value)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval verifier registration changed';END IF;
 INSERT INTO zasp_approval_maintenance.verifiers VALUES(purpose_value,version_value,key_value) ON CONFLICT DO NOTHING;RETURN true;
END $register_verifier$;
CREATE FUNCTION zasp_approval_maintenance.worker() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $w$
 SELECT zasp_approval_maintenance.ready() AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.principals b JOIN pg_roles p ON p.rolname=b.principal_name JOIN pg_roles a ON a.rolname=b.authority_role WHERE b.principal_name=session_user AND p.rolcanlogin AND NOT(p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls OR p.rolinherit) AND pg_has_role(p.oid,a.oid,'MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE m.member=p.oid AND(r.rolname<>b.authority_role OR m.admin_option)))
$w$;
CREATE FUNCTION zasp_approval_maintenance.capture_origin_intent(family_value text,q jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $capture$
DECLARE f jsonb;old_facts jsonb;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR zasp_approval_maintenance.ready() IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval origin unavailable';END IF;
 -- These are the real original signed/native readers; no caller-supplied
 -- facts, principal, grantor, task, source digest or after-the-fact grant.
 CASE family_value
 WHEN 'finding78' THEN PERFORM zasp_authorization80_worker.require_planning78('admit',q);f:=zasp_authorization80_worker.planning78_source('admit',q);
 WHEN 'test74' THEN PERFORM zasp_authorization80_worker.require_planning74('admit',q);f:=zasp_authorization80_worker.planning74_source('admit',q);
 WHEN 'ordered68' THEN PERFORM zasp_authorization80_worker.require_planning68('admit',q);f:=zasp_authorization80_worker.planning68_source('admit',q);
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval origin unsupported';END CASE;
 IF f->>'source_digest' IS NULL OR f->>'source_digest'!~'^[a-f0-9]{64}$' OR f->>'principal_id' IS NULL OR f->>'grantor_id' IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval origin unavailable';END IF;
 INSERT INTO zasp_approval_maintenance.origin_intents VALUES(f->>'organization_id',f->>'workspace_id',f->>'environment_id',f->>'run_id',family_value,f,f->>'source_digest',txid_current(),pg_backend_pid(),session_user) ON CONFLICT DO NOTHING;
 SELECT facts INTO STRICT old_facts FROM zasp_approval_maintenance.origin_intents WHERE(organization_id,workspace_id,environment_id,run_id,transaction_id,backend_id,principal_name,family)=(f->>'organization_id',f->>'workspace_id',f->>'environment_id',f->>'run_id',txid_current(),pg_backend_pid(),session_user,family_value);
 IF old_facts IS DISTINCT FROM f THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval origin changed';END IF;
END $capture$;
CREATE FUNCTION zasp_approval_maintenance.bind_enqueue_origin() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $bind$
DECLARE i zasp_approval_maintenance.origin_intents%ROWTYPE;a public.zasp_security_agent_approvals%ROWTYPE;BEGIN
 SELECT * INTO STRICT a FROM public.zasp_security_agent_approvals WHERE(organization_id,workspace_id,environment_id,approval_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.approval_id,NEW.run_id) FOR SHARE;
 SELECT * INTO i FROM zasp_approval_maintenance.origin_intents WHERE(organization_id,workspace_id,environment_id,run_id,transaction_id,backend_id,principal_name)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id,txid_current(),pg_backend_pid(),session_user);
 IF digest(convert_to(NEW.payload::text,'UTF8'),'sha256') IS DISTINCT FROM NEW.payload_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval payload changed';END IF;
 -- No task delegation is synthesized here. Validated origins are INACTIVE
 -- until a reviewed successor captures genuine bounded delivery delegation.
 INSERT INTO zasp_approval_maintenance.origins VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.delivery_id,NEW.approval_id,NEW.run_id,i.family,i.source_digest,i.facts,NEW.payload_digest,NEW.destination_url,NEW.secret_reference,CASE WHEN i.run_id IS NULL THEN 'paused_unsupported' ELSE 'captured_inactive' END,NULL);
 RETURN NEW;
END $bind$;
-- Trigger/wrapper attachment is deliberately NOT installed by this source:
-- predecessor catalog/trigger noninterference must first be proved. The exact
-- closed native admit wrapper must capture before original effect in SAME TX.

CREATE FUNCTION zasp_approval_maintenance.reference(n public.zasp_security_agent_approval_notifications) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public AS $ref$
 SELECT jsonb_build_object('organization_id',n.organization_id,'workspace_id',n.workspace_id,'environment_id',n.environment_id,'delivery_id',n.delivery_id,'lease_owner',n.lease_owner,'lease_token',n.lease_token,'payload_digest','sha256:'||encode(n.payload_digest,'hex'))
$ref$;
CREATE FUNCTION zasp_approval_maintenance.reserved(q jsonb) RETURNS zasp_approval_maintenance.reservations LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $reserved$
DECLARE r zasp_approval_maintenance.reservations%ROWTYPE;n public.zasp_security_agent_approval_notifications%ROWTYPE;BEGIN
 IF zasp_approval_maintenance.worker() IS NOT TRUE OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','delivery_id','lease_owner','lease_token','payload_digest']) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval reservation rejected';END IF;
 SELECT * INTO STRICT n FROM public.zasp_security_agent_approval_notifications WHERE(organization_id,workspace_id,environment_id,delivery_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'delivery_id') FOR UPDATE;
 SELECT * INTO STRICT r FROM zasp_approval_maintenance.reservations WHERE(organization_id,workspace_id,environment_id,delivery_id,lease_token)=(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id,q->>'lease_token') FOR UPDATE;
 IF zasp_approval_maintenance.reference(n) IS DISTINCT FROM q OR n.state<>'leased' OR n.lease_expires_at<=clock_timestamp() OR(r.lease_owner,r.lease_token,r.lease_expires_at,r.payload_digest) IS DISTINCT FROM(n.lease_owner,n.lease_token,n.lease_expires_at,n.payload_digest) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval reservation lost';END IF;RETURN r;
END $reserved$;
CREATE FUNCTION zasp_approval_maintenance.reserve(owner_value text,token_value text,seconds_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $reserve$
DECLARE n public.zasp_security_agent_approval_notifications%ROWTYPE;BEGIN
 IF zasp_approval_maintenance.worker() IS NOT TRUE OR owner_value IS NULL OR char_length(owner_value) NOT BETWEEN 3 AND 128 OR owner_value<>btrim(owner_value) OR owner_value~E'[\\x00\\r\\n]' OR token_value IS NULL OR seconds_value IS NULL OR token_value!~'^[a-f0-9]{64}$' OR seconds_value NOT BETWEEN 15 AND 60 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval reservation rejected';END IF;
 -- Only genuinely ACTIVE origins are candidates. Unsupported/inactive origins
 -- remain visible in origins; originals stay durable, not exhausted/deleted.
 SELECT x.* INTO n FROM public.zasp_security_agent_approval_notifications x JOIN zasp_approval_maintenance.origins o USING(organization_id,workspace_id,environment_id,delivery_id) WHERE o.status='active' AND o.delegation IS NOT NULL AND x.attempt<10 AND NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.reservations y WHERE(y.organization_id,y.workspace_id,y.environment_id,y.delivery_id,y.state)=(x.organization_id,x.workspace_id,x.environment_id,x.delivery_id,'attempted')) AND((x.state IN('pending','retryable') AND x.available_at<=clock_timestamp()) OR(x.state='leased' AND x.lease_expires_at<=clock_timestamp())) ORDER BY x.available_at,x.created_at,x.delivery_id FOR UPDATE OF x SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN '{"found":false}'::jsonb;END IF;
 -- Expired attempted receipts are not blindly resent. Exact recovery policy
 -- must settle/quarantine before another reservation can be issued.
 IF EXISTS(SELECT 1 FROM zasp_approval_maintenance.reservations r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id,r.state)=(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id,'attempted')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval attempt recovery required';END IF;
 UPDATE public.zasp_security_agent_approval_notifications SET state='leased',lease_owner=owner_value,lease_token=token_value,lease_expires_at=clock_timestamp()+make_interval(secs=>seconds_value),updated_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,delivery_id)=(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id) RETURNING * INTO n;
 INSERT INTO zasp_approval_maintenance.reservations(organization_id,workspace_id,environment_id,delivery_id,lease_owner,lease_token,lease_expires_at,payload_digest,state,attempt,kind,receipt) VALUES(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id,n.lease_owner,n.lease_token,n.lease_expires_at,n.payload_digest,'reserved',NULL,NULL,NULL);
 RETURN jsonb_build_object('found',true,'reference',zasp_approval_maintenance.reference(n),'expires_at',n.lease_expires_at);
END $reserve$;
CREATE FUNCTION zasp_approval_maintenance.release(q jsonb,denied boolean) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $release$
DECLARE r zasp_approval_maintenance.reservations%ROWTYPE;BEGIN
 IF denied IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval release rejected';END IF;r:=zasp_approval_maintenance.reserved(q);
 IF r.state<>'reserved' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval attempt recovery required';END IF;
 UPDATE public.zasp_security_agent_approval_notifications SET state='retryable',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,delivery_id)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id);
 UPDATE zasp_approval_maintenance.reservations SET state=CASE WHEN denied THEN 'paused' ELSE 'released' END WHERE(organization_id,workspace_id,environment_id,delivery_id,lease_token)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id,r.lease_token);
 IF denied THEN UPDATE zasp_approval_maintenance.origins SET status='paused_denied' WHERE(organization_id,workspace_id,environment_id,delivery_id)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id);END IF;
 RETURN jsonb_build_object('transition',CASE WHEN denied THEN 'paused' ELSE 'released' END);
END $release$;
ALTER TABLE zasp_approval_maintenance.reservations ADD COLUMN forward_digest bytea;
CREATE FUNCTION zasp_approval_maintenance.source(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $source$
DECLARE r zasp_approval_maintenance.reservations%ROWTYPE;n public.zasp_security_agent_approval_notifications%ROWTYPE;o zasp_approval_maintenance.origins%ROWTYPE;BEGIN
 r:=zasp_approval_maintenance.reserved(q);
 SELECT * INTO STRICT n FROM public.zasp_security_agent_approval_notifications WHERE(organization_id,workspace_id,environment_id,delivery_id)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id);
 SELECT * INTO STRICT o FROM zasp_approval_maintenance.origins WHERE(organization_id,workspace_id,environment_id,delivery_id)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id) FOR SHARE;
 IF o.status<>'active' OR o.delegation IS NULL OR o.family IS NULL OR o.family NOT IN('finding78','test74','ordered68') OR o.source_digest IS NULL OR o.source_digest!~'^[a-f0-9]{64}$' OR o.facts IS NULL OR(o.approval_id,o.run_id,o.payload_digest,o.destination_url,o.secret_reference) IS DISTINCT FROM(n.approval_id,n.run_id,n.payload_digest,n.destination_url,n.secret_reference) OR digest(convert_to(n.payload::text,'UTF8'),'sha256') IS DISTINCT FROM n.payload_digest THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval delegation unavailable';END IF;
 RETURN jsonb_build_object('reference',q,'approval_id',o.approval_id,'run_id',o.run_id,'family',o.family,'source_digest',o.source_digest,'facts',o.facts,'delegation',o.delegation,'destination_digest',encode(digest(convert_to(o.destination_url,'UTF8'),'sha256'),'hex'),'secret_reference_digest',encode(digest(convert_to(o.secret_reference,'UTF8'),'sha256'),'hex'),'lease_expires_at',r.lease_expires_at,'attempt',n.attempt,'session_user',session_user);
END $source$;
CREATE FUNCTION zasp_approval_maintenance.require_forward(phase text,q jsonb,envelope_value json) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $forward$
DECLARE b bytea;p jsonb;k bytea;now_ms bigint;v zasp_authorization79.organizations%ROWTYPE;f jsonb;BEGIN
 IF phase IS NULL OR phase NOT IN('before_secrets','before_delivery','before_secret_failure') OR zasp_approval_maintenance.worker() IS NOT TRUE OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval forward rejected';END IF;
 IF envelope_value IS NULL OR octet_length(envelope_value::text)>65536 OR NOT zasp_authorization80.unique_json(envelope_value) OR NOT zasp_sa_multistep_prior.closed(envelope_value::jsonb,ARRAY['body','version','mac']) OR EXISTS(SELECT 1 FROM json_each(envelope_value) WHERE json_typeof(value)<>'string') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval proof rejected';END IF;
 SELECT key INTO k FROM zasp_approval_maintenance.verifiers WHERE purpose='approval-forward' AND version=envelope_value->>'version' FOR SHARE;b:=decode(envelope_value->>'body','base64');
 IF k IS NULL OR octet_length(b) NOT BETWEEN 1 AND 32768 OR replace(encode(b,'base64'),E'\n','') IS DISTINCT FROM envelope_value->>'body' OR envelope_value->>'mac' IS DISTINCT FROM encode(hmac(convert_to('zasp-approval-forward-v1','UTF8')||decode('00','hex')||b,k,'sha256'),'hex') OR NOT zasp_authorization80.unique_json(convert_from(b,'UTF8')::json) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval proof rejected';END IF;
 p:=convert_from(b,'UTF8')::jsonb;
 IF NOT zasp_sa_multistep_prior.closed(p,ARRAY['purpose','key_version','phase','reference','revision','facts','issued_at','expires_at','session_user']) OR p->>'purpose' IS DISTINCT FROM 'approval-forward' OR p->>'key_version' IS DISTINCT FROM envelope_value->>'version' OR p->>'phase' IS DISTINCT FROM phase OR p->'reference' IS DISTINCT FROM q OR p->>'session_user' IS DISTINCT FROM session_user THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval proof binding rejected';END IF;
 SELECT * INTO STRICT v FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;
 IF v.desired<>v.applied OR p->'revision' IS DISTINCT FROM jsonb_build_object('organization_id',v.organization_id,'desired',v.desired,'applied',v.applied,'generation',v.generation,'store_id',v.store_id,'model_id',v.model_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval revision changed';END IF;
 f:=zasp_approval_maintenance.source(q);now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF p->'facts' IS DISTINCT FROM f OR NOT coalesce((p->>'issued_at')::bigint<=now_ms+5000 AND(p->>'expires_at')::bigint>now_ms AND(p->>'expires_at')::bigint-(p->>'issued_at')::bigint BETWEEN 1 AND 60000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval proof stale';END IF;
EXCEPTION WHEN data_exception THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval proof rejected';END $forward$;
CREATE FUNCTION zasp_approval_maintenance.begin_attempt(q jsonb,kind_value text,envelope_value json) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $begin_attempt$
DECLARE r zasp_approval_maintenance.reservations%ROWTYPE;n public.zasp_security_agent_approval_notifications%ROWTYPE;version_value text;k bytea;body_value bytea;receipt_value jsonb;decision_digest bytea;BEGIN
 IF kind_value IS NULL OR kind_value NOT IN('delivery','secret_failure') OR envelope_value IS NULL OR octet_length(envelope_value::text)>65536 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval attempt rejected';END IF;
 IF zasp_approval_maintenance.worker() IS NOT TRUE OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','delivery_id','lease_owner','lease_token','payload_digest']) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval attempt rejected';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;
 r:=zasp_approval_maintenance.reserved(q);decision_digest:=digest(convert_to(envelope_value::text,'UTF8'),'sha256');
 IF r.state='attempted' THEN
  IF r.kind IS DISTINCT FROM kind_value OR r.forward_digest IS DISTINCT FROM decision_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval attempt changed';END IF;
  RETURN jsonb_build_object('created',false,'captured_proof',replace(encode(convert_to(r.receipt::text,'UTF8'),'base64'),E'\n',''));
 END IF;
 IF r.state<>'reserved' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval attempt unavailable';END IF;
 PERFORM zasp_approval_maintenance.require_forward(CASE kind_value WHEN 'delivery' THEN 'before_delivery' ELSE 'before_secret_failure' END,q,envelope_value);
 UPDATE public.zasp_security_agent_approval_notifications SET attempt=attempt+1,updated_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,delivery_id)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id) AND state='leased' AND attempt<10 AND lease_expires_at>clock_timestamp() RETURNING * INTO n;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval attempt unavailable';END IF;
 SELECT version,key INTO STRICT version_value,k FROM zasp_approval_maintenance.verifiers WHERE purpose='approval-captured';
 body_value:=convert_to(jsonb_build_object('purpose','approval-captured','key_version',version_value,'reference',q,'attempt',n.attempt,'kind',kind_value,'lease_expires_at',r.lease_expires_at)::text,'UTF8');
 receipt_value:=jsonb_build_object('body',replace(encode(body_value,'base64'),E'\n',''),'version',version_value,'mac',encode(hmac(convert_to('zasp-approval-captured-v1','UTF8')||decode('00','hex')||body_value,k,'sha256'),'hex'));
 UPDATE zasp_approval_maintenance.reservations SET state='attempted',attempt=n.attempt,kind=kind_value,receipt=receipt_value,forward_digest=decision_digest WHERE(organization_id,workspace_id,environment_id,delivery_id,lease_token)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id,r.lease_token);
 RETURN jsonb_build_object('created',true,'captured_proof',replace(encode(convert_to(receipt_value::text,'UTF8'),'base64'),E'\n',''));
END $begin_attempt$;
CREATE FUNCTION zasp_approval_maintenance.settle(q jsonb,envelope_value json,successful boolean) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $settle$
DECLARE r zasp_approval_maintenance.reservations%ROWTYPE;n public.zasp_security_agent_approval_notifications%ROWTYPE;k bytea;b bytea;transition_value text;BEGIN
 IF successful IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval settlement rejected';END IF;r:=zasp_approval_maintenance.reserved(q);
 IF r.state<>'attempted' OR successful AND r.kind<>'delivery' OR envelope_value IS NULL OR octet_length(envelope_value::text)>65536 OR NOT zasp_authorization80.unique_json(envelope_value) OR envelope_value::jsonb IS DISTINCT FROM r.receipt THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval captured receipt rejected';END IF;
 SELECT key INTO STRICT k FROM zasp_approval_maintenance.verifiers WHERE purpose='approval-captured' AND version=envelope_value->>'version' FOR SHARE;b:=decode(envelope_value->>'body','base64');
 IF envelope_value->>'mac' IS DISTINCT FROM encode(hmac(convert_to('zasp-approval-captured-v1','UTF8')||decode('00','hex')||b,k,'sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval captured receipt rejected';END IF;
 SELECT * INTO STRICT n FROM public.zasp_security_agent_approval_notifications WHERE(organization_id,workspace_id,environment_id,delivery_id)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id);
 IF r.lease_expires_at<=clock_timestamp() OR n.attempt IS DISTINCT FROM r.attempt THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval attempt changed';END IF;
 transition_value:=CASE WHEN successful THEN 'delivered' WHEN n.attempt>=10 THEN 'exhausted' ELSE 'retryable' END;
 UPDATE public.zasp_security_agent_approval_notifications SET state=transition_value,available_at=CASE WHEN transition_value='retryable' THEN clock_timestamp()+make_interval(secs=>least(60,n.attempt*n.attempt)) ELSE available_at END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completed_at=CASE WHEN successful THEN clock_timestamp() ELSE NULL END,updated_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,delivery_id,state,lease_owner,lease_token,payload_digest,attempt)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id,'leased',r.lease_owner,r.lease_token,r.payload_digest,r.attempt) AND lease_expires_at=r.lease_expires_at AND lease_expires_at>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval captured lease lost';END IF;
 UPDATE zasp_approval_maintenance.reservations SET state='settled' WHERE(organization_id,workspace_id,environment_id,delivery_id,lease_token)=(r.organization_id,r.workspace_id,r.environment_id,r.delivery_id,r.lease_token);
 RETURN jsonb_build_object('transition',transition_value);
END $settle$;
-- Supported-family wrapper preserves the original native plan/admit body.
-- Original signed intent is checked BEFORE the original command mutates facts.
CREATE FUNCTION zasp_approval_maintenance.admit_with_origin(family_value text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $admit_origin$
DECLARE result_value jsonb;i zasp_approval_maintenance.origin_intents%ROWTYPE;n public.zasp_security_agent_approval_notifications%ROWTYPE;a public.zasp_security_agent_approvals%ROWTYPE;step_value text;BEGIN
 IF q->>'operation' IS DISTINCT FROM 'admit' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval admission rejected';END IF;
 PERFORM zasp_approval_maintenance.capture_origin_intent(family_value,q);
 CASE family_value WHEN 'finding78' THEN result_value:=zasp_temporal78.plan(q);WHEN 'test74' THEN result_value:=zasp_temporal74.plan(q);WHEN 'ordered68' THEN result_value:=zasp_temporal68.plan(q);ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval origin unsupported';END CASE;
 IF result_value->>'approval_id' IS NULL THEN RETURN result_value;END IF;
 step_value:=CASE family_value WHEN 'ordered68' THEN result_value->'step_ids'->>0 ELSE result_value->>'step_id' END;
 SELECT * INTO STRICT a FROM public.zasp_security_agent_approvals WHERE(organization_id,workspace_id,environment_id,run_id,approval_id,step_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',result_value->>'approval_id',step_value) AND 'sha256:'||encode(plan_hash,'hex')=result_value->>'plan_hash' FOR SHARE;
 SELECT * INTO n FROM public.zasp_security_agent_approval_notifications WHERE(organization_id,workspace_id,environment_id,run_id,approval_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.approval_id) AND created_at=transaction_timestamp() AND xmin::text::bigint=txid_current()%4294967296 FOR SHARE;
 -- No notification means original webhook configuration did not enqueue it.
 -- Old replayed notifications are not retroactively attributed to this proof.
 IF n.delivery_id IS NULL THEN RETURN result_value;END IF;
 SELECT * INTO STRICT i FROM zasp_approval_maintenance.origin_intents WHERE(organization_id,workspace_id,environment_id,run_id,transaction_id,backend_id,principal_name,family)=(n.organization_id,n.workspace_id,n.environment_id,n.run_id,txid_current(),pg_backend_pid(),session_user,family_value);
 IF digest(convert_to(n.payload::text,'UTF8'),'sha256') IS DISTINCT FROM n.payload_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval payload changed';END IF;
 INSERT INTO zasp_approval_maintenance.origins VALUES(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id,n.approval_id,n.run_id,i.family,i.source_digest,i.facts,n.payload_digest,n.destination_url,n.secret_reference,'captured_inactive',NULL) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.origins o WHERE(o.organization_id,o.workspace_id,o.environment_id,o.delivery_id,o.approval_id,o.run_id,o.family,o.source_digest,o.facts,o.payload_digest,o.destination_url,o.secret_reference)=(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id,n.approval_id,n.run_id,i.family,i.source_digest,i.facts,n.payload_digest,n.destination_url,n.secret_reference)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval origin changed';END IF;
 RETURN result_value;
END $admit_origin$;
CREATE FUNCTION zasp_approval_maintenance.record_unsupported() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $unsupported$
DECLARE changed integer;BEGIN
 IF zasp_approval_maintenance.worker() IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval maintenance unavailable';END IF;
 INSERT INTO zasp_approval_maintenance.origins
 SELECT n.organization_id,n.workspace_id,n.environment_id,n.delivery_id,n.approval_id,n.run_id,NULL,NULL,NULL,n.payload_digest,n.destination_url,n.secret_reference,'paused_unsupported',NULL FROM public.zasp_security_agent_approval_notifications n WHERE n.state NOT IN('delivered','exhausted') AND NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.origins o WHERE(o.organization_id,o.workspace_id,o.environment_id,o.delivery_id)=(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id)) ORDER BY n.available_at,n.created_at,n.delivery_id LIMIT 20 ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS changed=ROW_COUNT;RETURN changed;
END $unsupported$;
CREATE FUNCTION zasp_approval_maintenance.caller_ready(pin text,version_value text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $caller$
 SELECT zasp_approval_maintenance.worker() IS TRUE AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE checksum=pin) AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.verifiers WHERE purpose='approval-forward' AND version=version_value)
$caller$;
CREATE FUNCTION zasp_approval_maintenance.revision(o text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $revision$
DECLARE v jsonb;BEGIN
 IF zasp_approval_maintenance.worker() IS NOT TRUE OR NOT public.zasp_valid_product_id(o) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='approval revision unavailable';END IF;
 SELECT jsonb_build_object('organization_id',organization_id,'desired',desired,'applied',applied,'generation',generation,'store_id',store_id,'model_id',model_id) INTO STRICT v FROM zasp_authorization79.organizations WHERE organization_id=o;RETURN v;
END $revision$;
CREATE FUNCTION zasp_approval_maintenance.authorized_payload(q jsonb,envelope_value json) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $payload$
DECLARE n public.zasp_security_agent_approval_notifications%ROWTYPE;BEGIN
 PERFORM zasp_approval_maintenance.require_forward('before_secrets',q,envelope_value);
 SELECT * INTO STRICT n FROM public.zasp_security_agent_approval_notifications WHERE(organization_id,workspace_id,environment_id,delivery_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'delivery_id') FOR SHARE;
 IF n.lease_expires_at<=clock_timestamp() OR zasp_approval_maintenance.reference(n) IS DISTINCT FROM q THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval payload lease lost';END IF;
 RETURN jsonb_build_object('organization_id',n.organization_id,'workspace_id',n.workspace_id,'environment_id',n.environment_id,'delivery_id',n.delivery_id,'approval_id',n.approval_id,'run_id',n.run_id,'payload',n.payload::text,'payload_digest','sha256:'||encode(n.payload_digest,'hex'),'destination_url',n.destination_url,'secret_reference',n.secret_reference,'lease_token',n.lease_token,'lease_expires_at',n.lease_expires_at,'attempt',n.attempt);
END $payload$;
-- No public/API role can execute any of the functions. Registration and exact
-- restricted grants are pending reviewed native installer integration.
DO $seal$ DECLARE n record;BEGIN
 FOR n IN SELECT tablename FROM pg_tables WHERE schemaname='zasp_approval_maintenance' LOOP
  EXECUTE format('ALTER TABLE zasp_approval_maintenance.%I OWNER TO zasp_discovery_authority',n.tablename);
  EXECUTE format('ALTER TABLE zasp_approval_maintenance.%I ENABLE ROW LEVEL SECURITY',n.tablename);
  EXECUTE format('ALTER TABLE zasp_approval_maintenance.%I FORCE ROW LEVEL SECURITY',n.tablename);
  EXECUTE format('CREATE POLICY authority ON zasp_approval_maintenance.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n.tablename);
  EXECUTE format('REVOKE ALL ON TABLE zasp_approval_maintenance.%I FROM PUBLIC',n.tablename);
 END LOOP;
 FOR n IN SELECT p.oid::regprocedure signature FROM pg_proc p WHERE p.pronamespace='zasp_approval_maintenance'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',n.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',n.signature);
 END LOOP;
END $seal$;

-- Grants are included BEFORE installer fingerprint registration. Native role
-- is restricted/non-inheriting; clients SET LOCAL ROLE within owned calls.
GRANT USAGE ON SCHEMA zasp_approval_maintenance TO zasp_approval_maintenance_worker,zasp_temporal_executor,zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_approval_maintenance.catalog_ready(),zasp_approval_maintenance.ready(),zasp_approval_maintenance.worker(),zasp_approval_maintenance.reserve(text,text,integer),zasp_approval_maintenance.release(jsonb,boolean),zasp_approval_maintenance.source(jsonb),zasp_approval_maintenance.begin_attempt(jsonb,text,json),zasp_approval_maintenance.settle(jsonb,json,boolean),zasp_approval_maintenance.record_unsupported() TO zasp_approval_maintenance_worker;
GRANT EXECUTE ON FUNCTION zasp_approval_maintenance.admit_with_origin(text,jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_approval_maintenance.register_principal(name),zasp_approval_maintenance.register_verifier(text,text,bytea) TO zasp_discovery_authority;

GRANT EXECUTE ON FUNCTION zasp_approval_maintenance.caller_ready(text,text),zasp_approval_maintenance.revision(text),zasp_approval_maintenance.authorized_payload(jsonb,json) TO zasp_approval_maintenance_worker;
