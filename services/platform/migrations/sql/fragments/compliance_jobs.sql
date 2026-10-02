-- A single invocation is the transaction boundary. No process counters, audit
-- export identities, renderer output regeneration, or caller-selected storage.
CREATE ROLE zasp_compliance_worker NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_compliance_cleanup NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT zasp_compliance_worker,zasp_compliance_cleanup TO zasp_discovery_authority WITH ADMIN OPTION;
CREATE TABLE public.zasp_compliance_worker_bindings (
 principal_name text PRIMARY KEY CHECK(principal_name ~ '^[a-z][a-z0-9_]{2,62}$'),
 authority_role text UNIQUE NOT NULL CHECK(authority_role IN('zasp_compliance_worker','zasp_compliance_cleanup'))
);
CREATE TABLE public.zasp_compliance_export_policy (
 revision text PRIMARY KEY,
 controls integer NOT NULL CHECK(controls=500), records_per_control integer NOT NULL CHECK(records_per_control=100),
 format_bytes bigint NOT NULL CHECK(format_bytes=4194304), package_bytes bigint NOT NULL CHECK(package_bytes=8388608), snapshot_bytes bigint NOT NULL CHECK(snapshot_bytes=4194304),
 scope_active integer NOT NULL CHECK(scope_active=2), deployment_active integer NOT NULL CHECK(deployment_active=100),
 attempts integer NOT NULL CHECK(attempts=5), lease_seconds integer NOT NULL CHECK(lease_seconds=60), retry_seconds integer NOT NULL CHECK(retry_seconds=30), retention_seconds integer NOT NULL CHECK(retention_seconds=86400),
 scope_bytes bigint NOT NULL CHECK(scope_bytes=268435456), deployment_bytes bigint NOT NULL CHECK(deployment_bytes=17179869184),
 scope_jobs integer NOT NULL CHECK(scope_jobs=100), deployment_jobs integer NOT NULL CHECK(deployment_jobs=10000),
 job_grants integer NOT NULL CHECK(job_grants=5), principal_grants integer NOT NULL CHECK(principal_grants=20),
 CHECK(revision='compliance-limits-v1')
);
INSERT INTO public.zasp_compliance_export_policy VALUES('compliance-limits-v1',500,100,4194304,8388608,4194304,2,100,5,60,30,86400,268435456,17179869184,100,10000,5,20);
CREATE TABLE public.zasp_compliance_export_scopes (
 organization_id text NOT NULL CHECK(public.zasp_valid_product_id(organization_id)),
 workspace_id text NOT NULL CHECK(public.zasp_valid_product_id(workspace_id)),
 environment_id text NOT NULL CHECK(public.zasp_valid_product_id(environment_id)),
 last_claimed_at timestamptz NOT NULL DEFAULT '-infinity',
 PRIMARY KEY(organization_id,workspace_id,environment_id)
);
CREATE TABLE public.zasp_compliance_export_jobs (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 export_id text NOT NULL CHECK(public.zasp_valid_product_id(export_id)),
 principal_id text NOT NULL CHECK(public.zasp_valid_product_id(principal_id)),session_digest bytea NOT NULL CHECK(octet_length(session_digest)=32),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 policy_revision text NOT NULL REFERENCES public.zasp_compliance_export_policy(revision),mapping_revision text NOT NULL DEFAULT 'product-evidence-v1' CHECK(mapping_revision='product-evidence-v1'),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','completed','failed')),
 phase text NOT NULL DEFAULT 'queued' CHECK(phase IN('queued','collecting','uploading','terminal')),
 storage_state text NOT NULL DEFAULT 'reserved' CHECK(storage_state IN('reserved','intent','unknown','verified','reconcile_required','delete_pending','deleted')),
 failure_code text,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),retrieval_expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
 generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 5),
 worker_id text,lease_digest bytea CHECK(octet_length(lease_digest)=32),lease_expires_at timestamptz,lane text CHECK(lane IN('execute','reconcile','cleanup')),
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 snapshot jsonb,snapshot_digest bytea,snapshot_at timestamptz,
 package bytea,renderer_revision text,artifact_reference text,artifact_size bigint,artifact_digest bytea,format_sizes jsonb,
 receipt_version text,receipt_at timestamptz,
 retained_bytes bigint NOT NULL DEFAULT 12582912 CHECK(retained_bytes>=0),deleted_at timestamptz,deletion_audit_id text,
 PRIMARY KEY(organization_id,workspace_id,environment_id,export_id),
 UNIQUE(organization_id,workspace_id,environment_id,principal_id,idempotency_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_compliance_export_scopes,
 CHECK((snapshot IS NULL AND snapshot_digest IS NULL AND snapshot_at IS NULL) OR (snapshot IS NOT NULL AND octet_length(snapshot_digest)=32 AND snapshot_at IS NOT NULL)),
 CHECK((package IS NULL AND renderer_revision IS NULL AND artifact_reference IS NULL AND artifact_size IS NULL AND artifact_digest IS NULL AND format_sizes IS NULL) OR (package IS NOT NULL AND renderer_revision IS NOT NULL AND artifact_reference IS NOT NULL AND artifact_size=octet_length(package) AND artifact_size BETWEEN 1 AND 8388608 AND octet_length(artifact_digest)=32 AND format_sizes IS NOT NULL)),
 CHECK(receipt_version IS NULL OR length(receipt_version) BETWEEN 1 AND 1024),
 CHECK(state<>'completed' OR receipt_version IS NOT NULL),
 CHECK(storage_state<>'deleted' OR retained_bytes=0 AND package IS NULL AND snapshot IS NULL AND deleted_at IS NOT NULL AND deletion_audit_id IS NOT NULL)
);
CREATE INDEX zasp_compliance_export_due ON public.zasp_compliance_export_jobs(state,storage_state,next_attempt_at,lease_expires_at);
CREATE TABLE public.zasp_compliance_export_grants (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,export_id text NOT NULL,
 grant_digest bytea PRIMARY KEY CHECK(octet_length(grant_digest)=32),principal_id text NOT NULL,session_digest bytea NOT NULL CHECK(octet_length(session_digest)=32),
 format text NOT NULL CHECK(format IN('json','csv','readable')),expires_at timestamptz NOT NULL,used_at timestamptz,read_expires_at timestamptz,
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id) REFERENCES public.zasp_compliance_export_jobs
);
CREATE INDEX zasp_compliance_export_grant_quota ON public.zasp_compliance_export_grants(organization_id,workspace_id,environment_id,principal_id,export_id);

DO $tables$
DECLARE name_value text;
BEGIN
 FOREACH name_value IN ARRAY ARRAY['zasp_compliance_worker_bindings','zasp_compliance_export_policy','zasp_compliance_export_scopes','zasp_compliance_export_jobs','zasp_compliance_export_grants'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',name_value);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name_value);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name_value);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',name_value);
  EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',name_value||'_authority',name_value);
 END LOOP;
END $tables$;

CREATE FUNCTION public.zasp_compliance_jobs_catalog() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $catalog$
 WITH identities(value) AS (
 SELECT concat_ws('|','relation',c.relname,c.relowner::regrole::text,c.relkind,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings')
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,''),a.attidentity,a.attgenerated,a.attcollation::regcollation::text) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings'
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings'
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,(SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(p.polroles) r),pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings'
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND (starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings')
 UNION ALL SELECT concat_ws('|','role',rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolconnlimit,COALESCE(rolconfig::text,''),COALESCE(rolvaliduntil::text,'')) FROM pg_roles WHERE rolname IN('zasp_compliance_worker','zasp_compliance_cleanup')
 UNION ALL SELECT 'limits|'||to_jsonb(p)::text FROM public.zasp_compliance_export_policy p
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$catalog$;

CREATE FUNCTION public.zasp_compliance_worker_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $security$
 SELECT (SELECT count(*)=2 FROM pg_roles WHERE rolname IN('zasp_compliance_worker','zasp_compliance_cleanup') AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolconfig IS NULL)
 AND (SELECT count(*) IN(0,2) FROM public.zasp_compliance_worker_bindings)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_compliance_worker_bindings b LEFT JOIN pg_roles r ON r.rolname=b.principal_name WHERE r.oid IS NULL OR NOT r.rolcanlogin OR NOT r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR NOT pg_has_role(r.oid,b.authority_role,'MEMBER') OR EXISTS(SELECT 1 FROM pg_roles a WHERE starts_with(a.rolname,'zasp_') AND a.oid<>r.oid AND a.rolname<>b.authority_role AND pg_has_role(r.oid,a.oid,'MEMBER')) OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.roleid WHERE m.member=r.oid AND starts_with(a.rolname,'zasp_') AND (a.rolname<>b.authority_role OR m.admin_option OR NOT m.inherit_option OR m.set_option)))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname IN('zasp_compliance_worker','zasp_compliance_cleanup'))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.roleid JOIN pg_roles p ON p.oid=m.member WHERE a.rolname IN('zasp_compliance_worker','zasp_compliance_cleanup') AND NOT (p.rolname='zasp_discovery_authority' AND m.admin_option OR EXISTS(SELECT 1 FROM public.zasp_compliance_worker_bindings b WHERE b.principal_name=p.rolname AND b.authority_role=a.rolname AND NOT m.admin_option AND m.inherit_option AND NOT m.set_option)))
 AND (SELECT count(*)=2 FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.roleid JOIN pg_roles p ON p.oid=m.member WHERE a.rolname IN('zasp_compliance_worker','zasp_compliance_cleanup') AND p.rolname='zasp_discovery_authority' AND m.admin_option)
$security$;
CREATE FUNCTION public.zasp_compliance_require(expected_checksum text,expected_fingerprint text,role_value text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $require$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='compliance requires read committed';END IF;
 IF NOT public.zasp_compliance_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance release unavailable';END IF;
 IF role_value='zasp_discovery_api' THEN
  IF NOT public.zasp_discovery_principal_ready(role_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance API principal rejected';END IF;
 ELSIF role_value IN('zasp_compliance_worker','zasp_compliance_cleanup') THEN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_compliance_worker_bindings WHERE principal_name=session_user AND authority_role=role_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance worker principal rejected';END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance role rejected';END IF;
END $require$;
CREATE FUNCTION public.zasp_compliance_register_workers(executor_value text,cleanup_value text,expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $register$
DECLARE names text[]:=ARRAY[executor_value,cleanup_value];roles text[]:=ARRAY['zasp_compliance_worker','zasp_compliance_cleanup'];i integer;r record;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') OR NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance registration rejected';END IF;
 IF NOT COALESCE(executor_value~'^[a-z][a-z0-9_]{2,62}$' AND cleanup_value~'^[a-z][a-z0-9_]{2,62}$' AND executor_value<>cleanup_value,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance worker names rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-compliance-registration',0));
 IF NOT public.zasp_compliance_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance release unavailable';END IF;
 FOR i IN 1..2 LOOP
  SELECT * INTO r FROM pg_roles WHERE rolname=names[i];
  IF NOT FOUND OR NOT r.rolcanlogin OR NOT r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR EXISTS(SELECT 1 FROM pg_roles a WHERE starts_with(a.rolname,'zasp_') AND a.oid<>r.oid AND a.rolname<>roles[i] AND pg_has_role(r.oid,a.oid,'MEMBER')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance worker principal rejected';END IF;
  IF EXISTS(SELECT 1 FROM public.zasp_compliance_worker_bindings WHERE authority_role=roles[i] AND principal_name<>names[i]) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance worker already registered';END IF;
  EXECUTE format('GRANT %I TO %I WITH INHERIT TRUE, SET FALSE',roles[i],names[i]);
  INSERT INTO public.zasp_compliance_worker_bindings VALUES(names[i],roles[i]) ON CONFLICT DO NOTHING;
 END LOOP;
 IF NOT public.zasp_compliance_worker_security_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance worker security rejected';END IF;
 RETURN true;
END $register$;

CREATE FUNCTION public.zasp_compliance_export_public(j public.zasp_compliance_export_jobs) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $public$
 SELECT jsonb_build_object('export_id',j.export_id,'organization_id',j.organization_id,'workspace_id',j.workspace_id,'environment_id',j.environment_id,'state',j.state,'phase',j.phase,'failure_code',j.failure_code,'created_at',j.created_at,'retrieval_expires_at',j.retrieval_expires_at,'mapping_revision',j.mapping_revision)
$public$;
CREATE FUNCTION public.zasp_compliance_export_identity(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $identity$
BEGIN
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[org_value,workspace_value,environment_value,principal_value]) v WHERE NOT COALESCE(public.zasp_valid_product_id(v),false)) OR octet_length(session_value) IS DISTINCT FROM 32 OR session_value=decode(repeat('00',32),'hex') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance identity rejected';END IF;
 PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,principal_value,session_value);
END $identity$;
CREATE FUNCTION public.zasp_compliance_export_create(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,key_value text,request_value jsonb,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $create$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;p public.zasp_compliance_export_policy%ROWTYPE;request_hash bytea;
BEGIN
 PERFORM public.zasp_compliance_require(expected_checksum,expected_fingerprint,'zasp_discovery_api');
 PERFORM public.zasp_compliance_export_identity(org_value,workspace_value,environment_value,principal_value,session_value);
 IF key_value IS NULL OR length(key_value) NOT BETWEEN 1 AND 128 OR key_value !~ '^[A-Za-z0-9_.:-]+$' OR request_value IS NULL OR jsonb_typeof(request_value)<>'object' OR octet_length(request_value::text)>4096 OR EXISTS(SELECT 1 FROM jsonb_object_keys(request_value) k WHERE k NOT IN('framework','control_id')) OR request_value ? 'framework' AND (jsonb_typeof(request_value->'framework')<>'string' OR request_value->>'framework' NOT IN('soc2_security','hipaa')) OR request_value ? 'control_id' AND (jsonb_typeof(request_value->'control_id')<>'string' OR NOT EXISTS(SELECT 1 FROM public.zasp_compliance_mappings() m WHERE m.control_id=request_value->>'control_id' AND (NOT request_value?'framework' OR m.framework=request_value->>'framework'))) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance request rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_product_sessions WHERE token_digest=session_value AND authenticated_at>clock_timestamp()-interval '15 minutes') THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='compliance fresh authentication required';END IF;
 -- One persisted policy-row lock serializes admissions across replicas.
 SELECT * INTO STRICT p FROM public.zasp_compliance_export_policy WHERE revision='compliance-limits-v1' FOR UPDATE;
 PERFORM public.zasp_compliance_export_identity(org_value,workspace_value,environment_value,principal_value,session_value);
 IF NOT EXISTS(SELECT 1 FROM public.zasp_product_sessions WHERE token_digest=session_value AND authenticated_at>clock_timestamp()-interval '15 minutes') THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='compliance fresh authentication required';END IF;
 request_hash:=digest(convert_to(request_value::text,'UTF8'),'sha256');
 SELECT * INTO j FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,principal_id,idempotency_key)=(org_value,workspace_value,environment_value,principal_value,key_value);
 IF FOUND THEN IF j.request_digest<>request_hash THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance idempotency conflict';END IF;RETURN public.zasp_compliance_export_public(j);END IF;
 IF (SELECT count(*)>=p.scope_active FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id)=(org_value,workspace_value,environment_value) AND state='pending') OR (SELECT count(*)>=p.deployment_active FROM public.zasp_compliance_export_jobs WHERE state='pending') OR (SELECT count(*)>=p.scope_jobs OR COALESCE(sum(retained_bytes),0)+p.snapshot_bytes+p.package_bytes>p.scope_bytes FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id)=(org_value,workspace_value,environment_value) AND storage_state<>'deleted') OR (SELECT count(*)>=p.deployment_jobs OR COALESCE(sum(retained_bytes),0)+p.snapshot_bytes+p.package_bytes>p.deployment_bytes FROM public.zasp_compliance_export_jobs WHERE storage_state<>'deleted') THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='compliance capacity exhausted';END IF;
 INSERT INTO public.zasp_compliance_export_scopes(organization_id,workspace_id,environment_id) VALUES(org_value,workspace_value,environment_value) ON CONFLICT DO NOTHING;
 INSERT INTO public.zasp_compliance_export_jobs(organization_id,workspace_id,environment_id,export_id,principal_id,session_digest,idempotency_key,request,request_digest,policy_revision) VALUES(org_value,workspace_value,environment_value,'pid_'||gen_random_uuid(),principal_value,session_value,key_value,request_value,request_hash,p.revision) RETURNING * INTO j;
 RETURN public.zasp_compliance_export_public(j);
END $create$;
CREATE FUNCTION public.zasp_compliance_export_get(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,id_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $get$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;
BEGIN
 PERFORM public.zasp_compliance_require(expected_checksum,expected_fingerprint,'zasp_discovery_api');
 PERFORM public.zasp_compliance_export_identity(org_value,workspace_value,environment_value,principal_value,session_value);
 SELECT * INTO j FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,export_id,principal_id)=(org_value,workspace_value,environment_value,id_value,principal_value) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='compliance export not found';END IF;
 PERFORM public.zasp_compliance_export_identity(org_value,workspace_value,environment_value,principal_value,session_value);
 RETURN public.zasp_compliance_export_public(j);
END $get$;

CREATE FUNCTION public.zasp_compliance_export_claim(org_value text,workspace_value text,environment_value text,id_value text,worker_value text,token_value text,lane_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;first_scope record;
BEGIN
 PERFORM public.zasp_compliance_require(expected_checksum,expected_fingerprint,CASE WHEN lane_value='execute' THEN 'zasp_compliance_worker' ELSE 'zasp_compliance_cleanup' END);
 IF NOT COALESCE(worker_value~'^[A-Za-z0-9_.:-]{1,128}$' AND token_value~'^[a-f0-9]{64}$' AND lane_value IN('execute','reconcile','cleanup') AND public.zasp_valid_product_id(org_value) AND public.zasp_valid_product_id(workspace_value) AND public.zasp_valid_product_id(environment_value) AND public.zasp_valid_product_id(id_value),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance claim rejected';END IF;
 PERFORM 1 FROM public.zasp_compliance_export_policy WHERE revision='compliance-limits-v1' FOR UPDATE;
 SELECT * INTO j FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) FOR UPDATE;
 IF NOT FOUND OR j.lease_expires_at>clock_timestamp() OR j.next_attempt_at>clock_timestamp() THEN RETURN 'null'::jsonb;END IF;
 IF lane_value='execute' THEN
  IF j.state<>'pending' OR j.storage_state NOT IN('reserved','intent','unknown') OR j.attempt>=5 OR j.retrieval_expires_at<=clock_timestamp() THEN RETURN 'null'::jsonb;END IF;
  -- Round-robin scope service, including after executor restart. A discovery
  -- poll lists candidates in this same order; a caller cannot skip the head.
  SELECT s.organization_id,s.workspace_id,s.environment_id INTO first_scope FROM public.zasp_compliance_export_scopes s WHERE EXISTS(SELECT 1 FROM public.zasp_compliance_export_jobs x WHERE (x.organization_id,x.workspace_id,x.environment_id)=(s.organization_id,s.workspace_id,s.environment_id) AND x.state='pending' AND x.storage_state IN('reserved','intent','unknown') AND x.attempt<5 AND x.next_attempt_at<=clock_timestamp() AND (x.lease_expires_at IS NULL OR x.lease_expires_at<=clock_timestamp()) AND x.retrieval_expires_at>clock_timestamp()) ORDER BY s.last_claimed_at,s.organization_id,s.workspace_id,s.environment_id LIMIT 1;
  IF (first_scope.organization_id,first_scope.workspace_id,first_scope.environment_id) IS DISTINCT FROM (org_value,workspace_value,environment_value) THEN RETURN 'null'::jsonb;END IF;
  UPDATE public.zasp_compliance_export_scopes SET last_claimed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id)=(org_value,workspace_value,environment_value);
 ELSIF lane_value='reconcile' THEN IF j.storage_state<>'reconcile_required' THEN RETURN 'null'::jsonb;END IF;
 ELSE
  IF j.retrieval_expires_at>clock_timestamp() OR j.storage_state NOT IN('verified','reserved','delete_pending') OR EXISTS(SELECT 1 FROM public.zasp_compliance_export_grants g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.export_id)=(org_value,workspace_value,environment_value,id_value) AND g.read_expires_at>clock_timestamp()) THEN RETURN 'null'::jsonb;END IF;
 END IF;
 UPDATE public.zasp_compliance_export_jobs SET worker_id=worker_value,lease_digest=digest(token_value,'sha256'),generation=generation+1,lease_expires_at=clock_timestamp()+interval '60 seconds',lane=lane_value,attempt=attempt+CASE WHEN lane_value='execute' THEN 1 ELSE 0 END,phase=CASE WHEN lane_value='execute' THEN CASE WHEN package IS NULL THEN 'collecting' ELSE 'uploading' END ELSE phase END,storage_state=CASE WHEN lane_value='cleanup' THEN 'delete_pending' ELSE storage_state END WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) RETURNING * INTO j;
 RETURN jsonb_build_object('organization_id',org_value,'workspace_id',workspace_value,'environment_id',environment_value,'export_id',id_value,'generation',j.generation,'attempt',j.attempt,'lease_expires_at',j.lease_expires_at,'lane',j.lane,'captured',j.snapshot IS NOT NULL,'prepared',j.package IS NOT NULL,'reference',j.artifact_reference,'version',j.receipt_version,'size',j.artifact_size,'sha256',encode(j.artifact_digest,'hex'));
END $claim$;

CREATE FUNCTION public.zasp_compliance_export_locked(org_value text,workspace_value text,environment_value text,id_value text,worker_value text,token_value text,generation_value bigint,expected_checksum text,expected_fingerprint text) RETURNS public.zasp_compliance_export_jobs LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $locked$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='compliance requires read committed';END IF;
 SELECT * INTO j FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) FOR UPDATE;
 IF NOT FOUND OR j.worker_id IS DISTINCT FROM worker_value OR j.generation IS DISTINCT FROM generation_value OR j.lease_digest IS DISTINCT FROM digest(token_value,'sha256') OR NOT COALESCE(j.lease_expires_at>clock_timestamp(),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance lease rejected';END IF;
 PERFORM public.zasp_compliance_require(expected_checksum,expected_fingerprint,CASE WHEN j.lane='execute' THEN 'zasp_compliance_worker' ELSE 'zasp_compliance_cleanup' END);
 IF j.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance lease expired after readiness';END IF;
 RETURN j;
END $locked$;

CREATE FUNCTION public.zasp_compliance_export_capture(org_value text,workspace_value text,environment_value text,id_value text,worker_value text,token_value text,generation_value bigint,parameters_value jsonb,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $capture$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;captured jsonb;stamp timestamptz;valid_value boolean;overflow_value boolean;
BEGIN
 -- Statement1 locks the job; authorize locks session/membership before capture.
 -- VOLATILE SPI statements obtain new snapshots under READ COMMITTED. Raising
 -- below aborts the outer QueryRow statement, including the snapshot INSERT.
 j:=public.zasp_compliance_export_locked(org_value,workspace_value,environment_value,id_value,worker_value,token_value,generation_value,expected_checksum,expected_fingerprint);
 IF j.lane<>'execute' OR j.state<>'pending' OR parameters_value IS DISTINCT FROM '{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance capture rejected';END IF;
 PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,j.principal_id,j.session_digest);
 IF j.snapshot IS NULL THEN
  stamp:=clock_timestamp();
  -- Exactly one statement reads every source family and inserts the snapshot.
  -- Each mapped category reads one extra row and raises on overflow below.
  WITH sources AS MATERIALIZED (SELECT * FROM public.zasp_compliance_sources(org_value,workspace_value,environment_value)),
  mappings AS MATERIALIZED (SELECT * FROM public.zasp_compliance_mappings() m WHERE (NOT j.request?'framework' OR m.framework=j.request->>'framework') AND (NOT j.request?'control_id' OR m.control_id=j.request->>'control_id') LIMIT 501),
  records AS MATERIALIZED (SELECT m.control_id,to_jsonb(s) item FROM mappings m CROSS JOIN LATERAL (SELECT * FROM sources s WHERE s.source_family=ANY(m.required_sources) ORDER BY s.source_kind COLLATE "C",s.source_id COLLATE "C" LIMIT 101) s),
  document AS (SELECT jsonb_build_object('mapping_revision',j.mapping_revision,'snapshot_at',stamp,'organization_id',org_value,'workspace_id',workspace_value,'environment_id',environment_value,'controls',COALESCE((SELECT jsonb_agg(to_jsonb(m)||jsonb_build_object('records',COALESCE((SELECT jsonb_agg(r.item ORDER BY r.item->>'source_kind',r.item->>'source_id') FROM records r WHERE r.control_id=m.control_id),'[]'::jsonb)) ORDER BY m.framework,m.control_id) FROM mappings m),'[]'::jsonb)) body,
   (SELECT COALESCE(bool_and(source_valid AND source_time IS NOT NULL AND source_time<=stamp AND source_version>0 AND public.zasp_compliance_valid_target(source_kind,source_id)),true) FROM sources) valid,
   (SELECT count(*)>500 FROM mappings) OR EXISTS(SELECT 1 FROM records GROUP BY control_id HAVING count(*)>100) overflow),
  saved AS (UPDATE public.zasp_compliance_export_jobs SET snapshot=d.body,snapshot_at=stamp,snapshot_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') FROM document d WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) RETURNING snapshot)
  SELECT s.snapshot,d.valid,d.overflow INTO captured,valid_value,overflow_value FROM saved s CROSS JOIN document d;
  IF NOT valid_value THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance invalid source';END IF;
  IF overflow_value OR octet_length(captured::text)>4194304 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='compliance source overflow';END IF;
 ELSE captured:=j.snapshot;END IF;
 -- Separate post-capture statement, never a cached/pre-lock authority result.
 PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,j.principal_id,j.session_digest);
 IF j.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance lease expired during capture';END IF;
 RETURN jsonb_build_object('snapshot',captured,'sha256',encode(digest(convert_to(captured::text,'UTF8'),'sha256'),'hex'),'mapping_revision',j.mapping_revision);
END $capture$;

CREATE FUNCTION public.zasp_compliance_export_prepare_artifact(org_value text,workspace_value text,environment_value text,id_value text,worker_value text,token_value text,generation_value bigint,parameters_value jsonb,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $prepare$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;body bytea;
BEGIN
 j:=public.zasp_compliance_export_locked(org_value,workspace_value,environment_value,id_value,worker_value,token_value,generation_value,expected_checksum,expected_fingerprint);
 IF j.lane NOT IN('execute','reconcile') OR j.snapshot IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance preparation rejected';END IF;
 IF j.lane='execute' THEN PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,j.principal_id,j.session_digest);END IF;
 IF j.package IS NULL THEN
  IF j.lane<>'execute' OR jsonb_typeof(parameters_value) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(parameters_value))<>6 OR parameters_value->>'renderer_revision' !~ '^compliance-envelope-v[1-9][0-9]{0,3}$' OR parameters_value->>'reference' IS DISTINCT FROM id_value OR NOT COALESCE(parameters_value->>'bytes_hex' ~ '^[a-f0-9]+$' AND length(parameters_value->>'bytes_hex') BETWEEN 2 AND 16777216 AND length(parameters_value->>'bytes_hex')%2=0,false) OR parameters_value->>'sha256' !~ '^[a-f0-9]{64}$' OR jsonb_typeof(parameters_value->'format_sizes') IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(parameters_value->'format_sizes'))<>3 OR NOT (parameters_value->'format_sizes' ?& ARRAY['json','csv','readable']) OR EXISTS(SELECT 1 FROM jsonb_each_text(parameters_value->'format_sizes') f WHERE f.value !~ '^[1-9][0-9]{0,6}$' OR f.value::bigint>4194304) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance artifact intent rejected';END IF;
  body:=decode(parameters_value->>'bytes_hex','hex');
  IF parameters_value->>'size' IS DISTINCT FROM octet_length(body)::text OR decode(parameters_value->>'sha256','hex') IS DISTINCT FROM digest(body,'sha256') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance artifact digest rejected';END IF;
  UPDATE public.zasp_compliance_export_jobs SET package=body,renderer_revision=parameters_value->>'renderer_revision',artifact_reference=id_value,artifact_size=octet_length(body),artifact_digest=digest(body,'sha256'),format_sizes=parameters_value->'format_sizes',retained_bytes=octet_length(snapshot::text)+octet_length(body),phase='uploading',storage_state='intent' WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) RETURNING * INTO j;
 ELSIF parameters_value IS DISTINCT FROM '{}'::jsonb AND (parameters_value->>'bytes_hex' IS DISTINCT FROM encode(j.package,'hex') OR parameters_value->>'renderer_revision' IS DISTINCT FROM j.renderer_revision OR parameters_value->>'reference' IS DISTINCT FROM j.artifact_reference OR parameters_value->>'sha256' IS DISTINCT FROM encode(j.artifact_digest,'hex') OR parameters_value->>'size' IS DISTINCT FROM j.artifact_size::text OR parameters_value->'format_sizes' IS DISTINCT FROM j.format_sizes) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance artifact intent immutable';END IF;
 IF j.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance lease expired during preparation';END IF;
 RETURN jsonb_build_object('bytes_hex',encode(j.package,'hex'),'renderer_revision',j.renderer_revision,'reference',j.artifact_reference,'size',j.artifact_size,'sha256',encode(j.artifact_digest,'hex'),'format_sizes',j.format_sizes);
END $prepare$;
CREATE FUNCTION public.zasp_compliance_export_finish(org_value text,workspace_value text,environment_value text,id_value text,worker_value text,token_value text,generation_value bigint,parameters_value jsonb,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $finish$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;
BEGIN
 j:=public.zasp_compliance_export_locked(org_value,workspace_value,environment_value,id_value,worker_value,token_value,generation_value,expected_checksum,expected_fingerprint);
 IF j.lane NOT IN('execute','reconcile') OR j.package IS NULL OR jsonb_typeof(parameters_value) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(parameters_value))<>4 OR parameters_value->>'reference' IS DISTINCT FROM j.artifact_reference OR parameters_value->>'sha256' IS DISTINCT FROM encode(j.artifact_digest,'hex') OR parameters_value->>'size' IS DISTINCT FROM j.artifact_size::text OR NOT COALESCE(length(parameters_value->>'version') BETWEEN 1 AND 1024,false) OR digest(j.package,'sha256') IS DISTINCT FROM j.artifact_digest THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance receipt rejected';END IF;
 IF j.receipt_version IS NOT NULL AND j.receipt_version IS DISTINCT FROM parameters_value->>'version' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance receipt immutable';END IF;
 -- Reconciliation records storage facts even after requester revocation, but
 -- it never publishes a completed export or changes the prior public failure.
 IF j.lane='execute' THEN PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,j.principal_id,j.session_digest);END IF;
 IF j.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance lease expired during final authorization';END IF;
 UPDATE public.zasp_compliance_export_jobs SET receipt_version=parameters_value->>'version',receipt_at=clock_timestamp(),storage_state='verified',state=CASE WHEN lane='execute' THEN 'completed' ELSE state END,phase='terminal',lease_expires_at=NULL,lease_digest=NULL WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) RETURNING * INTO j;
 RETURN public.zasp_compliance_export_public(j);
END $finish$;
CREATE FUNCTION public.zasp_compliance_export_retry(org_value text,workspace_value text,environment_value text,id_value text,worker_value text,token_value text,generation_value bigint,parameters_value jsonb,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $retry$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;unknown_value boolean;
BEGIN
 j:=public.zasp_compliance_export_locked(org_value,workspace_value,environment_value,id_value,worker_value,token_value,generation_value,expected_checksum,expected_fingerprint);
 IF parameters_value IS NULL OR parameters_value NOT IN('{"outcome":"unknown"}'::jsonb,'{"outcome":"absent"}'::jsonb,'{"outcome":"source_failed"}'::jsonb,'{"outcome":"heartbeat"}'::jsonb) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance retry rejected';END IF;
 IF parameters_value->>'outcome'='heartbeat' THEN UPDATE public.zasp_compliance_export_jobs SET lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) RETURNING * INTO j;RETURN jsonb_build_object('renewed',true,'generation',j.generation,'attempt',j.attempt,'lease_expires_at',j.lease_expires_at);END IF;
 -- An absent/failed response cannot erase a previously uncertain write.
 unknown_value:=j.package IS NOT NULL AND (parameters_value->>'outcome'='unknown' OR j.storage_state IN('unknown','reconcile_required','intent'));
 UPDATE public.zasp_compliance_export_jobs SET state=CASE WHEN lane='execute' AND (attempt>=5 OR parameters_value->>'outcome'='source_failed') THEN 'failed' ELSE state END,phase=CASE WHEN lane='execute' AND (attempt>=5 OR parameters_value->>'outcome'='source_failed') THEN 'terminal' ELSE phase END,failure_code=CASE WHEN lane='execute' AND (attempt>=5 OR parameters_value->>'outcome'='source_failed') THEN CASE WHEN unknown_value THEN 'storage_unresolved' ELSE 'collection_failed' END ELSE failure_code END,storage_state=CASE WHEN lane='execute' AND unknown_value THEN CASE WHEN attempt>=5 OR parameters_value->>'outcome'='source_failed' THEN 'reconcile_required' ELSE 'unknown' END ELSE storage_state END,lease_expires_at=NULL,lease_digest=NULL,next_attempt_at=clock_timestamp()+interval '30 seconds' WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) RETURNING * INTO j;
 RETURN public.zasp_compliance_export_public(j);
END $retry$;

-- Grants count until bounded pruning removes them. The caller supplies only a
-- random bearer token; SQL stores its digest and never returns it in public JSON.
CREATE FUNCTION public.zasp_compliance_export_grant(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,id_value text,token_value text,format_value text,operation_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $grant$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;g public.zasp_compliance_export_grants%ROWTYPE;stamp timestamptz;
BEGIN
 PERFORM public.zasp_compliance_require(expected_checksum,expected_fingerprint,'zasp_discovery_api');
 PERFORM 1 FROM public.zasp_compliance_export_policy WHERE revision='compliance-limits-v1' FOR UPDATE;
 PERFORM public.zasp_compliance_export_identity(org_value,workspace_value,environment_value,principal_value,session_value);
 SELECT * INTO j FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,export_id,principal_id)=(org_value,workspace_value,environment_value,id_value,principal_value) FOR UPDATE;
 stamp:=clock_timestamp();
 IF NOT FOUND OR j.state<>'completed' OR j.storage_state<>'verified' OR j.retrieval_expires_at<=stamp THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='compliance export unavailable';END IF;
 IF NOT COALESCE(token_value~'^[a-f0-9]{64}$' AND format_value IN('json','csv','readable') AND operation_value IN('issue','read','consume','integrity_failure'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance grant rejected';END IF;
 IF operation_value='issue' THEN
  PERFORM public.zasp_compliance_export_identity(org_value,workspace_value,environment_value,principal_value,session_value);
  stamp:=clock_timestamp();
  IF j.retrieval_expires_at<=stamp THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='compliance retrieval expired';END IF;
  IF (SELECT count(*)>=5 FROM public.zasp_compliance_export_grants WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value)) OR (SELECT count(*)>=20 FROM public.zasp_compliance_export_grants WHERE (organization_id,workspace_id,environment_id,principal_id)=(org_value,workspace_value,environment_value,principal_value)) THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='compliance grant capacity exhausted';END IF;
  INSERT INTO public.zasp_compliance_export_grants VALUES(org_value,workspace_value,environment_value,id_value,digest(token_value,'sha256'),principal_value,session_value,format_value,least(stamp+interval '60 seconds',j.retrieval_expires_at),NULL,NULL) RETURNING * INTO g;
 ELSE
  SELECT * INTO g FROM public.zasp_compliance_export_grants WHERE grant_digest=digest(token_value,'sha256') AND (organization_id,workspace_id,environment_id,export_id,principal_id,session_digest,format)=(org_value,workspace_value,environment_value,id_value,principal_value,session_value,format_value) FOR UPDATE;
  IF NOT FOUND OR g.used_at IS NOT NULL OR g.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='compliance grant expired or used';END IF;
  -- Both job and grant locks have been acquired. A later statement snapshot
  -- must authorize read/consume before changing the grant or returning storage.
  PERFORM public.zasp_compliance_export_identity(org_value,workspace_value,environment_value,principal_value,session_value);
  IF j.retrieval_expires_at<=clock_timestamp() OR g.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='compliance retrieval expired';END IF;
  IF operation_value='read' THEN
   IF g.read_expires_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance read already leased';END IF;
   UPDATE public.zasp_compliance_export_grants SET read_expires_at=least(clock_timestamp()+interval '30 seconds',g.expires_at,j.retrieval_expires_at) WHERE grant_digest=g.grant_digest RETURNING * INTO g;
  ELSE
   IF g.read_expires_at IS NULL OR g.read_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='compliance read lease expired';END IF;
   UPDATE public.zasp_compliance_export_grants SET used_at=clock_timestamp(),read_expires_at=NULL WHERE grant_digest=g.grant_digest;
   IF operation_value='integrity_failure' THEN
    -- Commit safe bookkeeping; the HTTP caller denies disclosure separately.
    -- Marking the grant used makes this audit exactly once under replay.
    INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at)
    VALUES(org_value,workspace_value,environment_value,'pid_'||gen_random_uuid(),principal_value,'compliance.export.integrity_failed',id_value,'rejected',jsonb_build_object('export_id',id_value,'format',format_value,'reason','artifact_integrity'),clock_timestamp());
   END IF;
  END IF;
 END IF;
 RETURN CASE WHEN operation_value='read' THEN jsonb_build_object('reference',j.artifact_reference,'version',j.receipt_version,'size',j.artifact_size,'sha256',encode(j.artifact_digest,'hex'),'renderer_revision',j.renderer_revision,'read_expires_at',g.read_expires_at) ELSE jsonb_build_object('expires_at',g.expires_at,'consumed',operation_value IN('consume','integrity_failure')) END;
END $grant$;
CREATE FUNCTION public.zasp_compliance_export_cleanup(org_value text,workspace_value text,environment_value text,id_value text,worker_value text,token_value text,generation_value bigint,parameters_value jsonb,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $cleanup$
DECLARE j public.zasp_compliance_export_jobs%ROWTYPE;audit_value text;
BEGIN
 j:=public.zasp_compliance_export_locked(org_value,workspace_value,environment_value,id_value,worker_value,token_value,generation_value,expected_checksum,expected_fingerprint);
 IF j.lane<>'cleanup' OR j.storage_state<>'delete_pending' OR j.retrieval_expires_at>clock_timestamp() OR EXISTS(SELECT 1 FROM public.zasp_compliance_export_grants WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) AND read_expires_at>clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance cleanup blocked';END IF;
 IF parameters_value->>'outcome' IS DISTINCT FROM 'verified_absent' OR parameters_value->>'reference' IS DISTINCT FROM j.artifact_reference OR parameters_value->>'version' IS DISTINCT FROM j.receipt_version OR j.package IS NOT NULL AND j.receipt_version IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance exact-version absence required';END IF;
 audit_value:='pid_'||gen_random_uuid();
 INSERT INTO public.zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES(org_value,workspace_value,environment_value,audit_value,j.principal_id,'compliance.export.deleted',id_value,'succeeded',jsonb_build_object('export_id',id_value,'version',j.receipt_version,'reference',j.artifact_reference),clock_timestamp());
 UPDATE public.zasp_compliance_export_jobs SET state=CASE WHEN state='pending' THEN 'failed' ELSE state END,phase='terminal',storage_state='deleted',snapshot=NULL,snapshot_digest=NULL,snapshot_at=NULL,package=NULL,renderer_revision=NULL,artifact_reference=NULL,artifact_size=NULL,artifact_digest=NULL,format_sizes=NULL,retained_bytes=0,deleted_at=clock_timestamp(),deletion_audit_id=audit_value,lease_expires_at=NULL,lease_digest=NULL WHERE (organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) RETURNING * INTO j;
 RETURN public.zasp_compliance_export_public(j);
END $cleanup$;
CREATE FUNCTION public.zasp_compliance_export_maintenance(expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $maintenance$
DECLARE removed integer;
BEGIN
 PERFORM public.zasp_compliance_require(expected_checksum,expected_fingerprint,'zasp_compliance_cleanup');
 -- A process can die on attempt five, before recording a retry outcome. Intent
 -- already permits egress, so an expired final lease is an unknown write.
 WITH exhausted AS (SELECT organization_id,workspace_id,environment_id,export_id FROM public.zasp_compliance_export_jobs WHERE state='pending' AND (attempt>=5 OR retrieval_expires_at<=clock_timestamp()) AND (lease_expires_at IS NULL OR lease_expires_at<=clock_timestamp()) ORDER BY created_at LIMIT 100 FOR UPDATE SKIP LOCKED)
 UPDATE public.zasp_compliance_export_jobs j SET state='failed',phase='terminal',failure_code=CASE WHEN j.package IS NULL THEN 'collection_failed' ELSE 'storage_unresolved' END,storage_state=CASE WHEN j.package IS NULL THEN j.storage_state ELSE 'reconcile_required' END,lease_expires_at=NULL,lease_digest=NULL,next_attempt_at=clock_timestamp() FROM exhausted e WHERE (j.organization_id,j.workspace_id,j.environment_id,j.export_id)=(e.organization_id,e.workspace_id,e.environment_id,e.export_id);
 WITH expired AS (SELECT grant_digest FROM public.zasp_compliance_export_grants WHERE (used_at IS NOT NULL OR expires_at<=clock_timestamp()) AND (read_expires_at IS NULL OR read_expires_at<=clock_timestamp()) ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED) DELETE FROM public.zasp_compliance_export_grants g USING expired e WHERE g.grant_digest=e.grant_digest;
 GET DIAGNOSTICS removed=ROW_COUNT;
 RETURN jsonb_build_object('pruned_grants',removed);
END $maintenance$;

CREATE FUNCTION public.zasp_compliance_export_candidates(lane_value text,limit_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $candidates$
DECLARE result_value jsonb;
BEGIN
 PERFORM public.zasp_compliance_require(expected_checksum,expected_fingerprint,CASE WHEN lane_value='execute' THEN 'zasp_compliance_worker' ELSE 'zasp_compliance_cleanup' END);
 IF lane_value IS NULL OR lane_value NOT IN('execute','reconcile','cleanup') OR limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance discovery rejected';END IF;
 WITH due AS (
 SELECT j.organization_id,j.workspace_id,j.environment_id,j.export_id,s.last_claimed_at,j.created_at,row_number() OVER(PARTITION BY j.organization_id,j.workspace_id,j.environment_id ORDER BY j.created_at,j.export_id) ordinal
 FROM public.zasp_compliance_export_jobs j JOIN public.zasp_compliance_export_scopes s USING(organization_id,workspace_id,environment_id)
 WHERE (j.lease_expires_at IS NULL OR j.lease_expires_at<=clock_timestamp()) AND j.next_attempt_at<=clock_timestamp()
 AND CASE lane_value WHEN 'execute' THEN j.state='pending' AND j.storage_state IN('reserved','intent','unknown') AND j.attempt<5 AND j.retrieval_expires_at>clock_timestamp()
 WHEN 'reconcile' THEN j.storage_state='reconcile_required'
 ELSE j.retrieval_expires_at<=clock_timestamp() AND j.storage_state IN('verified','reserved','delete_pending') AND NOT EXISTS(SELECT 1 FROM public.zasp_compliance_export_grants g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.export_id)=(j.organization_id,j.workspace_id,j.environment_id,j.export_id) AND g.read_expires_at>clock_timestamp()) END),
 -- Execute scope ties must match claim admission even when an older job belongs
 -- to a later scope. Preserve the other lanes' age ordering and each scope's
 -- oldest-job ordinal before applying the bounded batch.
 bounded AS (SELECT * FROM due ORDER BY ordinal,last_claimed_at,CASE WHEN lane_value<>'execute' THEN created_at END,organization_id,workspace_id,environment_id,created_at,export_id LIMIT limit_value)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'export_id',export_id) ORDER BY ordinal,last_claimed_at,CASE WHEN lane_value<>'execute' THEN created_at END,organization_id,workspace_id,environment_id,created_at,export_id),'[]'::jsonb)) INTO result_value FROM bounded;
 RETURN result_value;
END $candidates$;

GRANT EXECUTE ON FUNCTION public.zasp_compliance_export_candidates(text,integer,text,text) TO zasp_compliance_worker,zasp_compliance_cleanup;
GRANT EXECUTE ON FUNCTION public.zasp_compliance_register_workers(text,text,text,text) TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION public.zasp_compliance_export_create(text,text,text,text,bytea,text,jsonb,text,text),public.zasp_compliance_export_get(text,text,text,text,bytea,text,text,text),public.zasp_compliance_export_grant(text,text,text,text,bytea,text,text,text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_compliance_export_claim(text,text,text,text,text,text,text,text,text),public.zasp_compliance_export_prepare_artifact(text,text,text,text,text,text,bigint,jsonb,text,text),public.zasp_compliance_export_finish(text,text,text,text,text,text,bigint,jsonb,text,text),public.zasp_compliance_export_retry(text,text,text,text,text,text,bigint,jsonb,text,text) TO zasp_compliance_worker,zasp_compliance_cleanup;
GRANT EXECUTE ON FUNCTION public.zasp_compliance_export_capture(text,text,text,text,text,text,bigint,jsonb,text,text) TO zasp_compliance_worker;
GRANT EXECUTE ON FUNCTION public.zasp_compliance_export_cleanup(text,text,text,text,text,text,bigint,jsonb,text,text),public.zasp_compliance_export_maintenance(text,text) TO zasp_compliance_cleanup;
