DO $release_guard$
BEGIN
 IF NOT public.zasp_attack_lab_execution_readiness(
   (SELECT checksum FROM public.zasp_schema_versions WHERE version=26 AND name='attack_lab_execution'),
   (SELECT value FROM public.zasp_schema_metadata WHERE key='attack_lab_execution_fingerprint'))
   OR EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>26) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production recovery prerequisite rejected';
 END IF;
END
$release_guard$;

DO $roles$
DECLARE role_name text;role_row record;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['zasp_recovery_worker','zasp_recovery_outbox_worker'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',role_name);END IF;
  SELECT * INTO STRICT role_row FROM pg_roles WHERE rolname=role_name;
  IF role_row.rolcanlogin OR role_row.rolinherit OR role_row.rolsuper OR role_row.rolcreatedb OR role_row.rolcreaterole OR role_row.rolreplication OR role_row.rolbypassrls
    OR EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.member=role_row.oid OR membership.roleid=role_row.oid) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production recovery role rejected';
  END IF;
 END LOOP;
 GRANT zasp_recovery_worker,zasp_recovery_outbox_worker TO zasp_discovery_authority WITH ADMIN OPTION;
END
$roles$;

CREATE TABLE public.zasp_recovery_principal_bindings(
 principal_name text PRIMARY KEY CHECK(principal_name~'^[a-z][a-z0-9_]{2,62}$'),
 authority_role text NOT NULL UNIQUE CHECK(authority_role IN('zasp_recovery_worker','zasp_recovery_outbox_worker')),
 registered_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.zasp_recovery_backups(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,backup_id text NOT NULL,
 version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 1000000),state text NOT NULL DEFAULT 'queued' CHECK(state IN('queued','draining','capturing','publishing','succeeded','retryable','failed')),
 retention_days integer NOT NULL CHECK(retention_days BETWEEN 7 AND 90),actor_id text NOT NULL,idempotency_key text NOT NULL,request_digest bytea NOT NULL,
 hold_epoch bigint,attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),worker_id text,lease_token bytea,lease_expires_at timestamptz,available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 manifest jsonb,manifest_digest bytea,error_code text,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),started_at timestamptz,completed_at timestamptz,updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,backup_id),UNIQUE(organization_id,workspace_id,environment_id,actor_id,idempotency_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id),
 CHECK(zasp_valid_product_id(backup_id) AND zasp_valid_product_id(actor_id)),CHECK(length(idempotency_key) BETWEEN 16 AND 128),CHECK(octet_length(request_digest)=32),
 CHECK(hold_epoch IS NULL OR hold_epoch BETWEEN 1 AND 9223372036854775807),CHECK(worker_id IS NULL OR worker_id~'^[a-z][a-z0-9.-]{2,127}$'),CHECK(lease_token IS NULL OR octet_length(lease_token)=32),
 CHECK((state IN('draining','capturing','publishing'))=(worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK(manifest IS NULL OR jsonb_typeof(manifest)='object'),CHECK(manifest_digest IS NULL OR octet_length(manifest_digest)=32),CHECK(error_code IS NULL OR error_code~'^[a-z][a-z0-9_]{0,63}$'),
 CHECK((state='succeeded')=(manifest IS NOT NULL AND manifest_digest IS NOT NULL AND completed_at IS NOT NULL)),CHECK(state NOT IN('failed') OR completed_at IS NOT NULL)
);

CREATE TABLE public.zasp_recovery_restores(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,restore_id text NOT NULL,
 version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 1000000),state text NOT NULL DEFAULT 'queued' CHECK(state IN('queued','verifying','provisioning','validating','rebuilding','cleanup_required','cleaning','succeeded','retryable','failed','failed_cleanup')),
 actor_id text NOT NULL,idempotency_key text NOT NULL,request_digest bytea NOT NULL,target_environment text NOT NULL CHECK(target_environment~'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' AND target_environment<>'production'),manifest jsonb NOT NULL,manifest_digest bytea NOT NULL,
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),worker_id text,lease_token bytea,lease_expires_at timestamptz,available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 observed_counts jsonb,validation_evidence jsonb,cleanup_evidence jsonb,error_code text,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),started_at timestamptz,completed_at timestamptz,updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,restore_id),UNIQUE(organization_id,workspace_id,environment_id,actor_id,idempotency_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id),
 CHECK(zasp_valid_product_id(restore_id) AND zasp_valid_product_id(actor_id)),CHECK(length(idempotency_key) BETWEEN 16 AND 128),CHECK(octet_length(request_digest)=32),CHECK(octet_length(manifest_digest)=32),CHECK(jsonb_typeof(manifest)='object'),
 CHECK(worker_id IS NULL OR worker_id~'^[a-z][a-z0-9.-]{2,127}$'),CHECK(lease_token IS NULL OR octet_length(lease_token)=32),
 CHECK((state IN('verifying','provisioning','validating','rebuilding','cleanup_required','cleaning'))=(worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK(observed_counts IS NULL OR jsonb_typeof(observed_counts)='object'),CHECK(validation_evidence IS NULL OR jsonb_typeof(validation_evidence)='object'),CHECK(cleanup_evidence IS NULL OR jsonb_typeof(cleanup_evidence)='object'),
 CHECK(error_code IS NULL OR error_code~'^[a-z][a-z0-9_]{0,63}$'),CHECK((state IN('succeeded','failed','failed_cleanup'))=(completed_at IS NOT NULL))
);

CREATE TABLE public.zasp_recovery_holds(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,epoch bigint NOT NULL CHECK(epoch BETWEEN 1 AND 9223372036854775807),operation_id text NOT NULL,
 state text NOT NULL CHECK(state IN('requested','draining','held','released')),requested_at timestamptz NOT NULL DEFAULT transaction_timestamp(),held_at timestamptz,released_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id),FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id),
 CHECK(zasp_valid_product_id(operation_id)),CHECK((state='held')=(held_at IS NOT NULL AND released_at IS NULL) OR state<>'held'),CHECK(state<>'released' OR released_at IS NOT NULL)
);

CREATE TABLE public.zasp_recovery_outbox(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,outbox_id text NOT NULL,
 topic text NOT NULL CHECK(topic IN('recovery-backup-jobs','recovery-restore-jobs')),deterministic_key text NOT NULL,payload jsonb NOT NULL,payload_digest bytea NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','leased','published','retryable','exhausted')),attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 worker_id text,lease_token bytea,lease_expires_at timestamptz,provider_ack text,published_at timestamptz,error_code text,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,outbox_id),UNIQUE(topic,deterministic_key),FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id),
 CHECK(zasp_valid_product_id(outbox_id)),CHECK(length(deterministic_key) BETWEEN 16 AND 256),CHECK(jsonb_typeof(payload)='object'),CHECK(octet_length(payload_digest)=32),
 CHECK(worker_id IS NULL OR worker_id~'^[a-z][a-z0-9.-]{2,127}$'),CHECK(lease_token IS NULL OR octet_length(lease_token)=32),CHECK((state='leased')=(worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK(provider_ack IS NULL OR provider_ack~'^sha256:[a-f0-9]{64}$'),CHECK(error_code IS NULL OR error_code IN('queue_publish_unknown','lease_lost'))
);

CREATE TABLE public.zasp_recovery_fairness(
 topic text PRIMARY KEY CHECK(topic IN('recovery-backup-jobs','recovery-restore-jobs','recovery-operations')),
 last_organization_id text CHECK(last_organization_id IS NULL OR zasp_valid_product_id(last_organization_id)),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
INSERT INTO public.zasp_recovery_fairness(topic) VALUES('recovery-backup-jobs'),('recovery-restore-jobs'),('recovery-operations');

CREATE TABLE public.zasp_recovery_request_receipts(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,actor_id text NOT NULL,operation text NOT NULL,idempotency_key text NOT NULL,
 resource_id text NOT NULL,request_digest bytea NOT NULL,result jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),expires_at timestamptz NOT NULL DEFAULT transaction_timestamp()+interval '24 hours',
 PRIMARY KEY(organization_id,workspace_id,environment_id,actor_id,operation,idempotency_key),
 CHECK(zasp_valid_product_id(actor_id) AND zasp_valid_product_id(resource_id)),CHECK(operation IN('startRecoveryBackup','startRecoveryRestore')),CHECK(length(idempotency_key) BETWEEN 16 AND 128),CHECK(octet_length(request_digest)=32),CHECK(jsonb_typeof(result)='object')
);

CREATE TABLE public.zasp_recovery_audit(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,audit_id text NOT NULL,correlation_id text NOT NULL,receipt_id text NOT NULL,actor_id text NOT NULL,
 event_kind text NOT NULL CHECK(event_kind IN('recovery_backup_requested','recovery_restore_requested')),resource_id text NOT NULL,event_digest bytea NOT NULL,body jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,audit_id),UNIQUE(organization_id,receipt_id),CHECK(zasp_valid_product_id(audit_id) AND zasp_valid_product_id(correlation_id) AND zasp_valid_product_id(receipt_id) AND zasp_valid_product_id(actor_id) AND zasp_valid_product_id(resource_id)),
 CHECK(octet_length(event_digest)=32),CHECK(jsonb_typeof(body)='object')
);

CREATE INDEX zasp_recovery_backups_claim_idx ON public.zasp_recovery_backups(available_at,created_at) WHERE state IN('queued','retryable','draining','capturing','publishing');
CREATE INDEX zasp_recovery_restores_claim_idx ON public.zasp_recovery_restores(available_at,created_at) WHERE state IN('queued','retryable','verifying','provisioning','validating','rebuilding','cleanup_required','cleaning');
CREATE INDEX zasp_recovery_outbox_claim_idx ON public.zasp_recovery_outbox(topic,available_at,created_at) WHERE state IN('pending','retryable','leased');
CREATE INDEX zasp_recovery_receipts_expiry_idx ON public.zasp_recovery_request_receipts(expires_at);

DO $tables$
DECLARE table_name text;
BEGIN
 FOREACH table_name IN ARRAY ARRAY['zasp_recovery_principal_bindings','zasp_recovery_backups','zasp_recovery_restores','zasp_recovery_holds','zasp_recovery_outbox','zasp_recovery_fairness','zasp_recovery_request_receipts','zasp_recovery_audit'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',table_name);
  EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',table_name||'_authority',table_name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_discovery_api,zasp_recovery_worker,zasp_recovery_outbox_worker',table_name);EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO zasp_discovery_authority',table_name);
 END LOOP;
END
$tables$;

CREATE FUNCTION public.zasp_recovery_register_principals(migration_principal text,worker_principal text,outbox_principal text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $register$
DECLARE principals text[]:=ARRAY[worker_principal,outbox_principal];authorities text[]:=ARRAY['zasp_recovery_worker','zasp_recovery_outbox_worker'];index_value integer;role_value record;
BEGIN
 IF migration_principal<>session_user OR cardinality(ARRAY(SELECT DISTINCT unnest(ARRAY[migration_principal,worker_principal,outbox_principal])))<>3 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery principals rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-recovery-principal-registration',0));
 FOR index_value IN 1..2 LOOP
  SELECT role_row.oid,role_row.rolcanlogin,role_row.rolsuper,role_row.rolcreatedb,role_row.rolcreaterole,role_row.rolreplication,role_row.rolinherit,role_row.rolbypassrls INTO STRICT role_value FROM pg_roles role_row WHERE role_row.rolname=principals[index_value];
  IF NOT role_value.rolcanlogin OR NOT role_value.rolinherit OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR role_value.rolbypassrls OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=role_value.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>authorities[index_value]) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='recovery principal rejected';END IF;
  EXECUTE format('GRANT %I TO %I',authorities[index_value],principals[index_value]);
  INSERT INTO zasp_recovery_principal_bindings(principal_name,authority_role) VALUES(principals[index_value],authorities[index_value]) ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role WHERE zasp_recovery_principal_bindings.authority_role=excluded.authority_role;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='recovery principal conflict';END IF;
 END LOOP;
 RETURN true;
END
$register$;

CREATE FUNCTION public.zasp_recovery_principal_ready(expected_authority text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $principal$
 SELECT expected_authority IN('zasp_recovery_worker','zasp_recovery_outbox_worker')
 AND EXISTS(SELECT 1 FROM zasp_recovery_principal_bindings binding JOIN pg_roles principal ON principal.rolname=binding.principal_name WHERE binding.principal_name=session_user AND binding.authority_role=expected_authority AND principal.rolcanlogin AND principal.rolinherit AND NOT principal.rolsuper AND NOT principal.rolcreatedb AND NOT principal.rolcreaterole AND NOT principal.rolreplication AND NOT principal.rolbypassrls)
 AND pg_has_role(session_user,expected_authority,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
$principal$;

CREATE FUNCTION public.zasp_recovery_principals_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $principals$
 SELECT (SELECT count(*) FROM zasp_recovery_principal_bindings)=2
 AND NOT EXISTS(SELECT 1 FROM zasp_recovery_principal_bindings binding LEFT JOIN pg_roles principal ON principal.rolname=binding.principal_name WHERE principal.oid IS NULL OR NOT principal.rolcanlogin OR NOT principal.rolinherit OR principal.rolsuper OR principal.rolcreatedb OR principal.rolcreaterole OR principal.rolreplication OR principal.rolbypassrls OR NOT pg_has_role(principal.rolname,binding.authority_role,'MEMBER'))
$principals$;

CREATE FUNCTION public.zasp_recovery_scope_mutable(organization_value text,workspace_value text,environment_value text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $mutable$
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) THEN RETURN false;END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-recovery-hold',organization_value,workspace_value,environment_value),0));
 RETURN NOT EXISTS(SELECT 1 FROM zasp_recovery_holds WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND state IN('requested','draining','held'));
END
$mutable$;

CREATE FUNCTION public.zasp_recovery_guard_scope_mutation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard$
BEGIN
 IF TG_OP IN('UPDATE','DELETE') AND NOT zasp_recovery_scope_mutable(OLD.organization_id,OLD.workspace_id,OLD.environment_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='tenant recovery hold active';END IF;
 IF TG_OP IN('INSERT','UPDATE') AND NOT zasp_recovery_scope_mutable(NEW.organization_id,NEW.workspace_id,NEW.environment_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='tenant recovery hold active';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END
$guard$;

DO $guards$
DECLARE table_name text;
BEGIN
 FOR table_name IN
  SELECT class.relname
  FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace
  WHERE namespace.nspname='public' AND class.relkind='r' AND class.relname LIKE 'zasp_%' AND class.relname NOT LIKE 'zasp_recovery_%'
    AND EXISTS(SELECT 1 FROM pg_attribute attribute WHERE attribute.attrelid=class.oid AND attribute.attname='organization_id' AND attribute.attnum>0 AND NOT attribute.attisdropped)
    AND EXISTS(SELECT 1 FROM pg_attribute attribute WHERE attribute.attrelid=class.oid AND attribute.attname='workspace_id' AND attribute.attnum>0 AND NOT attribute.attisdropped)
    AND EXISTS(SELECT 1 FROM pg_attribute attribute WHERE attribute.attrelid=class.oid AND attribute.attname='environment_id' AND attribute.attnum>0 AND NOT attribute.attisdropped)
  ORDER BY class.relname
 LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.zasp_recovery_guard_scope_mutation()',table_name||'_recovery_hold',table_name);
 END LOOP;
END
$guards$;

CREATE FUNCTION public.zasp_recovery_create_backup(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,backup_value text,correlation_value text,retention_value integer,audit_value text,receipt_value text,request_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $create$
DECLARE receipt_row zasp_recovery_request_receipts%ROWTYPE;result_value jsonb;outbox_value text;payload_value jsonb;
BEGIN
 IF NOT zasp_discovery_principal_ready('zasp_discovery_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(backup_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(receipt_value) OR retention_value NOT BETWEEN 7 AND 90 OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR octet_length(request_digest_value)<>32 OR NOT zasp_recovery_scope_mutable(organization_value,workspace_value,environment_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery backup request rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'startRecoveryBackup',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_recovery_request_receipts WHERE (organization_id,workspace_id,environment_id,actor_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'startRecoveryBackup',idempotency_value);
 IF FOUND THEN IF receipt_row.resource_id<>backup_value OR receipt_row.request_digest<>request_digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery backup replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 INSERT INTO zasp_recovery_backups(organization_id,workspace_id,environment_id,backup_id,retention_days,actor_id,idempotency_key,request_digest) VALUES(organization_value,workspace_value,environment_value,backup_value,retention_value,actor_value,idempotency_value,request_digest_value);
 outbox_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'recovery_backup_outbox',backup_value);payload_value:=jsonb_build_object('backup_id',backup_value,'environment_id',environment_value,'organization_id',organization_value,'workspace_id',workspace_value);
 INSERT INTO zasp_recovery_outbox(organization_id,workspace_id,environment_id,outbox_id,topic,deterministic_key,payload,payload_digest) VALUES(organization_value,workspace_value,environment_value,outbox_value,'recovery-backup-jobs','backup:'||backup_value,payload_value,digest(convert_to(payload_value::text,'UTF8'),'sha256'));
 result_value:=jsonb_build_object('audit_id',audit_value,'body',jsonb_build_object('id',backup_value,'version',1,'state','queued','retention_days',retention_value,'attempt',0,'created_at',transaction_timestamp()),'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
 INSERT INTO zasp_recovery_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,receipt_value,actor_value,'recovery_backup_requested',backup_value,request_digest_value,result_value->'body');
 INSERT INTO zasp_recovery_request_receipts(organization_id,workspace_id,environment_id,actor_id,operation,idempotency_key,resource_id,request_digest,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'startRecoveryBackup',idempotency_value,backup_value,request_digest_value,result_value);
 RETURN result_value;
END
$create$;

CREATE FUNCTION public.zasp_recovery_create_restore(organization_value text,workspace_value text,environment_value text,actor_value text,idempotency_value text,restore_value text,target_value text,correlation_value text,audit_value text,receipt_value text,request_digest_value bytea,manifest_value jsonb,manifest_digest_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $create$
DECLARE receipt_row zasp_recovery_request_receipts%ROWTYPE;result_value jsonb;outbox_value text;payload_value jsonb;
BEGIN
 IF NOT zasp_discovery_principal_ready('zasp_discovery_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(restore_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(receipt_value) OR target_value!~'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' OR target_value='production' OR target_value=environment_value OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR octet_length(request_digest_value)<>32 OR octet_length(manifest_digest_value)<>32 OR jsonb_typeof(manifest_value)<>'object' OR octet_length(manifest_value::text)>8192
  OR (SELECT count(*) FROM jsonb_object_keys(manifest_value))<>8 OR NOT zasp_discovery_s3_object_reference(manifest_value->>'reference') OR substring(manifest_value->>'reference' FROM '^s3://[a-z0-9][a-z0-9.-]{2,62}/(.+)$') IS DISTINCT FROM 'organizations/'||organization_value||'/workspaces/'||workspace_value||'/environments/'||environment_value||'/artifacts/'||substring(manifest_value->>'reference' FROM '/artifacts/([^/]+)$') OR NOT zasp_valid_product_id(substring(manifest_value->>'reference' FROM '/artifacts/([^/]+)$')) OR length(manifest_value->>'version_id') NOT BETWEEN 1 AND 1024 OR manifest_value->>'version_id'<>btrim(manifest_value->>'version_id') OR manifest_value->>'version_id'~'[[:space:][:cntrl:]]'
  OR NOT (CASE WHEN manifest_value->>'sha256'~'^[a-f0-9]{64}$' THEN decode(manifest_value->>'sha256','hex')=manifest_digest_value ELSE false END) OR NOT (CASE WHEN jsonb_typeof(manifest_value->'size_bytes')='number' AND manifest_value->>'size_bytes'~'^[0-9]+$' THEN (manifest_value->>'size_bytes')::bigint BETWEEN 1 AND 67108864 ELSE false END)
  OR manifest_value->>'media_type'<>'application/vnd.zasp.recovery-manifest+json' OR manifest_value->>'schema'<>'recovery_signed_manifest_v1' OR manifest_value->>'signing_key_id'!~'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR jsonb_typeof(manifest_value->'signature')<>'string' OR length(manifest_value->>'signature') NOT BETWEEN 43 AND 684
  OR NOT zasp_recovery_scope_mutable(organization_value,workspace_value,environment_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery restore request rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'startRecoveryRestore',idempotency_value),0));
 SELECT * INTO receipt_row FROM zasp_recovery_request_receipts WHERE (organization_id,workspace_id,environment_id,actor_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'startRecoveryRestore',idempotency_value);
 IF FOUND THEN IF receipt_row.resource_id<>restore_value OR receipt_row.request_digest<>request_digest_value OR receipt_row.expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery restore replay rejected';END IF;RETURN receipt_row.result||jsonb_build_object('replayed',true);END IF;
 INSERT INTO zasp_recovery_restores(organization_id,workspace_id,environment_id,restore_id,actor_id,idempotency_key,request_digest,target_environment,manifest,manifest_digest) VALUES(organization_value,workspace_value,environment_value,restore_value,actor_value,idempotency_value,request_digest_value,target_value,manifest_value,manifest_digest_value);
 outbox_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'recovery_restore_outbox',restore_value);payload_value:=jsonb_build_object('environment_id',environment_value,'organization_id',organization_value,'restore_id',restore_value,'target_environment',target_value,'workspace_id',workspace_value);
 INSERT INTO zasp_recovery_outbox(organization_id,workspace_id,environment_id,outbox_id,topic,deterministic_key,payload,payload_digest) VALUES(organization_value,workspace_value,environment_value,outbox_value,'recovery-restore-jobs','restore:'||restore_value,payload_value,digest(convert_to(payload_value::text,'UTF8'),'sha256'));
 result_value:=jsonb_build_object('audit_id',audit_value,'body',jsonb_build_object('id',restore_value,'version',1,'state','queued','target_environment',target_value,'attempt',0,'manifest',manifest_value,'created_at',transaction_timestamp()),'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
 INSERT INTO zasp_recovery_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,receipt_value,actor_value,'recovery_restore_requested',restore_value,request_digest_value,result_value->'body');
 INSERT INTO zasp_recovery_request_receipts(organization_id,workspace_id,environment_id,actor_id,operation,idempotency_key,resource_id,request_digest,result) VALUES(organization_value,workspace_value,environment_value,actor_value,'startRecoveryRestore',idempotency_value,restore_value,request_digest_value,result_value);
 RETURN result_value;
END
$create$;

CREATE FUNCTION public.zasp_recovery_get_backup(organization_value text,workspace_value text,environment_value text,backup_value text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $get$
 SELECT jsonb_strip_nulls(jsonb_build_object('id',backup_id,'version',version,'state',state,'retention_days',retention_days,'attempt',attempt,'manifest',manifest,'error_code',error_code,'created_at',created_at,'started_at',started_at,'completed_at',completed_at)) FROM zasp_recovery_backups WHERE zasp_discovery_principal_ready('zasp_discovery_api') AND (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,backup_value)
$get$;

CREATE FUNCTION public.zasp_recovery_get_restore(organization_value text,workspace_value text,environment_value text,restore_value text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $get$
 SELECT jsonb_strip_nulls(jsonb_build_object('id',restore_id,'version',version,'state',state,'target_environment',target_environment,'attempt',attempt,'manifest',manifest,'observed_counts',observed_counts,'validation_evidence',validation_evidence,'cleanup_evidence',cleanup_evidence,'error_code',error_code,'created_at',created_at,'started_at',started_at,'completed_at',completed_at)) FROM zasp_recovery_restores WHERE zasp_discovery_principal_ready('zasp_discovery_api') AND (organization_id,workspace_id,environment_id,restore_id)=(organization_value,workspace_value,environment_value,restore_value)
$get$;

CREATE FUNCTION public.zasp_recovery_claim_outbox(topic_value text,worker_value text,token_value bytea,lease_seconds integer,limit_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE last_value text;items_value jsonb;new_last text;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_outbox_worker') OR topic_value NOT IN('recovery-backup-jobs','recovery-restore-jobs') OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 5 AND 900 OR limit_value NOT BETWEEN 1 AND 25 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery outbox claim rejected';END IF;
 UPDATE zasp_recovery_outbox SET state='exhausted',error_code='queue_publish_unknown',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE topic=topic_value AND state IN('pending','retryable','leased') AND attempt>=100 AND available_at<=transaction_timestamp() AND (state<>'leased' OR lease_expires_at<=transaction_timestamp());
 SELECT last_organization_id INTO last_value FROM zasp_recovery_fairness WHERE topic=topic_value FOR UPDATE;
 WITH ranked AS (SELECT outbox.*,row_number() OVER(PARTITION BY organization_id ORDER BY available_at,created_at,outbox_id) AS organization_rank FROM zasp_recovery_outbox outbox WHERE topic=topic_value AND state IN('pending','retryable','leased') AND attempt<100 AND available_at<=transaction_timestamp() AND (state<>'leased' OR lease_expires_at<=transaction_timestamp()) AND NOT EXISTS(SELECT 1 FROM zasp_recovery_outbox live WHERE live.organization_id=outbox.organization_id AND live.topic=topic_value AND live.state='leased' AND live.lease_expires_at>transaction_timestamp())),
 candidates AS (SELECT organization_id,workspace_id,environment_id,outbox_id FROM ranked WHERE organization_rank=1 ORDER BY (organization_id>COALESCE(last_value,'')) DESC,organization_id,available_at,created_at,outbox_id LIMIT limit_value FOR UPDATE SKIP LOCKED),
 claimed AS (UPDATE zasp_recovery_outbox target SET state='leased',attempt=attempt+1,worker_id=worker_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() FROM candidates WHERE (target.organization_id,target.workspace_id,target.environment_id,target.outbox_id)=(candidates.organization_id,candidates.workspace_id,candidates.environment_id,candidates.outbox_id) RETURNING target.*)
 SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'outbox_id',outbox_id,'topic',topic,'payload',payload,'payload_digest',payload_digest,'attempt',attempt,'lease_expires_at',lease_expires_at) ORDER BY organization_id),'[]'::jsonb),max(organization_id) INTO items_value,new_last FROM claimed;
 IF new_last IS NOT NULL THEN UPDATE zasp_recovery_fairness SET last_organization_id=new_last,updated_at=transaction_timestamp() WHERE topic=topic_value;END IF;
 RETURN jsonb_build_object('items',items_value);
END
$claim$;

CREATE FUNCTION public.zasp_recovery_heartbeat_outbox(topic_value text,worker_value text,token_value bytea,lease_seconds integer,expected_count integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
DECLARE renewed integer;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_outbox_worker') OR topic_value NOT IN('recovery-backup-jobs','recovery-restore-jobs') OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 5 AND 900 OR expected_count NOT BETWEEN 1 AND 25 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery outbox heartbeat rejected';END IF;
 UPDATE zasp_recovery_outbox SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp() WHERE topic=topic_value AND state='leased' AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp();GET DIAGNOSTICS renewed=ROW_COUNT;
 IF renewed<>expected_count THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery outbox lease lost';END IF;RETURN jsonb_build_object('lease_expires_at',transaction_timestamp()+make_interval(secs=>lease_seconds),'renewed',renewed);
END
$heartbeat$;

CREATE FUNCTION public.zasp_recovery_ack_outbox(organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value bytea,ack_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $ack$
DECLARE row_value zasp_recovery_outbox%ROWTYPE;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_outbox_worker') OR ack_value!~'^sha256:[a-f0-9]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery outbox ack rejected';END IF;
 SELECT * INTO STRICT row_value FROM zasp_recovery_outbox WHERE (organization_id,workspace_id,environment_id,outbox_id)=(organization_value,workspace_value,environment_value,outbox_value) FOR UPDATE;
 IF row_value.state='published' THEN IF row_value.provider_ack<>ack_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery outbox ack conflict';END IF;RETURN jsonb_build_object('replayed',true);END IF;
 IF row_value.state<>'leased' OR row_value.worker_id<>worker_value OR row_value.lease_token<>token_value OR row_value.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery outbox lease lost';END IF;
 UPDATE zasp_recovery_outbox SET state='published',provider_ack=ack_value,published_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,outbox_id)=(organization_value,workspace_value,environment_value,outbox_value);RETURN jsonb_build_object('replayed',false);
END
$ack$;

CREATE FUNCTION public.zasp_recovery_retry_outbox(organization_value text,workspace_value text,environment_value text,outbox_value text,worker_value text,token_value bytea,retry_seconds integer,error_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $retry$
DECLARE row_value zasp_recovery_outbox%ROWTYPE;next_state text;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_outbox_worker') OR retry_seconds NOT BETWEEN 1 AND 86400 OR error_value<>'queue_publish_unknown' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery outbox retry rejected';END IF;
 SELECT * INTO STRICT row_value FROM zasp_recovery_outbox WHERE (organization_id,workspace_id,environment_id,outbox_id)=(organization_value,workspace_value,environment_value,outbox_value) FOR UPDATE;
 IF row_value.state<>'leased' OR row_value.worker_id<>worker_value OR row_value.lease_token<>token_value OR row_value.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery outbox lease lost';END IF;
 next_state:=CASE WHEN row_value.attempt>=100 THEN 'exhausted' ELSE 'retryable' END;UPDATE zasp_recovery_outbox SET state=next_state,available_at=transaction_timestamp()+make_interval(secs=>retry_seconds),error_code=error_value,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,outbox_id)=(organization_value,workspace_value,environment_value,outbox_value);RETURN jsonb_build_object('state',next_state);
END
$retry$;

CREATE FUNCTION public.zasp_recovery_claim_operation(kind_value text,worker_value text,token_value bytea,lease_seconds integer,limit_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE last_value text;items_value jsonb;new_last text;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_worker') OR kind_value NOT IN('backup','restore') OR worker_value!~'^[a-z][a-z0-9.-]{2,127}$' OR octet_length(token_value)<>32 OR lease_seconds NOT BETWEEN 5 AND 900 OR limit_value NOT BETWEEN 1 AND 25 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery operation claim rejected';END IF;
 UPDATE zasp_recovery_backups SET state='failed',error_code='exhausted',completed_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE kind_value='backup' AND state IN('queued','retryable','draining','capturing','publishing') AND attempt>=100 AND available_at<=transaction_timestamp() AND (state NOT IN('draining','capturing','publishing') OR lease_expires_at<=transaction_timestamp());
 UPDATE zasp_recovery_holds hold SET state='released',released_at=transaction_timestamp() FROM zasp_recovery_backups backup WHERE kind_value='backup' AND (hold.organization_id,hold.workspace_id,hold.environment_id,hold.operation_id,hold.state)=(backup.organization_id,backup.workspace_id,backup.environment_id,backup.backup_id,'held') AND backup.state='failed' AND backup.error_code='exhausted';
 UPDATE zasp_recovery_restores SET state='failed',error_code='exhausted',completed_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE kind_value='restore' AND state IN('queued','retryable','verifying','provisioning','validating','rebuilding') AND attempt>=100 AND available_at<=transaction_timestamp() AND (state NOT IN('verifying','provisioning','validating','rebuilding') OR lease_expires_at<=transaction_timestamp());
 UPDATE zasp_recovery_restores SET state='failed_cleanup',error_code='cleanup_failed',completed_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE kind_value='restore' AND state IN('cleanup_required','cleaning') AND attempt>=100 AND available_at<=transaction_timestamp() AND lease_expires_at<=transaction_timestamp();
 SELECT last_organization_id INTO last_value FROM zasp_recovery_fairness WHERE topic='recovery-operations' FOR UPDATE;
 IF kind_value='backup' THEN
  WITH ranked AS (SELECT operation.*,row_number() OVER(PARTITION BY organization_id ORDER BY available_at,created_at,backup_id) AS organization_rank FROM zasp_recovery_backups operation WHERE state IN('queued','retryable','draining','capturing','publishing') AND attempt<100 AND available_at<=transaction_timestamp() AND (state NOT IN('draining','capturing','publishing') OR lease_expires_at<=transaction_timestamp()) AND NOT EXISTS(SELECT 1 FROM zasp_recovery_backups live WHERE live.organization_id=operation.organization_id AND live.state IN('draining','capturing','publishing') AND live.lease_expires_at>transaction_timestamp()) AND NOT EXISTS(SELECT 1 FROM zasp_recovery_restores live WHERE live.organization_id=operation.organization_id AND live.state IN('verifying','provisioning','validating','rebuilding','cleanup_required','cleaning') AND live.lease_expires_at>transaction_timestamp())),
  candidates AS (SELECT organization_id,workspace_id,environment_id,backup_id FROM ranked WHERE organization_rank=1 ORDER BY (organization_id>COALESCE(last_value,'')) DESC,organization_id,available_at,created_at,backup_id LIMIT limit_value FOR UPDATE SKIP LOCKED),
  claimed AS (UPDATE zasp_recovery_backups target SET state='draining',attempt=attempt+1,worker_id=worker_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),started_at=COALESCE(started_at,transaction_timestamp()),updated_at=transaction_timestamp() FROM candidates WHERE (target.organization_id,target.workspace_id,target.environment_id,target.backup_id)=(candidates.organization_id,candidates.workspace_id,candidates.environment_id,candidates.backup_id) RETURNING target.*)
  SELECT COALESCE(jsonb_agg(jsonb_build_object('attempt',attempt,'backup_id',backup_id,'environment_id',environment_id,'lease_expires_at',lease_expires_at,'organization_id',organization_id,'request_digest',request_digest,'retention_days',retention_days,'workspace_id',workspace_id) ORDER BY organization_id),'[]'::jsonb),max(organization_id) INTO items_value,new_last FROM claimed;
 ELSE
  WITH ranked AS (SELECT operation.*,row_number() OVER(PARTITION BY organization_id ORDER BY available_at,created_at,restore_id) AS organization_rank FROM zasp_recovery_restores operation WHERE state IN('queued','retryable','verifying','provisioning','validating','rebuilding','cleanup_required','cleaning') AND attempt<100 AND available_at<=transaction_timestamp() AND (state NOT IN('verifying','provisioning','validating','rebuilding','cleanup_required','cleaning') OR lease_expires_at<=transaction_timestamp()) AND NOT EXISTS(SELECT 1 FROM zasp_recovery_backups live WHERE live.organization_id=operation.organization_id AND live.state IN('draining','capturing','publishing') AND live.lease_expires_at>transaction_timestamp()) AND NOT EXISTS(SELECT 1 FROM zasp_recovery_restores live WHERE live.organization_id=operation.organization_id AND live.state IN('verifying','provisioning','validating','rebuilding','cleanup_required','cleaning') AND live.lease_expires_at>transaction_timestamp())),
  candidates AS (SELECT organization_id,workspace_id,environment_id,restore_id FROM ranked WHERE organization_rank=1 ORDER BY (organization_id>COALESCE(last_value,'')) DESC,organization_id,available_at,created_at,restore_id LIMIT limit_value FOR UPDATE SKIP LOCKED),
  claimed AS (UPDATE zasp_recovery_restores target SET state='verifying',attempt=attempt+1,worker_id=worker_value,lease_token=token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),started_at=COALESCE(started_at,transaction_timestamp()),updated_at=transaction_timestamp() FROM candidates WHERE (target.organization_id,target.workspace_id,target.environment_id,target.restore_id)=(candidates.organization_id,candidates.workspace_id,candidates.environment_id,candidates.restore_id) RETURNING target.*)
  SELECT COALESCE(jsonb_agg(jsonb_build_object('attempt',attempt,'environment_id',environment_id,'lease_expires_at',lease_expires_at,'manifest',manifest,'manifest_digest',manifest_digest,'organization_id',organization_id,'request_digest',request_digest,'restore_id',restore_id,'target_environment',target_environment,'workspace_id',workspace_id) ORDER BY organization_id),'[]'::jsonb),max(organization_id) INTO items_value,new_last FROM claimed;
 END IF;
 IF new_last IS NOT NULL THEN UPDATE zasp_recovery_fairness SET last_organization_id=new_last,updated_at=transaction_timestamp() WHERE topic='recovery-operations';END IF;RETURN jsonb_build_object('items',items_value);
END
$claim$;

CREATE FUNCTION public.zasp_recovery_heartbeat_operation(kind_value text,organization_value text,workspace_value text,environment_value text,operation_value text,worker_value text,token_value bytea,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
DECLARE expires_value timestamptz:=transaction_timestamp()+make_interval(secs=>lease_seconds);updated integer;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_worker') OR kind_value NOT IN('backup','restore') OR lease_seconds NOT BETWEEN 5 AND 900 OR octet_length(token_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery heartbeat rejected';END IF;
 IF kind_value='backup' THEN UPDATE zasp_recovery_backups SET lease_expires_at=expires_value,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,operation_value) AND state IN('draining','capturing','publishing') AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp();
 ELSE UPDATE zasp_recovery_restores SET lease_expires_at=expires_value,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,restore_id)=(organization_value,workspace_value,environment_value,operation_value) AND state IN('verifying','provisioning','validating','rebuilding','cleanup_required','cleaning') AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp();END IF;
 GET DIAGNOSTICS updated=ROW_COUNT;IF updated<>1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery operation lease lost';END IF;RETURN jsonb_build_object('lease_expires_at',expires_value);
END
$heartbeat$;

CREATE FUNCTION public.zasp_recovery_begin_hold(organization_value text,workspace_value text,environment_value text,backup_value text,worker_value text,token_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $hold$
DECLARE row_value zasp_recovery_backups%ROWTYPE;epoch_value bigint;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_worker') OR octet_length(token_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery hold rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-recovery-hold',organization_value,workspace_value,environment_value),0));
 SELECT * INTO STRICT row_value FROM zasp_recovery_backups WHERE (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,backup_value) FOR UPDATE;
 IF row_value.state<>'draining' OR row_value.worker_id<>worker_value OR row_value.lease_token<>token_value OR row_value.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery hold lease lost';END IF;
 epoch_value:=COALESCE((SELECT epoch+1 FROM zasp_recovery_holds WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value)),1);
 INSERT INTO zasp_recovery_holds(organization_id,workspace_id,environment_id,epoch,operation_id,state,requested_at,held_at) VALUES(organization_value,workspace_value,environment_value,epoch_value,backup_value,'held',transaction_timestamp(),transaction_timestamp()) ON CONFLICT(organization_id,workspace_id,environment_id) DO UPDATE SET epoch=excluded.epoch,operation_id=excluded.operation_id,state='held',requested_at=excluded.requested_at,held_at=excluded.held_at,released_at=NULL;
 UPDATE zasp_recovery_backups SET state='capturing',hold_epoch=epoch_value,version=version+1,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,backup_value);RETURN jsonb_build_object('epoch',epoch_value,'state','held');
END
$hold$;

CREATE FUNCTION public.zasp_recovery_release_hold(organization_value text,workspace_value text,environment_value text,backup_value text,worker_value text,token_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $release$
DECLARE updated integer;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_worker') OR octet_length(token_value)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery hold release rejected';END IF;
 PERFORM 1 FROM zasp_recovery_backups WHERE (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,backup_value) AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery hold lease lost';END IF;
 UPDATE zasp_recovery_holds SET state='released',released_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,operation_id,state)=(organization_value,workspace_value,environment_value,backup_value,'held');GET DIAGNOSTICS updated=ROW_COUNT;RETURN jsonb_build_object('released',updated=1);
END
$release$;

CREATE FUNCTION public.zasp_recovery_capture_page(organization_value text,workspace_value text,environment_value text,backup_value text,worker_value text,token_value bytea,section_value text,after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $capture$
DECLARE items_value jsonb;next_value text;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_worker') OR octet_length(token_value)<>32 OR section_value NOT IN('configuration','projection','evidence','counts') OR limit_value NOT BETWEEN 1 AND 100
  OR section_value='configuration' AND after_value IS NOT NULL AND after_value!~'^(integration|security_agent):pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR section_value IN('projection','evidence') AND after_value IS NOT NULL AND NOT zasp_valid_product_id(after_value)
  OR section_value='counts' AND (after_value IS NOT NULL OR limit_value<>1)
  OR NOT EXISTS(SELECT 1 FROM zasp_recovery_backups WHERE (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,backup_value) AND state='capturing' AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery capture rejected';END IF;
 IF section_value='configuration' THEN
  WITH entries AS (
   SELECT 'integration:'||integration.id cursor_value,jsonb_build_object(
    'configuration',integration.configuration,'connections',COALESCE((SELECT jsonb_agg(jsonb_build_object('connection_reference',connection.connection_reference,'id',connection.id,'provider',connection.provider,'state',connection.state,'version',connection.version) ORDER BY connection.id) FROM zasp_integration_connections connection WHERE (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)),'[]'::jsonb),
    'connector_version',integration.connector_version,'display_name',integration.display_name,'id',integration.id,'kind',integration.kind,
    'resource_kind','integration','schedule',(SELECT jsonb_build_object('cadence_seconds',schedule.cadence_seconds,'id',schedule.id,'state',schedule.state,'time_zone',schedule.time_zone,'version',schedule.version) FROM zasp_discovery_schedules schedule WHERE (schedule.organization_id,schedule.workspace_id,schedule.environment_id,schedule.integration_id)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)),'state',integration.state,'version',integration.version) item
   FROM zasp_integrations integration WHERE (integration.organization_id,integration.workspace_id,integration.environment_id)=(organization_value,workspace_value,environment_value)
   UNION ALL
   SELECT 'security_agent:'||definition.definition_id,jsonb_build_object('activation',definition.activation,'body',definition.body,'definition_version',definition.definition_version,'id',definition.definition_id,'plan_catalog_version',definition.plan_catalog_version,'resource_kind','security_agent','version',definition.version)
   FROM zasp_security_agent_definitions definition WHERE (definition.organization_id,definition.workspace_id,definition.environment_id)=(organization_value,workspace_value,environment_value) AND definition.deleted_at IS NULL
  ),page AS (SELECT cursor_value,item FROM entries WHERE cursor_value>COALESCE(after_value,'') ORDER BY cursor_value LIMIT limit_value)
  SELECT COALESCE(jsonb_agg(item ORDER BY cursor_value),'[]'::jsonb),CASE WHEN count(*)=limit_value THEN max(cursor_value) END INTO items_value,next_value FROM page;
 ELSIF section_value='projection' THEN
  WITH integration_ids AS (
   SELECT integration_id FROM zasp_discovery_cursors WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value)
   UNION SELECT integration_id FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value)
   UNION SELECT integration_id FROM zasp_discovery_projection_cursors WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value)
  ),page AS (SELECT integration_id id,jsonb_build_object(
   'collection_cursors',COALESCE((SELECT jsonb_agg(jsonb_build_object('committed_at',cursor.committed_at,'cursor_value',cursor.cursor_value,'provider',cursor.provider,'snapshot_id',cursor.snapshot_id) ORDER BY cursor.provider) FROM zasp_discovery_cursors cursor WHERE (cursor.organization_id,cursor.workspace_id,cursor.environment_id,cursor.integration_id)=(organization_value,workspace_value,environment_value,integration_ids.integration_id)),'[]'::jsonb),
   'integration_id',integration_id,
   'projection_cursors',COALESCE((SELECT jsonb_agg(jsonb_build_object('generation',cursor.generation,'input_digest',encode(cursor.input_digest,'hex'),'kind',cursor.kind,'snapshot_id',cursor.snapshot_id,'source',cursor.source,'updated_at',cursor.updated_at) ORDER BY cursor.source,cursor.kind) FROM zasp_discovery_projection_cursors cursor WHERE (cursor.organization_id,cursor.workspace_id,cursor.environment_id,cursor.integration_id)=(organization_value,workspace_value,environment_value,integration_ids.integration_id)),'[]'::jsonb),
   'snapshot_inputs',COALESCE((SELECT jsonb_agg(jsonb_build_object('candidate_digest',encode(input.candidate_digest,'hex'),'generation',input.generation,'manifest_checksum',encode(input.manifest_checksum,'hex'),'manifest_key',input.manifest_key,'manifest_media_type',input.manifest_media_type,'manifest_reference',input.manifest_reference,'manifest_schema_version',input.manifest_schema_version,'manifest_size_bytes',input.manifest_size_bytes,'manifest_version_id',input.manifest_version_id,'parser_version',input.parser_version,'snapshot_id',input.snapshot_id,'source',input.source,'tool_version',input.tool_version) ORDER BY input.source,input.generation) FROM zasp_discovery_snapshot_inputs input WHERE (input.organization_id,input.workspace_id,input.environment_id,input.integration_id)=(organization_value,workspace_value,environment_value,integration_ids.integration_id)),'[]'::jsonb)) item
   FROM integration_ids WHERE integration_id>COALESCE(after_value,'') ORDER BY integration_id LIMIT limit_value)
  SELECT COALESCE(jsonb_agg(item ORDER BY id),'[]'::jsonb),CASE WHEN count(*)=limit_value THEN max(id) END INTO items_value,next_value FROM page;
 ELSIF section_value='evidence' THEN
  WITH page AS (SELECT id,jsonb_build_object('artifact_key',artifact_key,'artifact_reference',artifact_reference,'artifact_version_id',artifact_version_id,'checksum',encode(checksum,'hex'),'collected_at',collected_at,'id',id,'media_type',media_type,'object_reference',object_reference,'schema_version',schema_version,'size_bytes',size_bytes) item FROM zasp_inventory_evidence WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND id>COALESCE(after_value,'') ORDER BY id LIMIT limit_value)
  SELECT COALESCE(jsonb_agg(item ORDER BY id),'[]'::jsonb),CASE WHEN count(*)=limit_value THEN max(id) END INTO items_value,next_value FROM page;
 ELSE
  SELECT jsonb_build_array(jsonb_build_object(
   'assets',(SELECT count(*) FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,state)=(organization_value,workspace_value,environment_value,'active')),
   'findings',(SELECT count(*) FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value)),
   'policies',COALESCE((SELECT sum(jsonb_array_length(bundle.policies)) FROM zasp_runtime_gateway_policy_bundles bundle WHERE (bundle.organization_id,bundle.workspace_id,bundle.environment_id)=(organization_value,workspace_value,environment_value) AND NOT EXISTS(SELECT 1 FROM zasp_runtime_gateway_policy_bundles later WHERE (later.organization_id,later.workspace_id,later.environment_id,later.device_id)=(bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id) AND later.sequence>bundle.sequence)),0))) INTO items_value;next_value:=NULL;
 END IF;
 RETURN jsonb_build_object('items',items_value,'next_cursor',next_value,'section',section_value);
END
$capture$;

CREATE FUNCTION public.zasp_recovery_finish_backup(organization_value text,workspace_value text,environment_value text,backup_value text,worker_value text,token_value bytea,manifest_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
DECLARE row_value zasp_recovery_backups%ROWTYPE;requested_value bytea;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_worker') OR jsonb_typeof(manifest_value)<>'object' OR octet_length(manifest_value::text)>8192 OR octet_length(token_value)<>32
  OR (SELECT count(*) FROM jsonb_object_keys(manifest_value))<>8 OR NOT zasp_discovery_s3_object_reference(manifest_value->>'reference') OR substring(manifest_value->>'reference' FROM '^s3://[a-z0-9][a-z0-9.-]{2,62}/(.+)$') IS DISTINCT FROM 'organizations/'||organization_value||'/workspaces/'||workspace_value||'/environments/'||environment_value||'/artifacts/'||substring(manifest_value->>'reference' FROM '/artifacts/([^/]+)$') OR NOT zasp_valid_product_id(substring(manifest_value->>'reference' FROM '/artifacts/([^/]+)$')) OR length(manifest_value->>'version_id') NOT BETWEEN 1 AND 1024 OR manifest_value->>'version_id'<>btrim(manifest_value->>'version_id') OR manifest_value->>'version_id'~'[[:space:][:cntrl:]]'
  OR manifest_value->>'sha256'!~'^[a-f0-9]{64}$' OR NOT (CASE WHEN jsonb_typeof(manifest_value->'size_bytes')='number' AND manifest_value->>'size_bytes'~'^[0-9]+$' THEN (manifest_value->>'size_bytes')::bigint BETWEEN 1 AND 67108864 ELSE false END)
  OR manifest_value->>'media_type'<>'application/vnd.zasp.recovery-manifest+json' OR manifest_value->>'schema'<>'recovery_signed_manifest_v1' OR manifest_value->>'signing_key_id'!~'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR jsonb_typeof(manifest_value->'signature')<>'string' OR length(manifest_value->>'signature') NOT BETWEEN 43 AND 684 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery backup finish rejected';END IF;requested_value:=decode(manifest_value->>'sha256','hex');
 SELECT * INTO STRICT row_value FROM zasp_recovery_backups WHERE (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,backup_value) FOR UPDATE;
 IF row_value.state='succeeded' THEN IF row_value.manifest_digest<>requested_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery backup finish conflict';END IF;RETURN jsonb_build_object('manifest_digest',row_value.manifest_digest,'replayed',true,'state','succeeded');END IF;
 IF row_value.state NOT IN('capturing','publishing') OR row_value.worker_id<>worker_value OR row_value.lease_token<>token_value OR row_value.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery operation lease lost';END IF;
 UPDATE zasp_recovery_holds SET state='released',released_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,operation_id,state)=(organization_value,workspace_value,environment_value,backup_value,'held');
 UPDATE zasp_recovery_backups SET state='succeeded',version=version+1,manifest=manifest_value,manifest_digest=requested_value,completed_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,backup_value);RETURN jsonb_build_object('manifest_digest',requested_value,'replayed',false,'state','succeeded');
END
$finish$;

CREATE FUNCTION public.zasp_recovery_checkpoint_restore(organization_value text,workspace_value text,environment_value text,restore_value text,worker_value text,token_value bytea,expected_state text,next_state text,evidence_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $checkpoint$
DECLARE updated integer;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_worker') OR octet_length(token_value)<>32 OR jsonb_typeof(evidence_value)<>'object' OR (expected_state,next_state) NOT IN(('verifying','provisioning'),('provisioning','validating'),('validating','rebuilding'),('rebuilding','cleanup_required'),('cleanup_required','cleaning')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery restore checkpoint rejected';END IF;
 UPDATE zasp_recovery_restores SET state=next_state,version=version+1,validation_evidence=CASE WHEN next_state='rebuilding' THEN evidence_value ELSE validation_evidence END,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,restore_id)=(organization_value,workspace_value,environment_value,restore_value) AND state=expected_state AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp();GET DIAGNOSTICS updated=ROW_COUNT;
 IF updated<>1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery operation lease lost';END IF;RETURN jsonb_build_object('state',next_state);
END
$checkpoint$;

CREATE FUNCTION public.zasp_recovery_finish_restore(organization_value text,workspace_value text,environment_value text,restore_value text,worker_value text,token_value bytea,observed_value jsonb,validation_value jsonb,cleanup_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $finish$
DECLARE row_value zasp_recovery_restores%ROWTYPE;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_worker') OR octet_length(token_value)<>32 OR jsonb_typeof(observed_value)<>'object' OR jsonb_typeof(validation_value)<>'object' OR jsonb_typeof(cleanup_value)<>'object'
  OR (SELECT count(*) FROM jsonb_object_keys(observed_value))<>3 OR NOT observed_value ?& ARRAY['assets','findings','policies'] OR EXISTS(SELECT 1 FROM jsonb_each(observed_value) item WHERE jsonb_typeof(item.value)<>'number' OR item.value::text!~'^[0-9]+$' OR (item.value::text)::numeric>1000000000)
  OR (SELECT count(*) FROM jsonb_object_keys(validation_value))<>4 OR validation_value->>'state'<>'validated' OR validation_value->'expected_counts'<>observed_value OR validation_value->'observed_counts'<>observed_value OR jsonb_typeof(validation_value->'evidence')<>'object'
  OR (SELECT count(*) FROM jsonb_object_keys(cleanup_value))<>2 OR cleanup_value->>'state'<>'deleted' OR jsonb_typeof(cleanup_value->'evidence')<>'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery restore finish rejected';END IF;
 SELECT * INTO STRICT row_value FROM zasp_recovery_restores WHERE (organization_id,workspace_id,environment_id,restore_id)=(organization_value,workspace_value,environment_value,restore_value) FOR UPDATE;
 IF row_value.state='succeeded' THEN IF row_value.observed_counts<>observed_value OR row_value.validation_evidence<>validation_value OR row_value.cleanup_evidence<>cleanup_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery restore finish conflict';END IF;RETURN jsonb_build_object('replayed',true,'state','succeeded');END IF;
 IF row_value.state<>'cleaning' OR row_value.worker_id<>worker_value OR row_value.lease_token<>token_value OR row_value.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery operation lease lost';END IF;
 UPDATE zasp_recovery_restores SET state='succeeded',version=version+1,observed_counts=observed_value,validation_evidence=validation_value,cleanup_evidence=cleanup_value,completed_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,restore_id)=(organization_value,workspace_value,environment_value,restore_value);RETURN jsonb_build_object('replayed',false,'state','succeeded');
END
$finish$;

CREATE FUNCTION public.zasp_recovery_fail_operation(kind_value text,organization_value text,workspace_value text,environment_value text,operation_value text,worker_value text,token_value bytea,error_value text,retry_seconds integer,cleanup_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $fail$
DECLARE attempt_value integer;next_state text;
BEGIN
 IF NOT zasp_recovery_principal_ready('zasp_recovery_worker') OR kind_value NOT IN('backup','restore') OR octet_length(token_value)<>32 OR error_value!~'^[a-z][a-z0-9_]{0,63}$' OR retry_seconds NOT BETWEEN 0 AND 86400 OR cleanup_value IS NOT NULL AND jsonb_typeof(cleanup_value)<>'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery operation failure rejected';END IF;
 IF kind_value='backup' THEN SELECT attempt INTO STRICT attempt_value FROM zasp_recovery_backups WHERE (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,operation_value) AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp() FOR UPDATE;next_state:=CASE WHEN attempt_value>=100 OR retry_seconds=0 THEN 'failed' ELSE 'retryable' END;UPDATE zasp_recovery_holds SET state='released',released_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,operation_id,state)=(organization_value,workspace_value,environment_value,operation_value,'held');UPDATE zasp_recovery_backups SET state=next_state,error_code=error_value,available_at=transaction_timestamp()+make_interval(secs=>retry_seconds),completed_at=CASE WHEN next_state='failed' THEN transaction_timestamp() END,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,backup_id)=(organization_value,workspace_value,environment_value,operation_value);
 ELSE SELECT attempt INTO STRICT attempt_value FROM zasp_recovery_restores WHERE (organization_id,workspace_id,environment_id,restore_id)=(organization_value,workspace_value,environment_value,operation_value) AND worker_id=worker_value AND lease_token=token_value AND lease_expires_at>transaction_timestamp() FOR UPDATE;next_state:=CASE WHEN cleanup_value IS NOT NULL AND cleanup_value->>'state'<>'deleted' THEN 'failed_cleanup' WHEN attempt_value>=100 OR retry_seconds=0 THEN 'failed' ELSE 'retryable' END;UPDATE zasp_recovery_restores SET state=next_state,error_code=error_value,cleanup_evidence=cleanup_value,available_at=transaction_timestamp()+make_interval(secs=>retry_seconds),completed_at=CASE WHEN next_state IN('failed','failed_cleanup') THEN transaction_timestamp() END,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,restore_id)=(organization_value,workspace_value,environment_value,operation_value);END IF;
 RETURN jsonb_build_object('state',next_state);
END
$fail$;

DO $function_authority$
DECLARE function_value regprocedure;
BEGIN
 FOREACH function_value IN ARRAY ARRAY[
  'public.zasp_recovery_register_principals(text,text,text)'::regprocedure,'public.zasp_recovery_principal_ready(text)'::regprocedure,'public.zasp_recovery_principals_ready()'::regprocedure,'public.zasp_recovery_scope_mutable(text,text,text)'::regprocedure,'public.zasp_recovery_guard_scope_mutation()'::regprocedure,
  'public.zasp_recovery_create_backup(text,text,text,text,text,text,text,integer,text,text,bytea)'::regprocedure,'public.zasp_recovery_create_restore(text,text,text,text,text,text,text,text,text,text,bytea,jsonb,bytea)'::regprocedure,'public.zasp_recovery_get_backup(text,text,text,text)'::regprocedure,'public.zasp_recovery_get_restore(text,text,text,text)'::regprocedure,
  'public.zasp_recovery_claim_outbox(text,text,bytea,integer,integer)'::regprocedure,'public.zasp_recovery_heartbeat_outbox(text,text,bytea,integer,integer)'::regprocedure,'public.zasp_recovery_ack_outbox(text,text,text,text,text,bytea,text)'::regprocedure,'public.zasp_recovery_retry_outbox(text,text,text,text,text,bytea,integer,text)'::regprocedure,
  'public.zasp_recovery_claim_operation(text,text,bytea,integer,integer)'::regprocedure,'public.zasp_recovery_heartbeat_operation(text,text,text,text,text,text,bytea,integer)'::regprocedure,'public.zasp_recovery_begin_hold(text,text,text,text,text,bytea)'::regprocedure,'public.zasp_recovery_release_hold(text,text,text,text,text,bytea)'::regprocedure,'public.zasp_recovery_capture_page(text,text,text,text,text,bytea,text,text,integer)'::regprocedure,
  'public.zasp_recovery_finish_backup(text,text,text,text,text,bytea,jsonb)'::regprocedure,'public.zasp_recovery_checkpoint_restore(text,text,text,text,text,bytea,text,text,jsonb)'::regprocedure,'public.zasp_recovery_finish_restore(text,text,text,text,text,bytea,jsonb,jsonb,jsonb)'::regprocedure,'public.zasp_recovery_fail_operation(text,text,text,text,text,text,bytea,text,integer,jsonb)'::regprocedure
 ] LOOP EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',function_value);END LOOP;
END
$function_authority$;

REVOKE ALL ON FUNCTION public.zasp_recovery_register_principals(text,text,text),public.zasp_recovery_principal_ready(text),public.zasp_recovery_principals_ready(),public.zasp_recovery_scope_mutable(text,text,text),public.zasp_recovery_guard_scope_mutation(),public.zasp_recovery_create_backup(text,text,text,text,text,text,text,integer,text,text,bytea),public.zasp_recovery_create_restore(text,text,text,text,text,text,text,text,text,text,bytea,jsonb,bytea),public.zasp_recovery_get_backup(text,text,text,text),public.zasp_recovery_get_restore(text,text,text,text),public.zasp_recovery_claim_outbox(text,text,bytea,integer,integer),public.zasp_recovery_heartbeat_outbox(text,text,bytea,integer,integer),public.zasp_recovery_ack_outbox(text,text,text,text,text,bytea,text),public.zasp_recovery_retry_outbox(text,text,text,text,text,bytea,integer,text),public.zasp_recovery_claim_operation(text,text,bytea,integer,integer),public.zasp_recovery_heartbeat_operation(text,text,text,text,text,text,bytea,integer),public.zasp_recovery_begin_hold(text,text,text,text,text,bytea),public.zasp_recovery_release_hold(text,text,text,text,text,bytea),public.zasp_recovery_capture_page(text,text,text,text,text,bytea,text,text,integer),public.zasp_recovery_finish_backup(text,text,text,text,text,bytea,jsonb),public.zasp_recovery_checkpoint_restore(text,text,text,text,text,bytea,text,text,jsonb),public.zasp_recovery_finish_restore(text,text,text,text,text,bytea,jsonb,jsonb,jsonb),public.zasp_recovery_fail_operation(text,text,text,text,text,text,bytea,text,integer,jsonb) FROM PUBLIC,zasp_discovery_api,zasp_recovery_worker,zasp_recovery_outbox_worker;
GRANT EXECUTE ON FUNCTION public.zasp_recovery_create_backup(text,text,text,text,text,text,text,integer,text,text,bytea),public.zasp_recovery_create_restore(text,text,text,text,text,text,text,text,text,text,bytea,jsonb,bytea),public.zasp_recovery_get_backup(text,text,text,text),public.zasp_recovery_get_restore(text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_recovery_principal_ready(text),public.zasp_recovery_claim_operation(text,text,bytea,integer,integer),public.zasp_recovery_heartbeat_operation(text,text,text,text,text,text,bytea,integer),public.zasp_recovery_begin_hold(text,text,text,text,text,bytea),public.zasp_recovery_release_hold(text,text,text,text,text,bytea),public.zasp_recovery_capture_page(text,text,text,text,text,bytea,text,text,integer),public.zasp_recovery_finish_backup(text,text,text,text,text,bytea,jsonb),public.zasp_recovery_checkpoint_restore(text,text,text,text,text,bytea,text,text,jsonb),public.zasp_recovery_finish_restore(text,text,text,text,text,bytea,jsonb,jsonb,jsonb),public.zasp_recovery_fail_operation(text,text,text,text,text,text,bytea,text,integer,jsonb) TO zasp_recovery_worker;
GRANT EXECUTE ON FUNCTION public.zasp_recovery_principal_ready(text),public.zasp_recovery_claim_outbox(text,text,bytea,integer,integer),public.zasp_recovery_heartbeat_outbox(text,text,bytea,integer,integer),public.zasp_recovery_ack_outbox(text,text,text,text,text,bytea,text),public.zasp_recovery_retry_outbox(text,text,text,text,text,bytea,integer,text) TO zasp_recovery_outbox_worker;

CREATE FUNCTION public.zasp_recovery_execution_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_attack_lab_execution_security_ready() AND (SELECT count(*) FROM pg_roles WHERE rolname IN('zasp_recovery_worker','zasp_recovery_outbox_worker'))=2
 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN('zasp_recovery_worker','zasp_recovery_outbox_worker') AND (rolsuper OR rolinherit OR rolcanlogin OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
 AND (SELECT count(*) FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_recovery_worker','zasp_recovery_outbox_worker') AND member.rolname='zasp_discovery_authority' AND membership.admin_option)=2
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_recovery_backups','SELECT') AND NOT has_table_privilege('zasp_recovery_worker','public.zasp_recovery_backups','SELECT') AND NOT has_table_privilege('zasp_recovery_outbox_worker','public.zasp_recovery_outbox','SELECT')
 AND has_function_privilege('zasp_discovery_api','public.zasp_recovery_create_backup(text,text,text,text,text,text,text,integer,text,text,bytea)','EXECUTE')
 AND has_function_privilege('zasp_discovery_api','public.zasp_recovery_create_restore(text,text,text,text,text,text,text,text,text,text,bytea,jsonb,bytea)','EXECUTE')
 AND has_function_privilege('zasp_recovery_worker','public.zasp_recovery_claim_operation(text,text,bytea,integer,integer)','EXECUTE')
 AND has_function_privilege('zasp_recovery_outbox_worker','public.zasp_recovery_claim_outbox(text,text,bytea,integer,integer)','EXECUTE')
$security$;

CREATE FUNCTION public.zasp_recovery_execution_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
  SELECT concat_ws('|','prior',zasp_attack_lab_execution_live_fingerprint())
  UNION ALL SELECT concat_ws('|','role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls) FROM pg_roles WHERE rolname IN('zasp_recovery_worker','zasp_recovery_outbox_worker')
  UNION ALL SELECT concat_ws('|','membership',granted.rolname,member.rolname,membership.admin_option) FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_recovery_worker','zasp_recovery_outbox_worker') AND member.rolname='zasp_discovery_authority'
  UNION ALL SELECT concat_ws('|','table',class.relname,owner.rolname,class.relrowsecurity,class.relforcerowsecurity,COALESCE(class.relacl::text,'')) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_recovery_%' AND class.relkind IN('r','i')
  UNION ALL SELECT concat_ws('|','index',class.relname,pg_get_indexdef(class.oid)) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_recovery_%' AND class.relkind='i'
  UNION ALL SELECT concat_ws('|','column',class.relname,attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_recovery_%' AND attribute.attnum>0 AND NOT attribute.attisdropped
  UNION ALL SELECT concat_ws('|','constraint',class.relname,constraint_value.conname,constraint_value.contype,constraint_value.convalidated,pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_recovery_%'
  UNION ALL SELECT concat_ws('|','policy',class.relname,policy.polname,policy.polpermissive,pg_get_expr(policy.polqual,policy.polrelid),pg_get_expr(policy.polwithcheck,policy.polrelid)) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_recovery_%'
  UNION ALL SELECT concat_ws('|','trigger',class.relname,trigger.tgname,pg_get_triggerdef(trigger.oid,true)) FROM pg_trigger trigger JOIN pg_class class ON class.oid=trigger.tgrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND trigger.tgname LIKE '%_recovery_hold' AND NOT trigger.tgisinternal
  UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_recovery_%'
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_recovery_execution_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=27 AND name='production_recovery' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='production-recovery-v1') AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>27)
 AND zasp_recovery_execution_security_ready() AND zasp_recovery_execution_live_fingerprint()=expected_fingerprint
$readiness$;

ALTER FUNCTION public.zasp_recovery_execution_security_ready() OWNER TO zasp_discovery_authority;ALTER FUNCTION public.zasp_recovery_execution_live_fingerprint() OWNER TO zasp_discovery_authority;ALTER FUNCTION public.zasp_recovery_execution_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_recovery_execution_security_ready(),public.zasp_recovery_execution_live_fingerprint(),public.zasp_recovery_execution_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_recovery_worker,zasp_recovery_outbox_worker;
GRANT EXECUTE ON FUNCTION public.zasp_recovery_execution_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_api,zasp_recovery_worker,zasp_recovery_outbox_worker;

DO $product_release_evolution$
DECLARE definition text;original_definition text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'attack-lab-execution-v1','production-recovery-v1');definition:=replace(definition,'release."version" = 26','release."version" = 27');definition:=replace(definition,'release."name" = ''attack_lab_execution''','release."name" = ''production_recovery''');definition:=replace(definition,'later_release."version" > 26','later_release."version" > 27');IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v27 compatibility evolution failed';END IF;EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;original_definition:=definition;definition:=replace(definition,'attack-lab-execution-v1','production-recovery-v1');definition:=replace(replace(definition,'release."version"=26','release."version"=27'),'release."version" = 26','release."version" = 27');definition:=replace(replace(definition,'release."name"=''attack_lab_execution''','release."name"=''production_recovery'''),'release."name" = ''attack_lab_execution''','release."name" = ''production_recovery''');definition:=replace(replace(definition,'later."version">26','later."version">27'),'later."version" > 26','later."version" > 27');IF definition=original_definition OR position('production-recovery-v1' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v27 compatibility evolution failed';END IF;EXECUTE definition;
END
$product_release_evolution$;

UPDATE public.zasp_schema_metadata SET value='production-recovery-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='attack-lab-execution-v1';
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_recovery_fingerprint', '3a2920ee808fcc33514547fc18771d2f3d54be7ad112ead7874f03230740810b') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
