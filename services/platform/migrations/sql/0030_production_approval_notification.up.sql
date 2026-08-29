DO $guard$
BEGIN
  IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>29)
     OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=29 AND name='production_home_attention' AND checksum='5cedd66930d0eea225a2454b233085463407c2acee946c194d941396070e908e')
     OR NOT public.zasp_production_home_attention_readiness('5cedd66930d0eea225a2454b233085463407c2acee946c194d941396070e908e','45a16f5d9eb8265c606796bea9d096bee4edb10826284e9e169a4bd911d9d93c') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='approval notification prerequisite rejected';
  END IF;
END
$guard$;

CREATE TABLE public.zasp_security_agent_approval_notifications(
 organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),
 workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),
 environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
 delivery_id text NOT NULL CHECK(zasp_valid_product_id(delivery_id)),
 approval_id text NOT NULL CHECK(zasp_valid_product_id(approval_id)),
 run_id text NOT NULL CHECK(zasp_valid_product_id(run_id)),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(convert_to(payload::text,'UTF8'))<=16384),
 payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32),
 destination_url text NOT NULL CHECK(char_length(destination_url) BETWEEN 12 AND 2048),
 secret_reference text NOT NULL CHECK(secret_reference~'^secret_ref_[A-Za-z0-9][A-Za-z0-9._/-]{0,115}$'),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','leased','retryable','delivered','exhausted')),
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 10),
 available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 lease_owner text CHECK(lease_owner IS NULL OR char_length(lease_owner) BETWEEN 3 AND 128),
 lease_token text CHECK(lease_token IS NULL OR lease_token~'^[0-9a-f]{64}$'),
 lease_expires_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 completed_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,delivery_id),
 UNIQUE(organization_id,workspace_id,environment_id,approval_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,approval_id) REFERENCES public.zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id) ON DELETE RESTRICT,
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id) ON DELETE RESTRICT,
 CHECK((state='leased')=(lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK((state='delivered')=(completed_at IS NOT NULL))
);
CREATE INDEX zasp_security_agent_approval_notifications_claim_v30_idx ON public.zasp_security_agent_approval_notifications(available_at,created_at,delivery_id) WHERE state IN('pending','retryable','leased');
ALTER TABLE public.zasp_security_agent_approval_notifications OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_approval_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_approval_notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_security_agent_approval_notifications_authority ON public.zasp_security_agent_approval_notifications TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON TABLE public.zasp_security_agent_approval_notifications FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

CREATE FUNCTION public.zasp_security_agent_enqueue_approval_notification() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $enqueue$
DECLARE webhook_count integer;webhook_body jsonb;configuration_value jsonb;delivery_value text;payload_value jsonb;destination_value text;destination_host text;
BEGIN
 IF NEW.state<>'pending' THEN RETURN NEW;END IF;
 SELECT count(*),(jsonb_agg(record_value.body ORDER BY record_value.id)->0) INTO webhook_count,webhook_body
   FROM zasp_workflow_records record_value
  WHERE (record_value.organization_id,record_value.workspace_id,record_value.environment_id,record_value.kind)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,'integration')
    AND record_value.deleted_at IS NULL AND record_value.body->>'connector_key'='generic-webhook' AND record_value.body->>'status'='configured';
 IF webhook_count<>1 OR jsonb_typeof(webhook_body->'configuration')<>'object' OR (webhook_body->'configuration')-ARRAY['destination_url','signing_secret_reference']<>'{}'::jsonb THEN RETURN NEW;END IF;
 configuration_value:=webhook_body->'configuration';
 destination_value:=configuration_value->>'destination_url';
 destination_host:=split_part(split_part(substr(destination_value,9),'/',1),':',1);
 IF destination_value IS NULL OR char_length(destination_value) NOT BETWEEN 12 AND 2048 OR destination_value!~'^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:443)?/[^?#]*$' OR destination_host='' OR destination_host='localhost' OR destination_host LIKE '%.localhost' OR destination_host LIKE '%.local' OR destination_host LIKE '%..%' OR destination_host~'^[0-9.]+$' OR configuration_value->>'signing_secret_reference'!~'^secret_ref_[A-Za-z0-9][A-Za-z0-9._/-]{0,115}$' THEN RETURN NEW;END IF;
 delivery_value:=zasp_discovery_canonical_id(NEW.organization_id,NEW.workspace_id,NEW.environment_id,'security_agent_approval_notification',NEW.approval_id);
 payload_value:=jsonb_build_object('approval',jsonb_build_object('id',NEW.approval_id,'run_id',NEW.run_id),'delivery_id',delivery_value,'event','security_agent.approval_required','scope',jsonb_build_object('environment_id',NEW.environment_id,'organization_id',NEW.organization_id,'workspace_id',NEW.workspace_id),'version',1);
 INSERT INTO zasp_security_agent_approval_notifications(organization_id,workspace_id,environment_id,delivery_id,approval_id,run_id,payload,payload_digest,destination_url,secret_reference)
 VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,delivery_value,NEW.approval_id,NEW.run_id,payload_value,digest(convert_to(payload_value::text,'UTF8'),'sha256'),destination_value,configuration_value->>'signing_secret_reference')
 ON CONFLICT(organization_id,workspace_id,environment_id,approval_id) DO NOTHING;
 RETURN NEW;
END
$enqueue$;
ALTER FUNCTION public.zasp_security_agent_enqueue_approval_notification() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_enqueue_approval_notification() FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
CREATE TRIGGER zasp_security_agent_enqueue_approval_notification_v30 AFTER INSERT ON public.zasp_security_agent_approvals FOR EACH ROW EXECUTE FUNCTION public.zasp_security_agent_enqueue_approval_notification();

CREATE FUNCTION public.zasp_security_agent_claim_approval_notification(owner_value text,lease_token_value text,lease_seconds_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim$
DECLARE notification zasp_security_agent_approval_notifications%ROWTYPE;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR owner_value IS NULL OR char_length(owner_value) NOT BETWEEN 3 AND 128 OR owner_value<>btrim(owner_value) OR owner_value~E'[\\x00\\r\\n]' OR lease_token_value!~'^[0-9a-f]{64}$' OR lease_seconds_value NOT BETWEEN 15 AND 60 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='approval notification claim rejected';END IF;
 UPDATE zasp_security_agent_approval_notifications SET state='exhausted',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE state='leased' AND lease_expires_at<=transaction_timestamp() AND attempt>=10;
 SELECT * INTO notification FROM zasp_security_agent_approval_notifications row_value
  WHERE (row_value.state IN('pending','retryable') AND row_value.available_at<=transaction_timestamp()) OR (row_value.state='leased' AND row_value.lease_expires_at<=transaction_timestamp() AND row_value.attempt<10)
  ORDER BY row_value.available_at,row_value.created_at,row_value.delivery_id FOR UPDATE SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN jsonb_build_object('found',false);END IF;
 UPDATE zasp_security_agent_approval_notifications SET state='leased',attempt=attempt+1,lease_owner=owner_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds_value),updated_at=transaction_timestamp()
  WHERE (organization_id,workspace_id,environment_id,delivery_id)=(notification.organization_id,notification.workspace_id,notification.environment_id,notification.delivery_id) RETURNING * INTO notification;
 RETURN jsonb_build_object('found',true,'organization_id',notification.organization_id,'workspace_id',notification.workspace_id,'environment_id',notification.environment_id,'delivery_id',notification.delivery_id,'approval_id',notification.approval_id,'run_id',notification.run_id,'payload',notification.payload::text,'payload_digest','sha256:'||encode(notification.payload_digest,'hex'),'destination_url',notification.destination_url,'secret_reference',notification.secret_reference,'lease_token',notification.lease_token,'lease_expires_at',notification.lease_expires_at,'attempt',notification.attempt);
END
$claim$;

CREATE FUNCTION public.zasp_security_agent_complete_approval_notification(organization_value text,workspace_value text,environment_value text,delivery_value text,lease_token_value text,payload_digest_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $complete$
DECLARE changed integer;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(delivery_value) OR lease_token_value!~'^[0-9a-f]{64}$' OR payload_digest_value!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='approval notification completion rejected';END IF;
 UPDATE zasp_security_agent_approval_notifications SET state='delivered',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completed_at=transaction_timestamp(),updated_at=transaction_timestamp()
  WHERE (organization_id,workspace_id,environment_id,delivery_id,state,lease_token,payload_digest)=(organization_value,workspace_value,environment_value,delivery_value,'leased',lease_token_value,decode(substr(payload_digest_value,8),'hex')) AND lease_expires_at>transaction_timestamp();
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval notification lease lost';END IF;
 RETURN jsonb_build_object('transition','delivered');
END
$complete$;

CREATE FUNCTION public.zasp_security_agent_fail_approval_notification(organization_value text,workspace_value text,environment_value text,delivery_value text,lease_token_value text,payload_digest_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $fail$
DECLARE notification zasp_security_agent_approval_notifications%ROWTYPE;
BEGIN
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR NOT zasp_valid_product_id(delivery_value) OR lease_token_value!~'^[0-9a-f]{64}$' OR payload_digest_value!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='approval notification failure rejected';END IF;
 SELECT * INTO notification FROM zasp_security_agent_approval_notifications row_value WHERE (row_value.organization_id,row_value.workspace_id,row_value.environment_id,row_value.delivery_id)=(organization_value,workspace_value,environment_value,delivery_value) FOR UPDATE;
 IF NOT FOUND OR notification.state<>'leased' OR notification.lease_token<>lease_token_value OR notification.lease_expires_at<=transaction_timestamp() OR notification.payload_digest<>decode(substr(payload_digest_value,8),'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='approval notification lease lost';END IF;
 IF notification.attempt>=10 THEN
  UPDATE zasp_security_agent_approval_notifications SET state='exhausted',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,delivery_id)=(organization_value,workspace_value,environment_value,delivery_value);
  RETURN jsonb_build_object('transition','exhausted');
 END IF;
 UPDATE zasp_security_agent_approval_notifications SET state='retryable',available_at=transaction_timestamp()+make_interval(secs=>LEAST(60,attempt*attempt)),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,delivery_id)=(organization_value,workspace_value,environment_value,delivery_value);
 RETURN jsonb_build_object('transition','retryable');
END
$fail$;

ALTER FUNCTION public.zasp_security_agent_claim_approval_notification(text,text,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_complete_approval_notification(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_fail_approval_notification(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_claim_approval_notification(text,text,integer),public.zasp_security_agent_complete_approval_notification(text,text,text,text,text,text),public.zasp_security_agent_fail_approval_notification(text,text,text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_claim_approval_notification(text,text,integer),public.zasp_security_agent_complete_approval_notification(text,text,text,text,text,text),public.zasp_security_agent_fail_approval_notification(text,text,text,text,text,text) TO zasp_security_agent_api;

CREATE FUNCTION public.zasp_production_approval_notification_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_home_attention_security_ready()
 AND EXISTS(SELECT 1 FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_approval_notifications' AND class.relkind='r' AND owner.rolname='zasp_discovery_authority' AND class.relrowsecurity AND class.relforcerowsecurity)
 AND EXISTS(SELECT 1 FROM pg_policy policy_value WHERE policy_value.polrelid='public.zasp_security_agent_approval_notifications'::regclass AND policy_value.polname='zasp_security_agent_approval_notifications_authority' AND policy_value.polroles=ARRAY[(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority')])
 AND EXISTS(SELECT 1 FROM pg_trigger trigger_value WHERE trigger_value.tgrelid='public.zasp_security_agent_approvals'::regclass AND trigger_value.tgname='zasp_security_agent_enqueue_approval_notification_v30' AND NOT trigger_value.tgisinternal AND trigger_value.tgenabled='O' AND trigger_value.tgfoid='public.zasp_security_agent_enqueue_approval_notification()'::regprocedure)
 AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_enqueue_approval_notification','zasp_security_agent_claim_approval_notification','zasp_security_agent_complete_approval_notification','zasp_security_agent_fail_approval_notification']) AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR has_function_privilege('public',procedure.oid,'EXECUTE')))
 AND has_function_privilege('zasp_security_agent_api','public.zasp_security_agent_claim_approval_notification(text,text,integer)','EXECUTE')
 AND NOT has_function_privilege('zasp_security_agent_worker','public.zasp_security_agent_claim_approval_notification(text,text,integer)','EXECUTE')
$security$;

CREATE FUNCTION public.zasp_production_approval_notification_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
  SELECT concat_ws('|','prior',zasp_production_home_attention_live_fingerprint())
  UNION ALL SELECT concat_ws('|','table',class.relname,owner.rolname,class.relrowsecurity,class.relforcerowsecurity,COALESCE(class.relacl::text,'')) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_approval_notifications' AND class.relkind IN('r','i')
  UNION ALL SELECT concat_ws('|','column',class.relname,attribute.attnum,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=class.oid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_approval_notifications' AND attribute.attnum>0 AND NOT attribute.attisdropped
  UNION ALL SELECT concat_ws('|','constraint',constraint_value.conname,constraint_value.contype,constraint_value.convalidated,pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_approval_notifications'::regclass
  UNION ALL SELECT concat_ws('|','index',index_value.relname,pg_get_indexdef(index_value.oid)) FROM pg_index index_metadata JOIN pg_class index_value ON index_value.oid=index_metadata.indexrelid WHERE index_metadata.indrelid='public.zasp_security_agent_approval_notifications'::regclass
  UNION ALL SELECT concat_ws('|','policy',policy_value.polname,policy_value.polpermissive,COALESCE((SELECT string_agg(CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE role_value.rolname END,',' ORDER BY CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE role_value.rolname END) FROM unnest(policy_value.polroles) role_oid LEFT JOIN pg_roles role_value ON role_value.oid=role_oid),''),COALESCE(pg_get_expr(policy_value.polqual,policy_value.polrelid),''),COALESCE(pg_get_expr(policy_value.polwithcheck,policy_value.polrelid),'')) FROM pg_policy policy_value WHERE policy_value.polrelid='public.zasp_security_agent_approval_notifications'::regclass
  UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_enqueue_approval_notification','zasp_security_agent_claim_approval_notification','zasp_security_agent_complete_approval_notification','zasp_security_agent_fail_approval_notification','zasp_production_approval_notification_security_ready','zasp_production_approval_notification_readiness','zasp_production_home_attention_readiness'])
  UNION ALL SELECT concat_ws('|','trigger',trigger_value.tgname,pg_get_triggerdef(trigger_value.oid,true)) FROM pg_trigger trigger_value WHERE trigger_value.tgrelid='public.zasp_security_agent_approvals'::regclass AND trigger_value.tgname='zasp_security_agent_enqueue_approval_notification_v30' AND NOT trigger_value.tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_production_approval_notification_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=30 AND name='production_approval_notification' AND checksum=expected_checksum)
 AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>30)
 AND zasp_production_approval_notification_security_ready() AND zasp_production_approval_notification_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_approval_notification_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_approval_notification_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_approval_notification_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_approval_notification_security_ready(),public.zasp_production_approval_notification_live_fingerprint(),public.zasp_production_approval_notification_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION public.zasp_production_approval_notification_readiness(text,text) TO zasp_security_agent_api;

ALTER FUNCTION public.zasp_production_home_attention_readiness(text,text) RENAME TO zasp_production_home_attention_readiness_v29;
REVOKE ALL ON FUNCTION public.zasp_production_home_attention_readiness_v29(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
CREATE FUNCTION public.zasp_production_home_attention_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
 AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=29 AND name='production_home_attention' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_home_attention_fingerprint' AND value=expected_fingerprint)
 AND zasp_production_approval_notification_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=30 AND name='production_approval_notification'),(SELECT value FROM zasp_schema_metadata WHERE key='production_approval_notification_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_home_attention_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_home_attention_readiness(text,text) FROM PUBLIC;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_approval_notification_fingerprint', '38492f1a329e45c28f2cd982d59b952e5ba42963e7921e8d1711a7a4a2541a58') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
