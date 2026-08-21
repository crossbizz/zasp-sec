DO $product_release_evolution$ DECLARE definition text;original_definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'security-agent-execution-v1','identity-administration-v1');
 definition:=replace(definition,'release."version" = 18','release."version" = 19');
 definition:=replace(definition,'release."name" = ''security_agent_execution''','release."name" = ''identity_administration''');
 definition:=replace(definition,'later_release."version" > 18','later_release."version" > 19');
 IF definition=original_definition OR position('identity-administration-v1' IN definition)=0 OR position('release."version" = 19' IN definition)=0 OR position('release."name" = ''identity_administration''' IN definition)=0 OR position('later_release."version" > 19' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v19 compatibility evolution failed';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'security-agent-execution-v1','identity-administration-v1');
 definition:=replace(replace(definition,'release."version"=18','release."version"=19'),'release."version" = 18','release."version" = 19');
 definition:=replace(replace(definition,'release."name"=''security_agent_execution''','release."name"=''identity_administration'''),'release."name" = ''security_agent_execution''','release."name" = ''identity_administration''');
 definition:=replace(replace(definition,'later."version">18','later."version">19'),'later."version" > 18','later."version" > 19');
 IF definition=original_definition OR position('identity-administration-v1' IN definition)=0 OR position('identity_administration' IN definition)=0 OR position('release."version"=19' IN definition)=0 AND position('release."version" = 19' IN definition)=0 OR position('later."version">19' IN definition)=0 AND position('later."version" > 19' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v19 compatibility evolution failed';END IF;
 EXECUTE definition;
END $product_release_evolution$;

CREATE TABLE public.zasp_identity_administration_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  used_at timestamptz
);
INSERT INTO public.zasp_identity_administration_state(singleton) VALUES(true);

ALTER TABLE public.zasp_group_mappings DROP CONSTRAINT zasp_group_mappings_group_reference_check;
ALTER TABLE public.zasp_group_mappings ADD CONSTRAINT zasp_group_mappings_group_reference_check
  CHECK(group_reference~'^(idp-group-[A-Za-z0-9_-]+|scim-group-(test|live)-[A-Za-z0-9_-]+)$' AND length(group_reference) BETWEEN 11 AND 128);
ALTER TABLE public.zasp_group_mappings ADD CONSTRAINT zasp_group_mappings_scope_fkey
  FOREIGN KEY(organization_id,workspace_id,environment_id)
  REFERENCES public.zasp_environments(organization_id,workspace_id,id) ON DELETE CASCADE;

CREATE TABLE public.zasp_identity_provider_connections (
  organization_id text NOT NULL,
  connection_reference text NOT NULL CHECK(length(connection_reference) BETWEEN 12 AND 128),
  kind text NOT NULL CHECK(kind IN('sso','scim')),
  protocol text CHECK(protocol IS NULL OR protocol IN('saml','oidc')),
  status text NOT NULL CHECK(status IN('active','pending','disabled')),
  display_name text NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
  identity_provider text NOT NULL CHECK(length(identity_provider) BETWEEN 1 AND 64),
  base_url text,
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  deleted_at timestamptz,
  PRIMARY KEY(organization_id,connection_reference),
  CHECK((kind='sso' AND protocol IS NOT NULL AND base_url IS NULL) OR (kind='scim' AND protocol IS NULL AND base_url IS NOT NULL AND length(base_url) BETWEEN 8 AND 2048))
);

CREATE TABLE public.zasp_identity_provider_mutations (
  organization_id text NOT NULL,
  principal_id text NOT NULL,
  provider_organization_reference text NOT NULL CHECK(provider_organization_reference~'^organization-[A-Za-z0-9_-]+$' AND length(provider_organization_reference) BETWEEN 14 AND 128),
  operation text NOT NULL CHECK(operation IN('createSSOConnection','deleteSSOConnection','testSSOConnection','createSCIMConnection','deleteSCIMConnection')),
  idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key~'^[A-Za-z0-9][A-Za-z0-9._:-]*$'),
  mutation_id text NOT NULL CHECK(zasp_valid_product_id(mutation_id)),
  intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
  intent jsonb NOT NULL CHECK(jsonb_typeof(intent)='object' AND pg_column_size(intent)<=4096),
  state text NOT NULL DEFAULT 'reserved' CHECK(state IN('reserved','provider_unknown','completed','failed')),
  provider_reference text,
  response jsonb CHECK(response IS NULL OR jsonb_typeof(response)='object'),
  owner_token bytea NOT NULL CHECK(octet_length(owner_token)=32),
  lease_expires_at timestamptz NOT NULL,
  audit_id text NOT NULL CHECK(zasp_valid_product_id(audit_id)),
  correlation_id text NOT NULL CHECK(zasp_valid_product_id(correlation_id)),
  receipt_id text NOT NULL CHECK(zasp_valid_product_id(receipt_id)),
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT transaction_timestamp()+interval '7 days',
  PRIMARY KEY(organization_id,principal_id,operation,idempotency_key),
  UNIQUE(organization_id,mutation_id),
  UNIQUE(organization_id,receipt_id),
  CHECK(expires_at>created_at AND expires_at<=created_at+interval '7 days'),
  CHECK(lease_expires_at>=created_at AND lease_expires_at<=updated_at+interval '2 minutes'),
  CHECK((state IN('reserved','provider_unknown') AND response IS NULL) OR (state IN('completed','failed') AND response IS NOT NULL))
);

CREATE TABLE public.zasp_identity_secret_reveal_grants (
  organization_id text NOT NULL,
  principal_id text NOT NULL,
  mutation_id text NOT NULL,
  grant_id text NOT NULL CHECK(zasp_valid_product_id(grant_id)),
  ciphertext bytea CHECK(ciphertext IS NULL OR octet_length(ciphertext) BETWEEN 1 AND 8192),
  nonce bytea CHECK(nonce IS NULL OR octet_length(nonce)=12),
  authentication_tag bytea CHECK(authentication_tag IS NULL OR octet_length(authentication_tag)=16),
  expires_at timestamptz NOT NULL,
  acknowledged_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,grant_id),
  UNIQUE(organization_id,mutation_id),
  CHECK(expires_at>created_at AND expires_at<=created_at+interval '15 minutes'),
  CHECK((acknowledged_at IS NULL AND ciphertext IS NOT NULL AND nonce IS NOT NULL AND authentication_tag IS NOT NULL) OR
        (acknowledged_at IS NOT NULL AND ciphertext IS NULL AND nonce IS NULL AND authentication_tag IS NULL))
);

CREATE TABLE public.zasp_identity_webhook_events (
  project_id text NOT NULL CHECK(length(project_id) BETWEEN 8 AND 128),
  event_id text PRIMARY KEY CHECK(event_id~'^webhook-event-(test|live)-[A-Za-z0-9_-]+$' AND length(event_id) BETWEEN 24 AND 128),
  organization_id text NOT NULL,
  member_reference text NOT NULL CHECK(length(member_reference) BETWEEN 8 AND 128),
  event_kind text NOT NULL CHECK(event_kind='scim.member.delete'),
  event_digest bytea NOT NULL CHECK(octet_length(event_digest)=32),
  audit_id text NOT NULL CHECK(zasp_valid_product_id(audit_id)),
  processed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  revoked_sessions integer NOT NULL CHECK(revoked_sessions>=0),
  revoked_tokens integer NOT NULL CHECK(revoked_tokens>=0)
);

CREATE TABLE public.zasp_identity_member_groups (
  organization_id text NOT NULL,
  principal_id text NOT NULL,
  group_reference text NOT NULL CHECK(group_reference~'^scim-group-(test|live)-[A-Za-z0-9_-]+$' AND length(group_reference) BETWEEN 17 AND 128),
  observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,principal_id,group_reference)
);

CREATE INDEX zasp_identity_connections_page_v19_idx ON public.zasp_identity_provider_connections(organization_id,kind,connection_reference) WHERE deleted_at IS NULL;
CREATE INDEX zasp_identity_mutations_expiry_v19_idx ON public.zasp_identity_provider_mutations(expires_at,organization_id,mutation_id) WHERE state IN('reserved','provider_unknown');
CREATE INDEX zasp_identity_reveal_expiry_v19_idx ON public.zasp_identity_secret_reveal_grants(expires_at,organization_id,grant_id) WHERE acknowledged_at IS NULL;

DO $authority$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['zasp_identity_administration_state','zasp_identity_provider_connections','zasp_identity_provider_mutations','zasp_identity_secret_reveal_grants','zasp_identity_webhook_events','zasp_identity_member_groups'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',table_name);
    EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',table_name||'_authority',table_name);
    EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_discovery_api',table_name);
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO zasp_discovery_authority',table_name);
  END LOOP;
END
$authority$;

GRANT SELECT,UPDATE ON public.zasp_identity_memberships TO zasp_discovery_authority;
GRANT SELECT,UPDATE ON public.zasp_product_sessions,public.zasp_product_api_tokens TO zasp_discovery_authority;
GRANT SELECT,DELETE ON public.zasp_authorized_scopes TO zasp_discovery_authority;
GRANT SELECT ON public.zasp_group_mappings TO zasp_discovery_authority;
GRANT INSERT ON public.zasp_admin_audit TO zasp_discovery_authority;

CREATE FUNCTION public.zasp_identity_admin_authorized(organization_value text,principal_value text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $authorized$
  SELECT EXISTS(SELECT 1 FROM zasp_identity_memberships membership WHERE membership.organization_id=organization_value AND membership.principal_id=principal_value AND membership.active AND membership.role IN('organization_admin','security_admin'))
$authorized$;

CREATE FUNCTION public.zasp_identity_admin_provider_organization(organization_value text,principal_value text) RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $provider_organization$
  SELECT membership.organization_reference FROM zasp_identity_memberships membership WHERE membership.organization_id=organization_value AND membership.principal_id=principal_value AND membership.active AND membership.role IN('organization_admin','security_admin') AND zasp_identity_admin_authorized(organization_value,principal_value)
$provider_organization$;

CREATE FUNCTION public.zasp_identity_admin_intent_valid(operation_value text,intent_value jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog, public AS $intent$
  SELECT CASE operation_value
    WHEN 'createSSOConnection' THEN
      jsonb_typeof(intent_value)='object'
      AND intent_value=jsonb_build_object('display_name',intent_value->>'display_name','protocol',intent_value->>'protocol','identity_provider',intent_value->>'identity_provider')
      AND length(intent_value->>'display_name') BETWEEN 1 AND 128
      AND intent_value->>'protocol' IN('saml','oidc')
      AND intent_value->>'identity_provider' IN('classlink','cyberark','duo','generic','google-workspace','jumpcloud','keycloak','miniorange','microsoft-entra','okta','onelogin','pingfederate','rippling','salesforce','shibboleth')
    WHEN 'createSCIMConnection' THEN
      jsonb_typeof(intent_value)='object'
      AND intent_value=jsonb_build_object('display_name',intent_value->>'display_name','identity_provider',intent_value->>'identity_provider')
      AND length(intent_value->>'display_name') BETWEEN 1 AND 128
      AND intent_value->>'identity_provider' IN('generic','okta','microsoft-entra','cyberark','jumpcloud','onelogin','pingfederate','rippling')
    WHEN 'deleteSSOConnection' THEN
      jsonb_typeof(intent_value)='object' AND intent_value=jsonb_build_object('reference',intent_value->>'reference')
      AND intent_value->>'reference'~'^(saml|oidc|external)-connection-[A-Za-z0-9_-]+$' AND length(intent_value->>'reference') BETWEEN 18 AND 128
    WHEN 'testSSOConnection' THEN
      jsonb_typeof(intent_value)='object' AND intent_value=jsonb_build_object('reference',intent_value->>'reference')
      AND intent_value->>'reference'~'^(saml|oidc|external)-connection-[A-Za-z0-9_-]+$' AND length(intent_value->>'reference') BETWEEN 18 AND 128
    WHEN 'deleteSCIMConnection' THEN
      jsonb_typeof(intent_value)='object' AND intent_value=jsonb_build_object('reference',intent_value->>'reference')
      AND intent_value->>'reference'~'^scim-connection-[A-Za-z0-9_-]+$' AND length(intent_value->>'reference') BETWEEN 20 AND 128
    ELSE false
  END
$intent$;

CREATE FUNCTION public.zasp_identity_admin_reserve_mutation(organization_value text,principal_value text,operation_value text,idempotency_value text,mutation_value text,intent_digest_value bytea,intent_value jsonb,audit_value text,correlation_value text,receipt_value text,owner_token_value bytea,lease_seconds_value integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $reserve$
DECLARE existing zasp_identity_provider_mutations%ROWTYPE;provider_organization_value text;
BEGIN
  IF NOT zasp_identity_admin_authorized(organization_value,principal_value) OR operation_value NOT IN('createSSOConnection','deleteSSOConnection','testSSOConnection','createSCIMConnection','deleteSCIMConnection')
     OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$'
     OR NOT zasp_valid_product_id(mutation_value) OR octet_length(intent_digest_value)<>32 OR NOT zasp_identity_admin_intent_valid(operation_value,intent_value) OR pg_column_size(intent_value)>4096
     OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(receipt_value) OR octet_length(owner_token_value)<>32 OR lease_seconds_value NOT BETWEEN 5 AND 120 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity mutation rejected';
  END IF;
  SELECT membership.organization_reference INTO provider_organization_value FROM zasp_identity_memberships membership WHERE membership.organization_id=organization_value AND membership.principal_id=principal_value AND membership.active;
  IF NOT FOUND OR provider_organization_value!~'^organization-[A-Za-z0-9_-]+$' OR length(provider_organization_value) NOT BETWEEN 14 AND 128 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity provider organization denied';END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,principal_value,operation_value,idempotency_value),0));
  SELECT * INTO existing FROM zasp_identity_provider_mutations mutation WHERE (mutation.organization_id,mutation.principal_id,mutation.operation,mutation.idempotency_key)=(organization_value,principal_value,operation_value,idempotency_value);
  IF FOUND THEN
    IF existing.intent_digest<>intent_digest_value OR existing.intent<>intent_value OR existing.expires_at<=transaction_timestamp() THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='identity mutation replay conflict';
    END IF;
    IF existing.state='completed' THEN RETURN existing.response||jsonb_build_object('replayed',true);END IF;
    IF existing.state='reserved' AND existing.lease_expires_at>transaction_timestamp() AND existing.owner_token<>owner_token_value THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='identity mutation lease busy';END IF;
    UPDATE zasp_identity_provider_mutations SET owner_token=owner_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds_value),updated_at=transaction_timestamp(),version=version+1 WHERE (organization_id,principal_id,operation,idempotency_key)=(organization_value,principal_value,operation_value,idempotency_value) RETURNING * INTO existing;
    RETURN jsonb_build_object('mutation_id',existing.mutation_id,'state',existing.state,'version',existing.version,'provider_organization_reference',existing.provider_organization_reference,'audit_id',existing.audit_id,'correlation_id',existing.correlation_id,'receipt_id',existing.receipt_id,'replayed',true);
  END IF;
  INSERT INTO zasp_identity_provider_mutations(organization_id,principal_id,provider_organization_reference,operation,idempotency_key,mutation_id,intent_digest,intent,audit_id,correlation_id,receipt_id,owner_token,lease_expires_at)
  VALUES(organization_value,principal_value,provider_organization_value,operation_value,idempotency_value,mutation_value,intent_digest_value,intent_value,audit_value,correlation_value,receipt_value,owner_token_value,transaction_timestamp()+make_interval(secs=>lease_seconds_value));
  UPDATE zasp_identity_administration_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN jsonb_build_object('mutation_id',mutation_value,'state','reserved','version',1,'provider_organization_reference',provider_organization_value,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
END
$reserve$;

CREATE FUNCTION public.zasp_identity_admin_mark_unknown(organization_value text,principal_value text,operation_value text,idempotency_value text,mutation_value text,owner_token_value bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $unknown$
DECLARE changed zasp_identity_provider_mutations%ROWTYPE;
BEGIN
  IF NOT zasp_identity_admin_authorized(organization_value,principal_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity mutation denied';END IF;
  UPDATE zasp_identity_provider_mutations mutation SET state='provider_unknown',version=mutation.version+1,lease_expires_at=transaction_timestamp(),updated_at=transaction_timestamp()
  WHERE (mutation.organization_id,mutation.principal_id,mutation.operation,mutation.idempotency_key,mutation.mutation_id)=(organization_value,principal_value,operation_value,idempotency_value,mutation_value)
    AND mutation.owner_token=owner_token_value AND mutation.lease_expires_at>transaction_timestamp() AND mutation.state IN('reserved','provider_unknown') RETURNING * INTO changed;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='identity mutation transition rejected';END IF;
  RETURN jsonb_build_object('mutation_id',changed.mutation_id,'state',changed.state,'version',changed.version);
END
$unknown$;

CREATE FUNCTION public.zasp_identity_admin_complete_mutation(organization_value text,principal_value text,operation_value text,idempotency_value text,mutation_value text,owner_token_value bytea,connection_value jsonb,grant_value text,ciphertext_value bytea,nonce_value bytea,tag_value bytea,grant_expires_value timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $complete$
DECLARE mutation_row zasp_identity_provider_mutations%ROWTYPE;reference_value text;kind_value text;protocol_value text;status_value text;display_value text;provider_value text;base_value text;connection_version bigint;response_value jsonb;workspace_value text;environment_value text;
BEGIN
  IF NOT zasp_identity_admin_authorized(organization_value,principal_value) OR jsonb_typeof(connection_value)<>'object' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity mutation completion denied';END IF;
  SELECT * INTO mutation_row FROM zasp_identity_provider_mutations mutation WHERE (mutation.organization_id,mutation.principal_id,mutation.operation,mutation.idempotency_key,mutation.mutation_id)=(organization_value,principal_value,operation_value,idempotency_value,mutation_value) FOR UPDATE;
  IF NOT FOUND OR mutation_row.state NOT IN('reserved','provider_unknown') OR mutation_row.owner_token<>owner_token_value OR mutation_row.lease_expires_at<=transaction_timestamp() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='identity mutation completion rejected';END IF;
  reference_value:=connection_value->>'reference';kind_value:=connection_value->>'kind';
  IF operation_value IN('deleteSSOConnection','deleteSCIMConnection') THEN
    IF reference_value<>mutation_row.intent->>'reference'
       OR kind_value<>(CASE operation_value WHEN 'deleteSSOConnection' THEN 'sso' ELSE 'scim' END)
       OR connection_value<>jsonb_build_object('reference',reference_value,'kind',kind_value,'deleted',true)
       OR (kind_value='sso' AND (reference_value!~'^(saml|oidc|external)-connection-[A-Za-z0-9_-]+$' OR length(reference_value) NOT BETWEEN 18 AND 128))
       OR (kind_value='scim' AND (reference_value!~'^scim-connection-[A-Za-z0-9_-]+$' OR length(reference_value) NOT BETWEEN 20 AND 128)) THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity deletion result rejected';
    END IF;
  ELSE
    protocol_value:=connection_value->>'protocol';status_value:=connection_value->>'status';display_value:=connection_value->>'display_name';provider_value:=connection_value->>'identity_provider';base_value:=connection_value->>'base_url';
    IF length(reference_value) NOT BETWEEN 12 AND 128 OR kind_value NOT IN('sso','scim') OR status_value NOT IN('active','pending','disabled') OR length(display_value) NOT BETWEEN 1 AND 128 OR length(provider_value) NOT BETWEEN 1 AND 64
       OR (kind_value='sso' AND (protocol_value NOT IN('saml','oidc') OR base_value IS NOT NULL)) OR (kind_value='scim' AND (protocol_value IS NOT NULL OR length(base_value) NOT BETWEEN 8 AND 2048))
       OR connection_value<>jsonb_build_object('reference',reference_value,'kind',kind_value,'protocol',protocol_value,'status',status_value,'display_name',display_value,'identity_provider',provider_value,'base_url',base_value)
       OR (operation_value LIKE '%SSO%' AND kind_value<>'sso') OR (operation_value LIKE '%SCIM%' AND kind_value<>'scim')
       OR (operation_value='createSSOConnection' AND (display_value<>mutation_row.intent->>'display_name' OR protocol_value<>mutation_row.intent->>'protocol' OR provider_value<>mutation_row.intent->>'identity_provider'))
       OR (operation_value='createSCIMConnection' AND (display_value<>mutation_row.intent->>'display_name' OR provider_value<>mutation_row.intent->>'identity_provider'))
       OR (operation_value='testSSOConnection' AND (reference_value<>mutation_row.intent->>'reference' OR status_value<>'active')) THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity connection result rejected';
    END IF;
  END IF;
  SELECT scope.workspace_id,scope.environment_id INTO workspace_value,environment_value FROM zasp_authorized_scopes scope WHERE scope.principal_id=principal_value AND scope.organization_id=organization_value ORDER BY scope.is_default DESC,scope.workspace_id,scope.environment_id LIMIT 1;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity audit scope denied';END IF;
  IF operation_value IN('deleteSSOConnection','deleteSCIMConnection') THEN
    UPDATE zasp_identity_provider_connections connection SET deleted_at=COALESCE(connection.deleted_at,transaction_timestamp()),observed_at=transaction_timestamp(),version=CASE WHEN connection.deleted_at IS NULL THEN connection.version+1 ELSE connection.version END
    WHERE (connection.organization_id,connection.connection_reference)=(organization_value,reference_value) RETURNING version INTO connection_version;
    IF NOT FOUND THEN connection_version:=1;END IF;
  ELSE
    INSERT INTO zasp_identity_provider_connections(organization_id,connection_reference,kind,protocol,status,display_name,identity_provider,base_url)
    VALUES(organization_value,reference_value,kind_value,protocol_value,status_value,display_value,provider_value,base_value)
    ON CONFLICT(organization_id,connection_reference) DO UPDATE SET kind=EXCLUDED.kind,protocol=EXCLUDED.protocol,status=EXCLUDED.status,display_name=EXCLUDED.display_name,identity_provider=EXCLUDED.identity_provider,base_url=EXCLUDED.base_url,deleted_at=NULL,observed_at=transaction_timestamp(),version=zasp_identity_provider_connections.version+1
    RETURNING version INTO connection_version;
  END IF;
  IF operation_value='createSCIMConnection' THEN
    IF NOT zasp_valid_product_id(grant_value) OR octet_length(ciphertext_value) NOT BETWEEN 1 AND 8192 OR octet_length(nonce_value)<>12 OR octet_length(tag_value)<>16 OR grant_expires_value<=transaction_timestamp() OR grant_expires_value>transaction_timestamp()+interval '15 minutes' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity secret reveal rejected';
    END IF;
    INSERT INTO zasp_identity_secret_reveal_grants(organization_id,principal_id,mutation_id,grant_id,ciphertext,nonce,authentication_tag,expires_at)
    VALUES(organization_value,principal_value,mutation_value,grant_value,ciphertext_value,nonce_value,tag_value,grant_expires_value);
  ELSIF grant_value IS NOT NULL OR ciphertext_value IS NOT NULL OR nonce_value IS NOT NULL OR tag_value IS NOT NULL OR grant_expires_value IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity secret reveal forbidden';
  END IF;
  response_value:=jsonb_build_object('body',connection_value,'version',connection_version,'mutation_id',mutation_row.mutation_id,'audit_id',mutation_row.audit_id,'correlation_id',mutation_row.correlation_id,'receipt_id',mutation_row.receipt_id,'replayed',false,'secret_grant_id',grant_value);
  UPDATE zasp_identity_provider_mutations SET state='completed',provider_reference=reference_value,response=response_value,version=version+1,updated_at=transaction_timestamp()
  WHERE (organization_id,principal_id,operation,idempotency_key)=(organization_value,principal_value,operation_value,idempotency_value);
  INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
  VALUES(organization_value,workspace_value,environment_value,mutation_row.audit_id,principal_value,'identity_provider.'||operation_value,reference_value,'succeeded',jsonb_build_object('mutation_id',mutation_value,'kind',kind_value));
  RETURN response_value;
END
$complete$;

CREATE FUNCTION public.zasp_identity_admin_connection_page(organization_value text,principal_value text,kind_value text,after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $page$
DECLARE items_value jsonb;next_value text;
BEGIN
  IF NOT zasp_identity_admin_authorized(organization_value,principal_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='identity connection page denied';END IF;
  IF kind_value NOT IN('sso','scim') OR limit_value NOT BETWEEN 1 AND 100 OR (after_value IS NOT NULL AND length(after_value) NOT BETWEEN 12 AND 128) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity connection page rejected';END IF;
  WITH candidates AS (SELECT * FROM zasp_identity_provider_connections connection WHERE connection.organization_id=organization_value AND connection.kind=kind_value AND connection.deleted_at IS NULL AND (after_value IS NULL OR connection.connection_reference>after_value) ORDER BY connection.connection_reference LIMIT limit_value+1), page_rows AS (SELECT * FROM candidates ORDER BY connection_reference LIMIT limit_value)
  SELECT COALESCE(jsonb_agg(jsonb_build_object('reference',connection_reference,'kind',kind,'protocol',protocol,'status',status,'display_name',display_name,'identity_provider',identity_provider,'base_url',base_url,'version',version,'observed_at',to_char(observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY connection_reference),'[]'::jsonb),(SELECT connection_reference FROM candidates ORDER BY connection_reference OFFSET limit_value LIMIT 1) INTO items_value,next_value FROM page_rows;
  RETURN jsonb_build_object('items',items_value,'next_id',next_value);
END
$page$;

CREATE FUNCTION public.zasp_identity_admin_reveal_secret(organization_value text,principal_value text,grant_value text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog, public AS $reveal$
  SELECT jsonb_build_object('ciphertext',replace(encode(ciphertext,'base64'),E'\n',''),'nonce',replace(encode(nonce,'base64'),E'\n',''),'authentication_tag',replace(encode(authentication_tag,'base64'),E'\n',''),'expires_at',to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM zasp_identity_secret_reveal_grants WHERE organization_id=organization_value AND principal_id=principal_value AND grant_id=grant_value AND acknowledged_at IS NULL AND expires_at>transaction_timestamp() AND zasp_identity_admin_authorized(organization_value,principal_value)
$reveal$;

CREATE FUNCTION public.zasp_identity_admin_ack_secret(organization_value text,principal_value text,grant_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $ack$
BEGIN
  UPDATE zasp_identity_secret_reveal_grants SET acknowledged_at=transaction_timestamp(),ciphertext=NULL,nonce=NULL,authentication_tag=NULL WHERE organization_id=organization_value AND principal_id=principal_value AND grant_id=grant_value AND acknowledged_at IS NULL AND zasp_identity_admin_authorized(organization_value,principal_value);
  IF NOT FOUND AND NOT EXISTS(SELECT 1 FROM zasp_identity_secret_reveal_grants WHERE organization_id=organization_value AND principal_id=principal_value AND grant_id=grant_value AND acknowledged_at IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='identity secret grant not found';END IF;
  RETURN jsonb_build_object('acknowledged',true);
END
$ack$;

CREATE FUNCTION public.zasp_identity_admin_reconcile_deprovision(project_value text,event_value text,organization_reference_value text,member_value text,event_digest_value bytea,audit_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $deprovision$
DECLARE existing zasp_identity_webhook_events%ROWTYPE;session_count integer;token_count integer;principal_value text;organization_value text;workspace_value text;environment_value text;member_active boolean;
BEGIN
  IF length(project_value) NOT BETWEEN 8 AND 128 OR event_value!~'^webhook-event-(test|live)-[A-Za-z0-9_-]+$' OR length(event_value) NOT BETWEEN 24 AND 128 OR organization_reference_value!~'^organization-[A-Za-z0-9_-]+$' OR length(organization_reference_value) NOT BETWEEN 14 AND 128 OR member_value!~'^member-[A-Za-z0-9_-]+$' OR length(member_value) NOT BETWEEN 8 AND 128 OR octet_length(event_digest_value)<>32 OR NOT zasp_valid_product_id(audit_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity deprovision rejected';END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(event_value,0));
  SELECT membership.organization_id,membership.principal_id,membership.active INTO organization_value,principal_value,member_active FROM zasp_identity_memberships membership WHERE membership.organization_reference=organization_reference_value AND membership.member_reference=member_value FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='identity member not found';END IF;
  SELECT * INTO existing FROM zasp_identity_webhook_events WHERE event_id=event_value;
  IF FOUND THEN
    IF existing.project_id<>project_value OR existing.organization_id<>organization_value OR existing.member_reference<>member_value OR existing.event_digest<>event_digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='identity webhook replay conflict';END IF;
    RETURN jsonb_build_object('processed',false,'replayed',true,'revoked_sessions',existing.revoked_sessions,'revoked_tokens',existing.revoked_tokens);
  END IF;
  IF NOT member_active THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='identity member not found';END IF;
  UPDATE zasp_identity_memberships SET active=false,version=version+1 WHERE organization_id=organization_value AND principal_id=principal_value;
  UPDATE zasp_product_sessions SET revoked_at=COALESCE(revoked_at,transaction_timestamp()),version=CASE WHEN revoked_at IS NULL THEN version+1 ELSE version END WHERE organization_id=organization_value AND principal_id=principal_value AND revoked_at IS NULL;GET DIAGNOSTICS session_count=ROW_COUNT;
  UPDATE zasp_product_api_tokens SET revoked_at=COALESCE(revoked_at,transaction_timestamp()),version=CASE WHEN revoked_at IS NULL THEN version+1 ELSE version END WHERE organization_id=organization_value AND principal_id=principal_value AND revoked_at IS NULL;GET DIAGNOSTICS token_count=ROW_COUNT;
  SELECT scope.workspace_id,scope.environment_id INTO workspace_value,environment_value FROM zasp_authorized_scopes scope WHERE scope.organization_id=organization_value AND scope.principal_id=principal_value ORDER BY scope.is_default DESC,scope.workspace_id,scope.environment_id LIMIT 1;
  IF NOT FOUND THEN SELECT mapping.workspace_id,mapping.environment_id INTO workspace_value,environment_value FROM zasp_group_mappings mapping WHERE mapping.organization_id=organization_value ORDER BY mapping.group_reference LIMIT 1;END IF;
  IF workspace_value IS NULL OR environment_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='identity audit scope not found';END IF;
  DELETE FROM zasp_authorized_scopes WHERE organization_id=organization_value AND principal_id=principal_value;
  DELETE FROM zasp_identity_member_groups WHERE organization_id=organization_value AND principal_id=principal_value;
  INSERT INTO zasp_identity_webhook_events(project_id,event_id,organization_id,member_reference,event_kind,event_digest,audit_id,revoked_sessions,revoked_tokens) VALUES(project_value,event_value,organization_value,member_value,'scim.member.delete',event_digest_value,audit_value,session_count,token_count);
  INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES(organization_value,workspace_value,environment_value,audit_value,principal_value,'identity.member.deprovision',principal_value,'succeeded',jsonb_build_object('event_id',event_value,'member_reference',member_value,'revoked_sessions',session_count,'revoked_tokens',token_count));
  UPDATE zasp_identity_administration_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN jsonb_build_object('processed',true,'replayed',false,'revoked_sessions',session_count,'revoked_tokens',token_count);
END
$deprovision$;

CREATE FUNCTION public.zasp_identity_admin_effective_scopes(principal_value text,organization_value text) RETURNS TABLE(organization_id text,workspace_id text,environment_id text,label text,permissions jsonb,is_default boolean) LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $effective$
  WITH membership AS (
    SELECT item.principal_id,item.organization_id,item.role FROM zasp_identity_memberships item
    WHERE item.principal_id=principal_value AND item.organization_id=organization_value AND item.active
  ), grants AS (
    SELECT scope.organization_id,scope.workspace_id,scope.environment_id,scope.label,zasp_effective_scope_permissions(scope.permissions,membership.role) AS permissions,scope.is_default,0 AS source
    FROM zasp_authorized_scopes scope JOIN membership ON membership.principal_id=scope.principal_id AND membership.organization_id=scope.organization_id
    UNION ALL
    SELECT mapping.organization_id,mapping.workspace_id,mapping.environment_id,mapping.group_reference,zasp_effective_scope_permissions('[]'::jsonb,mapping.role),false,1
    FROM zasp_identity_member_groups member_group JOIN membership ON membership.principal_id=member_group.principal_id AND membership.organization_id=member_group.organization_id
    JOIN zasp_group_mappings mapping ON mapping.organization_id=member_group.organization_id AND mapping.group_reference=member_group.group_reference
  ), scope_keys AS (
    SELECT grant_row.organization_id,grant_row.workspace_id,grant_row.environment_id,
      COALESCE(min(grant_row.label) FILTER(WHERE grant_row.source=0),min(grant_row.label)) AS label,
      bool_or(grant_row.is_default) AS is_default
    FROM grants grant_row GROUP BY grant_row.organization_id,grant_row.workspace_id,grant_row.environment_id
  )
  SELECT scope_key.organization_id,scope_key.workspace_id,scope_key.environment_id,scope_key.label,
    COALESCE((SELECT jsonb_agg(permission ORDER BY permission) FROM (SELECT DISTINCT jsonb_array_elements_text(grant_row.permissions) AS permission FROM grants grant_row WHERE (grant_row.organization_id,grant_row.workspace_id,grant_row.environment_id)=(scope_key.organization_id,scope_key.workspace_id,scope_key.environment_id)) permission_values),'[]'::jsonb),
    scope_key.is_default
  FROM scope_keys scope_key
$effective$;

CREATE FUNCTION public.zasp_identity_admin_resolve_session(organization_reference_value text,member_reference_value text,group_values jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $resolve$
DECLARE membership_row zasp_identity_memberships%ROWTYPE;removed_count integer;added_count integer;workspace_value text;environment_value text;permissions_value jsonb;
BEGIN
  IF organization_reference_value!~'^organization-[A-Za-z0-9_-]+$' OR length(organization_reference_value) NOT BETWEEN 14 AND 128
     OR member_reference_value!~'^member-[A-Za-z0-9_-]+$' OR length(member_reference_value) NOT BETWEEN 8 AND 128
     OR jsonb_typeof(group_values)<>'array' OR jsonb_array_length(group_values)>100
     OR EXISTS(SELECT 1 FROM jsonb_array_elements(group_values) item WHERE jsonb_typeof(item)<>'string' OR item#>>'{}'!~'^scim-group-(test|live)-[A-Za-z0-9_-]+$' OR length(item#>>'{}') NOT BETWEEN 17 AND 128)
     OR (SELECT count(*) FROM jsonb_array_elements_text(group_values))<>(SELECT count(DISTINCT value) FROM jsonb_array_elements_text(group_values) AS claim(value)) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='identity group claims rejected';
  END IF;
  SELECT * INTO membership_row FROM zasp_identity_memberships membership WHERE membership.organization_reference=organization_reference_value AND membership.member_reference=member_reference_value AND membership.active FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='02000',MESSAGE='identity member not found';END IF;
  WITH claims AS MATERIALIZED (SELECT value AS group_reference FROM jsonb_array_elements_text(group_values)),removed AS (DELETE FROM zasp_identity_member_groups member_group WHERE member_group.organization_id=membership_row.organization_id AND member_group.principal_id=membership_row.principal_id AND NOT EXISTS(SELECT 1 FROM claims WHERE claims.group_reference=member_group.group_reference) RETURNING 1),added AS (INSERT INTO zasp_identity_member_groups(organization_id,principal_id,group_reference) SELECT membership_row.organization_id,membership_row.principal_id,claims.group_reference FROM claims ON CONFLICT DO NOTHING RETURNING 1) SELECT (SELECT count(*) FROM removed),(SELECT count(*) FROM added) INTO removed_count,added_count;
  IF removed_count+added_count>0 THEN
    UPDATE zasp_product_sessions SET revoked_at=COALESCE(revoked_at,transaction_timestamp()),version=CASE WHEN revoked_at IS NULL THEN version+1 ELSE version END WHERE organization_id=membership_row.organization_id AND principal_id=membership_row.principal_id AND revoked_at IS NULL;
    UPDATE zasp_product_api_tokens SET revoked_at=COALESCE(revoked_at,transaction_timestamp()),version=CASE WHEN revoked_at IS NULL THEN version+1 ELSE version END WHERE organization_id=membership_row.organization_id AND principal_id=membership_row.principal_id AND revoked_at IS NULL;
    UPDATE zasp_identity_administration_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  END IF;
  SELECT scope.workspace_id,scope.environment_id,scope.permissions INTO workspace_value,environment_value,permissions_value FROM zasp_identity_admin_effective_scopes(membership_row.principal_id,membership_row.organization_id) scope ORDER BY scope.is_default DESC,scope.workspace_id,scope.environment_id LIMIT 1;
  IF NOT FOUND THEN RETURN NULL;END IF;
  RETURN jsonb_build_object('principal_id',membership_row.principal_id,'organization_id',membership_row.organization_id,'organization_reference',membership_row.organization_reference,'member_reference',membership_row.member_reference,'role',membership_row.role,'active',membership_row.active,'workspace_id',workspace_value,'environment_id',environment_value,'permissions',permissions_value);
END
$resolve$;

DO $functions$
DECLARE procedure_oid oid;
BEGIN
  FOR procedure_oid IN SELECT procedure_row.oid FROM pg_proc procedure_row JOIN pg_namespace namespace_row ON namespace_row.oid=procedure_row.pronamespace WHERE namespace_row.nspname='public' AND procedure_row.proname IN('zasp_identity_admin_authorized','zasp_identity_admin_provider_organization','zasp_identity_admin_intent_valid','zasp_identity_admin_reserve_mutation','zasp_identity_admin_mark_unknown','zasp_identity_admin_complete_mutation','zasp_identity_admin_connection_page','zasp_identity_admin_reveal_secret','zasp_identity_admin_ack_secret','zasp_identity_admin_reconcile_deprovision','zasp_identity_admin_effective_scopes','zasp_identity_admin_resolve_session') LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure);
  END LOOP;
END
$functions$;

GRANT EXECUTE ON FUNCTION public.zasp_identity_admin_provider_organization(text,text),public.zasp_identity_admin_reserve_mutation(text,text,text,text,text,bytea,jsonb,text,text,text,bytea,integer),public.zasp_identity_admin_mark_unknown(text,text,text,text,text,bytea),public.zasp_identity_admin_complete_mutation(text,text,text,text,text,bytea,jsonb,text,bytea,bytea,bytea,timestamptz),public.zasp_identity_admin_connection_page(text,text,text,text,integer),public.zasp_identity_admin_reveal_secret(text,text,text),public.zasp_identity_admin_ack_secret(text,text,text),public.zasp_identity_admin_reconcile_deprovision(text,text,text,text,bytea,text),public.zasp_identity_admin_effective_scopes(text,text),public.zasp_identity_admin_resolve_session(text,text,jsonb) TO zasp_discovery_api;

CREATE FUNCTION public.zasp_identity_admin_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $security$
  SELECT
    has_table_privilege('zasp_discovery_authority','public.zasp_identity_memberships','SELECT,UPDATE')
    AND has_table_privilege('zasp_discovery_authority','public.zasp_product_sessions','SELECT,UPDATE')
    AND has_table_privilege('zasp_discovery_authority','public.zasp_product_api_tokens','SELECT,UPDATE')
    AND has_table_privilege('zasp_discovery_authority','public.zasp_authorized_scopes','SELECT,DELETE')
    AND has_table_privilege('zasp_discovery_authority','public.zasp_group_mappings','SELECT')
    AND has_table_privilege('zasp_discovery_authority','public.zasp_admin_audit','INSERT')
    AND NOT EXISTS(
      SELECT 1 FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace
      WHERE namespace.nspname='public' AND class.relname IN('zasp_identity_administration_state','zasp_identity_provider_connections','zasp_identity_provider_mutations','zasp_identity_secret_reveal_grants','zasp_identity_webhook_events','zasp_identity_member_groups')
        AND (class.relowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT class.relrowsecurity OR NOT class.relforcerowsecurity
          OR (SELECT count(*) FROM pg_policy policy WHERE policy.polrelid=class.oid)<>1
          OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(class.relacl,acldefault('r',class.relowner))) acl WHERE acl.grantee<>class.relowner))
    )
    AND NOT EXISTS(
      SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace
      WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_identity_admin_authorized','zasp_identity_admin_provider_organization','zasp_identity_admin_intent_valid','zasp_identity_admin_reserve_mutation','zasp_identity_admin_mark_unknown','zasp_identity_admin_complete_mutation','zasp_identity_admin_connection_page','zasp_identity_admin_reveal_secret','zasp_identity_admin_ack_secret','zasp_identity_admin_reconcile_deprovision','zasp_identity_admin_effective_scopes','zasp_identity_admin_resolve_session','zasp_identity_admin_security_ready'])
        AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']
          OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee NOT IN(procedure.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api')))
          OR has_function_privilege('zasp_discovery_api',procedure.oid,'EXECUTE')<>(procedure.proname=ANY(ARRAY['zasp_identity_admin_provider_organization','zasp_identity_admin_reserve_mutation','zasp_identity_admin_mark_unknown','zasp_identity_admin_complete_mutation','zasp_identity_admin_connection_page','zasp_identity_admin_reveal_secret','zasp_identity_admin_ack_secret','zasp_identity_admin_reconcile_deprovision','zasp_identity_admin_effective_scopes','zasp_identity_admin_resolve_session'])))
    )
$security$;

ALTER FUNCTION public.zasp_identity_admin_security_ready() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_identity_admin_security_ready() FROM PUBLIC,zasp_discovery_api;

CREATE FUNCTION public.zasp_identity_administration_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
  WITH identities(value) AS (
    SELECT concat_ws('|','table',class.relname,owner.rolname,class.relrowsecurity,class.relforcerowsecurity,COALESCE(class.relacl::text,'')) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_identity_%' AND class.relname IN('zasp_identity_administration_state','zasp_identity_provider_connections','zasp_identity_provider_mutations','zasp_identity_secret_reveal_grants','zasp_identity_webhook_events','zasp_identity_member_groups') AND class.relkind IN('r','i')
    UNION ALL
    SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_identity_admin%'
    UNION ALL
    SELECT concat_ws('|','column',class.relname,attribute.attnum,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=class.oid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname IN('zasp_identity_administration_state','zasp_identity_provider_connections','zasp_identity_provider_mutations','zasp_identity_secret_reveal_grants','zasp_identity_webhook_events','zasp_identity_member_groups') AND attribute.attnum>0 AND NOT attribute.attisdropped
    UNION ALL
    SELECT concat_ws('|','constraint',class.relname,constraint_value.conname,constraint_value.contype,constraint_value.convalidated,pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname IN('zasp_identity_administration_state','zasp_identity_provider_connections','zasp_identity_provider_mutations','zasp_identity_secret_reveal_grants','zasp_identity_webhook_events','zasp_identity_member_groups','zasp_group_mappings')
    UNION ALL
    SELECT concat_ws('|','index',class.relname,index_value.relname,pg_get_indexdef(index_value.oid)) FROM pg_index index_metadata JOIN pg_class class ON class.oid=index_metadata.indrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_class index_value ON index_value.oid=index_metadata.indexrelid WHERE namespace.nspname='public' AND class.relname IN('zasp_identity_administration_state','zasp_identity_provider_connections','zasp_identity_provider_mutations','zasp_identity_secret_reveal_grants','zasp_identity_webhook_events','zasp_identity_member_groups')
  ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_identity_administration_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
  SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$' AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
    AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=19 AND name='identity_administration' AND checksum=expected_checksum)
    AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='identity-administration-v1') AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>19)
    AND (SELECT count(*) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname IN('zasp_identity_administration_state','zasp_identity_provider_connections','zasp_identity_provider_mutations','zasp_identity_secret_reveal_grants','zasp_identity_webhook_events','zasp_identity_member_groups') AND class.relkind='r' AND class.relowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND class.relrowsecurity AND class.relforcerowsecurity)=6
    AND zasp_identity_admin_security_ready()
    AND has_function_privilege('zasp_discovery_api','public.zasp_identity_administration_readiness(text,text)','EXECUTE')
    AND zasp_identity_administration_live_fingerprint()=expected_fingerprint
$readiness$;

ALTER FUNCTION public.zasp_identity_administration_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_identity_administration_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_identity_administration_live_fingerprint(),public.zasp_identity_administration_readiness(text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION public.zasp_identity_administration_readiness(text,text) TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker,zasp_runtime_coordinator,zasp_runtime_archive_worker,zasp_runtime_index_worker,zasp_runtime_correlation_worker,zasp_runtime_projection_worker,zasp_gateway_control,zasp_security_agent_api,zasp_security_agent_worker;

DO $schema_marker$
BEGIN
  UPDATE public.zasp_schema_metadata SET value='identity-administration-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-execution-v1';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='identity administration schema marker drift';END IF;
END
$schema_marker$;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('identity_administration_fingerprint', '7653d0b6a753d4644866621014c887fdc4e52d57ef58a0b8a72ef112f7ab2228') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;
