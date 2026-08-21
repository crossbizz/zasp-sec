DO $roles$
DECLARE role_name text; role_oid oid;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['zasp_security_agent_api','zasp_security_agent_worker'] LOOP
    SELECT oid INTO role_oid FROM pg_roles WHERE rolname=role_name;
    IF role_oid IS NULL THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',role_name);
    ELSE
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent role authority rejected';
    END IF;
  END LOOP;
END $roles$;

GRANT zasp_security_agent_api,zasp_security_agent_worker TO zasp_discovery_authority WITH ADMIN OPTION;

CREATE TABLE public.zasp_security_agent_execution_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  used_at timestamptz
);

CREATE TABLE public.zasp_security_agent_principal_bindings (
  principal_name text PRIMARY KEY CHECK(principal_name~'^[a-z][a-z0-9_]{2,62}$'),
  authority_role text NOT NULL UNIQUE CHECK(authority_role IN('zasp_security_agent_api','zasp_security_agent_worker')),
  registered_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.zasp_security_agent_definitions (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  definition_id text NOT NULL,
  activation text NOT NULL DEFAULT 'draft' CHECK(activation IN('draft','validated','supervised','autonomous')),
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  definition_version integer NOT NULL CHECK(definition_version>0),
  body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
  plan_catalog_version text NOT NULL CHECK(length(plan_catalog_version) BETWEEN 1 AND 64),
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id)
);

CREATE TABLE public.zasp_security_agent_definition_versions (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  definition_id text NOT NULL,
  version bigint NOT NULL CHECK(version>0),
  activation text NOT NULL CHECK(activation IN('draft','validated','supervised','autonomous')),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'),
  definition_digest bytea NOT NULL CHECK(octet_length(definition_digest)=32),
  actor_id text NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 128),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,version)
);

CREATE TABLE public.zasp_security_agent_request_receipts (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  principal_id text NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 128),
  operation text NOT NULL CHECK(operation IN('activateSecurityAgent','simulateSecurityAgent','runSecurityAgent','cancelSecurityAgentRun','decideSecurityAgentApproval')),
  idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key~'^[A-Za-z0-9][A-Za-z0-9._:-]*$'),
  resource_id text NOT NULL CHECK(length(resource_id) BETWEEN 1 AND 128),
  expected_version bigint NOT NULL CHECK(expected_version>=0),
  intent jsonb NOT NULL CHECK(jsonb_typeof(intent)='object'),
  intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
  response jsonb NOT NULL CHECK(jsonb_typeof(response)='object'),
  audit_id text NOT NULL CHECK(length(audit_id) BETWEEN 1 AND 128),
  correlation_id text NOT NULL CHECK(length(correlation_id) BETWEEN 1 AND 128),
  receipt_id text NOT NULL CHECK(length(receipt_id) BETWEEN 1 AND 128),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT transaction_timestamp()+interval '7 days',
  PRIMARY KEY(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key),
  UNIQUE(organization_id,receipt_id),
  CHECK(expires_at>created_at AND expires_at<=created_at+interval '7 days')
);

CREATE TABLE public.zasp_security_agent_kill_switches (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  action_key text NOT NULL DEFAULT '*',
  execution_enabled boolean NOT NULL DEFAULT false,
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  updated_by text NOT NULL CHECK(length(updated_by) BETWEEN 1 AND 128),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,action_key)
);

CREATE TABLE public.zasp_security_agent_trigger_receipts (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  definition_id text NOT NULL,
  trigger_id text NOT NULL,
  trigger_kind text NOT NULL CHECK(trigger_kind IN('finding','attack_path','runtime_decision','manual')),
  trigger_version bigint NOT NULL CHECK(trigger_version>0),
  trigger_digest bytea NOT NULL CHECK(octet_length(trigger_digest)=32),
  run_id text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_version),
  UNIQUE(organization_id,workspace_id,environment_id,run_id)
);

CREATE TABLE public.zasp_security_agent_runs (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  run_id text NOT NULL,
  definition_id text NOT NULL,
  definition_version bigint NOT NULL CHECK(definition_version>0),
  trigger_id text NOT NULL,
  state text NOT NULL CHECK(state IN('queued','planning','waiting_approval','running','verifying','contained','remediated','needs_human','failed','inconclusive','cancelled')),
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  plan_hash bytea CHECK(plan_hash IS NULL OR octet_length(plan_hash)=32),
  available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),
  lease_owner text,
  lease_token text,
  lease_expires_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  completed_at timestamptz,
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
  CHECK((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (state IN('planning','running','verifying') AND length(lease_owner) BETWEEN 1 AND 128 AND length(lease_token) BETWEEN 16 AND 128 AND lease_expires_at IS NOT NULL))
);

CREATE TABLE public.zasp_security_agent_plans (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  run_id text NOT NULL,
  definition_id text NOT NULL,
  definition_version bigint NOT NULL CHECK(definition_version>0),
  trigger_digest bytea NOT NULL CHECK(octet_length(trigger_digest)=32),
  catalog_version text NOT NULL CHECK(length(catalog_version) BETWEEN 1 AND 64),
  plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object'),
  plan_hash bytea NOT NULL CHECK(octet_length(plan_hash)=32),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
  UNIQUE(organization_id,workspace_id,environment_id,plan_hash)
);

CREATE TABLE public.zasp_security_agent_steps (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  run_id text NOT NULL,
  step_id text NOT NULL,
  step_index integer NOT NULL CHECK(step_index BETWEEN 0 AND 99),
  action_key text NOT NULL CHECK(length(action_key) BETWEEN 1 AND 128),
  input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
  authorization_result text NOT NULL CHECK(authorization_result IN('allow','approval_required','deny')),
  state text NOT NULL CHECK(state IN('queued','authorized','waiting_approval','executing','verifying','succeeded','failed','inconclusive','cancelled')),
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
  UNIQUE(organization_id,workspace_id,environment_id,run_id,step_index)
);

CREATE TABLE public.zasp_security_agent_approvals (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  approval_id text NOT NULL,
  run_id text NOT NULL,
  step_id text NOT NULL,
  plan_hash bytea NOT NULL CHECK(octet_length(plan_hash)=32),
  state text NOT NULL CHECK(state IN('pending','approved','rejected','cancelled','expired')),
  requester_id text NOT NULL CHECK(length(requester_id) BETWEEN 1 AND 128),
  approver_id text,
  fresh_auth_at timestamptz,
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  decided_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,approval_id),
  UNIQUE(organization_id,workspace_id,environment_id,run_id,step_id)
);

CREATE TABLE public.zasp_security_agent_effects (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  run_id text NOT NULL,
  step_id text NOT NULL,
  action_key text NOT NULL,
  input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
  state text NOT NULL CHECK(state IN('pending','leased','succeeded','known_failure','unknown_outcome','verified','cleanup_pending','cleaned','cleanup_failed')),
  outcome_id text,
  result_digest bytea CHECK(result_digest IS NULL OR octet_length(result_digest)=32),
  lease_owner text,
  lease_token text,
  lease_expires_at timestamptz,
  attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 100),
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id,action_key)
);

CREATE TABLE public.zasp_security_agent_controls (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  control_id text NOT NULL,
  run_id text NOT NULL,
  step_id text NOT NULL,
  action_key text NOT NULL,
  target_id text NOT NULL,
  state text NOT NULL CHECK(state IN('active','claimed','disabled','cleanup_failed')),
  expires_at timestamptz NOT NULL,
  lease_owner text,
  lease_token text,
  lease_expires_at timestamptz,
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  PRIMARY KEY(organization_id,workspace_id,environment_id,control_id)
);

CREATE TABLE public.zasp_security_agent_audit (
  organization_id text NOT NULL,
  workspace_id text NOT NULL,
  environment_id text NOT NULL,
  audit_id text NOT NULL,
  correlation_id text NOT NULL,
  run_id text,
  step_id text,
  approval_id text,
  actor_id text NOT NULL,
  event_kind text NOT NULL,
  event_digest bytea NOT NULL CHECK(octet_length(event_digest)=32),
  body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,audit_id),
  UNIQUE(organization_id,correlation_id,event_kind,run_id,step_id)
);

CREATE INDEX zasp_security_agent_definitions_list_v18_idx ON public.zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id) WHERE deleted_at IS NULL;
CREATE INDEX zasp_security_agent_runs_claim_v18_idx ON public.zasp_security_agent_runs(available_at,organization_id,workspace_id,environment_id,run_id) WHERE state IN('queued','planning','running','verifying');
CREATE INDEX zasp_security_agent_approvals_pending_v18_idx ON public.zasp_security_agent_approvals(expires_at,organization_id,workspace_id,environment_id,approval_id) WHERE state='pending';
CREATE INDEX zasp_security_agent_effects_claim_v18_idx ON public.zasp_security_agent_effects(updated_at,organization_id,workspace_id,environment_id,run_id,step_id) WHERE state IN('pending','leased','unknown_outcome','cleanup_pending');
CREATE INDEX zasp_security_agent_controls_expiry_v18_idx ON public.zasp_security_agent_controls(expires_at,organization_id,workspace_id,environment_id,control_id) WHERE state IN('active','claimed','cleanup_failed');

DO $authority$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'zasp_security_agent_execution_state','zasp_security_agent_principal_bindings','zasp_security_agent_definitions','zasp_security_agent_definition_versions','zasp_security_agent_request_receipts','zasp_security_agent_kill_switches','zasp_security_agent_trigger_receipts','zasp_security_agent_runs','zasp_security_agent_plans','zasp_security_agent_steps','zasp_security_agent_approvals','zasp_security_agent_effects','zasp_security_agent_controls','zasp_security_agent_audit'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',table_name);
    EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',table_name||'_authority',table_name);
    EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker',table_name);
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO zasp_discovery_authority',table_name);
  END LOOP;
END $authority$;

INSERT INTO public.zasp_security_agent_execution_state(singleton) VALUES(true);
INSERT INTO public.zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by)
VALUES('*','*','*','*',false,'migration-v18');

INSERT INTO public.zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version,deleted_at,created_at,updated_at)
SELECT organization_id,workspace_id,environment_id,id,'draft',version,COALESCE((body->>'definition_version')::integer,1),body||jsonb_build_object('enabled',false),'security-agent-actions-v1',deleted_at,created_at,updated_at
FROM public.zasp_workflow_records
WHERE kind='security_agent'
ON CONFLICT DO NOTHING;

INSERT INTO public.zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id,created_at)
SELECT organization_id,workspace_id,environment_id,definition_id,version,'draft',body,digest(convert_to(body::text,'UTF8'),'sha256'),'migration-v18',created_at
FROM public.zasp_security_agent_definitions
ON CONFLICT DO NOTHING;

CREATE FUNCTION public.zasp_security_agent_register_principals(migration_principal text,api_principal text,worker_principal text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $register_principals$
DECLARE principals text[]:=ARRAY[api_principal,worker_principal];authorities text[]:=ARRAY['zasp_security_agent_api','zasp_security_agent_worker'];index_value integer;role_value record;
BEGIN
  IF migration_principal<>session_user OR cardinality(ARRAY(SELECT DISTINCT unnest(ARRAY[migration_principal,api_principal,worker_principal])))<>3
     OR EXISTS(SELECT 1 FROM unnest(principals) principal_value WHERE principal_value!~'^[a-z][a-z0-9_]{2,62}$') THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid security agent principals';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('zasp-security-agent-principal-registration',0));
  FOR index_value IN 1..2 LOOP
    SELECT role_row.oid,role_row.rolcanlogin,role_row.rolinherit,role_row.rolsuper,role_row.rolcreatedb,role_row.rolcreaterole,role_row.rolreplication,role_row.rolbypassrls INTO role_value FROM pg_roles role_row WHERE role_row.rolname=principals[index_value];
    IF NOT FOUND OR NOT role_value.rolcanlogin OR NOT role_value.rolinherit OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR role_value.rolbypassrls
       OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=role_value.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>authorities[index_value]) THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe security agent principal';
    END IF;
    EXECUTE format('GRANT %I TO %I',authorities[index_value],principals[index_value]);
    INSERT INTO zasp_security_agent_principal_bindings(principal_name,authority_role) VALUES(principals[index_value],authorities[index_value])
    ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role WHERE zasp_security_agent_principal_bindings.authority_role=excluded.authority_role;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent principal conflict';END IF;
  END LOOP;
  RETURN true;
END
$register_principals$;

CREATE FUNCTION public.zasp_security_agent_principal_ready(expected_authority text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $principal_ready$
  SELECT expected_authority IN('zasp_security_agent_api','zasp_security_agent_worker')
    AND EXISTS(SELECT 1 FROM zasp_security_agent_principal_bindings binding JOIN pg_roles principal ON principal.rolname=binding.principal_name WHERE binding.principal_name=session_user AND binding.authority_role=expected_authority AND principal.rolcanlogin AND principal.rolinherit AND NOT principal.rolsuper AND NOT principal.rolcreatedb AND NOT principal.rolcreaterole AND NOT principal.rolreplication AND NOT principal.rolbypassrls)
    AND pg_has_role(session_user,expected_authority,'MEMBER') AND NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
$principal_ready$;

CREATE FUNCTION public.zasp_security_agent_principals_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $principals_ready$
  SELECT (SELECT count(*) FROM zasp_security_agent_principal_bindings)=2
    AND NOT EXISTS(
      SELECT 1 FROM zasp_security_agent_principal_bindings binding
      LEFT JOIN pg_roles principal ON principal.rolname=binding.principal_name
      LEFT JOIN pg_roles authority ON authority.rolname=binding.authority_role
      WHERE principal.oid IS NULL OR authority.oid IS NULL OR NOT principal.rolcanlogin OR NOT principal.rolinherit OR principal.rolsuper OR principal.rolcreatedb OR principal.rolcreaterole OR principal.rolreplication OR principal.rolbypassrls
        OR NOT pg_has_role(principal.rolname,authority.rolname,'MEMBER')
        OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid WHERE membership.member=principal.oid AND granted.rolname LIKE 'zasp_%' AND granted.rolname<>authority.rolname)
    )
$principals_ready$;

CREATE FUNCTION public.zasp_security_agent_sync_definition_trigger() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $sync_definition$
DECLARE synchronized zasp_security_agent_definitions%ROWTYPE;
BEGIN
  IF NEW.kind<>'security_agent' THEN RETURN NEW;END IF;
  INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version,deleted_at,created_at,updated_at)
  VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.id,'draft',1,(NEW.body->>'definition_version')::integer,NEW.body||jsonb_build_object('enabled',false),'security-agent-actions-v1',NEW.deleted_at,NEW.created_at,NEW.updated_at)
  ON CONFLICT(organization_id,workspace_id,environment_id,definition_id) DO UPDATE SET activation='draft',version=zasp_security_agent_definitions.version+1,definition_version=(excluded.body->>'definition_version')::integer,body=excluded.body||jsonb_build_object('enabled',false),plan_catalog_version='security-agent-actions-v1',deleted_at=excluded.deleted_at,updated_at=excluded.updated_at
  RETURNING * INTO synchronized;
  INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id,created_at)
  VALUES(synchronized.organization_id,synchronized.workspace_id,synchronized.environment_id,synchronized.definition_id,synchronized.version,'draft',synchronized.body,digest(convert_to(synchronized.body::text,'UTF8'),'sha256'),session_user,synchronized.updated_at);
  UPDATE zasp_security_agent_execution_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN NEW;
END
$sync_definition$;

CREATE FUNCTION public.zasp_security_agent_guard_definition_trigger() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $guard_definition$
BEGIN
  IF NEW.kind='security_agent' AND NOT zasp_security_agent_principal_ready('zasp_security_agent_api') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent definition authority denied';
  END IF;
  RETURN NEW;
END
$guard_definition$;

ALTER FUNCTION public.zasp_security_agent_sync_definition_trigger() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_guard_definition_trigger() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_sync_definition_trigger() FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker;
REVOKE ALL ON FUNCTION public.zasp_security_agent_guard_definition_trigger() FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker;
CREATE TRIGGER zasp_security_agent_guard_definition_v18 BEFORE INSERT OR UPDATE OF body,deleted_at ON public.zasp_workflow_records FOR EACH ROW EXECUTE FUNCTION public.zasp_security_agent_guard_definition_trigger();
CREATE TRIGGER zasp_security_agent_sync_definition_v18 AFTER INSERT OR UPDATE OF body,deleted_at ON public.zasp_workflow_records FOR EACH ROW EXECUTE FUNCTION public.zasp_security_agent_sync_definition_trigger();

CREATE FUNCTION public.zasp_security_agent_definition_page(organization_value text,workspace_value text,environment_value text,after_value text,limit_value integer) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $definition_page$
  WITH page AS (
    SELECT definition_id,body FROM zasp_security_agent_definitions
    WHERE zasp_security_agent_principal_ready('zasp_security_agent_api') AND (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) AND deleted_at IS NULL AND definition_id>COALESCE(after_value,'')
    ORDER BY definition_id LIMIT limit_value+1
  ), visible AS (SELECT * FROM page ORDER BY definition_id LIMIT limit_value)
  SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(body ORDER BY definition_id) FROM visible),'[]'::jsonb),'next_id',CASE WHEN (SELECT count(*) FROM page)>limit_value THEN (SELECT max(definition_id) FROM visible) ELSE NULL END)
$definition_page$;

CREATE FUNCTION public.zasp_security_agent_definition_value(organization_value text,workspace_value text,environment_value text,definition_value text) RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $definition_value$
  SELECT jsonb_build_object('body',body,'version',version,'secret_generation',1)
  FROM zasp_security_agent_definitions
  WHERE zasp_security_agent_principal_ready('zasp_security_agent_api') AND (organization_id,workspace_id,environment_id,definition_id)=(organization_value,workspace_value,environment_value,definition_value) AND deleted_at IS NULL
$definition_value$;

CREATE FUNCTION public.zasp_security_agent_replay_definition(organization_value text,workspace_value text,environment_value text,principal_value text,operation_value text,idempotency_value text,intent_value jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $replay_definition$
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR operation_value NOT IN('createSecurityAgent','updateSecurityAgent','deleteSecurityAgent') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent replay denied';END IF;
  RETURN zasp_workflow_replay(organization_value,workspace_value,environment_value,principal_value,operation_value,idempotency_value,intent_value);
END
$replay_definition$;

CREATE FUNCTION public.zasp_security_agent_mutate_definition(mutation_value text,definition_value text,organization_value text,workspace_value text,environment_value text,principal_value text,operation_value text,idempotency_value text,expected_version_value bigint,intent_value jsonb,body_value jsonb,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $mutate_definition$
DECLARE response_value jsonb;synchronized zasp_security_agent_definitions%ROWTYPE;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR mutation_value NOT IN('create','update','delete') OR operation_value<>(CASE mutation_value WHEN 'create' THEN 'createSecurityAgent' WHEN 'update' THEN 'updateSecurityAgent' ELSE 'deleteSecurityAgent' END)
     OR mutation_value<>'delete' AND (jsonb_typeof(body_value)<>'object' OR body_value->>'enabled'<>'false') OR mutation_value='delete' AND body_value<>'{}'::jsonb THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent definition mutation rejected';
  END IF;
  LOCK TABLE zasp_workflow_idempotency IN ROW EXCLUSIVE MODE;
  response_value:=zasp_workflow_mutate_v3(mutation_value,'security_agent',definition_value,organization_value,workspace_value,environment_value,principal_value,operation_value,idempotency_value,expected_version_value,intent_value,body_value,audit_value,correlation_value);
  IF COALESCE((response_value->>'replayed')::boolean,false) THEN RETURN response_value;END IF;
  SELECT * INTO STRICT synchronized FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(organization_value,workspace_value,environment_value,definition_value);
  response_value:=response_value||jsonb_build_object('body',synchronized.body,'version',synchronized.version);
  IF receipt_value<>'' THEN
    INSERT INTO zasp_workflow_receipts(organization_id,workspace_id,environment_id,principal_id,receipt_id,operation,idempotency_key,intent,result,resource_kind,resource_id,resource_version,audit_id,correlation_id)
    VALUES(organization_value,workspace_value,environment_value,principal_value,receipt_value,operation_value,idempotency_value,intent_value,synchronized.body,'security_agent',definition_value,synchronized.version,audit_value,correlation_value);
    response_value:=response_value||jsonb_build_object('receipt_id',receipt_value);
  ELSE
    UPDATE zasp_workflow_idempotency SET receipt_semantics='receiptless_incompatible' WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,principal_value,operation_value,idempotency_value);
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent receipt provenance missing';END IF;
  END IF;
  UPDATE zasp_workflow_idempotency SET response=response_value-'replayed',receipt_semantics=CASE WHEN receipt_value='' THEN 'receiptless_incompatible' ELSE 'receipt_backed' END WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,principal_value,operation_value,idempotency_value);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent replay authority missing';END IF;
  RETURN response_value;
END
$mutate_definition$;

CREATE FUNCTION public.zasp_security_agent_definition_detail(organization_value text,workspace_value text,environment_value text,definition_value text) RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $definition_detail$
  SELECT jsonb_build_object(
    'organization_id',definition_row.organization_id,
    'workspace_id',definition_row.workspace_id,
    'environment_id',definition_row.environment_id,
    'definition_id',definition_row.definition_id,
    'activation',definition_row.activation,
    'version',definition_row.version,
    'definition_version',definition_row.definition_version,
    'body',definition_row.body,
    'updated_at',to_char(definition_row.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  )
  FROM zasp_security_agent_definitions definition_row
  WHERE zasp_security_agent_principal_ready('zasp_security_agent_api')
    AND (definition_row.organization_id,definition_row.workspace_id,definition_row.environment_id,definition_row.definition_id)=(organization_value,workspace_value,environment_value,definition_value)
    AND definition_row.deleted_at IS NULL
$definition_detail$;

CREATE FUNCTION public.zasp_security_agent_set_kill_switch(organization_value text,workspace_value text,environment_value text,action_value text,enabled_value boolean,expected_version bigint,actor_value text,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $set_kill_switch$
DECLARE result_value zasp_security_agent_kill_switches%ROWTYPE;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR length(organization_value) NOT BETWEEN 1 AND 128 OR length(workspace_value) NOT BETWEEN 1 AND 128 OR length(environment_value) NOT BETWEEN 1 AND 128 OR length(action_value) NOT BETWEEN 1 AND 128
     OR length(actor_value) NOT BETWEEN 1 AND 128 OR length(audit_value) NOT BETWEEN 1 AND 128 OR length(correlation_value) NOT BETWEEN 1 AND 128 OR expected_version<0 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent kill switch rejected';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,action_value),0));
  IF expected_version=0 THEN
    INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by)
    VALUES(organization_value,workspace_value,environment_value,action_value,enabled_value,actor_value)
    RETURNING * INTO result_value;
  ELSE
    UPDATE zasp_security_agent_kill_switches switch_row SET execution_enabled=enabled_value,version=switch_row.version+1,updated_by=actor_value,updated_at=transaction_timestamp()
    WHERE (switch_row.organization_id,switch_row.workspace_id,switch_row.environment_id,switch_row.action_key,switch_row.version)=(organization_value,workspace_value,environment_value,action_value,expected_version)
    RETURNING * INTO result_value;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent kill switch version conflict';END IF;
  END IF;
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,actor_value,'kill_switch_changed',digest(convert_to(jsonb_build_object('action_key',action_value,'enabled',enabled_value,'version',result_value.version)::text,'UTF8'),'sha256'),jsonb_build_object('action_key',action_value,'enabled',enabled_value,'version',result_value.version));
  UPDATE zasp_security_agent_execution_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN jsonb_build_object('action_key',result_value.action_key,'enabled',result_value.execution_enabled,'version',result_value.version,'replayed',false);
EXCEPTION WHEN unique_violation THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent kill switch version conflict';
END
$set_kill_switch$;

CREATE FUNCTION public.zasp_security_agent_activate(organization_value text,workspace_value text,environment_value text,definition_value text,actor_value text,idempotency_value text,expected_version bigint,target_activation text,fresh_auth_expires_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $activate$
DECLARE definition_row zasp_security_agent_definitions%ROWTYPE; receipt_row zasp_security_agent_request_receipts%ROWTYPE; action_value text; intent_value jsonb; response_value jsonb; intent_digest_value bytea;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR expected_version<=0 OR target_activation NOT IN('validated','supervised','autonomous') OR length(actor_value) NOT BETWEEN 1 AND 128 OR length(audit_value) NOT BETWEEN 1 AND 128 OR length(correlation_value) NOT BETWEEN 1 AND 128 OR length(receipt_value) NOT BETWEEN 1 AND 128
     OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' OR fresh_auth_expires_value IS NULL OR fresh_auth_expires_value<=transaction_timestamp() OR fresh_auth_expires_value>transaction_timestamp()+interval '5 minutes 5 seconds' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent activation rejected';
  END IF;
  intent_value:=jsonb_build_object('activation',target_activation,'expected_version',expected_version,'resource_id',definition_value);
  intent_digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'activateSecurityAgent',idempotency_value),0));
  SELECT * INTO receipt_row FROM zasp_security_agent_request_receipts receipt
  WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.principal_id,receipt.operation,receipt.idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'activateSecurityAgent',idempotency_value);
  IF FOUND THEN
    IF receipt_row.resource_id<>definition_value OR receipt_row.expected_version<>expected_version OR receipt_row.intent_digest<>intent_digest_value OR receipt_row.expires_at<=transaction_timestamp()
       OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_definitions current_definition WHERE (current_definition.organization_id,current_definition.workspace_id,current_definition.environment_id,current_definition.definition_id)=(organization_value,workspace_value,environment_value,definition_value) AND current_definition.deleted_at IS NULL) THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent activation replay conflict';
    END IF;
    RETURN receipt_row.response||jsonb_build_object('replayed',true);
  END IF;
  SELECT * INTO definition_row FROM zasp_security_agent_definitions candidate
  WHERE (candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,candidate.version)=(organization_value,workspace_value,environment_value,definition_value,expected_version)
    AND candidate.deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND OR NOT ((definition_row.activation='draft' AND target_activation='validated') OR (definition_row.activation='validated' AND target_activation='supervised') OR (definition_row.activation='supervised' AND target_activation='autonomous')) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent activation conflict';
  END IF;
  IF target_activation IN('supervised','autonomous') THEN
    IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true))
       OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'*',true)) THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent execution disabled';
    END IF;
    FOR action_value IN SELECT jsonb_array_elements_text(definition_row.body->'allowed_actions') LOOP
      IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,action_value,true)) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent action disabled';
      END IF;
    END LOOP;
  END IF;
  UPDATE zasp_security_agent_definitions candidate SET activation=target_activation,version=candidate.version+1,body=candidate.body||jsonb_build_object('enabled',target_activation IN('supervised','autonomous')),updated_at=transaction_timestamp()
  WHERE (candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id)=(organization_value,workspace_value,environment_value,definition_value)
  RETURNING * INTO definition_row;
  INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
  VALUES(organization_value,workspace_value,environment_value,definition_value,definition_row.version,target_activation,definition_row.body,digest(convert_to(definition_row.body::text,'UTF8'),'sha256'),actor_value);
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,actor_value,'definition_activated',digest(convert_to(jsonb_build_object('definition_id',definition_value,'activation',target_activation,'version',definition_row.version)::text,'UTF8'),'sha256'),jsonb_build_object('definition_id',definition_value,'activation',target_activation,'version',definition_row.version));
  response_value:=jsonb_build_object('id',definition_value,'activation',target_activation,'enabled',target_activation IN('supervised','autonomous'),'version',definition_row.version,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
  INSERT INTO zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id)
  VALUES(organization_value,workspace_value,environment_value,actor_value,'activateSecurityAgent',idempotency_value,definition_value,expected_version,intent_value,intent_digest_value,response_value,audit_value,correlation_value,receipt_value);
  UPDATE zasp_security_agent_execution_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN response_value;
END
$activate$;

CREATE FUNCTION public.zasp_security_agent_create_run(organization_value text,workspace_value text,environment_value text,definition_value text,definition_version_value bigint,run_value text,trigger_kind_value text,trigger_version_value bigint,trigger_digest_value bytea,actor_value text,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $create_run$
DECLARE definition_row zasp_security_agent_definitions%ROWTYPE; action_value text; prior_run text;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR definition_version_value<=0 OR trigger_version_value<=0 OR octet_length(trigger_digest_value)<>32 OR trigger_kind_value NOT IN('finding','attack_path','runtime_decision','manual')
     OR length(run_value) NOT BETWEEN 1 AND 128 OR length(actor_value) NOT BETWEEN 1 AND 128 OR length(audit_value) NOT BETWEEN 1 AND 128 OR length(correlation_value) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent run rejected';
  END IF;
  SELECT * INTO definition_row FROM zasp_security_agent_definitions candidate
  WHERE (candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,candidate.version)=(organization_value,workspace_value,environment_value,definition_value,definition_version_value)
    AND candidate.deleted_at IS NULL AND candidate.activation IN('supervised','autonomous') FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent run rejected';END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'*',true)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent execution disabled';
  END IF;
  FOR action_value IN SELECT jsonb_array_elements_text(definition_row.body->'allowed_actions') LOOP
    IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,action_value,true)) THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent action disabled';
    END IF;
  END LOOP;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,definition_value,encode(trigger_digest_value,'hex')),0));
  SELECT run_id INTO prior_run FROM zasp_security_agent_trigger_receipts receipt
  WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.definition_id,receipt.trigger_id,receipt.trigger_version)=(organization_value,workspace_value,environment_value,definition_value,encode(trigger_digest_value,'hex'),trigger_version_value);
  IF FOUND THEN
    IF prior_run<>run_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent trigger replay conflict';END IF;
    RETURN jsonb_build_object('run_id',prior_run,'state','queued','version',1,'replayed',true);
  END IF;
  INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id)
  VALUES(organization_value,workspace_value,environment_value,definition_value,encode(trigger_digest_value,'hex'),trigger_kind_value,trigger_version_value,trigger_digest_value,run_value);
  INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,state)
  VALUES(organization_value,workspace_value,environment_value,run_value,definition_value,definition_version_value,encode(trigger_digest_value,'hex'),'queued');
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,actor_value,'run_queued',digest(convert_to(jsonb_build_object('run_id',run_value,'definition_id',definition_value,'definition_version',definition_version_value)::text,'UTF8'),'sha256'),jsonb_build_object('run_id',run_value,'definition_id',definition_value,'definition_version',definition_version_value));
  UPDATE zasp_security_agent_execution_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN jsonb_build_object('run_id',run_value,'state','queued','version',1,'replayed',false);
END
$create_run$;

CREATE FUNCTION public.zasp_security_agent_claim_runs(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $claim_runs$
DECLARE result_value jsonb;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 30 AND 300 OR claim_limit NOT BETWEEN 1 AND 25 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent claim rejected';
  END IF;
  UPDATE zasp_security_agent_runs run_row SET state='queued',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,available_at=transaction_timestamp(),last_error_code='lease_expired'
  WHERE run_row.state IN('planning','running','verifying') AND run_row.lease_expires_at<=transaction_timestamp();
  WITH selected AS (
    SELECT run_row.ctid FROM zasp_security_agent_runs run_row
    WHERE run_row.state='queued' AND run_row.available_at<=transaction_timestamp()
    ORDER BY run_row.available_at,run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id
    LIMIT claim_limit FOR UPDATE SKIP LOCKED
  ), claimed AS (
    UPDATE zasp_security_agent_runs run_row SET state='planning',attempt=run_row.attempt+1,lease_owner=worker_value,lease_token=lease_token_value,lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),version=run_row.version+1,updated_at=transaction_timestamp()
    FROM selected WHERE run_row.ctid=selected.ctid
    RETURNING run_row.*
  )
  SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_id',definition_id,'definition_version',definition_version,'trigger_id',trigger_id,'state',state,'version',version,'attempt',attempt,'lease_expires_at',to_char(lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY organization_id,workspace_id,environment_id,run_id),'[]'::jsonb)) INTO result_value FROM claimed;
  RETURN result_value;
END
$claim_runs$;

DO $functions$
DECLARE procedure_oid oid;
BEGIN
  FOR procedure_oid IN SELECT procedure_row.oid FROM pg_proc procedure_row JOIN pg_namespace namespace_row ON namespace_row.oid=procedure_row.pronamespace WHERE namespace_row.nspname='public' AND procedure_row.proname IN('zasp_security_agent_register_principals','zasp_security_agent_principal_ready','zasp_security_agent_principals_ready','zasp_security_agent_definition_page','zasp_security_agent_definition_value','zasp_security_agent_replay_definition','zasp_security_agent_mutate_definition','zasp_security_agent_definition_detail','zasp_security_agent_set_kill_switch','zasp_security_agent_activate','zasp_security_agent_create_run','zasp_security_agent_claim_runs') LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure);
  END LOOP;
END $functions$;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_principal_ready(text),public.zasp_security_agent_definition_page(text,text,text,text,integer),public.zasp_security_agent_definition_value(text,text,text,text),public.zasp_security_agent_replay_definition(text,text,text,text,text,text,jsonb),public.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),public.zasp_security_agent_definition_detail(text,text,text,text),public.zasp_security_agent_set_kill_switch(text,text,text,text,boolean,bigint,text,text,text),public.zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text),public.zasp_security_agent_create_run(text,text,text,text,bigint,text,text,bigint,bytea,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_principal_ready(text),public.zasp_security_agent_claim_runs(text,text,integer,integer) TO zasp_security_agent_worker;

CREATE FUNCTION public.zasp_security_agent_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
  WITH identities(value) AS (
    SELECT concat_ws('|','table',class.relname,owner.rolname,class.relrowsecurity,class.relforcerowsecurity,COALESCE(class.relacl::text,''))
    FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner
    WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_security_agent_%' AND class.relkind IN('r','i')
    UNION ALL
    SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid))
    FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner
    WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_security_agent_%'
    UNION ALL
    SELECT concat_ws('|','trigger',trigger_row.tgname,pg_get_triggerdef(trigger_row.oid,true))
    FROM pg_trigger trigger_row JOIN pg_class class ON class.oid=trigger_row.tgrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace
    WHERE namespace.nspname='public' AND trigger_row.tgname IN('zasp_security_agent_guard_definition_v18','zasp_security_agent_sync_definition_v18') AND NOT trigger_row.tgisinternal
  )
  SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;

CREATE FUNCTION public.zasp_security_agent_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
  SELECT length(expected_checksum)=64 AND expected_checksum~'^[a-f0-9]{64}$'
     AND length(expected_fingerprint)=64 AND expected_fingerprint~'^[a-f0-9]{64}$'
     AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=18 AND name='security_agent_execution' AND checksum=expected_checksum)
     AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_core_schema' AND value='security-agent-execution-v1')
     AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>18)
     AND (SELECT count(*) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname IN('zasp_security_agent_execution_state','zasp_security_agent_principal_bindings','zasp_security_agent_definitions','zasp_security_agent_definition_versions','zasp_security_agent_request_receipts','zasp_security_agent_kill_switches','zasp_security_agent_trigger_receipts','zasp_security_agent_runs','zasp_security_agent_plans','zasp_security_agent_steps','zasp_security_agent_approvals','zasp_security_agent_effects','zasp_security_agent_controls','zasp_security_agent_audit') AND class.relkind='r' AND class.relowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND class.relrowsecurity AND class.relforcerowsecurity)=14
     AND NOT EXISTS(SELECT 1 FROM pg_roles role_row WHERE role_row.rolname IN('zasp_security_agent_api','zasp_security_agent_worker') AND (role_row.rolcanlogin OR role_row.rolinherit OR role_row.rolsuper OR role_row.rolcreatedb OR role_row.rolcreaterole OR role_row.rolreplication OR role_row.rolbypassrls))
     AND zasp_security_agent_live_fingerprint()=expected_fingerprint
$readiness$;

ALTER FUNCTION public.zasp_security_agent_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_live_fingerprint(),public.zasp_security_agent_readiness(text,text) FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker;

DO $schema_marker$
BEGIN
  UPDATE public.zasp_schema_metadata SET value='security-agent-execution-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='runtime-data-plane-v1';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent schema marker drift';END IF;
END
$schema_marker$;

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('security_agent_execution_fingerprint', 'f37ac88ad69b7f59ade59d4704696ec0a9aae3aea81727ea44763f901e2eb024')
ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;
