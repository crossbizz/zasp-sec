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
  requested_by text NOT NULL CHECK(length(requested_by) BETWEEN 1 AND 128),
  state text NOT NULL CHECK(state IN('simulated','queued','planning','waiting_approval','running','verifying','contained','remediated','needs_human','failed','inconclusive','cancelled')),
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

CREATE FUNCTION public.zasp_security_agent_simulate(organization_value text,workspace_value text,environment_value text,definition_value text,actor_value text,idempotency_value text,expected_version bigint,run_value text,goal_value text,evidence_values jsonb,expires_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $simulate$
DECLARE definition_row zasp_security_agent_definitions%ROWTYPE; receipt_row zasp_security_agent_request_receipts%ROWTYPE; canonical_evidence jsonb; steps_value jsonb; plan_value jsonb; plan_digest bytea; trigger_digest_value bytea; intent_value jsonb; intent_digest_value bytea; response_value jsonb; summary_value text;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR expected_version<=0 OR NOT zasp_valid_product_id(definition_value) OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(receipt_value)
     OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' OR length(goal_value) NOT BETWEEN 1 AND 1024 OR btrim(goal_value)<>goal_value OR goal_value~'[[:cntrl:]]'
     OR jsonb_typeof(evidence_values)<>'array' OR jsonb_array_length(evidence_values) NOT BETWEEN 1 AND 100 OR expires_value IS NULL OR expires_value<=transaction_timestamp() OR expires_value>transaction_timestamp()+interval '16 minutes' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent simulation rejected';
  END IF;
  SELECT jsonb_agg(evidence ORDER BY evidence) INTO canonical_evidence FROM jsonb_array_elements_text(evidence_values) evidence;
  IF (SELECT count(*) FROM jsonb_array_elements_text(canonical_evidence))<>(SELECT count(DISTINCT evidence) FROM jsonb_array_elements_text(canonical_evidence) evidence)
     OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(canonical_evidence) evidence WHERE NOT zasp_valid_product_id(evidence)) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent simulation evidence rejected';
  END IF;
  intent_value:=jsonb_build_object('definition_id',definition_value,'expected_version',expected_version,'goal',goal_value,'evidence_ids',canonical_evidence,'expires_at',to_char(expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  intent_digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'simulateSecurityAgent',idempotency_value),0));
  SELECT * INTO receipt_row FROM zasp_security_agent_request_receipts receipt
  WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.principal_id,receipt.operation,receipt.idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'simulateSecurityAgent',idempotency_value);
  IF FOUND THEN
    IF receipt_row.resource_id<>definition_value OR receipt_row.expected_version<>expected_version OR receipt_row.intent_digest<>intent_digest_value OR receipt_row.expires_at<=transaction_timestamp() OR (receipt_row.response->>'expires_at')::timestamptz<=transaction_timestamp()
       OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_definitions current_definition WHERE (current_definition.organization_id,current_definition.workspace_id,current_definition.environment_id,current_definition.definition_id,current_definition.version)=(organization_value,workspace_value,environment_value,definition_value,expected_version) AND current_definition.deleted_at IS NULL) THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent simulation replay conflict';
    END IF;
    IF EXISTS(
      SELECT 1 FROM jsonb_array_elements_text(receipt_row.response->'matched_evidence_ids') evidence
      WHERE NOT EXISTS(SELECT 1 FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id)=(organization_value,workspace_value,environment_value,evidence) AND finding.status IN('open','under_review','accepted'))
        AND NOT EXISTS(SELECT 1 FROM zasp_risk_attack_paths path WHERE (path.organization_id,path.workspace_id,path.environment_id,path.id)=(organization_value,workspace_value,environment_value,evidence) AND path.state IN('observed','verified'))
        AND NOT EXISTS(SELECT 1 FROM zasp_inventory_entities entity WHERE (entity.organization_id,entity.workspace_id,entity.environment_id,entity.id,entity.state)=(organization_value,workspace_value,environment_value,evidence,'active'))
        AND NOT EXISTS(SELECT 1 FROM zasp_inventory_evidence evidence_row WHERE (evidence_row.organization_id,evidence_row.workspace_id,evidence_row.environment_id,evidence_row.id)=(organization_value,workspace_value,environment_value,evidence))
    ) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent simulation replay denied';END IF;
    RETURN receipt_row.response||jsonb_build_object('replayed',true);
  END IF;
  SELECT * INTO definition_row FROM zasp_security_agent_definitions candidate
  WHERE (candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.definition_id,candidate.version)=(organization_value,workspace_value,environment_value,definition_value,expected_version)
    AND candidate.deleted_at IS NULL AND candidate.activation IN('validated','supervised','autonomous') AND candidate.body->'environment_ids' ? environment_value FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent simulation definition rejected';END IF;
  IF EXISTS(
    SELECT 1 FROM jsonb_array_elements_text(canonical_evidence) evidence
    WHERE NOT EXISTS(SELECT 1 FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id)=(organization_value,workspace_value,environment_value,evidence) AND finding.status IN('open','under_review','accepted'))
      AND NOT EXISTS(SELECT 1 FROM zasp_risk_attack_paths path WHERE (path.organization_id,path.workspace_id,path.environment_id,path.id)=(organization_value,workspace_value,environment_value,evidence) AND path.state IN('observed','verified'))
      AND NOT EXISTS(SELECT 1 FROM zasp_inventory_entities entity WHERE (entity.organization_id,entity.workspace_id,entity.environment_id,entity.id,entity.state)=(organization_value,workspace_value,environment_value,evidence,'active'))
      AND NOT EXISTS(SELECT 1 FROM zasp_inventory_evidence evidence_row WHERE (evidence_row.organization_id,evidence_row.workspace_id,evidence_row.environment_id,evidence_row.id)=(organization_value,workspace_value,environment_value,evidence))
  ) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent simulation evidence denied';END IF;
  SELECT jsonb_agg(jsonb_build_object('index',ordinality-1,'action',action,'authorization',CASE WHEN definition_row.body->>'autonomy'='supervised' THEN 'approval_required' ELSE 'allow' END,'approval_required',definition_row.body->>'autonomy'='supervised') ORDER BY ordinality)
  INTO steps_value FROM jsonb_array_elements_text(definition_row.body->'allowed_actions') WITH ORDINALITY action_rows(action,ordinality) WHERE ordinality<=(definition_row.body->>'max_steps')::integer;
  IF jsonb_typeof(steps_value)<>'array' OR jsonb_array_length(steps_value) NOT BETWEEN 1 AND LEAST(100,(definition_row.body->>'max_steps')::integer) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent simulation plan rejected';END IF;
  summary_value:=format('Planned %s action(s) from %s evidence record(s)',jsonb_array_length(steps_value),jsonb_array_length(canonical_evidence));
  plan_value:=jsonb_build_object(
    'version',1,'definition_id',definition_value,'definition_version',expected_version,'catalog_version',definition_row.plan_catalog_version,
    'target_scope',jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value),
    'goal',goal_value,'summary',summary_value,'evidence_ids',canonical_evidence,'steps',steps_value,
    'budgets',jsonb_build_object('max_steps',(definition_row.body->>'max_steps')::integer,'max_duration_seconds',(definition_row.body->>'max_duration_seconds')::integer,'temporary_policy_seconds',(definition_row.body->>'temporary_policy_seconds')::integer,'ai_token_budget',(definition_row.body->>'ai_token_budget')::integer,'concurrency_limit',(definition_row.body->>'concurrency_limit')::integer),
    'verification',jsonb_build_object('kind',definition_row.body->>'verification_kind'),'expires_at',to_char(expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  plan_digest:=digest(convert_to(plan_value::text,'UTF8'),'sha256');trigger_digest_value:=digest(convert_to(jsonb_build_object('kind','simulation','evidence_ids',canonical_evidence,'goal',goal_value)::text,'UTF8'),'sha256');
  INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,plan_hash,completed_at)
  VALUES(organization_value,workspace_value,environment_value,run_value,definition_value,expected_version,encode(trigger_digest_value,'hex'),actor_value,'simulated',plan_digest,transaction_timestamp());
  INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
  VALUES(organization_value,workspace_value,environment_value,run_value,definition_value,expected_version,trigger_digest_value,definition_row.plan_catalog_version,plan_value,plan_digest,expires_value);
  INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
  SELECT organization_value,workspace_value,environment_value,run_value,zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'security_agent_step',run_value||chr(31)||(step->>'index')), (step->>'index')::integer,step->>'action',digest(convert_to(step::text,'UTF8'),'sha256'),step->>'authorization',CASE WHEN step->>'authorization'='approval_required' THEN 'waiting_approval' ELSE 'authorized' END
  FROM jsonb_array_elements(steps_value) step;
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,actor_value,'simulation_created',plan_digest,jsonb_build_object('run_id',run_value,'definition_id',definition_value,'definition_version',expected_version,'plan_hash','sha256:'||encode(plan_digest,'hex'),'side_effects',0));
  response_value:=jsonb_build_object('run_id',run_value,'definition_id',definition_value,'definition_version',expected_version,'plan_hash','sha256:'||encode(plan_digest,'hex'),'catalog_version',definition_row.plan_catalog_version,'expires_at',to_char(expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'matched_evidence_ids',canonical_evidence,'summary',summary_value,'steps',steps_value,'side_effects',0,'version',1,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
  INSERT INTO zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id)
  VALUES(organization_value,workspace_value,environment_value,actor_value,'simulateSecurityAgent',idempotency_value,definition_value,expected_version,intent_value,intent_digest_value,response_value,audit_value,correlation_value,receipt_value);
  UPDATE zasp_security_agent_execution_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN response_value;
END
$simulate$;

CREATE FUNCTION public.zasp_security_agent_run(organization_value text,workspace_value text,environment_value text,definition_value text,actor_value text,idempotency_value text,expected_version bigint,run_value text,trigger_kind_value text,trigger_value text,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $run$
DECLARE definition_row zasp_security_agent_definitions%ROWTYPE; finding_version bigint; trigger_digest_value bytea; intent_value jsonb; intent_digest_value bytea; receipt_row zasp_security_agent_request_receipts%ROWTYPE; prior_run text; prior_state text; prior_version bigint; response_value jsonb;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR expected_version<=0 OR trigger_kind_value<>'finding'
     OR NOT zasp_valid_product_id(definition_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(trigger_value)
     OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(receipt_value)
     OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent run rejected';
  END IF;
  intent_value:=jsonb_build_object('definition_id',definition_value,'expected_version',expected_version,'trigger_kind',trigger_kind_value,'trigger_id',trigger_value);
  intent_digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'runSecurityAgent',idempotency_value),0));
  SELECT * INTO receipt_row FROM zasp_security_agent_request_receipts receipt
  WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.principal_id,receipt.operation,receipt.idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'runSecurityAgent',idempotency_value);
  IF FOUND THEN
    IF receipt_row.resource_id<>definition_value OR receipt_row.expected_version<>expected_version OR receipt_row.intent_digest<>intent_digest_value OR receipt_row.expires_at<=transaction_timestamp()
       OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_definitions definition WHERE (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version)=(organization_value,workspace_value,environment_value,definition_value,expected_version) AND definition.deleted_at IS NULL)
       OR NOT EXISTS(SELECT 1 FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id)=(organization_value,workspace_value,environment_value,trigger_value) AND finding.status IN('open','under_review')) THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent run replay conflict';
    END IF;
    RETURN receipt_row.response||jsonb_build_object('replayed',true);
  END IF;
  SELECT * INTO definition_row FROM zasp_security_agent_definitions definition
  WHERE (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version)=(organization_value,workspace_value,environment_value,definition_value,expected_version)
    AND definition.deleted_at IS NULL AND definition.activation='supervised' AND definition.body->'environment_ids' ? environment_value
    AND definition.body->>'autonomy'='supervised' AND definition.body->'allowed_actions'=jsonb_build_array('update_finding_response') AND definition.body->>'verification_kind'='finding_state' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent run definition rejected';END IF;
  SELECT finding.version INTO finding_version FROM zasp_risk_findings finding
  WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id)=(organization_value,workspace_value,environment_value,trigger_value) AND finding.status='open' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent run trigger denied';END IF;
  IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'update_finding_response',true)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent execution disabled';
  END IF;
  trigger_digest_value:=digest(convert_to(jsonb_build_object('kind','finding','id',trigger_value,'version',finding_version)::text,'UTF8'),'sha256');
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,definition_value,trigger_value,finding_version),0));
  SELECT receipt.run_id INTO prior_run FROM zasp_security_agent_trigger_receipts receipt
  WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.definition_id,receipt.trigger_id,receipt.trigger_version)=(organization_value,workspace_value,environment_value,definition_value,trigger_value,finding_version);
  IF FOUND THEN
    SELECT state,version INTO STRICT prior_state,prior_version FROM zasp_security_agent_runs existing
    WHERE (existing.organization_id,existing.workspace_id,existing.environment_id,existing.run_id)=(organization_value,workspace_value,environment_value,prior_run);
    response_value:=jsonb_build_object('id',prior_run,'agent_id',definition_value,'state',prior_state,'evidence_ids',jsonb_build_array(trigger_value),'definition_version',expected_version,'version',prior_version,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',true);
  ELSE
    INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id)
    VALUES(organization_value,workspace_value,environment_value,definition_value,trigger_value,'finding',finding_version,trigger_digest_value,run_value);
    INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state)
    VALUES(organization_value,workspace_value,environment_value,run_value,definition_value,expected_version,trigger_value,actor_value,'queued');
    response_value:=jsonb_build_object('id',run_value,'agent_id',definition_value,'state','queued','evidence_ids',jsonb_build_array(trigger_value),'definition_version',expected_version,'version',1,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
  END IF;
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,response_value->>'id',actor_value,CASE WHEN prior_run IS NULL THEN 'run_queued' ELSE 'run_deduplicated' END,trigger_digest_value,jsonb_build_object('run_id',response_value->>'id','definition_id',definition_value,'definition_version',expected_version,'trigger_kind','finding','trigger_id',trigger_value));
  INSERT INTO zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id)
  VALUES(organization_value,workspace_value,environment_value,actor_value,'runSecurityAgent',idempotency_value,definition_value,expected_version,intent_value,intent_digest_value,response_value,audit_value,correlation_value,receipt_value);
  UPDATE zasp_security_agent_execution_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN response_value;
END
$run$;

CREATE FUNCTION public.zasp_security_agent_run_page(organization_value text,workspace_value text,environment_value text,definition_value text,state_value text,before_created_value timestamptz,before_id_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $run_page$
DECLARE items_value jsonb;next_created_value timestamptz;next_id_value text;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR limit_value NOT BETWEEN 1 AND 100
     OR (definition_value IS NOT NULL AND NOT zasp_valid_product_id(definition_value))
     OR (state_value IS NOT NULL AND state_value NOT IN('queued','planning','waiting_approval','running','verifying','contained','remediated','needs_human','failed','inconclusive','cancelled'))
     OR (before_created_value IS NULL)<>(before_id_value IS NULL) OR (before_id_value IS NOT NULL AND NOT zasp_valid_product_id(before_id_value)) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent run page rejected';
  END IF;
  WITH candidates AS (
    SELECT run.*,row_number() OVER(ORDER BY run.created_at DESC,run.run_id DESC) AS ordinal
    FROM zasp_security_agent_runs run
    WHERE (run.organization_id,run.workspace_id,run.environment_id)=(organization_value,workspace_value,environment_value)
      AND run.state<>'simulated' AND (definition_value IS NULL OR run.definition_id=definition_value) AND (state_value IS NULL OR run.state=state_value)
      AND (before_created_value IS NULL OR (run.created_at,run.run_id)<(before_created_value,before_id_value))
    ORDER BY run.created_at DESC,run.run_id DESC LIMIT limit_value+1
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object('id',run_id,'agent_id',definition_id,'state',state,'evidence_ids',jsonb_build_array(trigger_id),'definition_version',definition_version,'version',version) ORDER BY created_at DESC,run_id DESC) FILTER(WHERE ordinal<=limit_value),'[]'::jsonb),
         max(created_at) FILTER(WHERE ordinal=limit_value AND (SELECT count(*) FROM candidates)>limit_value),
         max(run_id) FILTER(WHERE ordinal=limit_value AND (SELECT count(*) FROM candidates)>limit_value)
  INTO items_value,next_created_value,next_id_value FROM candidates;
  RETURN jsonb_build_object('items',items_value,'next_created_at',CASE WHEN next_created_value IS NULL THEN NULL ELSE to_char(next_created_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,'next_id',next_id_value);
END
$run_page$;

CREATE FUNCTION public.zasp_security_agent_run_detail(organization_value text,workspace_value text,environment_value text,run_value text) RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $run_detail$
  SELECT jsonb_build_object(
    'run',jsonb_build_object('id',run.run_id,'agent_id',run.definition_id,'state',run.state,'evidence_ids',jsonb_build_array(run.trigger_id),'definition_version',run.definition_version,'version',run.version),
    'evidence_ids',jsonb_build_array(run.trigger_id),
    'plan',CASE WHEN plan.run_id IS NULL THEN NULL ELSE jsonb_build_object('plan_hash','sha256:'||encode(plan.plan_hash,'hex'),'catalog_version',plan.catalog_version,'expires_at',to_char(plan.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'steps',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',step.step_id,'index',step.step_index,'action',step.action_key,'authorization',step.authorization_result,'state',step.state,'version',step.version) ORDER BY step.step_index) FROM zasp_security_agent_steps step WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)),'[]'::jsonb)) END,
    'authorization',CASE WHEN plan.run_id IS NULL THEN 'not_planned' WHEN EXISTS(SELECT 1 FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id,approval.state)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id,'pending')) THEN 'approval_required' WHEN EXISTS(SELECT 1 FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id) AND approval.state IN('rejected','expired')) THEN 'denied' WHEN EXISTS(SELECT 1 FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id,approval.state)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id,'cancelled')) THEN 'cancelled' WHEN EXISTS(SELECT 1 FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id,approval.state)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id,'approved')) THEN 'approved' ELSE 'authorized' END,
    'approvals',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',approval.approval_id,'run_id',approval.run_id,'step_id',approval.step_id,'state',approval.state,'expires_at',to_char(approval.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'version',approval.version,'expected_effect','Move finding to under review','reversible',true,'ttl_seconds',0,'evidence_summary',jsonb_build_array(run.trigger_id)) ORDER BY approval.created_at,approval.approval_id) FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)),'[]'::jsonb),
    'execution',COALESCE((SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('step_id',step.step_id,'action',step.action_key,'state',step.state,'outcome_id',effect.outcome_id,'result_digest',CASE WHEN effect.result_digest IS NULL THEN NULL ELSE 'sha256:'||encode(effect.result_digest,'hex') END,'version',step.version)) ORDER BY step.step_index) FROM zasp_security_agent_steps step LEFT JOIN zasp_security_agent_effects effect ON (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key)=(step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id,step.action_key) WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)),'[]'::jsonb),
    'verification',CASE WHEN run.state IN('contained','remediated') THEN 'verified' WHEN run.state='verifying' THEN 'pending' WHEN run.state='failed' THEN 'failed' WHEN run.state IN('inconclusive','needs_human') THEN 'inconclusive' ELSE 'not_started' END)
  FROM zasp_security_agent_runs run LEFT JOIN zasp_security_agent_plans plan ON (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)
  WHERE zasp_security_agent_principal_ready('zasp_security_agent_api') AND zasp_valid_product_id(run_value)
    AND (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value) AND run.state<>'simulated'
$run_detail$;

CREATE FUNCTION public.zasp_security_agent_approval_page(organization_value text,workspace_value text,environment_value text,state_value text,run_value text,before_created_value timestamptz,before_id_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $approval_page$
DECLARE items_value jsonb;next_created_value timestamptz;next_id_value text;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR limit_value NOT BETWEEN 1 AND 100
     OR (state_value IS NOT NULL AND state_value NOT IN('pending','approved','rejected','cancelled','expired')) OR (run_value IS NOT NULL AND NOT zasp_valid_product_id(run_value))
     OR (before_created_value IS NULL)<>(before_id_value IS NULL) OR (before_id_value IS NOT NULL AND NOT zasp_valid_product_id(before_id_value)) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent approval page rejected';
  END IF;
  WITH candidates AS (
    SELECT approval.*,run.trigger_id,row_number() OVER(ORDER BY approval.created_at DESC,approval.approval_id DESC) AS ordinal
    FROM zasp_security_agent_approvals approval JOIN zasp_security_agent_runs run ON (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id)
    WHERE (approval.organization_id,approval.workspace_id,approval.environment_id)=(organization_value,workspace_value,environment_value)
      AND (state_value IS NULL OR approval.state=state_value) AND (run_value IS NULL OR approval.run_id=run_value)
      AND (before_created_value IS NULL OR (approval.created_at,approval.approval_id)<(before_created_value,before_id_value))
    ORDER BY approval.created_at DESC,approval.approval_id DESC LIMIT limit_value+1
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object('id',approval_id,'run_id',run_id,'step_id',step_id,'state',state,'expires_at',to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'version',version,'expected_effect','Move finding to under review','reversible',true,'ttl_seconds',0,'evidence_summary',jsonb_build_array(trigger_id)) ORDER BY created_at DESC,approval_id DESC) FILTER(WHERE ordinal<=limit_value),'[]'::jsonb),
         max(created_at) FILTER(WHERE ordinal=limit_value AND (SELECT count(*) FROM candidates)>limit_value),
         max(approval_id) FILTER(WHERE ordinal=limit_value AND (SELECT count(*) FROM candidates)>limit_value)
  INTO items_value,next_created_value,next_id_value FROM candidates;
  RETURN jsonb_build_object('items',items_value,'next_created_at',CASE WHEN next_created_value IS NULL THEN NULL ELSE to_char(next_created_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,'next_id',next_id_value);
END
$approval_page$;

CREATE FUNCTION public.zasp_security_agent_approval_detail(organization_value text,workspace_value text,environment_value text,approval_value text) RETURNS SETOF jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $approval_detail$
  SELECT jsonb_build_object('id',approval.approval_id,'run_id',approval.run_id,'step_id',approval.step_id,'state',approval.state,'expires_at',to_char(approval.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'version',approval.version,'expected_effect','Move finding to under review','reversible',true,'ttl_seconds',0,'evidence_summary',jsonb_build_array(run.trigger_id))
  FROM zasp_security_agent_approvals approval JOIN zasp_security_agent_runs run ON (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id)
  WHERE zasp_security_agent_principal_ready('zasp_security_agent_api') AND zasp_valid_product_id(approval_value)
    AND (approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id)=(organization_value,workspace_value,environment_value,approval_value)
$approval_detail$;

CREATE FUNCTION public.zasp_security_agent_cancel_run(organization_value text,workspace_value text,environment_value text,run_value text,actor_value text,idempotency_value text,expected_version bigint,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $cancel_run$
DECLARE run_row zasp_security_agent_runs%ROWTYPE;receipt_row zasp_security_agent_request_receipts%ROWTYPE;intent_value jsonb;intent_digest_value bytea;response_value jsonb;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR expected_version<=0 OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(receipt_value)
     OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent cancellation rejected';
  END IF;
  intent_value:=jsonb_build_object('run_id',run_value,'expected_version',expected_version);intent_digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'cancelSecurityAgentRun',idempotency_value),0));
  SELECT * INTO receipt_row FROM zasp_security_agent_request_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.principal_id,receipt.operation,receipt.idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'cancelSecurityAgentRun',idempotency_value);
  IF FOUND THEN
    IF receipt_row.resource_id<>run_value OR receipt_row.expected_version<>expected_version OR receipt_row.intent_digest<>intent_digest_value OR receipt_row.expires_at<=transaction_timestamp()
       OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state)=(organization_value,workspace_value,environment_value,run_value,'cancelled')) THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent cancellation replay conflict';
    END IF;
    RETURN receipt_row.response||jsonb_build_object('replayed',true);
  END IF;
  SELECT * INTO run_row FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.version)=(organization_value,workspace_value,environment_value,run_value,expected_version)
    AND run.state IN('queued','planning','waiting_approval','running','verifying') FOR UPDATE;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=(organization_value,workspace_value,environment_value,run_value)) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent cancellation conflict';
  END IF;
  UPDATE zasp_security_agent_approvals approval SET state='cancelled',version=approval.version+1,decided_at=transaction_timestamp() WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id,approval.state)=(organization_value,workspace_value,environment_value,run_value,'pending');
  UPDATE zasp_security_agent_steps step SET state='cancelled',version=step.version+1,updated_at=transaction_timestamp() WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id)=(organization_value,workspace_value,environment_value,run_value) AND step.state IN('queued','authorized','waiting_approval','executing','verifying');
  UPDATE zasp_security_agent_runs run SET state='cancelled',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=run.version+1,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  response_value:=jsonb_build_object('id',run_value,'agent_id',run_row.definition_id,'state','cancelled','evidence_ids',jsonb_build_array(run_row.trigger_id),'definition_version',run_row.definition_version,'version',run_row.version+1,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,actor_value,'run_cancelled',intent_digest_value,jsonb_build_object('run_id',run_value,'prior_state',run_row.state,'version',run_row.version+1));
  INSERT INTO zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id) VALUES(organization_value,workspace_value,environment_value,actor_value,'cancelSecurityAgentRun',idempotency_value,run_value,expected_version,intent_value,intent_digest_value,response_value,audit_value,correlation_value,receipt_value);
  UPDATE zasp_security_agent_execution_state SET used_at=COALESCE(used_at,transaction_timestamp()) WHERE singleton;
  RETURN response_value;
END
$cancel_run$;

CREATE FUNCTION public.zasp_security_agent_heartbeat_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,lease_seconds integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $heartbeat$
DECLARE expiry_value timestamptz;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_valid_product_id(run_value) OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR lease_seconds NOT BETWEEN 30 AND 300 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent heartbeat rejected';
  END IF;
  UPDATE zasp_security_agent_runs run SET lease_expires_at=transaction_timestamp()+make_interval(secs=>lease_seconds),updated_at=transaction_timestamp(),version=run.version+1
  WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.lease_owner,run.lease_token)=(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value)
    AND run.state IN('planning','running','verifying') AND run.lease_expires_at>transaction_timestamp()
  RETURNING lease_expires_at INTO expiry_value;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent lease lost';END IF;
  RETURN jsonb_build_object('run_id',run_value,'lease_expires_at',to_char(expiry_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END
$heartbeat$;

CREATE FUNCTION public.zasp_security_agent_prepare_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,approval_value text,approval_expires_value timestamptz,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $prepare$
DECLARE run_row zasp_security_agent_runs%ROWTYPE; definition_row zasp_security_agent_definitions%ROWTYPE; trigger_row zasp_security_agent_trigger_receipts%ROWTYPE; finding_version bigint; step_value text; trigger_digest_value bytea; plan_value jsonb; plan_digest bytea;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(approval_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value)
     OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 OR approval_expires_value<=transaction_timestamp() OR approval_expires_value>transaction_timestamp()+interval '16 minutes' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent plan rejected';
  END IF;
  SELECT * INTO run_row FROM zasp_security_agent_runs run
  WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state,run.lease_owner,run.lease_token)=(organization_value,workspace_value,environment_value,run_value,'planning',worker_value,lease_token_value)
    AND run.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent lease lost';END IF;
  SELECT * INTO STRICT definition_row FROM zasp_security_agent_definitions definition
  WHERE (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version)=(organization_value,workspace_value,environment_value,run_row.definition_id,run_row.definition_version)
    AND definition.activation='supervised' AND definition.deleted_at IS NULL AND definition.body->'allowed_actions'=jsonb_build_array('update_finding_response') AND definition.body->>'verification_kind'='finding_state' FOR SHARE;
  SELECT * INTO STRICT trigger_row FROM zasp_security_agent_trigger_receipts trigger_receipt
  WHERE (trigger_receipt.organization_id,trigger_receipt.workspace_id,trigger_receipt.environment_id,trigger_receipt.run_id,trigger_receipt.trigger_kind)=(organization_value,workspace_value,environment_value,run_value,'finding');
  SELECT finding.version INTO finding_version FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id,finding.status)=(organization_value,workspace_value,environment_value,trigger_row.trigger_id,'open') FOR SHARE;
  IF NOT FOUND OR finding_version<>trigger_row.trigger_version THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent evidence changed';END IF;
  trigger_digest_value:=trigger_row.trigger_digest;
  step_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'security_agent_step',run_value||chr(31)||'0');
  plan_value:=jsonb_build_object('definition_id',run_row.definition_id,'definition_version',run_row.definition_version,'catalog_version','security-agent-actions-v1','evidence_ids',jsonb_build_array(trigger_row.trigger_id),'steps',jsonb_build_array(jsonb_build_object('index',0,'step_id',step_value,'action','update_finding_response','target_id',trigger_row.trigger_id,'expected_version',trigger_row.trigger_version,'target_status','under_review','authorization','approval_required')),'verification',jsonb_build_object('kind','finding_state','expected_status','under_review'),'expires_at',to_char(approval_expires_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  plan_digest:=digest(convert_to(plan_value::text,'UTF8'),'sha256');
  INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
  VALUES(organization_value,workspace_value,environment_value,run_value,run_row.definition_id,run_row.definition_version,trigger_digest_value,'security-agent-actions-v1',plan_value,plan_digest,approval_expires_value);
  INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
  VALUES(organization_value,workspace_value,environment_value,run_value,step_value,0,'update_finding_response',digest(convert_to((plan_value->'steps'->0)::text,'UTF8'),'sha256'),'approval_required','waiting_approval');
  INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at)
  VALUES(organization_value,workspace_value,environment_value,approval_value,run_value,step_value,plan_digest,'pending',run_row.requested_by,approval_expires_value);
  UPDATE zasp_security_agent_runs run SET state='waiting_approval',plan_hash=plan_digest,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=run.version+1,updated_at=transaction_timestamp()
  WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,step_value,approval_value,worker_value,'approval_requested',plan_digest,jsonb_build_object('run_id',run_value,'step_id',step_value,'approval_id',approval_value,'action','update_finding_response','target_id',trigger_row.trigger_id,'plan_hash','sha256:'||encode(plan_digest,'hex')));
  RETURN jsonb_build_object('run_id',run_value,'state','waiting_approval','version',run_row.version+1,'approval_id',approval_value,'step_id',step_value,'plan_hash','sha256:'||encode(plan_digest,'hex'));
END
$prepare$;

CREATE FUNCTION public.zasp_security_agent_decide_approval(organization_value text,workspace_value text,environment_value text,approval_value text,actor_value text,idempotency_value text,expected_version bigint,decision_value text,fresh_auth_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $decide$
DECLARE approval_row zasp_security_agent_approvals%ROWTYPE; receipt_row zasp_security_agent_request_receipts%ROWTYPE; intent_value jsonb; intent_digest_value bytea; response_value jsonb; next_run_state text;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_api') OR NOT zasp_valid_product_id(approval_value) OR NOT zasp_valid_product_id(actor_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR NOT zasp_valid_product_id(receipt_value)
     OR length(idempotency_value) NOT BETWEEN 16 AND 128 OR idempotency_value!~'^[A-Za-z0-9][A-Za-z0-9._:-]*$' OR expected_version<=0 OR decision_value NOT IN('approved','rejected','cancelled')
     OR fresh_auth_value<transaction_timestamp()-interval '5 minutes' OR fresh_auth_value>transaction_timestamp()+interval '5 seconds' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent approval rejected';
  END IF;
  intent_value:=jsonb_build_object('approval_id',approval_value,'expected_version',expected_version,'decision',decision_value);
  intent_digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,actor_value,'decideSecurityAgentApproval',idempotency_value),0));
  SELECT * INTO receipt_row FROM zasp_security_agent_request_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.principal_id,receipt.operation,receipt.idempotency_key)=(organization_value,workspace_value,environment_value,actor_value,'decideSecurityAgentApproval',idempotency_value);
  IF FOUND THEN
    IF receipt_row.resource_id<>approval_value OR receipt_row.expected_version<>expected_version OR receipt_row.intent_digest<>intent_digest_value OR receipt_row.expires_at<=transaction_timestamp()
       OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id)=(organization_value,workspace_value,environment_value,approval_value)) THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent approval replay conflict';
    END IF;
    RETURN receipt_row.response||jsonb_build_object('replayed',true);
  END IF;
  SELECT * INTO approval_row FROM zasp_security_agent_approvals approval
  WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id,approval.state,approval.version)=(organization_value,workspace_value,environment_value,approval_value,'pending',expected_version) FOR UPDATE;
  IF NOT FOUND OR approval_row.expires_at<=transaction_timestamp() OR approval_row.requester_id=actor_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent approval conflict';END IF;
  PERFORM 1 FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state,run.plan_hash)=(organization_value,workspace_value,environment_value,approval_row.run_id,'waiting_approval',approval_row.plan_hash) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent approval run conflict';END IF;
  next_run_state:=CASE decision_value WHEN 'approved' THEN 'queued' WHEN 'rejected' THEN 'needs_human' ELSE 'cancelled' END;
  UPDATE zasp_security_agent_approvals approval SET state=decision_value,approver_id=actor_value,fresh_auth_at=fresh_auth_value,version=approval.version+1,decided_at=transaction_timestamp()
  WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id)=(organization_value,workspace_value,environment_value,approval_value);
  UPDATE zasp_security_agent_steps step SET state=CASE WHEN decision_value='approved' THEN 'authorized' ELSE 'cancelled' END,version=step.version+1,updated_at=transaction_timestamp()
  WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id)=(organization_value,workspace_value,environment_value,approval_row.run_id,approval_row.step_id);
  UPDATE zasp_security_agent_runs run SET state=next_run_state,available_at=transaction_timestamp(),version=run.version+1,updated_at=transaction_timestamp(),completed_at=CASE WHEN decision_value='approved' THEN NULL ELSE transaction_timestamp() END
  WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,approval_row.run_id);
  response_value:=jsonb_build_object('id',approval_value,'run_id',approval_row.run_id,'step_id',approval_row.step_id,'state',decision_value,'expires_at',to_char(approval_row.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'version',expected_version+1,'expected_effect','Move finding to under review','reversible',true,'ttl_seconds',0,'evidence_summary',(SELECT plan->'evidence_ids' FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(organization_value,workspace_value,environment_value,approval_row.run_id)),'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,approval_row.run_id,approval_row.step_id,approval_value,actor_value,'approval_decided',intent_digest_value,jsonb_build_object('approval_id',approval_value,'run_id',approval_row.run_id,'decision',decision_value,'version',expected_version+1));
  INSERT INTO zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id)
  VALUES(organization_value,workspace_value,environment_value,actor_value,'decideSecurityAgentApproval',idempotency_value,approval_value,expected_version,intent_value,intent_digest_value,response_value,audit_value,correlation_value,receipt_value);
  RETURN response_value;
END
$decide$;

CREATE FUNCTION public.zasp_security_agent_execute_run(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,audit_value text,correlation_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $execute$
DECLARE run_row zasp_security_agent_runs%ROWTYPE; trigger_row zasp_security_agent_trigger_receipts%ROWTYPE; plan_row zasp_security_agent_plans%ROWTYPE; step_row zasp_security_agent_steps%ROWTYPE; approval_row zasp_security_agent_approvals%ROWTYPE; finding_version bigint; outcome_value text; result_digest_value bytea;
BEGIN
  IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_valid_product_id(run_value) OR NOT zasp_valid_product_id(audit_value) OR NOT zasp_valid_product_id(correlation_value) OR length(worker_value) NOT BETWEEN 1 AND 128 OR length(lease_token_value) NOT BETWEEN 16 AND 128 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent execution rejected';
  END IF;
  SELECT * INTO run_row FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state,run.lease_owner,run.lease_token)=(organization_value,workspace_value,environment_value,run_value,'planning',worker_value,lease_token_value) AND run.lease_expires_at>transaction_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent lease lost';END IF;
  SELECT * INTO STRICT trigger_row FROM zasp_security_agent_trigger_receipts trigger_receipt WHERE (trigger_receipt.organization_id,trigger_receipt.workspace_id,trigger_receipt.environment_id,trigger_receipt.run_id,trigger_receipt.trigger_kind)=(organization_value,workspace_value,environment_value,run_value,'finding');
  SELECT * INTO STRICT plan_row FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id,plan.plan_hash)=(organization_value,workspace_value,environment_value,run_value,run_row.plan_hash) AND plan.expires_at>transaction_timestamp() FOR SHARE;
  SELECT * INTO STRICT step_row FROM zasp_security_agent_steps step WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.action_key,step.state)=(organization_value,workspace_value,environment_value,run_value,'update_finding_response','authorized') FOR UPDATE;
  SELECT * INTO STRICT approval_row FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id,approval.step_id,approval.state,approval.plan_hash)=(organization_value,workspace_value,environment_value,run_value,step_row.step_id,'approved',run_row.plan_hash) AND approval.expires_at>transaction_timestamp() FOR SHARE;
  IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_definitions definition WHERE (definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id,definition.version,definition.activation)=(organization_value,workspace_value,environment_value,run_row.definition_id,run_row.definition_version,'supervised') AND definition.deleted_at IS NULL AND definition.body->'allowed_actions'=jsonb_build_array('update_finding_response'))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'*',true))
     OR NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(organization_value,workspace_value,environment_value,'update_finding_response',true)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent execution disabled';
  END IF;
  INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,lease_owner,lease_token,lease_expires_at,attempt)
  VALUES(organization_value,workspace_value,environment_value,run_value,step_row.step_id,'update_finding_response',step_row.input_digest,'leased',worker_value,lease_token_value,run_row.lease_expires_at,1);
  UPDATE zasp_risk_findings finding SET status='under_review',acceptance_reason=NULL,version=finding.version+1,updated_at=transaction_timestamp()
  WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id,finding.status,finding.version)=(organization_value,workspace_value,environment_value,trigger_row.trigger_id,'open',trigger_row.trigger_version)
  RETURNING finding.version INTO finding_version;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent evidence changed';END IF;
  outcome_value:=zasp_discovery_canonical_id(organization_value,workspace_value,environment_value,'security_agent_effect',run_value||chr(31)||step_row.step_id||chr(31)||'update_finding_response');
  result_digest_value:=digest(convert_to(jsonb_build_object('finding_id',trigger_row.trigger_id,'status','under_review','version',finding_version)::text,'UTF8'),'sha256');
  UPDATE zasp_security_agent_effects effect SET state='verified',outcome_id=outcome_value,result_digest=result_digest_value,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=effect.version+1,updated_at=transaction_timestamp()
  WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key)=(organization_value,workspace_value,environment_value,run_value,step_row.step_id,'update_finding_response');
  UPDATE zasp_security_agent_steps step SET state='succeeded',version=step.version+1,updated_at=transaction_timestamp() WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id)=(organization_value,workspace_value,environment_value,run_value,step_row.step_id);
  UPDATE zasp_security_agent_runs run SET state='remediated',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=run.version+1,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(organization_value,workspace_value,environment_value,run_value);
  INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body)
  VALUES(organization_value,workspace_value,environment_value,audit_value,correlation_value,run_value,step_row.step_id,approval_row.approval_id,worker_value,'effect_verified',result_digest_value,jsonb_build_object('run_id',run_value,'step_id',step_row.step_id,'action','update_finding_response','target_id',trigger_row.trigger_id,'outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex')));
  RETURN jsonb_build_object('run_id',run_value,'state','remediated','version',run_row.version+1,'step_id',step_row.step_id,'effect_state','verified','outcome_id',outcome_value,'result_digest','sha256:'||encode(result_digest_value,'hex'));
END
$execute$;

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
  INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state)
  VALUES(organization_value,workspace_value,environment_value,run_value,definition_value,definition_version_value,encode(trigger_digest_value,'hex'),actor_value,'queued');
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
  SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_id',definition_id,'definition_version',definition_version,'trigger_id',trigger_id,'state',state,'version',version,'attempt',attempt,'lease_expires_at',to_char(lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'prepared',EXISTS(SELECT 1 FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(claimed.organization_id,claimed.workspace_id,claimed.environment_id,claimed.run_id))) ORDER BY organization_id,workspace_id,environment_id,run_id),'[]'::jsonb)) INTO result_value FROM claimed;
  RETURN result_value;
END
$claim_runs$;

DO $functions$
DECLARE procedure_oid oid;
BEGIN
  FOR procedure_oid IN SELECT procedure_row.oid FROM pg_proc procedure_row JOIN pg_namespace namespace_row ON namespace_row.oid=procedure_row.pronamespace WHERE namespace_row.nspname='public' AND procedure_row.proname IN('zasp_security_agent_register_principals','zasp_security_agent_principal_ready','zasp_security_agent_principals_ready','zasp_security_agent_definition_page','zasp_security_agent_definition_value','zasp_security_agent_replay_definition','zasp_security_agent_mutate_definition','zasp_security_agent_definition_detail','zasp_security_agent_set_kill_switch','zasp_security_agent_activate','zasp_security_agent_simulate','zasp_security_agent_run','zasp_security_agent_run_page','zasp_security_agent_run_detail','zasp_security_agent_cancel_run','zasp_security_agent_approval_page','zasp_security_agent_approval_detail','zasp_security_agent_decide_approval','zasp_security_agent_create_run','zasp_security_agent_claim_runs','zasp_security_agent_heartbeat_run','zasp_security_agent_prepare_run','zasp_security_agent_execute_run') LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure);
    EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure);
  END LOOP;
END $functions$;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_principal_ready(text),public.zasp_security_agent_definition_page(text,text,text,text,integer),public.zasp_security_agent_definition_value(text,text,text,text),public.zasp_security_agent_replay_definition(text,text,text,text,text,text,jsonb),public.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),public.zasp_security_agent_definition_detail(text,text,text,text),public.zasp_security_agent_set_kill_switch(text,text,text,text,boolean,bigint,text,text,text),public.zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text),public.zasp_security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text),public.zasp_security_agent_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text),public.zasp_security_agent_run_page(text,text,text,text,text,timestamptz,text,integer),public.zasp_security_agent_run_detail(text,text,text,text),public.zasp_security_agent_cancel_run(text,text,text,text,text,text,bigint,text,text,text),public.zasp_security_agent_approval_page(text,text,text,text,text,timestamptz,text,integer),public.zasp_security_agent_approval_detail(text,text,text,text),public.zasp_security_agent_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_principal_ready(text),public.zasp_security_agent_claim_runs(text,text,integer,integer),public.zasp_security_agent_heartbeat_run(text,text,text,text,text,text,integer),public.zasp_security_agent_prepare_run(text,text,text,text,text,text,text,timestamptz,text,text),public.zasp_security_agent_execute_run(text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;

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

INSERT INTO public.zasp_schema_metadata(key,value) VALUES('security_agent_execution_fingerprint', '6849308904dfab78dff862d4281281cc4c2a8a91a7dc9e75825b8d7f0fb083f1')
ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;
