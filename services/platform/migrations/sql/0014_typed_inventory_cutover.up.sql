DO $release_guard$ BEGIN
  IF NOT zasp_execution_readiness(
    '355815b171d2659421a55eed5d364b8aa5661e76798fd39957b13c399d0dfd52',
    '6a3a830ff7e43a220be6e0658a6262ed92c8c0165c803b34319acb0e0ed6cb9c'
  ) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production discovery execution release required';
  END IF;
END $release_guard$;

DO $inventory_role$ DECLARE created_role boolean;role_value record;marker_prefix text:=format('zasp-managed:typed-inventory-cutover-v1:database:%s:',(SELECT oid FROM pg_database WHERE datname=current_database()));BEGIN
  created_role:=NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_inventory_authority');
  IF created_role THEN
    CREATE ROLE zasp_inventory_authority NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  SELECT role.oid,role.rolcanlogin,role.rolinherit,role.rolsuper,role.rolcreatedb,role.rolcreaterole,role.rolreplication,role.rolbypassrls,shobj_description(role.oid,'pg_authid') marker
    INTO STRICT role_value FROM pg_roles role WHERE role.rolname='zasp_inventory_authority';
  IF role_value.rolcanlogin OR role_value.rolinherit OR role_value.rolsuper OR role_value.rolcreatedb OR role_value.rolcreaterole OR role_value.rolreplication OR role_value.rolbypassrls
     OR role_value.marker IS NOT NULL AND role_value.marker NOT IN(marker_prefix||'created',marker_prefix||'bound')
     OR EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.roleid=role_value.oid OR membership.member=role_value.oid)
     OR EXISTS(SELECT 1 FROM pg_class object WHERE object.relowner=role_value.oid OR EXISTS(SELECT 1 FROM aclexplode(object.relacl) acl WHERE acl.grantee=role_value.oid))
     OR EXISTS(SELECT 1 FROM pg_proc object WHERE object.proowner=role_value.oid OR EXISTS(SELECT 1 FROM aclexplode(object.proacl) acl WHERE acl.grantee=role_value.oid))
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unsafe pre-existing inventory role';END IF;
  EXECUTE format('COMMENT ON ROLE %I IS %L','zasp_inventory_authority',marker_prefix||CASE WHEN created_role OR role_value.marker=marker_prefix||'created' THEN 'created' ELSE 'bound' END);
END $inventory_role$;

CREATE TABLE public.zasp_inventory_cutover_state (
  organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),
  workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),
  environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
  phase text NOT NULL CHECK(phase IN('expanded','backfilled','equivalent','cutover')),
  rule_catalog_digest text NOT NULL CHECK(rule_catalog_digest='a2ac63a7fc968b0c0c883a999418e1eb14c2d8de3ffe62e95717b7dea6133c52'),
  legacy_digest bytea CHECK(legacy_digest IS NULL OR octet_length(legacy_digest)=32),
  typed_digest bytea CHECK(typed_digest IS NULL OR octet_length(typed_digest)=32),
  expanded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  backfilled_at timestamptz,
  equivalent_at timestamptz,
  cutover_at timestamptz,
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  PRIMARY KEY(organization_id,workspace_id,environment_id),
  CHECK(
    phase='expanded' AND backfilled_at IS NULL AND equivalent_at IS NULL AND cutover_at IS NULL AND legacy_digest IS NULL AND typed_digest IS NULL
    OR phase='backfilled' AND backfilled_at IS NOT NULL AND equivalent_at IS NULL AND cutover_at IS NULL AND legacy_digest IS NULL AND typed_digest IS NULL
    OR phase='equivalent' AND backfilled_at IS NOT NULL AND equivalent_at IS NOT NULL AND cutover_at IS NULL AND legacy_digest IS NOT NULL AND typed_digest IS NOT NULL AND legacy_digest=typed_digest
    OR phase='cutover' AND backfilled_at IS NOT NULL AND equivalent_at IS NOT NULL AND cutover_at IS NOT NULL AND legacy_digest IS NOT NULL AND typed_digest IS NOT NULL AND legacy_digest=typed_digest
  ),
  CHECK(backfilled_at IS NULL OR backfilled_at>=expanded_at),
  CHECK(equivalent_at IS NULL OR equivalent_at>=backfilled_at),
  CHECK(cutover_at IS NULL OR cutover_at>=equivalent_at)
);

CREATE TABLE public.zasp_inventory_legacy_restore (
  object_kind text NOT NULL CHECK(object_kind IN('function','constraint')),
  object_identity text NOT NULL CHECK(length(object_identity) BETWEEN 1 AND 256),
  definition text NOT NULL CHECK(length(definition) BETWEEN 1 AND 131072),
  definition_digest bytea NOT NULL CHECK(octet_length(definition_digest)=32),
  PRIMARY KEY(object_kind,object_identity)
);

INSERT INTO public.zasp_inventory_legacy_restore(object_kind,object_identity,definition,definition_digest)
SELECT 'function','public.zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb)',definition,digest(convert_to(definition,'UTF8'),'sha256')
FROM (SELECT pg_get_functiondef('public.zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb)'::regprocedure) definition) captured;

INSERT INTO public.zasp_inventory_legacy_restore(object_kind,object_identity,definition,definition_digest)
SELECT 'function','public.zasp_core_read(text,text,text,text)',definition,digest(convert_to(definition,'UTF8'),'sha256') FROM (SELECT pg_get_functiondef('public.zasp_core_read(text,text,text,text)'::regprocedure) definition) captured;

INSERT INTO public.zasp_inventory_legacy_restore(object_kind,object_identity,definition,definition_digest)
SELECT 'function','public.zasp_execution_job_input(text,text,text,text,text,text)',definition,digest(convert_to(definition,'UTF8'),'sha256') FROM (SELECT pg_get_functiondef('public.zasp_execution_job_input(text,text,text,text,text,text)'::regprocedure) definition) captured;

INSERT INTO public.zasp_inventory_legacy_restore(object_kind,object_identity,definition,definition_digest)
SELECT 'constraint',constraint_value.conname,format('ALTER TABLE public.zasp_inventory_evidence ADD CONSTRAINT %I %s',constraint_value.conname,pg_get_constraintdef(constraint_value.oid,true)),digest(convert_to(format('ALTER TABLE public.zasp_inventory_evidence ADD CONSTRAINT %I %s',constraint_value.conname,pg_get_constraintdef(constraint_value.oid,true)),'UTF8'),'sha256')
FROM pg_constraint constraint_value
WHERE constraint_value.conrelid='public.zasp_inventory_evidence'::regclass AND constraint_value.contype='u'
  AND pg_get_constraintdef(constraint_value.oid,true)='UNIQUE (organization_id, workspace_id, environment_id, object_reference)';

DO $legacy_restore_guard$ DECLARE constraint_name text;BEGIN
 IF (SELECT count(*) FROM zasp_inventory_legacy_restore)<>4 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory legacy authority missing';END IF;
 SELECT object_identity INTO STRICT constraint_name FROM zasp_inventory_legacy_restore WHERE object_kind='constraint';
 EXECUTE format('ALTER TABLE public.zasp_inventory_evidence DROP CONSTRAINT %I',constraint_name);
END $legacy_restore_guard$;

DO $job_input_helper$ DECLARE original_definition text;helper_definition text;BEGIN
 SELECT definition INTO STRICT original_definition FROM zasp_inventory_legacy_restore WHERE (object_kind,object_identity)=('function','public.zasp_execution_job_input(text,text,text,text,text,text)');
 helper_definition:=replace(original_definition,'CREATE OR REPLACE FUNCTION public.zasp_execution_job_input','CREATE FUNCTION public.zasp_typed_inventory_job_input_v13');
 IF helper_definition=original_definition THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory job input helper missing';END IF;
 EXECUTE helper_definition;
 ALTER FUNCTION public.zasp_typed_inventory_job_input_v13(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
 ALTER FUNCTION public.zasp_typed_inventory_job_input_v13(text,text,text,text,text,text) SECURITY DEFINER SET search_path TO pg_catalog, public;
 REVOKE ALL ON FUNCTION public.zasp_typed_inventory_job_input_v13(text,text,text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker;
END $job_input_helper$;

CREATE OR REPLACE FUNCTION public.zasp_execution_job_input(organization_value text,workspace_value text,environment_value text,job_value text,worker text,lease_token_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE result_value jsonb;observation_value timestamptz;
BEGIN
 result_value:=zasp_typed_inventory_job_input_v13(organization_value,workspace_value,environment_value,job_value,worker,lease_token_value);
 SELECT reservation.reserved_at INTO STRICT observation_value FROM zasp_discovery_generation_reservations reservation
  WHERE (reservation.organization_id,reservation.workspace_id,reservation.environment_id,reservation.sync_id,reservation.integration_id,reservation.source,reservation.generation,reservation.snapshot_id)=(organization_value,workspace_value,environment_value,result_value->>'sync_id',result_value->>'integration_id',result_value->>'provider',(result_value->>'generation')::bigint,result_value->>'snapshot_id');
 RETURN result_value||jsonb_build_object('observation_time',to_char(date_trunc('second',observation_value) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'));
END $$;
ALTER FUNCTION public.zasp_execution_job_input(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_execution_job_input(text,text,text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker;
GRANT EXECUTE ON FUNCTION public.zasp_execution_job_input(text,text,text,text,text,text) TO zasp_discovery_worker;

CREATE TABLE public.zasp_inventory_identity_rules (
  provider text NOT NULL CHECK(provider IN('aws','kubernetes','github','okta')),
  source_kind text NOT NULL CHECK(source_kind ~ '^[a-z][a-z0-9_]{1,63}$'),
  identity_namespace text NOT NULL CHECK(identity_namespace ~ '^[a-z][a-z0-9_]{1,63}$'),
  product_kind text NOT NULL CHECK(product_kind IN('asset','agent','tool','identity','runtime')),
  rule_version integer NOT NULL CHECK(rule_version BETWEEN 1 AND 1000000),
  priority integer NOT NULL CHECK(priority BETWEEN 1 AND 1000000),
  confidence_basis_points integer NOT NULL CHECK(confidence_basis_points BETWEEN 1 AND 10000),
  freshness_seconds integer NOT NULL CHECK(freshness_seconds BETWEEN 1 AND 604800),
  PRIMARY KEY(provider,source_kind),
  UNIQUE(provider,identity_namespace,rule_version)
);

INSERT INTO public.zasp_inventory_identity_rules(provider,source_kind,identity_namespace,product_kind,rule_version,priority,confidence_basis_points,freshness_seconds) VALUES
 ('aws','aws_account','aws_account','asset',1,100,9000,86400),
 ('aws','aws_resource','aws_resource','asset',1,100,9000,86400),
 ('aws','aws_role','aws_role','asset',1,100,9000,86400),
 ('aws','aws_service','aws_service','asset',1,100,9000,86400),
 ('github','github_installation','github_installation','asset',1,120,9000,86400),
 ('github','github_organization','github_organization','asset',1,120,9000,86400),
 ('github','github_repository','github_repository','tool',1,120,9000,86400),
 ('kubernetes','kubernetes_agent','kubernetes_agent','agent',1,80,9500,900),
 ('kubernetes','kubernetes_cluster','kubernetes_cluster','asset',1,80,9500,900),
 ('kubernetes','kubernetes_namespace','kubernetes_namespace','asset',1,80,9500,900),
 ('kubernetes','kubernetes_resource','kubernetes_resource','asset',1,80,9500,900),
 ('kubernetes','kubernetes_workload','kubernetes_workload','runtime',1,80,9500,900),
 ('okta','okta_application','okta_application','tool',1,110,9500,86400),
 ('okta','okta_group','okta_group','identity',1,110,9500,86400),
 ('okta','okta_tenant','okta_tenant','asset',1,110,9500,86400),
 ('okta','okta_user','okta_user','identity',1,110,9500,86400);

CREATE TABLE public.zasp_inventory_identity_bindings (
  organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),
  workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),
  environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
  provider text NOT NULL, source text NOT NULL CHECK(source ~ '^[a-z][a-z0-9_]{1,63}$'),
  identity_namespace text NOT NULL, source_native_id text NOT NULL CHECK(length(source_native_id) BETWEEN 1 AND 1024),
  entity_id text NOT NULL CHECK(zasp_valid_product_id(entity_id)), product_kind text NOT NULL,
  rule_version integer NOT NULL, priority integer NOT NULL,
  bound_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,provider,source,identity_namespace,source_native_id),
  FOREIGN KEY(provider,identity_namespace,rule_version) REFERENCES zasp_inventory_identity_rules(provider,identity_namespace,rule_version),
  FOREIGN KEY(organization_id,workspace_id,environment_id,entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id)
);

CREATE TABLE public.zasp_inventory_annotations (
  organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),
  workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),
  environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
  entity_id text NOT NULL CHECK(zasp_valid_product_id(entity_id)),
  owner_value text NOT NULL DEFAULT '' CHECK(owner_value='' OR length(owner_value) BETWEEN 1 AND 128),
  team_value text NOT NULL DEFAULT '' CHECK(team_value='' OR length(team_value) BETWEEN 1 AND 128),
  tags jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(tags)='array' AND jsonb_array_length(tags)<=32 AND octet_length(tags::text)<=4096),
  version integer NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 1000000),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(organization_id,workspace_id,environment_id,entity_id),
  FOREIGN KEY(organization_id,workspace_id,environment_id,entity_id) REFERENCES zasp_inventory_entities(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE
);

ALTER TABLE public.zasp_inventory_entities
  ADD COLUMN product_kind text CHECK(product_kind IS NULL OR product_kind IN('asset','agent','tool','identity','runtime')),
  ADD COLUMN confidence_basis_points integer CHECK(confidence_basis_points IS NULL OR confidence_basis_points BETWEEN 1 AND 10000),
  ADD COLUMN winning_evidence_id text CHECK(winning_evidence_id IS NULL OR zasp_valid_product_id(winning_evidence_id)),
  ADD COLUMN winning_snapshot_id text CHECK(winning_snapshot_id IS NULL OR zasp_valid_product_id(winning_snapshot_id)),
  ADD COLUMN winning_generation bigint CHECK(winning_generation IS NULL OR winning_generation>0),
  ADD COLUMN observed_at timestamptz,
  ADD COLUMN fresh_until timestamptz,
  ADD COLUMN projection_version integer CHECK(projection_version IS NULL OR projection_version BETWEEN 1 AND 1000000),
  ADD COLUMN winning_integration_id text CHECK(winning_integration_id IS NULL OR zasp_valid_product_id(winning_integration_id)),
  ADD COLUMN winning_provider text,
  ADD COLUMN winning_source text,
  ADD COLUMN winning_source_native_id text,
  ADD COLUMN winning_identity_rule integer CHECK(winning_identity_rule IS NULL OR winning_identity_rule BETWEEN 1 AND 1000000),
  ADD COLUMN winning_source_projection integer CHECK(winning_source_projection IS NULL OR winning_source_projection BETWEEN 1 AND 1000000),
  ADD COLUMN annotation_version integer NOT NULL DEFAULT 1 CHECK(annotation_version BETWEEN 1 AND 1000000),
  ADD CONSTRAINT zasp_inventory_entities_typed_times CHECK(observed_at IS NULL OR fresh_until>observed_at);

ALTER TABLE public.zasp_inventory_source_observations
  ADD COLUMN provider text,
  ADD COLUMN source_kind text,
  ADD COLUMN display_name text,
  ADD COLUMN stable_fields jsonb CHECK(stable_fields IS NULL OR jsonb_typeof(stable_fields)='object' AND octet_length(stable_fields::text)<=65536),
  ADD COLUMN identity_namespace text,
  ADD COLUMN product_kind text CHECK(product_kind IS NULL OR product_kind IN('asset','agent','tool','identity','runtime')),
  ADD COLUMN generation bigint CHECK(generation IS NULL OR generation>0),
  ADD COLUMN content_digest bytea CHECK(content_digest IS NULL OR octet_length(content_digest)=32),
  ADD COLUMN evidence_id text CHECK(evidence_id IS NULL OR zasp_valid_product_id(evidence_id)),
  ADD COLUMN confidence_basis_points integer CHECK(confidence_basis_points IS NULL OR confidence_basis_points BETWEEN 1 AND 10000),
  ADD COLUMN observed_at timestamptz,
  ADD COLUMN fresh_until timestamptz,
  ADD COLUMN identity_rule_version integer CHECK(identity_rule_version IS NULL OR identity_rule_version BETWEEN 1 AND 1000000),
  ADD COLUMN identity_priority integer CHECK(identity_priority IS NULL OR identity_priority BETWEEN 1 AND 1000000),
  ADD COLUMN source_projection_version integer CHECK(source_projection_version IS NULL OR source_projection_version BETWEEN 1 AND 1000000),
  ADD CONSTRAINT zasp_inventory_observations_typed_times CHECK(observed_at IS NULL OR fresh_until>observed_at);

ALTER TABLE public.zasp_inventory_evidence
  ADD COLUMN source text,
  ADD COLUMN generation bigint CHECK(generation IS NULL OR generation>0),
  ADD COLUMN artifact_reference text,
  ADD COLUMN artifact_key text,
  ADD COLUMN artifact_version_id text,
  ADD COLUMN size_bytes bigint CHECK(size_bytes IS NULL OR size_bytes BETWEEN 1 AND 536870912),
  ADD COLUMN tool_version text;

CREATE OR REPLACE FUNCTION public.zasp_core_read(operation text,organization_id text,workspace_id text,environment_id text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
 SELECT payload FROM public.zasp_core_payloads WHERE zasp_core_payloads.organization_id=zasp_core_read.organization_id AND zasp_core_payloads.workspace_id=zasp_core_read.workspace_id AND zasp_core_payloads.environment_id=zasp_core_read.environment_id AND zasp_core_payloads.operation=zasp_core_read.operation
$$;

CREATE FUNCTION public.zasp_inventory_validate_typed_entities(provider_value text,entities_value jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT provider_value IN('aws','kubernetes','github','okta') AND NOT EXISTS(
  SELECT 1 FROM jsonb_to_recordset(entities_value) entity_value(kind text,identity_namespace text,identity_rule_version integer,identity_priority integer,product_kind text,confidence_basis_points integer,observed_at text,fresh_until text,source_projection_version integer)
  LEFT JOIN zasp_inventory_identity_rules rule_value ON (rule_value.provider,rule_value.source_kind)=(provider_value,entity_value.kind)
  WHERE rule_value.provider IS NULL OR (entity_value.identity_namespace,entity_value.identity_rule_version,entity_value.identity_priority,entity_value.product_kind,entity_value.confidence_basis_points,entity_value.source_projection_version)<>(rule_value.identity_namespace,rule_value.rule_version,rule_value.priority,rule_value.product_kind,rule_value.confidence_basis_points,rule_value.rule_version)
   OR CASE WHEN entity_value.observed_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' AND entity_value.fresh_until ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' THEN to_char(entity_value.observed_at::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')<>entity_value.observed_at OR to_char(entity_value.fresh_until::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')<>entity_value.fresh_until OR extract(epoch FROM entity_value.fresh_until::timestamptz-entity_value.observed_at::timestamptz)::bigint<>rule_value.freshness_seconds ELSE true END
 )
$$;

CREATE FUNCTION public.zasp_inventory_bind_typed_entities(organization_value text,workspace_value text,environment_value text,provider_value text,source_value text,entities_value jsonb) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO zasp_inventory_identity_bindings(organization_id,workspace_id,environment_id,provider,source,identity_namespace,source_native_id,entity_id,product_kind,rule_version,priority)
 SELECT organization_value,workspace_value,environment_value,provider_value,source_value,candidate.identity_namespace,candidate.source_native_id,candidate.id,candidate.product_kind,candidate.identity_rule_version,candidate.identity_priority
 FROM jsonb_to_recordset(entities_value) candidate(id text,source_native_id text,identity_namespace text,identity_rule_version integer,identity_priority integer,product_kind text) ON CONFLICT DO NOTHING;
 RETURN NOT EXISTS(
  SELECT 1 FROM jsonb_to_recordset(entities_value) candidate(id text,source_native_id text,identity_namespace text,identity_rule_version integer,identity_priority integer,product_kind text)
  LEFT JOIN zasp_inventory_identity_bindings binding ON (binding.organization_id,binding.workspace_id,binding.environment_id,binding.provider,binding.source,binding.identity_namespace,binding.source_native_id)=(organization_value,workspace_value,environment_value,provider_value,source_value,candidate.identity_namespace,candidate.source_native_id)
  WHERE binding.entity_id IS NULL OR (binding.entity_id,binding.product_kind,binding.rule_version,binding.priority)<>(candidate.id,candidate.product_kind,candidate.identity_rule_version,candidate.identity_priority)
 );
END $$;

CREATE FUNCTION public.zasp_inventory_scope_state(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT to_jsonb(state_value) FROM zasp_inventory_cutover_state state_value WHERE (state_value.organization_id,state_value.workspace_id,state_value.environment_id)=(organization_value,workspace_value,environment_value)
$$;

CREATE FUNCTION public.zasp_inventory_advance_scope(organization_value text,workspace_value text,environment_value text,next_phase text,legacy_value bytea,typed_value bytea) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE current_value zasp_inventory_cutover_state%ROWTYPE;
BEGIN
 IF NOT zasp_valid_product_id(organization_value) OR NOT zasp_valid_product_id(workspace_value) OR NOT zasp_valid_product_id(environment_value) OR next_phase NOT IN('expanded','backfilled','equivalent','cutover') OR next_phase IN('equivalent','cutover') AND (octet_length(legacy_value)<>32 OR typed_value<>legacy_value) OR next_phase IN('expanded','backfilled') AND (legacy_value IS NOT NULL OR typed_value IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid inventory phase';END IF;
 SELECT * INTO current_value FROM zasp_inventory_cutover_state WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) FOR UPDATE;
 IF NOT FOUND THEN
  IF next_phase<>'expanded' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='inventory phase missing';END IF;
  INSERT INTO zasp_inventory_cutover_state(organization_id,workspace_id,environment_id,phase,rule_catalog_digest) VALUES(organization_value,workspace_value,environment_value,'expanded','a2ac63a7fc968b0c0c883a999418e1eb14c2d8de3ffe62e95717b7dea6133c52') RETURNING * INTO current_value;
 ELSIF current_value.phase=next_phase AND (next_phase NOT IN('equivalent','cutover') OR (current_value.legacy_digest,current_value.typed_digest)=(legacy_value,typed_value)) THEN
  NULL;
 ELSIF current_value.phase='expanded' AND next_phase='backfilled' THEN
  UPDATE zasp_inventory_cutover_state SET phase='backfilled',backfilled_at=transaction_timestamp(),version=version+1 WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) RETURNING * INTO current_value;
 ELSIF current_value.phase='backfilled' AND next_phase='equivalent' THEN
  UPDATE zasp_inventory_cutover_state SET phase='equivalent',legacy_digest=legacy_value,typed_digest=typed_value,equivalent_at=transaction_timestamp(),version=version+1 WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) RETURNING * INTO current_value;
 ELSIF current_value.phase='equivalent' AND next_phase='cutover' AND (current_value.legacy_digest,current_value.typed_digest)=(legacy_value,typed_value) THEN
  UPDATE zasp_inventory_cutover_state SET phase='cutover',cutover_at=transaction_timestamp(),version=version+1 WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value) RETURNING * INTO current_value;
 ELSE RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='invalid inventory phase transition';END IF;
 RETURN to_jsonb(current_value);
END $$;

CREATE FUNCTION public.zasp_inventory_import_annotations(organization_value text,workspace_value text,environment_value text,items_value jsonb) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
 IF jsonb_typeof(items_value)<>'array' OR EXISTS(SELECT 1 FROM jsonb_array_elements(items_value) item WHERE jsonb_typeof(item)<>'object' OR NOT item ?& ARRAY['id','owner','team','tags'] OR item-ARRAY['id','owner','team','tags']<>'{}'::jsonb) OR EXISTS(SELECT 1 FROM jsonb_to_recordset(items_value) item(id text,owner text,team text,tags jsonb) WHERE NOT zasp_valid_product_id(item.id) OR length(item.owner)>128 OR length(item.team)>128 OR item.owner ~ '[[:cntrl:]]' OR item.team ~ '[[:cntrl:]]' OR jsonb_typeof(item.tags)<>'array' OR jsonb_array_length(item.tags)>32 OR octet_length(item.tags::text)>4096 OR jsonb_array_length(item.tags)<>(SELECT count(DISTINCT tag#>>'{}') FROM jsonb_array_elements(item.tags) tag) OR EXISTS(SELECT 1 FROM jsonb_array_elements(item.tags) tag WHERE jsonb_typeof(tag)<>'string' OR length(tag#>>'{}') NOT BETWEEN 1 AND 64 OR tag#>>'{}' ~ '[[:cntrl:]]')) THEN RETURN false;END IF;
 INSERT INTO zasp_inventory_annotations(organization_id,workspace_id,environment_id,entity_id,owner_value,team_value,tags)
 SELECT organization_value,workspace_value,environment_value,item.id,item.owner,item.team,item.tags FROM jsonb_to_recordset(items_value) item(id text,owner text,team text,tags jsonb)
 ON CONFLICT(organization_id,workspace_id,environment_id,entity_id) DO NOTHING;
 RETURN NOT EXISTS(SELECT 1 FROM jsonb_to_recordset(items_value) item(id text,owner text,team text,tags jsonb) LEFT JOIN zasp_inventory_annotations annotation ON (annotation.organization_id,annotation.workspace_id,annotation.environment_id,annotation.entity_id)=(organization_value,workspace_value,environment_value,item.id) WHERE annotation.entity_id IS NULL OR (annotation.owner_value,annotation.team_value,annotation.tags) IS DISTINCT FROM (item.owner,item.team,item.tags));
END $$;

CREATE FUNCTION public.zasp_inventory_backfill_scope(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE input_value record;updated_count integer;annotation_items jsonb;state_value jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-inventory-cutover',organization_value,workspace_value,environment_value),0));
 state_value:=zasp_inventory_scope_state(organization_value,workspace_value,environment_value);
 IF state_value IS NULL THEN PERFORM zasp_inventory_advance_scope(organization_value,workspace_value,environment_value,'expanded',NULL,NULL);ELSIF state_value->>'phase'<>'expanded' THEN IF state_value->>'phase'='backfilled' THEN RETURN state_value;END IF;RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='inventory backfill phase conflict';END IF;
 FOR input_value IN
  SELECT input.integration_id,input.source,input.generation,input.snapshot_id,input.candidate_digest,input.entities,input.evidence,snapshot.collected_at
  FROM zasp_discovery_snapshot_inputs input JOIN zasp_discovery_snapshots snapshot ON (snapshot.organization_id,snapshot.workspace_id,snapshot.environment_id,snapshot.id,snapshot.integration_id,snapshot.source,snapshot.generation,snapshot.state,snapshot.is_last_good)=(input.organization_id,input.workspace_id,input.environment_id,input.snapshot_id,input.integration_id,input.source,input.generation,'complete',true)
  WHERE (input.organization_id,input.workspace_id,input.environment_id)=(organization_value,workspace_value,environment_value) ORDER BY input.integration_id,input.source
 LOOP
  IF jsonb_typeof(input_value.entities)<>'array' OR jsonb_typeof(input_value.evidence)<>'array' OR jsonb_array_length(input_value.entities)<>jsonb_array_length(input_value.evidence) OR NOT zasp_inventory_validate_typed_entities(input_value.source,input_value.entities)
   OR EXISTS(SELECT 1 FROM jsonb_to_recordset(input_value.entities) entity_value(id text,evidence_id text) LEFT JOIN jsonb_to_recordset(input_value.evidence) evidence_value(id text,entity_id text) ON (evidence_value.id,evidence_value.entity_id)=(entity_value.evidence_id,entity_value.id) WHERE evidence_value.id IS NULL)
  THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='legacy inventory lacks typed snapshot';END IF;
  UPDATE zasp_inventory_evidence stored SET source=input_value.source,generation=input_value.generation,artifact_reference=typed.artifact_reference,artifact_key=typed.artifact_key,artifact_version_id=typed.artifact_version_id,size_bytes=typed.size_bytes,tool_version=typed.tool_version
  FROM jsonb_to_recordset(input_value.evidence) typed(id text,artifact_reference text,artifact_key text,artifact_version_id text,size_bytes bigint,tool_version text)
  WHERE (stored.organization_id,stored.workspace_id,stored.environment_id,stored.integration_id,stored.snapshot_id,stored.id)=(organization_value,workspace_value,environment_value,input_value.integration_id,input_value.snapshot_id,typed.id);
  GET DIAGNOSTICS updated_count=ROW_COUNT;IF updated_count<>jsonb_array_length(input_value.evidence) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='legacy evidence authority incomplete';END IF;
  UPDATE zasp_inventory_source_observations stored SET provider=input_value.source,source_kind=typed.kind,display_name=typed.display_name,stable_fields=typed.stable_fields,identity_namespace=typed.identity_namespace,product_kind=typed.product_kind,generation=input_value.generation,content_digest=input_value.candidate_digest,evidence_id=typed.evidence_id,confidence_basis_points=typed.confidence_basis_points,observed_at=typed.observed_at,fresh_until=typed.fresh_until,identity_rule_version=typed.identity_rule_version,identity_priority=typed.identity_priority,source_projection_version=typed.source_projection_version,last_seen_at=typed.observed_at
  FROM jsonb_to_recordset(input_value.entities) typed(id text,kind text,display_name text,stable_fields jsonb,identity_namespace text,product_kind text,evidence_id text,confidence_basis_points integer,observed_at timestamptz,fresh_until timestamptz,identity_rule_version integer,identity_priority integer,source_projection_version integer)
  WHERE (stored.organization_id,stored.workspace_id,stored.environment_id,stored.integration_id,stored.source,stored.snapshot_id,stored.entity_id,stored.source_state)=(organization_value,workspace_value,environment_value,input_value.integration_id,input_value.source,input_value.snapshot_id,typed.id,'present');
  GET DIAGNOSTICS updated_count=ROW_COUNT;IF updated_count<>jsonb_array_length(input_value.entities) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='legacy observation authority incomplete';END IF;
  IF NOT zasp_inventory_bind_typed_entities(organization_value,workspace_value,environment_value,input_value.source,input_value.source,input_value.entities) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='legacy identity binding conflict';END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM zasp_inventory_source_observations observation WHERE (observation.organization_id,observation.workspace_id,observation.environment_id,observation.source_state)=(organization_value,workspace_value,environment_value,'present') AND (observation.provider IS NULL OR observation.product_kind IS NULL OR observation.content_digest IS NULL OR observation.evidence_id IS NULL OR observation.observed_at IS NULL OR observation.fresh_until IS NULL)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='legacy inventory lacks typed snapshot';END IF;
 WITH present AS (SELECT observation.*,row_number() OVER(PARTITION BY observation.entity_id ORDER BY observation.identity_priority,observation.integration_id,observation.provider,observation.source,observation.identity_namespace,observation.source_native_id) rank_value,min(observation.first_seen_at) OVER(PARTITION BY observation.entity_id) minimum_seen,max(observation.last_seen_at) OVER(PARTITION BY observation.entity_id) maximum_seen FROM zasp_inventory_source_observations observation WHERE (observation.organization_id,observation.workspace_id,observation.environment_id,observation.source_state)=(organization_value,workspace_value,environment_value,'present')),winner AS (SELECT * FROM present WHERE rank_value=1)
 UPDATE zasp_inventory_entities entity_value SET kind=winner.product_kind,display_name=winner.display_name,stable_fields=winner.stable_fields,state='active',first_seen_at=winner.minimum_seen,last_seen_at=winner.maximum_seen,tombstoned_at=NULL,product_kind=winner.product_kind,confidence_basis_points=winner.confidence_basis_points,winning_evidence_id=winner.evidence_id,winning_snapshot_id=winner.snapshot_id,winning_generation=winner.generation,observed_at=winner.observed_at,fresh_until=winner.fresh_until,projection_version=winner.source_projection_version,winning_integration_id=winner.integration_id,winning_provider=winner.provider,winning_source=winner.source,winning_source_native_id=winner.source_native_id,winning_identity_rule=winner.identity_rule_version,winning_source_projection=winner.source_projection_version FROM winner WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id)=(organization_value,workspace_value,environment_value,winner.entity_id);
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['agents','tools','identities','runtimes']) operation_value CROSS JOIN LATERAL (SELECT zasp_core_read(operation_value,organization_value,workspace_value,environment_value) payload) legacy WHERE legacy.payload IS NOT NULL AND jsonb_typeof(legacy.payload->'items')<>'array') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='legacy annotation payload malformed';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',candidate.id,'owner',candidate.owner_value,'team',candidate.team_value,'tags',candidate.tags) ORDER BY candidate.id),'[]'::jsonb) INTO annotation_items FROM (
  SELECT item.id,min(item.owner) owner_value,min(item.team) team_value,(array_agg(item.tags ORDER BY item.tags::text))[1] tags FROM unnest(ARRAY['agents','tools','identities','runtimes']) operation_value CROSS JOIN LATERAL (SELECT zasp_core_read(operation_value,organization_value,workspace_value,environment_value) payload) legacy CROSS JOIN LATERAL jsonb_to_recordset(COALESCE(legacy.payload->'items','[]'::jsonb)) item(id text,owner text,team text,tags jsonb)
  WHERE EXISTS(SELECT 1 FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id)=(organization_value,workspace_value,environment_value,item.id))
  GROUP BY item.id HAVING count(DISTINCT jsonb_build_object('owner',item.owner,'team',item.team,'tags',item.tags))=1
 ) candidate;
 IF NOT zasp_inventory_import_annotations(organization_value,workspace_value,environment_value,annotation_items) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='legacy annotation conflict';END IF;
 RETURN zasp_inventory_advance_scope(organization_value,workspace_value,environment_value,'backfilled',NULL,NULL);
END $$;

CREATE FUNCTION public.zasp_inventory_annotation_value(organization_value text,workspace_value text,environment_value text,entity_value text) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT COALESCE((SELECT jsonb_build_object('owner',annotation.owner_value,'team',annotation.team_value,'tags',annotation.tags) FROM zasp_inventory_annotations annotation WHERE (annotation.organization_id,annotation.workspace_id,annotation.environment_id,annotation.entity_id)=(organization_value,workspace_value,environment_value,entity_value)),jsonb_build_object('owner','','team','','tags','[]'::jsonb))
$$;

CREATE FUNCTION public.zasp_inventory_page(organization_value text,workspace_value text,environment_value text,kind_value text,after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE result_value jsonb;
BEGIN
 IF kind_value NOT IN('asset','agent','tool','identity','runtime') OR limit_value NOT BETWEEN 1 AND 100 OR after_value IS NOT NULL AND NOT zasp_valid_product_id(after_value) OR zasp_inventory_scope_state(organization_value,workspace_value,environment_value)->>'phase'<>'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed inventory page';END IF;
 IF EXISTS(WITH page_entities AS (SELECT * FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,'active',kind_value) AND (after_value IS NULL OR entity_value.id>after_value) ORDER BY entity_value.id LIMIT limit_value+1) SELECT 1 FROM page_entities entity_value LEFT JOIN zasp_inventory_source_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.provider,observation.source,observation.entity_id,observation.source_native_id,observation.snapshot_id,observation.generation,observation.evidence_id,observation.source_state)=(entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.winning_integration_id,entity_value.winning_provider,entity_value.winning_source,entity_value.id,entity_value.winning_source_native_id,entity_value.winning_snapshot_id,entity_value.winning_generation,entity_value.winning_evidence_id,'present') LEFT JOIN zasp_discovery_snapshots snapshot_value ON (snapshot_value.organization_id,snapshot_value.workspace_id,snapshot_value.environment_id,snapshot_value.integration_id,snapshot_value.source,snapshot_value.id,snapshot_value.state,snapshot_value.complete,snapshot_value.is_last_good)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.source,observation.snapshot_id,'complete',true,true) LEFT JOIN zasp_inventory_evidence evidence_value ON (evidence_value.organization_id,evidence_value.workspace_id,evidence_value.environment_id,evidence_value.id,evidence_value.integration_id,evidence_value.snapshot_id,evidence_value.entity_id,evidence_value.source,evidence_value.generation)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.evidence_id,observation.integration_id,observation.snapshot_id,observation.entity_id,observation.source,observation.generation) WHERE observation.entity_id IS NULL OR snapshot_value.id IS NULL OR evidence_value.id IS NULL) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory authority unavailable';END IF;
 WITH candidates AS (
  SELECT entity_value.*,zasp_inventory_annotation_value(organization_value,workspace_value,environment_value,entity_value.id) annotation_value FROM zasp_inventory_entities entity_value
  WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,'active',kind_value) AND (after_value IS NULL OR entity_value.id>after_value) ORDER BY entity_value.id LIMIT limit_value+1
 ),visible AS (SELECT * FROM candidates ORDER BY id LIMIT limit_value)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('id',id,'name',display_name,'kind',product_kind,'owner',annotation_value->>'owner','team',annotation_value->>'team','tags',annotation_value->'tags','evidence_id',winning_evidence_id,'confidence_basis_points',confidence_basis_points,'first_seen',rtrim(rtrim(to_char(first_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','last_seen',rtrim(rtrim(to_char(last_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','observed_at',rtrim(rtrim(to_char(observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','fresh_until',rtrim(rtrim(to_char(fresh_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','freshness_state',CASE WHEN fresh_until>statement_timestamp() THEN 'fresh' ELSE 'stale' END,'version',version) ORDER BY id),'[]'::jsonb),'next_id',CASE WHEN (SELECT count(*) FROM candidates)>limit_value THEN (SELECT id FROM visible ORDER BY id DESC LIMIT 1) ELSE NULL END) INTO result_value FROM visible;
 RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_inventory_detail(organization_value text,workspace_value text,environment_value text,id_value text,kind_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE result_value jsonb;summary_value jsonb;sources_value jsonb;evidence_value jsonb;entity_record zasp_inventory_entities%ROWTYPE;annotation_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(id_value) OR kind_value NOT IN('asset','agent','tool','identity','runtime') OR zasp_inventory_scope_state(organization_value,workspace_value,environment_value)->>'phase'<>'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed inventory detail';END IF;
 SELECT * INTO entity_record FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,id_value,'active',kind_value);IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='typed inventory missing';END IF;
 SELECT zasp_inventory_annotation_value(organization_value,workspace_value,environment_value,id_value) INTO annotation_value;
 SELECT jsonb_build_object('id',entity_record.id,'name',entity_record.display_name,'kind',entity_record.product_kind,'owner',annotation_value->>'owner','team',annotation_value->>'team','tags',annotation_value->'tags','evidence_id',entity_record.winning_evidence_id,'confidence_basis_points',entity_record.confidence_basis_points,'first_seen',rtrim(rtrim(to_char(entity_record.first_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','last_seen',rtrim(rtrim(to_char(entity_record.last_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','observed_at',rtrim(rtrim(to_char(entity_record.observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','fresh_until',rtrim(rtrim(to_char(entity_record.fresh_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','freshness_state',CASE WHEN entity_record.fresh_until>statement_timestamp() THEN 'fresh' ELSE 'stale' END,'version',entity_record.version) INTO summary_value;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('integration_id',observation.integration_id,'provider',observation.provider,'source',observation.source,'source_identifier','sha256:'||encode(digest(convert_to(concat_ws(chr(31),observation.provider,observation.identity_namespace,observation.source_native_id),'UTF8'),'sha256'),'hex'),'snapshot_id',observation.snapshot_id,'generation',observation.generation,'evidence_id',observation.evidence_id,'confidence_basis_points',observation.confidence_basis_points,'observed_at',rtrim(rtrim(to_char(observation.observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','fresh_until',rtrim(rtrim(to_char(observation.fresh_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','projection_version',observation.source_projection_version,'winning',(observation.integration_id,observation.provider,observation.source,observation.source_native_id,observation.snapshot_id,observation.generation,observation.evidence_id)=(entity_record.winning_integration_id,entity_record.winning_provider,entity_record.winning_source,entity_record.winning_source_native_id,entity_record.winning_snapshot_id,entity_record.winning_generation,entity_record.winning_evidence_id)) ORDER BY observation.integration_id,observation.provider,observation.source,observation.source_native_id),'[]'::jsonb),COALESCE(jsonb_agg(DISTINCT jsonb_build_object('id',evidence.id,'checksum','sha256:'||encode(evidence.checksum,'hex'),'media_type',evidence.media_type,'schema_version',evidence.schema_version,'parser_version',evidence.parser_version,'tool_version',evidence.tool_version,'collected_at',rtrim(rtrim(to_char(evidence.collected_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z','size_bytes',evidence.size_bytes)),'[]'::jsonb)
 INTO sources_value,evidence_value FROM zasp_inventory_source_observations observation JOIN zasp_discovery_snapshots snapshot_value ON (snapshot_value.organization_id,snapshot_value.workspace_id,snapshot_value.environment_id,snapshot_value.integration_id,snapshot_value.source,snapshot_value.id,snapshot_value.state,snapshot_value.complete,snapshot_value.is_last_good)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.source,observation.snapshot_id,'complete',true,true) JOIN zasp_inventory_evidence evidence ON (evidence.organization_id,evidence.workspace_id,evidence.environment_id,evidence.id,evidence.integration_id,evidence.snapshot_id,evidence.entity_id,evidence.source,evidence.generation)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.evidence_id,observation.integration_id,observation.snapshot_id,observation.entity_id,observation.source,observation.generation) WHERE (observation.organization_id,observation.workspace_id,observation.environment_id,observation.entity_id,observation.source_state)=(organization_value,workspace_value,environment_value,id_value,'present');
 IF jsonb_array_length(sources_value) NOT BETWEEN 1 AND 64 OR jsonb_array_length(evidence_value) NOT BETWEEN 1 AND 64 OR (SELECT count(*) FROM jsonb_array_elements(sources_value) source_item WHERE (source_item->>'winning')::boolean)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory detail authority unavailable';END IF;
 result_value:=jsonb_build_object('summary',summary_value,'sources',sources_value,'evidence',evidence_value);RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_inventory_agent_capabilities_page(organization_value text,workspace_value text,environment_value text,agent_value text,after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
BEGIN
 IF NOT zasp_valid_product_id(agent_value) OR after_value IS NOT NULL OR limit_value NOT BETWEEN 1 AND 100 OR zasp_inventory_scope_state(organization_value,workspace_value,environment_value)->>'phase'<>'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed capability page';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,agent_value,'active','agent')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='typed agent missing';END IF;
 RETURN jsonb_build_object('items','[]'::jsonb,'next_key',NULL);
END $$;

CREATE FUNCTION public.zasp_inventory_agent_relationships_page(organization_value text,workspace_value text,environment_value text,agent_value text,after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE result_value jsonb;
BEGIN
 IF NOT zasp_valid_product_id(agent_value) OR after_value IS NOT NULL AND NOT zasp_valid_product_id(after_value) OR limit_value NOT BETWEEN 1 AND 100 OR zasp_inventory_scope_state(organization_value,workspace_value,environment_value)->>'phase'<>'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed relationship page';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,agent_value,'active','agent')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='typed agent missing';END IF;
 WITH candidates AS (SELECT relationship_value.id,relationship_value.from_entity_id,relationship_value.to_entity_id,relationship_value.kind,observation.evidence_id FROM zasp_inventory_relationships relationship_value JOIN zasp_inventory_entities source_entity ON (source_entity.organization_id,source_entity.workspace_id,source_entity.environment_id,source_entity.id,source_entity.state)=(relationship_value.organization_id,relationship_value.workspace_id,relationship_value.environment_id,relationship_value.from_entity_id,'active') JOIN zasp_inventory_entities target_entity ON (target_entity.organization_id,target_entity.workspace_id,target_entity.environment_id,target_entity.id,target_entity.state)=(relationship_value.organization_id,relationship_value.workspace_id,relationship_value.environment_id,relationship_value.to_entity_id,'active') JOIN zasp_inventory_source_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.source,observation.snapshot_id,observation.entity_id,observation.source_state)=(relationship_value.organization_id,relationship_value.workspace_id,relationship_value.environment_id,relationship_value.integration_id,relationship_value.source,relationship_value.snapshot_id,relationship_value.from_entity_id,'present') JOIN zasp_inventory_evidence evidence ON (evidence.organization_id,evidence.workspace_id,evidence.environment_id,evidence.id,evidence.integration_id,evidence.snapshot_id,evidence.entity_id,evidence.source,evidence.generation)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.evidence_id,observation.integration_id,observation.snapshot_id,observation.entity_id,observation.source,observation.generation) WHERE (relationship_value.organization_id,relationship_value.workspace_id,relationship_value.environment_id,relationship_value.state)=(organization_value,workspace_value,environment_value,'present') AND (relationship_value.from_entity_id=agent_value OR relationship_value.to_entity_id=agent_value) AND (after_value IS NULL OR relationship_value.id>after_value) ORDER BY relationship_value.id LIMIT limit_value+1),visible AS (SELECT * FROM candidates ORDER BY id LIMIT limit_value)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('id',id,'from_id',from_entity_id,'to_id',to_entity_id,'type',kind,'evidence_id',evidence_id) ORDER BY id),'[]'::jsonb),'next_key',CASE WHEN (SELECT count(*) FROM candidates)>limit_value THEN (SELECT id FROM visible ORDER BY id DESC LIMIT 1) ELSE NULL END) INTO result_value FROM visible;RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_inventory_agent_sessions_page(organization_value text,workspace_value text,environment_value text,agent_value text,after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
BEGIN
 IF NOT zasp_valid_product_id(agent_value) OR after_value IS NOT NULL OR limit_value NOT BETWEEN 1 AND 100 OR zasp_inventory_scope_state(organization_value,workspace_value,environment_value)->>'phase'<>'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed session page';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,agent_value,'active','agent')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='typed agent missing';END IF;
 RETURN jsonb_build_object('items','[]'::jsonb,'next_key',NULL);
END $$;

CREATE FUNCTION public.zasp_inventory_home_summary(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE agent_count_value bigint;high_risk_value bigint;
BEGIN
 IF zasp_inventory_scope_state(organization_value,workspace_value,environment_value)->>'phase'<>'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='typed inventory scope unavailable';END IF;
 SELECT count(*) INTO agent_count_value FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,'active','agent');
 SELECT count(*) INTO high_risk_value FROM zasp_risk_attack_paths path_value WHERE (path_value.organization_id,path_value.workspace_id,path_value.environment_id)=(organization_value,workspace_value,environment_value) AND path_value.state IN('observed','verified');
 RETURN jsonb_build_object('agent_count',agent_count_value,'high_risk_paths',high_risk_value,'verified_changes',0,'blocked_changes',0,'pending_approvals',0,'oldest_approval_age_seconds',0,'needs_human_runs',0,'failed_runs',0,'inconclusive_runs',0,'recent_contained',0,'recent_remediated',0,'healthy',high_risk_value=0,'attention_required',high_risk_value>0);
END $$;

CREATE FUNCTION public.zasp_inventory_compat_read(operation_value text,organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE result_value jsonb;id_value text;kind_value text;annotation_value jsonb;
BEGIN
 IF operation_value IN('agents','tools','identities','runtimes') THEN
  kind_value:=CASE operation_value WHEN 'agents' THEN 'agent' WHEN 'tools' THEN 'tool' WHEN 'identities' THEN 'identity' ELSE 'runtime' END;
  SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('id',entity_value.id,'name',entity_value.display_name,'kind',entity_value.product_kind,'owner',annotation.annotation_value->>'owner','team',annotation.annotation_value->>'team','tags',annotation.annotation_value->'tags','evidence_id',entity_value.winning_evidence_id,'first_seen',to_char(entity_value.first_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'last_seen',to_char(entity_value.last_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) ORDER BY entity_value.id),'[]'::jsonb)) INTO result_value FROM zasp_inventory_entities entity_value CROSS JOIN LATERAL (SELECT zasp_inventory_annotation_value(organization_value,workspace_value,environment_value,entity_value.id) annotation_value) annotation
  WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,'active',kind_value);
  RETURN result_value;
 END IF;
 IF operation_value ~ '^(agent|tool|identity|runtime|asset):pid_[0-9a-f-]{36}$' THEN
  kind_value:=split_part(operation_value,':',1);id_value:=split_part(operation_value,':',2);
  IF NOT zasp_valid_product_id(id_value) THEN RETURN NULL;END IF;
  SELECT zasp_inventory_annotation_value(organization_value,workspace_value,environment_value,entity_value.id) INTO annotation_value FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,id_value,'active',kind_value);
  IF NOT FOUND THEN RETURN NULL;END IF;
  SELECT jsonb_build_object('id',entity_value.id,'name',entity_value.display_name,'kind',entity_value.product_kind,'owner',annotation_value->>'owner','team',annotation_value->>'team','tags',annotation_value->'tags','evidence_id',entity_value.winning_evidence_id,'first_seen',to_char(entity_value.first_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'last_seen',to_char(entity_value.last_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) INTO result_value FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id)=(organization_value,workspace_value,environment_value,id_value);
  RETURN result_value;
 END IF;
 IF operation_value ~ '^agent_(capabilities|sessions):pid_[0-9a-f-]{36}$' THEN RETURN jsonb_build_object('items','[]'::jsonb);END IF;
 IF operation_value ~ '^agent_relationships:pid_[0-9a-f-]{36}$' THEN
  id_value:=split_part(operation_value,':',2);IF NOT zasp_valid_product_id(id_value) THEN RETURN NULL;END IF;
  SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('from_id',relationship_value.from_entity_id,'to_id',relationship_value.to_entity_id,'type',relationship_value.kind,'evidence_id',entity_value.winning_evidence_id) ORDER BY relationship_value.id),'[]'::jsonb)) INTO result_value FROM zasp_inventory_relationships relationship_value JOIN zasp_inventory_entities entity_value ON (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.state)=(relationship_value.organization_id,relationship_value.workspace_id,relationship_value.environment_id,relationship_value.from_entity_id,'active') WHERE (relationship_value.organization_id,relationship_value.workspace_id,relationship_value.environment_id,relationship_value.state)=(organization_value,workspace_value,environment_value,'present') AND (relationship_value.from_entity_id=id_value OR relationship_value.to_entity_id=id_value);
  RETURN result_value;
 END IF;
 IF operation_value='home' THEN
  SELECT jsonb_build_object('agent_count',(SELECT count(*) FROM zasp_inventory_entities entity_value WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,'active','agent')),'high_risk_paths',(SELECT count(*) FROM zasp_risk_attack_paths path_value WHERE (path_value.organization_id,path_value.workspace_id,path_value.environment_id)=(organization_value,workspace_value,environment_value) AND path_value.state IN('observed','verified')),'verified_changes',0,'blocked_changes',0,'pending_approvals',0,'oldest_approval_age_seconds',0,'needs_human_runs',0,'failed_runs',0,'inconclusive_runs',0,'recent_contained',0,'recent_remediated',0,'healthy',true,'attention_required',false) INTO result_value;
  RETURN result_value;
 END IF;
 RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public.zasp_core_read(operation text,organization_id text,workspace_id text,environment_id text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $$
DECLARE phase_value text;result_value jsonb;
BEGIN
 IF zasp_core_read.operation='__inventory_operations__' THEN
  SELECT COALESCE(jsonb_object_agg(payload.operation,payload.payload ORDER BY payload.operation),'{}'::jsonb) INTO result_value FROM zasp_core_payloads payload WHERE (payload.organization_id,payload.workspace_id,payload.environment_id)=(zasp_core_read.organization_id,zasp_core_read.workspace_id,zasp_core_read.environment_id) AND (payload.operation IN('home','agents','tools','identities','runtimes') OR payload.operation ~ '^(agent|tool|identity|runtime|asset):pid_[0-9a-f-]{36}$' OR payload.operation ~ '^agent_(capabilities|relationships|sessions):pid_[0-9a-f-]{36}$');RETURN result_value;
 END IF;
 phase_value:=zasp_inventory_scope_state(zasp_core_read.organization_id,zasp_core_read.workspace_id,zasp_core_read.environment_id)->>'phase';
 IF phase_value='cutover' AND (zasp_core_read.operation IN('home','agents','tools','identities','runtimes') OR zasp_core_read.operation ~ '^(agent|tool|identity|runtime|asset):pid_[0-9a-f-]{36}$' OR zasp_core_read.operation ~ '^agent_(capabilities|relationships|sessions):pid_[0-9a-f-]{36}$') THEN RETURN zasp_inventory_compat_read(zasp_core_read.operation,zasp_core_read.organization_id,zasp_core_read.workspace_id,zasp_core_read.environment_id);END IF;
 SELECT payload.payload INTO result_value FROM zasp_core_payloads payload WHERE (payload.organization_id,payload.workspace_id,payload.environment_id,payload.operation)=(zasp_core_read.organization_id,zasp_core_read.workspace_id,zasp_core_read.environment_id,zasp_core_read.operation);RETURN result_value;
END $$;

CREATE FUNCTION public.zasp_core_inventory_cutover(organization_value text,workspace_value text,environment_value text,expected_digest bytea) RETURNS integer LANGUAGE plpgsql AS $$
DECLARE current_digest bytea;deleted_count integer;
BEGIN
 SELECT digest(convert_to(COALESCE(jsonb_object_agg(payload.operation,payload.payload ORDER BY payload.operation),'{}'::jsonb)::text,'UTF8'),'sha256') INTO current_digest FROM zasp_core_payloads payload WHERE (payload.organization_id,payload.workspace_id,payload.environment_id)=(organization_value,workspace_value,environment_value) AND (payload.operation IN('home','agents','tools','identities','runtimes') OR payload.operation ~ '^(agent|tool|identity|runtime|asset):pid_[0-9a-f-]{36}$' OR payload.operation ~ '^agent_(capabilities|relationships|sessions):pid_[0-9a-f-]{36}$');
 IF current_digest<>expected_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='legacy inventory changed during cutover';END IF;
 DELETE FROM zasp_core_payloads payload WHERE (payload.organization_id,payload.workspace_id,payload.environment_id)=(organization_value,workspace_value,environment_value) AND (payload.operation IN('home','agents','tools','identities','runtimes') OR payload.operation ~ '^(agent|tool|identity|runtime|asset):pid_[0-9a-f-]{36}$' OR payload.operation ~ '^agent_(capabilities|relationships|sessions):pid_[0-9a-f-]{36}$');GET DIAGNOSTICS deleted_count=ROW_COUNT;RETURN deleted_count;
END $$;

CREATE FUNCTION public.zasp_core_inventory_write_fence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE operation_value text:=CASE WHEN TG_OP='DELETE' THEN OLD.operation ELSE NEW.operation END;organization_value text:=CASE WHEN TG_OP='DELETE' THEN OLD.organization_id ELSE NEW.organization_id END;workspace_value text:=CASE WHEN TG_OP='DELETE' THEN OLD.workspace_id ELSE NEW.workspace_id END;environment_value text:=CASE WHEN TG_OP='DELETE' THEN OLD.environment_id ELSE NEW.environment_id END;
BEGIN
 IF operation_value IN('home','agents','tools','identities','runtimes') OR operation_value ~ '^(agent|tool|identity|runtime|asset):pid_[0-9a-f-]{36}$' OR operation_value ~ '^agent_(capabilities|relationships|sessions):pid_[0-9a-f-]{36}$' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-inventory-cutover',organization_value,workspace_value,environment_value),0));
  IF zasp_inventory_scope_state(organization_value,workspace_value,environment_value)->>'phase'='cutover' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory cutover write fence';END IF;
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;

CREATE TRIGGER zasp_core_inventory_write_fence BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_core_payloads FOR EACH ROW EXECUTE FUNCTION public.zasp_core_inventory_write_fence();

CREATE FUNCTION public.zasp_inventory_equivalence_scope(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE state_value jsonb;legacy_value jsonb;typed_value jsonb;legacy_digest_value bytea;typed_digest_value bytea;operation_value text;payload_value jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-inventory-cutover',organization_value,workspace_value,environment_value),0));state_value:=zasp_inventory_scope_state(organization_value,workspace_value,environment_value);IF state_value IS NULL OR state_value->>'phase' NOT IN('backfilled','equivalent') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='inventory equivalence phase conflict';END IF;
 legacy_value:=zasp_core_read('__inventory_operations__',organization_value,workspace_value,environment_value);typed_value:='{}'::jsonb;
 FOR operation_value,payload_value IN SELECT key,value FROM jsonb_each(legacy_value) ORDER BY key LOOP typed_value:=typed_value||jsonb_build_object(operation_value,zasp_inventory_compat_read(operation_value,organization_value,workspace_value,environment_value));END LOOP;
 legacy_digest_value:=digest(convert_to(legacy_value::text,'UTF8'),'sha256');typed_digest_value:=digest(convert_to(typed_value::text,'UTF8'),'sha256');IF legacy_value<>typed_value OR legacy_digest_value<>typed_digest_value THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory equivalence failed';END IF;
 IF state_value->>'phase'='equivalent' THEN IF decode(substring(state_value->>'legacy_digest' FROM 3),'hex')<>legacy_digest_value OR decode(substring(state_value->>'typed_digest' FROM 3),'hex')<>typed_digest_value THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory equivalence drift';END IF;RETURN state_value;END IF;
 RETURN zasp_inventory_advance_scope(organization_value,workspace_value,environment_value,'equivalent',legacy_digest_value,typed_digest_value);
END $$;

CREATE FUNCTION public.zasp_inventory_cutover_scope(organization_value text,workspace_value text,environment_value text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE state_value jsonb;legacy_digest_value bytea;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-inventory-cutover',organization_value,workspace_value,environment_value),0));state_value:=zasp_inventory_equivalence_scope(organization_value,workspace_value,environment_value);legacy_digest_value:=decode(substring(state_value->>'legacy_digest' FROM 3),'hex');PERFORM zasp_core_inventory_cutover(organization_value,workspace_value,environment_value,legacy_digest_value);RETURN zasp_inventory_advance_scope(organization_value,workspace_value,environment_value,'cutover',legacy_digest_value,legacy_digest_value);
END $$;

CREATE OR REPLACE FUNCTION public.zasp_discovery_apply_snapshot(organization_id text,workspace_id text,environment_id text,integration_id text,sync_id text,snapshot_id text,generation bigint,source text,manifest_reference text,manifest_checksum bytea,collected_at timestamptz,cursor_provider text,cursor_value text,entities jsonb,relationships jsonb,evidence jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $$
#variable_conflict use_column
DECLARE applied_discovered_count integer;applied_changed_count integer;applied_removed_count integer;committed timestamptz:=transaction_timestamp();requested_digest bytea;prior_digest bytea;prior_result jsonb;
BEGIN
 IF source<>cursor_provider OR source NOT IN('aws','kubernetes','github','okta') OR jsonb_typeof(entities)<>'array' OR jsonb_typeof(relationships)<>'array' OR jsonb_typeof(evidence)<>'array' OR jsonb_array_length(entities)>1000 OR jsonb_array_length(relationships)>2000 OR jsonb_array_length(evidence)>1000 OR jsonb_array_length(evidence)<>jsonb_array_length(entities) OR octet_length(manifest_checksum)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed complete snapshot';END IF;
 requested_digest:=digest(convert_to(jsonb_build_object('integration_id',$4,'sync_id',$5,'snapshot_id',$6,'generation',$7,'source',$8,'manifest_reference',$9,'manifest_checksum',encode($10,'hex'),'collected_at_epoch_us',floor(extract(epoch FROM $11)*1000000)::bigint,'cursor_provider',$12,'cursor_value',$13,'entities',$14,'relationships',$15,'evidence',$16)::text,'UTF8'),'sha256');
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-inventory-cutover',$1,$2,$3),0));PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4,$8),0));
 SELECT candidate_digest,apply_result INTO prior_digest,prior_result FROM zasp_discovery_snapshots snapshot WHERE (snapshot.organization_id,snapshot.workspace_id,snapshot.environment_id,snapshot.integration_id,snapshot.id)=($1,$2,$3,$4,$6);
 IF FOUND THEN IF prior_digest<>requested_digest OR prior_result IS NULL THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='snapshot replay conflict';END IF;RETURN prior_result;END IF;
 IF EXISTS(SELECT 1 FROM zasp_discovery_snapshots snapshot WHERE (snapshot.organization_id,snapshot.workspace_id,snapshot.environment_id,snapshot.integration_id,snapshot.source)=($1,$2,$3,$4,$8) AND snapshot.is_last_good AND snapshot.generation >= $7) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='stale snapshot generation';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_discovery_syncs sync_value WHERE (sync_value.organization_id,sync_value.workspace_id,sync_value.environment_id,sync_value.integration_id,sync_value.id)=($1,$2,$3,$4,$5) AND sync_value.state IN('queued','running')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='sync missing';END IF;
 IF $11 IS NULL OR $11<>date_trunc('second',$11) OR EXISTS(SELECT 1 FROM zasp_discovery_generation_reservations reservation WHERE (reservation.organization_id,reservation.workspace_id,reservation.environment_id,reservation.sync_id)=($1,$2,$3,$5)) AND NOT EXISTS(SELECT 1 FROM zasp_discovery_generation_reservations reservation WHERE (reservation.organization_id,reservation.workspace_id,reservation.environment_id,reservation.sync_id,reservation.integration_id,reservation.source,reservation.generation,reservation.snapshot_id)=($1,$2,$3,$5,$4,$8,$7,$6) AND date_trunc('second',reservation.reserved_at)=$11) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='typed observation authority conflict';END IF;

 IF EXISTS(SELECT 1 FROM jsonb_array_elements(entities) item WHERE jsonb_typeof(item)<>'object' OR NOT item ?& ARRAY['id','kind','source_native_id','display_name','stable_fields','attributes','identity_namespace','identity_rule_version','identity_priority','product_kind','confidence_basis_points','observed_at','fresh_until','evidence_id','source_projection_version'] OR item-ARRAY['id','kind','source_native_id','display_name','stable_fields','attributes','identity_namespace','identity_rule_version','identity_priority','product_kind','confidence_basis_points','observed_at','fresh_until','evidence_id','source_projection_version']<>'{}'::jsonb)
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(relationships) item WHERE jsonb_typeof(item)<>'object' OR NOT item ?& ARRAY['id','kind','source_native_id','from_entity_id','to_entity_id','attributes'] OR item-ARRAY['id','kind','source_native_id','from_entity_id','to_entity_id','attributes']<>'{}'::jsonb)
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(evidence) item WHERE jsonb_typeof(item)<>'object' OR NOT item ?& ARRAY['id','entity_id','object_reference','artifact_reference','artifact_key','artifact_version_id','checksum_hex','size_bytes','media_type','schema_version','parser_version','tool_version'] OR item-ARRAY['id','entity_id','object_reference','artifact_reference','artifact_key','artifact_version_id','checksum_hex','size_bytes','media_type','schema_version','parser_version','tool_version']<>'{}'::jsonb)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed snapshot shape';END IF;

 IF EXISTS(
  SELECT 1 FROM jsonb_to_recordset(entities) entity_value(id text,kind text,source_native_id text,display_name text,stable_fields jsonb,attributes jsonb,evidence_id text,observed_at timestamptz)
  WHERE NOT zasp_valid_product_id(entity_value.id) OR entity_value.kind !~ '^[a-z][a-z0-9_]{1,63}$' OR length(entity_value.source_native_id) NOT BETWEEN 1 AND 1024 OR length(entity_value.display_name) NOT BETWEEN 1 AND 256 OR jsonb_typeof(entity_value.stable_fields)<>'object' OR octet_length(entity_value.stable_fields::text)>65536 OR jsonb_typeof(entity_value.attributes)<>'object' OR octet_length(entity_value.attributes::text)>65536 OR NOT zasp_valid_product_id(entity_value.evidence_id) OR entity_value.observed_at<>$11
 ) OR EXISTS(SELECT id FROM jsonb_to_recordset(entities) entity_value(id text) GROUP BY id HAVING count(*)>1)
 OR EXISTS(SELECT source_native_id FROM jsonb_to_recordset(entities) entity_value(source_native_id text) GROUP BY source_native_id HAVING count(*)>1)
 OR NOT zasp_inventory_validate_typed_entities(source,entities)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed entity';END IF;

 IF EXISTS(
  SELECT 1 FROM jsonb_to_recordset(evidence) evidence_value(id text,entity_id text,object_reference text,artifact_reference text,artifact_key text,artifact_version_id text,checksum_hex text,size_bytes bigint,media_type text,schema_version text,parser_version text,tool_version text)
  LEFT JOIN jsonb_to_recordset(entities) entity_value(id text,evidence_id text) ON (entity_value.id,entity_value.evidence_id)=(evidence_value.entity_id,evidence_value.id)
  WHERE entity_value.id IS NULL OR NOT zasp_valid_product_id(evidence_value.id) OR NOT zasp_valid_product_id(evidence_value.artifact_reference) OR NOT zasp_discovery_s3_object_reference(evidence_value.object_reference) OR substring(evidence_value.object_reference FROM '^s3://[a-z0-9][a-z0-9.-]{2,62}/(.+)$') IS DISTINCT FROM evidence_value.artifact_key OR length(evidence_value.artifact_key) NOT BETWEEN 1 AND 2048 OR length(evidence_value.artifact_version_id) NOT BETWEEN 1 AND 1024 OR evidence_value.artifact_version_id ~ '[[:space:][:cntrl:]]' OR evidence_value.checksum_hex !~ '^[0-9a-f]{64}$' OR evidence_value.size_bytes NOT BETWEEN 1 AND 536870912 OR length(evidence_value.media_type) NOT BETWEEN 1 AND 128 OR evidence_value.media_type !~ '^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$' OR evidence_value.schema_version !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' OR evidence_value.parser_version !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' OR evidence_value.tool_version !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' OR (evidence_value.parser_version,evidence_value.tool_version)<>(SELECT sync_value.parser_version,sync_value.tool_version FROM zasp_discovery_syncs sync_value WHERE (sync_value.organization_id,sync_value.workspace_id,sync_value.environment_id,sync_value.id)=($1,$2,$3,$5))
 ) OR EXISTS(SELECT id FROM jsonb_to_recordset(evidence) evidence_value(id text) GROUP BY id HAVING count(*)>1)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed evidence';END IF;

 IF EXISTS(
  SELECT 1 FROM jsonb_to_recordset(relationships) relationship_value(id text,kind text,source_native_id text,from_entity_id text,to_entity_id text,attributes jsonb)
  LEFT JOIN jsonb_to_recordset(entities) from_entity(id text) ON from_entity.id=relationship_value.from_entity_id
  LEFT JOIN jsonb_to_recordset(entities) to_entity(id text) ON to_entity.id=relationship_value.to_entity_id
  WHERE NOT zasp_valid_product_id(relationship_value.id) OR relationship_value.kind !~ '^[a-z][a-z0-9_]{1,63}$' OR length(relationship_value.source_native_id) NOT BETWEEN 1 AND 1024 OR relationship_value.from_entity_id=relationship_value.to_entity_id OR from_entity.id IS NULL OR to_entity.id IS NULL OR jsonb_typeof(relationship_value.attributes)<>'object' OR octet_length(relationship_value.attributes::text)>65536
 ) OR EXISTS(SELECT id FROM jsonb_to_recordset(relationships) relationship_value(id text) GROUP BY id HAVING count(*)>1) OR EXISTS(SELECT source_native_id FROM jsonb_to_recordset(relationships) relationship_value(source_native_id text) GROUP BY source_native_id HAVING count(*)>1)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid typed relationship';END IF;

 WITH candidate AS (SELECT * FROM jsonb_to_recordset(entities) entity_value(id text,kind text,source_native_id text,display_name text,stable_fields jsonb,attributes jsonb,identity_namespace text,identity_rule_version integer,identity_priority integer,product_kind text,confidence_basis_points integer,observed_at timestamptz,fresh_until timestamptz,evidence_id text,source_projection_version integer))
 SELECT count(*) FILTER(WHERE current_entity.id IS NULL OR current_entity.state='tombstoned'),count(*) FILTER(WHERE current_entity.id IS NOT NULL AND current_entity.state='active' AND (observation.entity_id IS NULL OR observation.source_kind IS DISTINCT FROM candidate.kind OR observation.display_name IS DISTINCT FROM candidate.display_name OR observation.stable_fields IS DISTINCT FROM candidate.stable_fields OR observation.attributes IS DISTINCT FROM candidate.attributes OR observation.evidence_id IS DISTINCT FROM candidate.evidence_id OR observation.observed_at IS DISTINCT FROM candidate.observed_at OR observation.fresh_until IS DISTINCT FROM candidate.fresh_until))
 INTO applied_discovered_count,applied_changed_count FROM candidate
 LEFT JOIN zasp_inventory_entities current_entity ON (current_entity.organization_id,current_entity.workspace_id,current_entity.environment_id,current_entity.id)=($1,$2,$3,candidate.id)
 LEFT JOIN zasp_inventory_source_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.source,observation.entity_id)=($1,$2,$3,$4,$8,candidate.id) AND observation.source_state='present';

 INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,candidate_digest,state,complete,is_last_good,collected_at)
 VALUES($1,$2,$3,$6,$4,$5,$7,$8,$9,$10,requested_digest,'candidate',false,false,$11);

 WITH candidate AS (SELECT * FROM jsonb_to_recordset(entities) entity_value(id text,product_kind text,display_name text,stable_fields jsonb,observed_at timestamptz))
 INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,product_kind)
 SELECT $1,$2,$3,candidate.id,candidate.product_kind,candidate.display_name,candidate.stable_fields,'active',candidate.observed_at,candidate.observed_at,candidate.product_kind FROM candidate ON CONFLICT(organization_id,workspace_id,environment_id,id) DO NOTHING;

 IF NOT zasp_inventory_bind_typed_entities($1,$2,$3,$8,$8,entities) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='typed identity binding conflict';END IF;

 INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,finding_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
 SELECT $1,$2,$3,evidence_value.id,$4,$6,evidence_value.entity_id,NULL,evidence_value.object_reference,decode(evidence_value.checksum_hex,'hex'),evidence_value.media_type,evidence_value.schema_version,evidence_value.parser_version,$11,$8,$7,evidence_value.artifact_reference,evidence_value.artifact_key,evidence_value.artifact_version_id,evidence_value.size_bytes,evidence_value.tool_version
 FROM jsonb_to_recordset(evidence) evidence_value(id text,entity_id text,object_reference text,artifact_reference text,artifact_key text,artifact_version_id text,checksum_hex text,size_bytes bigint,media_type text,schema_version text,parser_version text,tool_version text);

 WITH candidate AS (SELECT * FROM jsonb_to_recordset(entities) entity_value(id text,kind text,source_native_id text,display_name text,stable_fields jsonb,attributes jsonb,identity_namespace text,identity_rule_version integer,identity_priority integer,product_kind text,confidence_basis_points integer,observed_at timestamptz,fresh_until timestamptz,evidence_id text,source_projection_version integer))
 INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version)
 SELECT $1,$2,$3,$4,$8,candidate.id,candidate.source_native_id,$6,'present',candidate.attributes,candidate.observed_at,candidate.observed_at,$8,candidate.kind,candidate.display_name,candidate.stable_fields,candidate.identity_namespace,candidate.product_kind,$7,requested_digest,candidate.evidence_id,candidate.confidence_basis_points,candidate.observed_at,candidate.fresh_until,candidate.identity_rule_version,candidate.identity_priority,candidate.source_projection_version FROM candidate
 ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,source,entity_id) DO UPDATE SET source_native_id=excluded.source_native_id,snapshot_id=$6,source_state='present',attributes=excluded.attributes,last_seen_at=excluded.observed_at,removed_at=NULL,provider=excluded.provider,source_kind=excluded.source_kind,display_name=excluded.display_name,stable_fields=excluded.stable_fields,identity_namespace=excluded.identity_namespace,product_kind=excluded.product_kind,generation=excluded.generation,content_digest=excluded.content_digest,evidence_id=excluded.evidence_id,confidence_basis_points=excluded.confidence_basis_points,observed_at=excluded.observed_at,fresh_until=excluded.fresh_until,identity_rule_version=excluded.identity_rule_version,identity_priority=excluded.identity_priority,source_projection_version=excluded.source_projection_version;

 UPDATE zasp_inventory_source_observations observation SET source_state='removed',removed_at=committed,last_seen_at=GREATEST(observation.last_seen_at,committed),snapshot_id=$6 WHERE (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.source)=($1,$2,$3,$4,$8) AND observation.source_state='present' AND NOT EXISTS(SELECT 1 FROM jsonb_to_recordset(entities) entity_value(id text) WHERE entity_value.id=observation.entity_id);
 GET DIAGNOSTICS applied_removed_count=ROW_COUNT;

 WITH present AS (
  SELECT observation.*,row_number() OVER(PARTITION BY observation.entity_id ORDER BY observation.identity_priority,observation.integration_id,observation.provider,observation.source,observation.identity_namespace,observation.source_native_id) rank_value,
   min(observation.first_seen_at) OVER(PARTITION BY observation.entity_id) minimum_seen,max(observation.last_seen_at) OVER(PARTITION BY observation.entity_id) maximum_seen
  FROM zasp_inventory_source_observations observation WHERE (observation.organization_id,observation.workspace_id,observation.environment_id)=($1,$2,$3) AND observation.source_state='present'
 ),winner AS (SELECT * FROM present WHERE rank_value=1)
 UPDATE zasp_inventory_entities entity_value SET
  version=entity_value.version+CASE WHEN (entity_value.kind,entity_value.display_name,entity_value.stable_fields,entity_value.state,entity_value.product_kind,entity_value.confidence_basis_points,entity_value.winning_evidence_id,entity_value.winning_snapshot_id,entity_value.winning_generation,entity_value.observed_at,entity_value.fresh_until,entity_value.projection_version,entity_value.winning_integration_id,entity_value.winning_provider,entity_value.winning_source,entity_value.winning_source_native_id,entity_value.winning_identity_rule,entity_value.winning_source_projection) IS DISTINCT FROM (winner.product_kind,winner.display_name,winner.stable_fields,'active',winner.product_kind,winner.confidence_basis_points,winner.evidence_id,winner.snapshot_id,winner.generation,winner.observed_at,winner.fresh_until,winner.source_projection_version,winner.integration_id,winner.provider,winner.source,winner.source_native_id,winner.identity_rule_version,winner.source_projection_version) THEN 1 ELSE 0 END,
  kind=winner.product_kind,display_name=winner.display_name,stable_fields=winner.stable_fields,state='active',first_seen_at=winner.minimum_seen,last_seen_at=winner.maximum_seen,tombstoned_at=NULL,product_kind=winner.product_kind,confidence_basis_points=winner.confidence_basis_points,winning_evidence_id=winner.evidence_id,winning_snapshot_id=winner.snapshot_id,winning_generation=winner.generation,observed_at=winner.observed_at,fresh_until=winner.fresh_until,projection_version=winner.source_projection_version,winning_integration_id=winner.integration_id,winning_provider=winner.provider,winning_source=winner.source,winning_source_native_id=winner.source_native_id,winning_identity_rule=winner.identity_rule_version,winning_source_projection=winner.source_projection_version,annotation_version=1
 FROM winner WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id)=($1,$2,$3,winner.entity_id);

 UPDATE zasp_inventory_entities entity_value SET state='tombstoned',tombstoned_at=committed,last_seen_at=GREATEST(entity_value.last_seen_at,committed),version=entity_value.version+1 WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id)=($1,$2,$3) AND entity_value.state='active' AND NOT EXISTS(SELECT 1 FROM zasp_inventory_source_observations observation WHERE (observation.organization_id,observation.workspace_id,observation.environment_id,observation.entity_id)=(entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id) AND observation.source_state='present');

 INSERT INTO zasp_inventory_relationships(organization_id,workspace_id,environment_id,id,integration_id,source,snapshot_id,from_entity_id,to_entity_id,kind,source_native_id,state,attributes,first_seen_at,last_seen_at)
 SELECT $1,$2,$3,relationship_value.id,$4,$8,$6,relationship_value.from_entity_id,relationship_value.to_entity_id,relationship_value.kind,relationship_value.source_native_id,'present',relationship_value.attributes,committed,committed FROM jsonb_to_recordset(relationships) relationship_value(id text,kind text,source_native_id text,from_entity_id text,to_entity_id text,attributes jsonb)
 ON CONFLICT(organization_id,workspace_id,environment_id,id) DO UPDATE SET snapshot_id=$6,from_entity_id=excluded.from_entity_id,to_entity_id=excluded.to_entity_id,kind=excluded.kind,state='present',attributes=excluded.attributes,last_seen_at=committed,removed_at=NULL;
 UPDATE zasp_inventory_relationships relationship_value SET state='removed',removed_at=committed,last_seen_at=committed,snapshot_id=$6 WHERE (relationship_value.organization_id,relationship_value.workspace_id,relationship_value.environment_id,relationship_value.integration_id,relationship_value.source)=($1,$2,$3,$4,$8) AND relationship_value.state='present' AND NOT EXISTS(SELECT 1 FROM jsonb_to_recordset(relationships) candidate(id text) WHERE candidate.id=relationship_value.id);

 UPDATE zasp_discovery_snapshots SET is_last_good=false WHERE (organization_id,workspace_id,environment_id,integration_id,source)=($1,$2,$3,$4,$8) AND is_last_good;
 UPDATE zasp_discovery_snapshots SET state='complete',complete=true,is_last_good=true,committed_at=committed WHERE (organization_id,workspace_id,environment_id,integration_id,id)=($1,$2,$3,$4,$6);
 INSERT INTO zasp_discovery_cursors(organization_id,workspace_id,environment_id,integration_id,provider,cursor_value,snapshot_id,committed_at) VALUES($1,$2,$3,$4,$12,$13,$6,committed) ON CONFLICT(organization_id,workspace_id,environment_id,integration_id,provider) DO UPDATE SET cursor_value=$13,snapshot_id=$6,committed_at=committed;
 INSERT INTO zasp_projection_work(organization_id,workspace_id,environment_id,snapshot_id,kind,version,input_digest) SELECT $1,$2,$3,$6,kind_value,'v1',$10 FROM unnest(ARRAY['risk','graph','search']) kind_value;
 UPDATE zasp_discovery_syncs SET state='succeeded',snapshot_id=$6,discovered_count=applied_discovered_count,changed_count=applied_changed_count,removed_count=applied_removed_count,completed_at=committed WHERE (organization_id,workspace_id,environment_id,integration_id,id)=($1,$2,$3,$4,$5);
 prior_result:=jsonb_build_object('snapshot_id',$6,'discovered_count',applied_discovered_count,'changed_count',applied_changed_count,'removed_count',applied_removed_count,'committed_at',committed);
 UPDATE zasp_discovery_snapshots SET apply_result=prior_result WHERE (organization_id,workspace_id,environment_id,integration_id,id)=($1,$2,$3,$4,$6);
 RETURN prior_result;
END $$;

ALTER FUNCTION public.zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb) SECURITY DEFINER;
ALTER FUNCTION public.zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb) SET search_path TO pg_catalog, public;

CREATE INDEX zasp_inventory_entities_kind_page_v14_idx ON public.zasp_inventory_entities(organization_id,workspace_id,environment_id,product_kind,id) WHERE state='active';
CREATE INDEX zasp_inventory_observations_identity_v14_idx ON public.zasp_inventory_source_observations(organization_id,workspace_id,environment_id,provider,source,identity_namespace,source_native_id) WHERE source_state='present';

INSERT INTO public.zasp_inventory_cutover_state(organization_id,workspace_id,environment_id,phase,rule_catalog_digest)
SELECT scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id,'expanded','a2ac63a7fc968b0c0c883a999418e1eb14c2d8de3ffe62e95717b7dea6133c52' FROM (
 SELECT organization_id,workspace_id,environment_id FROM zasp_core_payloads
 UNION SELECT organization_id,workspace_id,environment_id FROM zasp_inventory_entities
 UNION SELECT organization_id,workspace_id,environment_id FROM zasp_integrations
) scope_value ON CONFLICT DO NOTHING;

GRANT zasp_inventory_authority TO CURRENT_USER;
ALTER TABLE public.zasp_inventory_cutover_state OWNER TO zasp_inventory_authority;
ALTER TABLE public.zasp_inventory_legacy_restore OWNER TO zasp_inventory_authority;
ALTER TABLE public.zasp_inventory_identity_rules OWNER TO zasp_inventory_authority;
ALTER TABLE public.zasp_inventory_identity_bindings OWNER TO zasp_inventory_authority;
ALTER TABLE public.zasp_inventory_annotations OWNER TO zasp_inventory_authority;
GRANT SELECT ON public.zasp_inventory_cutover_state,public.zasp_inventory_legacy_restore,public.zasp_inventory_identity_rules,public.zasp_inventory_identity_bindings,public.zasp_inventory_annotations TO CURRENT_USER;
DO $typed_tables$ DECLARE table_name text;BEGIN
 FOREACH table_name IN ARRAY ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
  EXECUTE format('CREATE POLICY %I ON public.%I TO zasp_inventory_authority USING(true) WITH CHECK(true)',table_name||'_authority',table_name);
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker',table_name);
 END LOOP;
END $typed_tables$;

CREATE FUNCTION public.zasp_inventory_live_fingerprint() RETURNS text LANGUAGE sql STABLE AS $$
 WITH objects AS (
  SELECT 'table'::text kind,class.relname identity,jsonb_build_object('owner',class.relowner::regrole::text,'rls',class.relrowsecurity,'force',class.relforcerowsecurity,'acl',COALESCE((SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(class.relacl,acldefault('r',class.relowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor),'[]'::jsonb)) definition
    FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_evidence'])
  UNION ALL SELECT 'column',class.relname||'.'||attribute.attname,jsonb_build_object('type',format_type(attribute.atttypid,attribute.atttypmod),'not_null',attribute.attnotnull,'default',COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid,true),''))
    FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
    WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_evidence']) AND attribute.attnum>0 AND NOT attribute.attisdropped
  UNION ALL SELECT 'constraint',class.relname||'.'||constraint_value.conname,to_jsonb(pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_evidence'])
  UNION ALL SELECT 'index',index_value.relname,to_jsonb(pg_get_indexdef(index_value.oid)) FROM pg_class index_value JOIN pg_namespace namespace ON namespace.oid=index_value.relnamespace WHERE namespace.nspname='public' AND index_value.relname IN('zasp_inventory_entities_kind_page_v14_idx','zasp_inventory_observations_identity_v14_idx')
  UNION ALL SELECT 'policy',class.relname||'.'||policy.polname,jsonb_build_object('permissive',policy.polpermissive,'command',policy.polcmd,'roles',(SELECT jsonb_agg(role.rolname ORDER BY role.rolname) FROM unnest(policy.polroles) role_oid JOIN pg_roles role ON role.oid=role_oid),'using',pg_get_expr(policy.polqual,policy.polrelid),'check',pg_get_expr(policy.polwithcheck,policy.polrelid)) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations'])
  UNION ALL SELECT 'rule',provider||':'||source_kind,to_jsonb(rule)-ARRAY['provider','source_kind'] FROM zasp_inventory_identity_rules rule
  UNION ALL SELECT 'restore',object_kind||':'||object_identity,to_jsonb(encode(definition_digest,'hex')) FROM zasp_inventory_legacy_restore
  UNION ALL SELECT 'function',procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')',jsonb_build_object(
    'owner',CASE WHEN procedure.proname IN('zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence') AND procedure.proowner=(SELECT relowner FROM pg_class WHERE oid='zasp_core_payloads'::regclass) THEN 'zasp-core-owner' ELSE procedure.proowner::regrole::text END,
    'security',procedure.prosecdef,
    'config',COALESCE(to_jsonb(procedure.proconfig),'[]'::jsonb),
    'acl',COALESCE((
      SELECT jsonb_agg(
        jsonb_build_array(
          CASE WHEN acl.grantee=0 THEN 'PUBLIC' WHEN procedure.proname IN('zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence') AND acl.grantee=(SELECT relowner FROM pg_class WHERE oid='zasp_core_payloads'::regclass) THEN 'zasp-core-owner' ELSE grantee.rolname END,
          acl.privilege_type,
          acl.is_grantable,
          CASE WHEN procedure.proname IN('zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence') AND acl.grantor=(SELECT relowner FROM pg_class WHERE oid='zasp_core_payloads'::regclass) THEN 'zasp-core-owner' ELSE grantor.rolname END
        ) ORDER BY
          CASE WHEN acl.grantee=0 THEN 'PUBLIC' WHEN procedure.proname IN('zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence') AND acl.grantee=(SELECT relowner FROM pg_class WHERE oid='zasp_core_payloads'::regclass) THEN 'zasp-core-owner' ELSE grantee.rolname END,
          acl.privilege_type,
          acl.is_grantable,
          CASE WHEN procedure.proname IN('zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence') AND acl.grantor=(SELECT relowner FROM pg_class WHERE oid='zasp_core_payloads'::regclass) THEN 'zasp-core-owner' ELSE grantor.rolname END
      ) FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor
    ),'[]'::jsonb),
    'body',regexp_replace(btrim(procedure.prosrc),E'\s+',' ','g'))
    FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_inventory_%' OR procedure.proname IN('zasp_discovery_apply_snapshot','zasp_execution_job_input','zasp_typed_inventory_job_input_v13','zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence')) AND procedure.proname<>'zasp_inventory_live_fingerprint'
  UNION ALL SELECT 'trigger',class.relname||'.'||trigger_value.tgname,to_jsonb(pg_get_triggerdef(trigger_value.oid,true)) FROM pg_trigger trigger_value JOIN pg_class class ON class.oid=trigger_value.tgrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname='zasp_core_payloads' AND trigger_value.tgname='zasp_core_inventory_write_fence' AND NOT trigger_value.tgisinternal
  UNION ALL SELECT 'role',role.rolname,jsonb_build_object('login',role.rolcanlogin,'inherit',role.rolinherit,'super',role.rolsuper,'createdb',role.rolcreatedb,'createrole',role.rolcreaterole,'replication',role.rolreplication,'bypassrls',role.rolbypassrls,'managed_here',shobj_description(role.oid,'pg_authid')=ANY(ARRAY[format('zasp-managed:typed-inventory-cutover-v1:database:%s:created',(SELECT oid FROM pg_database WHERE datname=current_database())),format('zasp-managed:typed-inventory-cutover-v1:database:%s:bound',(SELECT oid FROM pg_database WHERE datname=current_database()))])) FROM pg_roles role WHERE role.rolname='zasp_inventory_authority'
 ) SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(kind,identity,definition) ORDER BY kind,identity,definition)::text,'[]'),'UTF8'),'sha256'),'hex') FROM objects
$$;

CREATE FUNCTION public.zasp_inventory_security_ready() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles role WHERE role.rolname='zasp_inventory_authority' AND NOT role.rolcanlogin AND NOT role.rolinherit AND NOT role.rolsuper AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls AND shobj_description(role.oid,'pg_authid')=ANY(ARRAY[format('zasp-managed:typed-inventory-cutover-v1:database:%s:created',(SELECT oid FROM pg_database WHERE datname=current_database())),format('zasp-managed:typed-inventory-cutover-v1:database:%s:bound',(SELECT oid FROM pg_database WHERE datname=current_database()))]))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.roleid=(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority') OR membership.member=(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority'))
 AND (SELECT count(*) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations']) AND class.relowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority') AND class.relrowsecurity AND class.relforcerowsecurity)=5
 AND NOT EXISTS(SELECT 1 FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations']) AND ((SELECT count(*) FROM pg_policy policy WHERE policy.polrelid=class.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy policy WHERE policy.polrelid=class.oid AND policy.polname=class.relname||'_authority' AND policy.polpermissive AND policy.polcmd='*' AND policy.polroles=ARRAY[(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority')] AND pg_get_expr(policy.polqual,policy.polrelid)='true' AND pg_get_expr(policy.polwithcheck,policy.polrelid)='true') OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(class.relacl,acldefault('r',class.relowner))) acl WHERE acl.grantee<>class.relowner)))
 AND (SELECT count(*) FROM zasp_inventory_identity_rules)=16
 AND (SELECT count(*) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_inventory_%')=19
 AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_inventory_%' AND procedure.proname NOT IN('zasp_inventory_readiness','zasp_inventory_backfill_scope','zasp_inventory_compat_read','zasp_inventory_equivalence_scope','zasp_inventory_cutover_scope','zasp_inventory_page','zasp_inventory_detail','zasp_inventory_agent_capabilities_page','zasp_inventory_agent_relationships_page','zasp_inventory_agent_sessions_page','zasp_inventory_home_summary') AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee NOT IN(procedure.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority')))))
 AND (SELECT count(*) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname IN('zasp_inventory_readiness','zasp_inventory_backfill_scope','zasp_inventory_compat_read','zasp_inventory_equivalence_scope','zasp_inventory_cutover_scope','zasp_inventory_page','zasp_inventory_detail','zasp_inventory_agent_capabilities_page','zasp_inventory_agent_relationships_page','zasp_inventory_agent_sessions_page','zasp_inventory_home_summary') AND procedure.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee NOT IN(procedure.proowner,CASE WHEN procedure.proname IN('zasp_inventory_page','zasp_inventory_detail','zasp_inventory_agent_capabilities_page','zasp_inventory_agent_relationships_page','zasp_inventory_agent_sessions_page','zasp_inventory_home_summary') THEN (SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api') ELSE procedure.proowner END)))=11
 AND (SELECT count(*) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname IN('zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence') AND procedure.proowner=(SELECT relowner FROM pg_class WHERE oid='zasp_core_payloads'::regclass) AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'])=3
 AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE namespace.nspname='public' AND procedure.proname IN('zasp_core_inventory_cutover','zasp_core_inventory_write_fence') AND acl.privilege_type='EXECUTE' AND acl.grantee NOT IN(procedure.proowner,CASE WHEN procedure.proname='zasp_core_inventory_cutover' THEN (SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') ELSE procedure.proowner END))
 AND EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname='zasp_typed_inventory_job_input_v13' AND procedure.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>procedure.proowner))
 AND EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname='zasp_execution_job_input' AND procedure.proowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND procedure.prosecdef AND COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND has_function_privilege('zasp_discovery_worker',procedure.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee NOT IN(procedure.proowner,(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_worker'))))
 AND EXISTS(SELECT 1 FROM pg_trigger trigger_value WHERE trigger_value.tgrelid='zasp_core_payloads'::regclass AND trigger_value.tgname='zasp_core_inventory_write_fence' AND trigger_value.tgenabled='O' AND trigger_value.tgfoid='zasp_core_inventory_write_fence()'::regprocedure AND NOT trigger_value.tgisinternal)
$$;

CREATE FUNCTION public.zasp_inventory_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(
  SELECT 1 FROM zasp_schema_versions release
  JOIN zasp_schema_metadata fingerprint ON fingerprint.key='typed_inventory_cutover_fingerprint' AND fingerprint.value=expected_fingerprint
  JOIN zasp_schema_metadata rules ON rules.key='typed_inventory_rule_catalog_digest' AND rules.value='a2ac63a7fc968b0c0c883a999418e1eb14c2d8de3ffe62e95717b7dea6133c52'
  WHERE release.version=14 AND release.name='typed_inventory_cutover' AND release.checksum=expected_checksum
    AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions later WHERE later.version>14)
 )
 AND EXISTS(SELECT 1 FROM zasp_schema_versions release WHERE release.version=13 AND release.name='production_discovery_execution' AND release.checksum='355815b171d2659421a55eed5d364b8aa5661e76798fd39957b13c399d0dfd52')
 AND EXISTS(SELECT 1 FROM zasp_schema_metadata marker WHERE marker.key='production_discovery_execution_fingerprint' AND marker.value='6a3a830ff7e43a220be6e0658a6262ed92c8c0165c803b34319acb0e0ed6cb9c')
 AND zasp_execution_security_ready()
 AND zasp_inventory_live_fingerprint()=expected_fingerprint
 AND zasp_inventory_security_ready()
$$;

DO $authority$ DECLARE procedure_oid oid;BEGIN
 FOR procedure_oid IN SELECT procedure.oid FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_inventory_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker',procedure_oid::regprocedure);
  EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure);
  EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure);
  IF procedure_oid NOT IN('public.zasp_inventory_readiness(text,text)'::regprocedure,'public.zasp_inventory_backfill_scope(text,text,text)'::regprocedure,'public.zasp_inventory_compat_read(text,text,text,text)'::regprocedure,'public.zasp_inventory_equivalence_scope(text,text,text)'::regprocedure,'public.zasp_inventory_cutover_scope(text,text,text)'::regprocedure,'public.zasp_inventory_page(text,text,text,text,text,integer)'::regprocedure,'public.zasp_inventory_detail(text,text,text,text,text)'::regprocedure,'public.zasp_inventory_agent_capabilities_page(text,text,text,text,text,integer)'::regprocedure,'public.zasp_inventory_agent_relationships_page(text,text,text,text,text,integer)'::regprocedure,'public.zasp_inventory_agent_sessions_page(text,text,text,text,text,integer)'::regprocedure,'public.zasp_inventory_home_summary(text,text,text)'::regprocedure) THEN
   EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_inventory_authority',procedure_oid::regprocedure);
   EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_authority',procedure_oid::regprocedure);
  ELSE
   EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
   IF procedure_oid IN('public.zasp_inventory_page(text,text,text,text,text,integer)'::regprocedure,'public.zasp_inventory_detail(text,text,text,text,text)'::regprocedure,'public.zasp_inventory_agent_capabilities_page(text,text,text,text,text,integer)'::regprocedure,'public.zasp_inventory_agent_relationships_page(text,text,text,text,text,integer)'::regprocedure,'public.zasp_inventory_agent_sessions_page(text,text,text,text,text,integer)'::regprocedure,'public.zasp_inventory_home_summary(text,text,text)'::regprocedure) THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',procedure_oid::regprocedure);END IF;
  END IF;
 END LOOP;
END $authority$;

DO $core_authority$ DECLARE owner_name text;BEGIN
 SELECT relowner::regrole::text INTO STRICT owner_name FROM pg_class WHERE oid='public.zasp_core_payloads'::regclass;
 EXECUTE format('ALTER FUNCTION public.zasp_core_inventory_cutover(text,text,text,bytea) OWNER TO %I',owner_name);
 EXECUTE format('ALTER FUNCTION public.zasp_core_inventory_write_fence() OWNER TO %I',owner_name);
 ALTER FUNCTION public.zasp_core_inventory_cutover(text,text,text,bytea) SECURITY DEFINER SET search_path TO pg_catalog, public;
 ALTER FUNCTION public.zasp_core_inventory_write_fence() SECURITY DEFINER SET search_path TO pg_catalog, public;
 REVOKE ALL ON FUNCTION public.zasp_core_inventory_cutover(text,text,text,bytea),public.zasp_core_inventory_write_fence() FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker;
 GRANT EXECUTE ON FUNCTION public.zasp_core_inventory_cutover(text,text,text,bytea) TO zasp_discovery_authority;
END $core_authority$;

REVOKE ALL ON public.zasp_inventory_cutover_state,public.zasp_inventory_legacy_restore,public.zasp_inventory_identity_rules,public.zasp_inventory_identity_bindings,public.zasp_inventory_annotations FROM CURRENT_USER;
REVOKE zasp_inventory_authority FROM CURRENT_USER;

DO $schema_marker$ BEGIN
 UPDATE zasp_schema_metadata SET value='typed-inventory-cutover-v1' WHERE key='production_core_schema' AND value='production-discovery-execution-v1';
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory schema marker missing';END IF;
END $schema_marker$;

INSERT INTO zasp_schema_metadata(key,value) VALUES
 ('typed_inventory_rule_catalog_digest','a2ac63a7fc968b0c0c883a999418e1eb14c2d8de3ffe62e95717b7dea6133c52'),
 ('typed_inventory_cutover_fingerprint', 'e0b088a7d3b779da2b76121f5718382b8cec5039bacfc85893b812083fe75c5f');
