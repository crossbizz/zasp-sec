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

GRANT zasp_inventory_authority TO CURRENT_USER;
ALTER TABLE public.zasp_inventory_cutover_state OWNER TO zasp_inventory_authority;
REVOKE zasp_inventory_authority FROM CURRENT_USER;
ALTER TABLE public.zasp_inventory_cutover_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_inventory_cutover_state FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_inventory_cutover_state_authority ON public.zasp_inventory_cutover_state TO zasp_inventory_authority USING(true) WITH CHECK(true);
REVOKE ALL ON TABLE public.zasp_inventory_cutover_state FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker;

CREATE FUNCTION public.zasp_inventory_live_fingerprint() RETURNS text LANGUAGE sql STABLE AS $$
 WITH objects AS (
  SELECT 'table'::text kind,class.relname identity,jsonb_build_object('owner',class.relowner::regrole::text,'rls',class.relrowsecurity,'force',class.relforcerowsecurity,'acl',COALESCE((SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(class.relacl,acldefault('r',class.relowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor),'[]'::jsonb)) definition
    FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname='zasp_inventory_cutover_state'
  UNION ALL SELECT 'column',class.relname||'.'||attribute.attname,jsonb_build_object('type',format_type(attribute.atttypid,attribute.atttypmod),'not_null',attribute.attnotnull,'default',COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid,true),''))
    FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
    WHERE namespace.nspname='public' AND class.relname='zasp_inventory_cutover_state' AND attribute.attnum>0 AND NOT attribute.attisdropped
  UNION ALL SELECT 'constraint',constraint_value.conname,to_jsonb(pg_get_constraintdef(constraint_value.oid,true)) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_inventory_cutover_state'::regclass
  UNION ALL SELECT 'policy',policy.polname,jsonb_build_object('permissive',policy.polpermissive,'command',policy.polcmd,'roles',(SELECT jsonb_agg(role.rolname ORDER BY role.rolname) FROM unnest(policy.polroles) role_oid JOIN pg_roles role ON role.oid=role_oid),'using',pg_get_expr(policy.polqual,policy.polrelid),'check',pg_get_expr(policy.polwithcheck,policy.polrelid)) FROM pg_policy policy WHERE policy.polrelid='public.zasp_inventory_cutover_state'::regclass
  UNION ALL SELECT 'function',procedure.proname||'('||pg_get_function_identity_arguments(procedure.oid)||')',jsonb_build_object('owner',procedure.proowner::regrole::text,'security',procedure.prosecdef,'config',COALESCE(to_jsonb(procedure.proconfig),'[]'::jsonb),'acl',COALESCE((SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor),'[]'::jsonb),'body',regexp_replace(btrim(procedure.prosrc),E'\s+',' ','g'))
    FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_inventory_%' AND procedure.proname<>'zasp_inventory_live_fingerprint'
  UNION ALL SELECT 'role',role.rolname,jsonb_build_object('login',role.rolcanlogin,'inherit',role.rolinherit,'super',role.rolsuper,'createdb',role.rolcreatedb,'createrole',role.rolcreaterole,'replication',role.rolreplication,'bypassrls',role.rolbypassrls,'managed_here',shobj_description(role.oid,'pg_authid')=ANY(ARRAY[format('zasp-managed:typed-inventory-cutover-v1:database:%s:created',(SELECT oid FROM pg_database WHERE datname=current_database())),format('zasp-managed:typed-inventory-cutover-v1:database:%s:bound',(SELECT oid FROM pg_database WHERE datname=current_database()))])) FROM pg_roles role WHERE role.rolname='zasp_inventory_authority'
 ) SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(kind,identity,definition) ORDER BY kind,identity,definition)::text,'[]'),'UTF8'),'sha256'),'hex') FROM objects
$$;

CREATE FUNCTION public.zasp_inventory_security_ready() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles role WHERE role.rolname='zasp_inventory_authority' AND NOT role.rolcanlogin AND NOT role.rolinherit AND NOT role.rolsuper AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls AND shobj_description(role.oid,'pg_authid')=ANY(ARRAY[format('zasp-managed:typed-inventory-cutover-v1:database:%s:created',(SELECT oid FROM pg_database WHERE datname=current_database())),format('zasp-managed:typed-inventory-cutover-v1:database:%s:bound',(SELECT oid FROM pg_database WHERE datname=current_database()))]))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.roleid=(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority') OR membership.member=(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority'))
 AND EXISTS(SELECT 1 FROM pg_class class WHERE class.oid='public.zasp_inventory_cutover_state'::regclass AND class.relowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority') AND class.relrowsecurity AND class.relforcerowsecurity)
 AND (SELECT count(*) FROM pg_policy policy WHERE policy.polrelid='public.zasp_inventory_cutover_state'::regclass)=1
 AND EXISTS(SELECT 1 FROM pg_policy policy WHERE policy.polrelid='public.zasp_inventory_cutover_state'::regclass AND policy.polname='zasp_inventory_cutover_state_authority' AND policy.polpermissive AND policy.polcmd='*' AND policy.polroles=ARRAY[(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority')] AND pg_get_expr(policy.polqual,policy.polrelid)='true' AND pg_get_expr(policy.polwithcheck,policy.polrelid)='true')
 AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE((SELECT relacl FROM pg_class WHERE oid='public.zasp_inventory_cutover_state'::regclass),acldefault('r',(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority')))) acl WHERE acl.grantee<>(SELECT oid FROM pg_roles WHERE rolname='zasp_inventory_authority'))
 AND (SELECT count(*) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_inventory_%')=3
 AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_inventory_%' AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>procedure.proowner)))
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
 AND zasp_execution_live_fingerprint()='6a3a830ff7e43a220be6e0658a6262ed92c8c0165c803b34319acb0e0ed6cb9c'
 AND zasp_execution_security_ready()
 AND zasp_inventory_live_fingerprint()=expected_fingerprint
 AND zasp_inventory_security_ready()
$$;

DO $authority$ DECLARE procedure_oid oid;BEGIN
 FOR procedure_oid IN SELECT procedure.oid FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_inventory_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker',procedure_oid::regprocedure);
  EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER',procedure_oid::regprocedure);
  EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, public',procedure_oid::regprocedure);
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',procedure_oid::regprocedure);
 END LOOP;
END $authority$;

INSERT INTO zasp_schema_metadata(key,value) VALUES
 ('typed_inventory_rule_catalog_digest','a2ac63a7fc968b0c0c883a999418e1eb14c2d8de3ffe62e95717b7dea6133c52'),
 ('typed_inventory_cutover_fingerprint', '442fb80f46d909b99dedbfa5d114cfdeb263fb50987284d224717b9781b48f84');
