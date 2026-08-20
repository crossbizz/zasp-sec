DO $semantic_guard$ BEGIN
 IF zasp_inventory_live_fingerprint()<>'442fb80f46d909b99dedbfa5d114cfdeb263fb50987284d224717b9781b48f84' OR NOT zasp_inventory_security_ready() THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory semantic drift blocks rollback';
 END IF;
 IF EXISTS(SELECT 1 FROM zasp_inventory_cutover_state WHERE phase='cutover') THEN
  RAISE EXCEPTION USING ERRCODE='2BP01',MESSAGE='typed inventory cutover blocks rollback';
 END IF;
END $semantic_guard$;

DROP FUNCTION zasp_inventory_readiness(text,text);
DROP FUNCTION zasp_inventory_security_ready();
DROP FUNCTION zasp_inventory_live_fingerprint();
DROP TABLE zasp_inventory_cutover_state;
DELETE FROM zasp_schema_metadata WHERE key IN('typed_inventory_cutover_fingerprint','typed_inventory_rule_catalog_digest');

DO $role_cleanup$ DECLARE role_value record;marker_prefix text:=format('zasp-managed:typed-inventory-cutover-v1:database:%s:',(SELECT oid FROM pg_database WHERE datname=current_database()));BEGIN
 SELECT role.oid,shobj_description(role.oid,'pg_authid') marker INTO role_value FROM pg_roles role WHERE role.rolname='zasp_inventory_authority';
 IF FOUND THEN
  IF role_value.marker NOT IN(marker_prefix||'created',marker_prefix||'bound') OR EXISTS(SELECT 1 FROM pg_auth_members membership WHERE membership.roleid=role_value.oid OR membership.member=role_value.oid) OR EXISTS(SELECT 1 FROM pg_shdepend dependency WHERE dependency.refclassid='pg_authid'::regclass AND dependency.refobjid=role_value.oid) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory role drift blocks rollback';
  END IF;
  IF role_value.marker=marker_prefix||'created' THEN DROP ROLE zasp_inventory_authority;ELSE COMMENT ON ROLE zasp_inventory_authority IS NULL;END IF;
 END IF;
END $role_cleanup$;

DO $release_restore$ BEGIN
 IF NOT zasp_execution_readiness(
   '355815b171d2659421a55eed5d364b8aa5661e76798fd39957b13c399d0dfd52',
   '6a3a830ff7e43a220be6e0658a6262ed92c8c0165c803b34319acb0e0ed6cb9c'
 ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production discovery execution readiness not restored';END IF;
END $release_restore$;
