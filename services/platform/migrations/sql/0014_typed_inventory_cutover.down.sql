DO $semantic_guard$ BEGIN
 IF zasp_inventory_live_fingerprint()<>'0687bb9714159f30f1cd41a536a30f9bb37e4d6ae5e3fb2979ba8bbd57a72c47' OR NOT zasp_inventory_security_ready() THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory semantic drift blocks rollback';
 END IF;
 IF EXISTS(SELECT 1 FROM zasp_inventory_cutover_state WHERE phase='cutover') THEN
  RAISE EXCEPTION USING ERRCODE='2BP01',MESSAGE='typed inventory cutover blocks rollback';
 END IF;
END $semantic_guard$;

DO $legacy_restore$ DECLARE restore_row record;BEGIN
 FOR restore_row IN SELECT * FROM zasp_inventory_legacy_restore ORDER BY object_kind DESC LOOP
  IF digest(convert_to(restore_row.definition,'UTF8'),'sha256')<>restore_row.definition_digest THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory restore authority drift';END IF;
  EXECUTE restore_row.definition;
 END LOOP;
END $legacy_restore$;

DROP FUNCTION zasp_typed_inventory_job_input_v13(text,text,text,text,text,text);

DROP TRIGGER zasp_core_inventory_write_fence ON zasp_core_payloads;
DROP FUNCTION zasp_core_inventory_write_fence();
DROP FUNCTION zasp_inventory_cutover_scope(text,text,text);
DROP FUNCTION zasp_inventory_equivalence_scope(text,text,text);
DROP FUNCTION zasp_core_inventory_cutover(text,text,text,bytea);

DROP FUNCTION zasp_inventory_readiness(text,text);
DROP FUNCTION zasp_inventory_compat_read(text,text,text,text);
DROP FUNCTION zasp_inventory_backfill_scope(text,text,text);
DROP FUNCTION zasp_inventory_security_ready();
DROP FUNCTION zasp_inventory_live_fingerprint();
DROP FUNCTION zasp_inventory_annotation_value(text,text,text,text);
DROP FUNCTION zasp_inventory_import_annotations(text,text,text,jsonb);
DROP FUNCTION zasp_inventory_advance_scope(text,text,text,text,bytea,bytea);
DROP FUNCTION zasp_inventory_scope_state(text,text,text);
DROP FUNCTION zasp_inventory_bind_typed_entities(text,text,text,text,text,jsonb);
DROP FUNCTION zasp_inventory_validate_typed_entities(text,jsonb);
DROP INDEX zasp_inventory_observations_identity_v14_idx;
DROP INDEX zasp_inventory_entities_kind_page_v14_idx;
DROP TABLE zasp_inventory_annotations;
DROP TABLE zasp_inventory_identity_bindings;
DROP TABLE zasp_inventory_identity_rules;
DROP TABLE zasp_inventory_legacy_restore;
DROP TABLE zasp_inventory_cutover_state;

ALTER TABLE zasp_inventory_evidence
 DROP COLUMN tool_version,
 DROP COLUMN size_bytes,
 DROP COLUMN artifact_version_id,
 DROP COLUMN artifact_key,
 DROP COLUMN artifact_reference,
 DROP COLUMN generation,
 DROP COLUMN source;

ALTER TABLE zasp_inventory_source_observations
 DROP CONSTRAINT zasp_inventory_observations_typed_times,
 DROP COLUMN source_projection_version,
 DROP COLUMN identity_priority,
 DROP COLUMN identity_rule_version,
 DROP COLUMN fresh_until,
 DROP COLUMN observed_at,
 DROP COLUMN confidence_basis_points,
 DROP COLUMN evidence_id,
 DROP COLUMN content_digest,
 DROP COLUMN generation,
 DROP COLUMN product_kind,
 DROP COLUMN identity_namespace,
 DROP COLUMN stable_fields,
 DROP COLUMN display_name,
 DROP COLUMN source_kind,
 DROP COLUMN provider;

ALTER TABLE zasp_inventory_entities
 DROP CONSTRAINT zasp_inventory_entities_typed_times,
 DROP COLUMN annotation_version,
 DROP COLUMN winning_source_projection,
 DROP COLUMN winning_identity_rule,
 DROP COLUMN winning_source_native_id,
 DROP COLUMN winning_source,
 DROP COLUMN winning_provider,
 DROP COLUMN winning_integration_id,
 DROP COLUMN projection_version,
 DROP COLUMN fresh_until,
 DROP COLUMN observed_at,
 DROP COLUMN winning_generation,
 DROP COLUMN winning_snapshot_id,
 DROP COLUMN winning_evidence_id,
 DROP COLUMN confidence_basis_points,
 DROP COLUMN product_kind;
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
