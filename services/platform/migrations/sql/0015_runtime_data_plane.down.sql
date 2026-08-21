DO $runtime_guard$ BEGIN
 IF zasp_runtime_data_plane_live_fingerprint()<>'c73433ada0f49a186f6772922caf87e1df457f1cb0a4ebfaea7db0cce7cf1b1d' OR NOT zasp_runtime_data_plane_security_ready() THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime data plane semantic drift blocks rollback';
 END IF;
 IF EXISTS(SELECT 1 FROM zasp_runtime_data_plane_state WHERE used_at IS NOT NULL) THEN
  RAISE EXCEPTION USING ERRCODE='2BP01',MESSAGE='runtime data plane use blocks rollback';
 END IF;
 IF EXISTS(
  SELECT 1 FROM zasp_runtime_legacy_token_transitions transition
  JOIN zasp_sensor_tokens token_value ON (token_value.organization_id,token_value.workspace_id,token_value.environment_id,token_value.sensor_id,token_value.id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.sensor_id,transition.token_id)
  WHERE token_value.format_version IS NOT NULL OR token_value.revoked_at IS DISTINCT FROM transition.transitioned_at
 ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime legacy token transition drift blocks rollback';END IF;
END $runtime_guard$;

ALTER TABLE public.zasp_discovery_outbox_topic_fairness
 DROP CONSTRAINT zasp_discovery_outbox_topic_fairness_topic_check,
 ADD CONSTRAINT zasp_discovery_outbox_topic_fairness_topic_check CHECK(topic='discovery-jobs');

DO $runtime_principals$
DECLARE binding record;
BEGIN
 EXECUTE 'SET LOCAL ROLE zasp_discovery_authority';
 FOR binding IN SELECT principal_name::text principal_name,authority_role::text authority_role FROM zasp_runtime_principal_bindings ORDER BY principal_name LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_roles principal WHERE principal.rolname=binding.principal_name AND principal.rolcanlogin AND principal.rolinherit AND NOT principal.rolsuper AND NOT principal.rolcreatedb AND NOT principal.rolcreaterole AND NOT principal.rolreplication AND NOT principal.rolbypassrls)
   OR NOT pg_has_role(binding.principal_name,binding.authority_role,'MEMBER')
   OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles principal ON principal.oid=membership.member JOIN pg_roles granted ON granted.oid=membership.roleid WHERE principal.rolname=binding.principal_name AND granted.rolname LIKE 'zasp_runtime_%' AND granted.rolname<>binding.authority_role)
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime principal drift blocks rollback';END IF;
  EXECUTE format('REVOKE %I FROM %I',binding.authority_role,binding.principal_name);
 END LOOP;
 DELETE FROM zasp_runtime_principal_bindings;
 EXECUTE 'RESET ROLE';
END $runtime_principals$;

DROP FUNCTION public.zasp_runtime_data_plane_readiness(text,text);
DROP FUNCTION public.zasp_runtime_data_plane_security_ready();
DROP FUNCTION public.zasp_runtime_data_plane_live_fingerprint();

DROP FUNCTION public.zasp_runtime_gateway_policy_bundle(text,bigint);
DROP FUNCTION public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz);
DROP FUNCTION public.zasp_runtime_gateway_put_policy_bundle(text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea);
DROP FUNCTION public.zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea);
DROP FUNCTION public.zasp_runtime_gateway_credential_authority(text,text);
DROP FUNCTION public.zasp_runtime_gateway_enroll(bytea,bytea,text,text,bigint,text,text,bytea,timestamptz);
DROP FUNCTION public.zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text);
DROP FUNCTION public.zasp_runtime_revoke_gateway_enrollment(text,text,text,text,text);
DROP FUNCTION public.zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz);
DROP FUNCTION public.zasp_runtime_gateway_enrollment_secret_hash(text,text,bigint,bytea,bytea);

DROP FUNCTION public.zasp_runtime_finish_stage(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer);
DROP FUNCTION public.zasp_runtime_heartbeat_stage(text,text,text,text,bigint,text,text,integer);
DROP FUNCTION public.zasp_runtime_claim_stage(text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_stage_for_session();
DROP FUNCTION public.zasp_runtime_retry_outbox(text,text,text,text,text,text,text,integer,text);
DROP FUNCTION public.zasp_runtime_ack_outbox(text,text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_runtime_heartbeat_outbox(text,text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_outbox(text,text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_ack_delivery(text,text,text,text,bigint,text,bytea,text,text,bytea);
DROP FUNCTION public.zasp_runtime_release_delivery(text,text,text,text,bigint,text,bytea,text,text,text,text);
DROP FUNCTION public.zasp_runtime_heartbeat_delivery(text,text,text,text,bigint,text,bytea,text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_claim_delivery(text,text,text,text,bigint,text,bytea,integer,text,text,integer,integer);
DROP FUNCTION public.zasp_runtime_reconcile_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text);
DROP FUNCTION public.zasp_runtime_finalize_batch(bytea,bytea,text,text,text,text,text,text,text,bytea,bigint,text);
DROP FUNCTION public.zasp_runtime_commit_reserved_batch(text,text,text,text,bigint,bytea,text,text,text,text,text,bytea,bigint,text);
DROP FUNCTION public.zasp_runtime_reserve_batch(bytea,bytea,text,text,text,bytea,text,text,text,bigint,integer);
DROP FUNCTION public.zasp_runtime_sensor_heartbeat(bytea,bytea,text,bigint,text,jsonb,text,boolean,bigint,bigint);
DROP FUNCTION public.zasp_runtime_authenticate_sensor(bytea,bytea,text);
DROP FUNCTION public.zasp_runtime_public_rotate_sensor(text,text,text,text,text,bigint,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz);
DROP FUNCTION public.zasp_runtime_public_delete_sensor(text,text,text,text,text,bigint,text,bytea);
DROP FUNCTION public.zasp_runtime_public_update_sensor(text,text,text,text,text,bigint,text,text,text,bytea);
DROP FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz);
DROP FUNCTION public.zasp_runtime_public_sensor_coverage(text,text,text,text);
DROP FUNCTION public.zasp_runtime_public_sensor_token_authority(text,text,text,text);
DROP FUNCTION public.zasp_runtime_public_sensor_detail(text,text,text,text);
DROP FUNCTION public.zasp_runtime_public_sensor_page(text,text,text,text,integer);
DROP FUNCTION public.zasp_runtime_public_sensor_value(text,text,text,text);
DROP FUNCTION public.zasp_runtime_revoke_sensor_token(text,text,text,text,text);
DROP FUNCTION public.zasp_runtime_rotate_sensor_token(text,text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz);
DROP FUNCTION public.zasp_runtime_issue_sensor_token(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz);
DROP FUNCTION public.zasp_runtime_mark_used();
DROP FUNCTION public.zasp_runtime_principals_ready();
DROP FUNCTION public.zasp_runtime_principal_ready(text);
DROP FUNCTION public.zasp_runtime_register_principals(text,text,text,text,text,text,text);
DROP FUNCTION public.zasp_runtime_sensor_secret_hash(text,text,bigint,bytea,bytea);

UPDATE public.zasp_sensor_tokens token_value SET revoked_at=transition.prior_revoked_at
 FROM public.zasp_runtime_legacy_token_transitions transition
 WHERE (token_value.organization_id,token_value.workspace_id,token_value.environment_id,token_value.sensor_id,token_value.id)=(transition.organization_id,transition.workspace_id,transition.environment_id,transition.sensor_id,transition.token_id);

DROP TABLE public.zasp_runtime_deliveries;
DROP TABLE public.zasp_runtime_stage_fairness;
DROP TABLE public.zasp_runtime_stage_work;
DROP TABLE public.zasp_runtime_batch_authorities;
DROP TABLE public.zasp_runtime_gateway_events;
DROP TABLE public.zasp_runtime_gateway_policy_bundles;
DROP TABLE public.zasp_runtime_gateway_replay_receipts;
DROP TABLE public.zasp_runtime_principal_bindings;
DROP TABLE public.zasp_runtime_sensor_mutations;

DROP INDEX public.zasp_gateway_credentials_live_v15_idx;
DROP INDEX public.zasp_gateway_credentials_generation_v15_idx;
DROP INDEX public.zasp_gateway_credentials_id_v15_idx;
ALTER TABLE public.zasp_gateway_credentials
 DROP CONSTRAINT zasp_gateway_credentials_v15_authority,
 DROP COLUMN v15_issued_at,
 DROP COLUMN algorithm,
 DROP COLUMN key_id,
 DROP COLUMN credential_generation,
 DROP COLUMN format_version;
DROP INDEX public.zasp_gateway_enrollment_live_v15_idx;
DROP INDEX public.zasp_gateway_enrollment_generation_v15_idx;
DROP INDEX public.zasp_gateway_enrollment_locator_v15_idx;
ALTER TABLE public.zasp_gateway_enrollment_tokens
 DROP CONSTRAINT zasp_gateway_enrollment_tokens_v15_authority,
 DROP COLUMN v15_issued_at,
 DROP COLUMN device_version_at_issue,
 DROP COLUMN token_generation,
 DROP COLUMN locator_digest,
 DROP COLUMN format_version;

DROP INDEX public.zasp_sensor_tokens_live_v15_idx;
DROP INDEX public.zasp_sensor_tokens_generation_v15_idx;
DROP INDEX public.zasp_sensor_tokens_locator_v15_idx;
ALTER TABLE public.zasp_sensor_tokens
 DROP CONSTRAINT zasp_sensor_tokens_v15_auth_time,
 DROP CONSTRAINT zasp_sensor_tokens_v15_authority,
 DROP COLUMN v15_issued_at,
 DROP COLUMN last_authenticated_at,
 DROP COLUMN sensor_version_at_issue,
 DROP COLUMN token_generation,
 DROP COLUMN locator_digest,
 DROP COLUMN format_version;
ALTER TABLE public.zasp_sensors DROP COLUMN runtime_contract_version,DROP COLUMN mode;

DROP TABLE public.zasp_runtime_legacy_token_transitions;
DROP TABLE public.zasp_runtime_data_plane_state;

DELETE FROM public.zasp_schema_metadata WHERE key='runtime_data_plane_fingerprint';
DO $schema_marker$ BEGIN UPDATE zasp_schema_metadata SET value='typed-inventory-cutover-v1' WHERE key='production_core_schema' AND value='runtime-data-plane-v1';IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime data plane schema marker drift';END IF;END $schema_marker$;

DO $product_release_restore$ DECLARE definition text;original_definition text;BEGIN
 SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'runtime-data-plane-v1','typed-inventory-cutover-v1');
 definition:=replace(definition,'release."version" = 15','release."version" = 14');
 definition:=replace(definition,'release."name" = ''runtime_data_plane''','release."name" = ''typed_inventory_cutover''');
 definition:=replace(definition,'later_release."version" > 15','later_release."version" > 14');
 IF definition=original_definition OR position('typed-inventory-cutover-v1' IN definition)=0 OR position('release."version" = 14' IN definition)=0 OR position('release."name" = ''typed_inventory_cutover''' IN definition)=0 OR position('later_release."version" > 14' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='workflow v14 compatibility restoration failed';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure) INTO STRICT definition;
 original_definition:=definition;
 definition:=replace(definition,'runtime-data-plane-v1','typed-inventory-cutover-v1');
 definition:=replace(replace(definition,'release."version"=15','release."version"=14'),'release."version" = 15','release."version" = 14');
 definition:=replace(replace(definition,'release."name"=''runtime_data_plane''','release."name"=''typed_inventory_cutover'''),'release."name" = ''runtime_data_plane''','release."name" = ''typed_inventory_cutover''');
 definition:=replace(replace(definition,'later."version">15','later."version">14'),'later."version" > 15','later."version" > 14');
 IF definition=original_definition OR position('typed-inventory-cutover-v1' IN definition)=0 OR position('typed_inventory_cutover' IN definition)=0 OR position('release."version"=14' IN definition)=0 AND position('release."version" = 14' IN definition)=0 OR position('later."version">14' IN definition)=0 AND position('later."version" > 14' IN definition)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='risk v14 compatibility restoration failed';END IF;
 EXECUTE definition;
END $product_release_restore$;

GRANT EXECUTE ON FUNCTION public.zasp_discovery_issue_sensor_token(text,text,text,text,text,bytea,bytea,timestamptz),public.zasp_discovery_sensor_rotate(text,text,text,text,text,text,bytea,bytea,timestamptz),public.zasp_discovery_sensor_revoke(text,text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_discovery_issue_gateway_enrollment(text,text,text,text,text,bytea,bytea,timestamptz),public.zasp_discovery_revoke_gateway_enrollment(text,text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_discovery_sensor_heartbeat(text,text,text,text,bigint,text,bigint,jsonb),public.zasp_discovery_create_runtime_batch(text,text,text,text,text,text,text,text,bytea,integer,text,bigint,text,text) TO zasp_runtime_ingest;
GRANT EXECUTE ON FUNCTION public.zasp_discovery_gateway_enroll(text,text,text,text,text,text,bytea,text,text,bytea,timestamptz),public.zasp_discovery_gateway_advance_replay(text,text,text,text,bigint,bigint),public.zasp_discovery_gateway_rotate(text,text,text,text,text,text,text,bytea,timestamptz),public.zasp_discovery_gateway_revoke(text,text,text,text,text),public.zasp_discovery_put_gateway_policy(text,text,text,text,text,bigint,bytea,bytea,timestamptz,timestamptz,bigint) TO zasp_runtime_gateway;

DO $runtime_roles$
DECLARE role_name text;role_value record;marker_prefix text:=format('zasp-managed:runtime-data-plane-v1:database:%s:',(SELECT oid FROM pg_database WHERE datname=current_database()));
BEGIN
 FOREACH role_name IN ARRAY ARRAY['zasp_runtime_coordinator','zasp_runtime_archive_worker','zasp_runtime_index_worker','zasp_runtime_correlation_worker','zasp_runtime_projection_worker','zasp_gateway_control'] LOOP
  SELECT role.oid,shobj_description(role.oid,'pg_authid') marker INTO STRICT role_value FROM pg_roles role WHERE role.rolname=role_name;
  IF role_value.marker NOT IN(marker_prefix||'created',marker_prefix||'bound') OR EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles member_value ON member_value.oid=membership.member WHERE membership.roleid=role_value.oid AND member_value.rolname<>'zasp_discovery_authority') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime role drift blocks rollback';END IF;
  EXECUTE format('REVOKE %I FROM zasp_discovery_authority',role_name);
  IF role_value.marker=marker_prefix||'created' THEN EXECUTE format('DROP ROLE %I',role_name);ELSE EXECUTE format('COMMENT ON ROLE %I IS NULL',role_name);END IF;
 END LOOP;
END $runtime_roles$;

DO $release_restore$ BEGIN
 IF NOT zasp_inventory_readiness('a018398e6c8aef3f23511392df9748b673be613eb1ad9e1eb5b0d571e326d445','c712e183558ad86f7464c034f304b12067bd49cd1ea18ee478878acb802df0ec') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='typed inventory readiness not restored';
 END IF;
END $release_restore$;
