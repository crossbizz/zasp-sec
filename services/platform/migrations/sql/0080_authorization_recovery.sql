-- Checked recovery enqueue/read boundary. Native27 receipts/audit/outbox and
-- validation remain in the unchanged source functions; no provider runs here.
CREATE FUNCTION zasp_authorization80.recovery_source_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(zasp_authorization80.ready('-- authorization80 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE(version,name,checksum)=(27,'production_recovery','-- authorization80 recovery27 checksum'))
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE(key,value)=('production_recovery_fingerprint','-- authorization80 recovery27 fingerprint'))
 AND NOT EXISTS(SELECT 1 FROM pg_class WHERE oid IN('public.zasp_recovery_backups'::regclass,'public.zasp_recovery_restores'::regclass,'public.zasp_recovery_outbox'::regclass,'public.zasp_recovery_request_receipts'::regclass,'public.zasp_recovery_audit'::regclass,'public.zasp_recovery_holds'::regclass)
  AND(relowner<>'zasp_discovery_authority'::regrole OR NOT relrowsecurity OR NOT relforcerowsecurity))
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_recovery_backups','SELECT')
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_recovery_restores','SELECT')
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_recovery_outbox','INSERT')
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_recovery_audit','INSERT')
 AND NOT has_function_privilege('zasp_discovery_api','public.zasp_recovery_validate_scope(text,text,text)','EXECUTE')
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'
  AND p.proname IN('zasp_recovery_create_backup','zasp_recovery_create_restore','zasp_recovery_get_backup','zasp_recovery_get_restore','zasp_recovery_scope_mutable')
  AND(p.proowner<>'zasp_discovery_authority'::regrole OR NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR has_function_privilege('public',p.oid,'EXECUTE'))),false)
$$;

CREATE FUNCTION zasp_authorization80.recovery_assert(o text,w text,e text,op text,i text,p text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb:=zasp_authorization80.context();kind text;
BEGIN
 kind:=CASE op WHEN 'startRecoveryBackup' THEN 'environment' WHEN 'startRecoveryRestore' THEN 'environment' WHEN 'getRecoveryBackup' THEN 'recovery_backup' WHEN 'getRecoveryRestore' THEN 'recovery_restore' END;
 IF NOT COALESCE(zasp_authorization80.recovery_source_ready() AND public.zasp_discovery_principal_ready('zasp_discovery_api')
 AND(proof->>'organization_id',proof->>'workspace_id',proof->>'environment_id',proof->>'operation_id')=(o,w,e,op)
 AND(p IS NULL OR proof->>'principal_id'=p)
 AND proof->>'permission'=CASE WHEN kind='environment' THEN 'manage_identity' ELSE 'view' END
 AND(kind<>'environment' OR COALESCE((proof->>'fresh_auth')::boolean,false))
 AND zasp_authorization80.allowed(o,w,e,kind,CASE WHEN kind='environment' THEN e ELSE i END),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current recovery authorization required';END IF;
END $$;

CREATE FUNCTION zasp_authorization80.recovery_create_backup(text,text,text,text,text,text,text,integer,text,text,bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.recovery_assert($1,$2,$3,'startRecoveryBackup',NULL,$4);
 RETURN public.zasp_recovery_create_backup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11);
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.recovery_create_backup(text,text,text,text,text,text,text,integer,text,text,bytea) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80.recovery_create_restore(text,text,text,text,text,text,text,text,text,text,bytea,jsonb,bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.recovery_assert($1,$2,$3,'startRecoveryRestore',NULL,$4);
 RETURN public.zasp_recovery_create_restore($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13);
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.recovery_create_restore(text,text,text,text,text,text,text,text,text,text,bytea,jsonb,bytea) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80.recovery_get_backup(text,text,text,text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.recovery_assert($1,$2,$3,'getRecoveryBackup',$4,NULL);
 RETURN public.zasp_recovery_get_backup($1,$2,$3,$4);
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.recovery_get_backup(text,text,text,text) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80.recovery_get_restore(text,text,text,text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.recovery_assert($1,$2,$3,'getRecoveryRestore',$4,NULL);
 RETURN public.zasp_recovery_get_restore($1,$2,$3,$4);
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.recovery_get_restore(text,text,text,text) TO zasp_discovery_api;
