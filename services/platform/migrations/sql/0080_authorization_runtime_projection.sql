-- Installed only by the current runtime profile, after its fixed source clones
-- and before its private owner/ACL closure and final catalog registration.
CREATE FUNCTION zasp_authorization80_runtime.projection_organization_lock(o text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $projection_lock$
BEGIN
 PERFORM zasp_authorization80_runtime.require_current();
 IF NOT COALESCE(public.zasp_runtime_principal_ready('zasp_runtime_coordinator'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime projection principal unavailable';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime projection organization unavailable';END IF;
 PERFORM zasp_authorization80_runtime.require_current();
 IF NOT COALESCE(public.zasp_runtime_principal_ready('zasp_runtime_coordinator'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime projection principal changed';END IF;
END $projection_lock$;

-- Keep original argument, receipt, tuple, stage, and replay checks. The earliest
-- source-row lock follows the organization lock. Recheck the wall-clock lease
-- after the complete-row wait and before returning, but preserve completed
-- receipt retries: only an original leased row has a live lease to expire.
DO $projection_writers$
DECLARE target_signature text;d text;needle text;replacement text;public_entry boolean;
 fence text:=$fence$ IF NOT COALESCE(public.zasp_runtime_principal_ready('zasp_runtime_coordinator'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime projection principal changed';END IF;
 IF complete_row.state='leased' AND complete_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime projection lease expired';END IF;
$fence$;
BEGIN
 FOREACH target_signature IN ARRAY ARRAY[
  'zasp_authorization80_runtime.runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)',
  'zasp_authorization80_runtime.runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)',
  'zasp_authorization80_runtime.runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)',
  'public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'
 ] LOOP
  d:=pg_get_functiondef(target_signature::regprocedure);
  public_entry:=starts_with(target_signature,'public.');
  IF public_entry AND NOT EXISTS(SELECT 1 FROM zasp_authorization80_runtime.predecessor_functions p WHERE to_regprocedure(p.signature)=target_signature::regprocedure AND p.definition=d AND p.owner_name='zasp_discovery_authority') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime public projection source changed';END IF;
  needle:=' SELECT * INTO predecessor FROM zasp_runtime_stage_work WHERE';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime projection predecessor lock changed';END IF;
  d:=replace(d,needle,E' PERFORM zasp_authorization80_runtime.projection_organization_lock(organization_value);\n'||needle);
  needle:=' receipt_value:=convert_from(receipt_bytes,''UTF8'')::jsonb;';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime projection complete-row fence changed';END IF;
  d:=replace(d,needle,fence||needle);
  needle:=' RETURN result_value;';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime projection return fence changed';END IF;
  replacement:=CASE WHEN public_entry THEN E' PERFORM zasp_authorization80_runtime.require_current();\n' ELSE '' END||fence||needle;
  d:=replace(d,needle,replacement);
  EXECUTE d;
  IF public_entry AND NOT EXISTS(SELECT 1 FROM pg_proc f JOIN zasp_authorization80_runtime.predecessor_functions p ON to_regprocedure(p.signature)=target_signature::regprocedure WHERE f.oid=target_signature::regprocedure AND f.proowner::regrole::text=p.owner_name AND COALESCE(f.proacl::text,'')=p.acl) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime public projection ACL changed';END IF;
 END LOOP;
END $projection_writers$;
