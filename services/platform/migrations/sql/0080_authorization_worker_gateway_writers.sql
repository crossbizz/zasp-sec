-- Gateway ingestion keeps native credential authentication. Serialize its
-- existing writers before device locks so worker source revocation has one order.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('public.zasp_discovery_create_gateway_device(text,text,text,text,text)'::regprocedure,
 'public.zasp_discovery_transition_gateway_device(text,text,text,text,bigint,text)'::regprocedure,
 'public.zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamp with time zone)'::regprocedure,
 'public.zasp_runtime_revoke_gateway_enrollment(text,text,text,text,text)'::regprocedure,
 'public.zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text)'::regprocedure,
 'public.zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea)'::regprocedure,
 'public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure,
 'public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,
 'public.zasp_runtime_data_plane_live_fingerprint()'::regprocedure,
 'public.zasp_security_agent_live_fingerprint()'::regprocedure,
 'public.zasp_security_agent_budgets_function_identity(oid)'::regprocedure,
 'public.zasp_security_agent_session_isolation_live_fingerprint()'::regprocedure,
 'public.zasp_recovery_execution_live_fingerprint()'::regprocedure);

CREATE FUNCTION zasp_authorization80_worker.gateway_organization_lock(o text) RETURNS void
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $lock$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed'
 OR NOT zasp_authorization80_worker.catalog_ready()
 OR NOT public.zasp_runtime_principal_ready('zasp_gateway_control')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway writer authority rejected';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND OR NOT zasp_authorization80_worker.catalog_ready()
 OR NOT public.zasp_runtime_principal_ready('zasp_gateway_control')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway writer organization rejected';END IF;
END $lock$;

-- Device management has a distinct registered API login. This preserves the
-- existing caller contract; it is not a replacement for HTTP/OpenFGA checks.
CREATE FUNCTION zasp_authorization80_worker.gateway_api_organization_lock(o text) RETURNS void
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $lock$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed'
 OR NOT zasp_authorization80_worker.catalog_ready()
 OR NOT public.zasp_discovery_principal_ready('zasp_discovery_api')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway API writer authority rejected';END IF;
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND OR NOT zasp_authorization80_worker.catalog_ready()
 OR NOT public.zasp_discovery_principal_ready('zasp_discovery_api')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='gateway API writer organization rejected';END IF;
END $lock$;

DO $api_writers$ DECLARE p record;d text;needle text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN(
 'zasp_discovery_create_gateway_device(text,text,text,text,text)',
 'zasp_discovery_transition_gateway_device(text,text,text,text,bigint,text)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway API writer owner changed';END IF;
  d:=p.definition;
  needle:='DECLARE result jsonb;BEGIN ';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway API writer entry changed';END IF;
  d:=replace(d,needle,needle||'PERFORM zasp_authorization80_worker.gateway_api_organization_lock(p_organization_id);');
  IF p.signature='zasp_discovery_create_gateway_device(text,text,text,text,text)' THEN
   needle:='PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1,$2,$3,$4),0));';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway API create advisory changed';END IF;
   d:=replace(d,needle,needle||'PERFORM zasp_authorization80_worker.gateway_api_organization_lock(p_organization_id);');
  ELSE
   -- UPDATE can wait on the device row. Keep its FOUND/fallback predicates
   -- intact; a refusal before returning rolls back the entire mutation.
   needle:='RETURN result;';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway API transition return changed';END IF;
   d:=replace(d,needle,'PERFORM zasp_authorization80_worker.gateway_api_organization_lock(p_organization_id);'||needle);
  END IF;
  EXECUTE d;
 END LOOP;
END $api_writers$;

DO $api_enrollment$ DECLARE p record;d text;needle text;replacement text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN(
 'zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamp with time zone)',
 'zasp_runtime_revoke_gateway_enrollment(text,text,text,text,text)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway enrollment API owner changed';END IF;
  d:=p.definition;
  needle:='PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value),0));';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway enrollment API advisory changed';END IF;
  replacement:='PERFORM zasp_authorization80_worker.gateway_api_organization_lock(organization_value);'||E'\n '||needle||E'\n PERFORM zasp_authorization80_worker.gateway_api_organization_lock(organization_value);';
  IF p.signature LIKE 'zasp_runtime_issue_gateway_enrollment(%' THEN
   -- Recheck after both possible waits. The original transaction clock does
   -- not advance while waiting for organization or device serialization.
   replacement:=replacement||E'\n '||$expiry$IF expires_value<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='gateway enrollment expired while waiting';END IF;$expiry$;
  END IF;
  EXECUTE replace(d,needle,replacement);
 END LOOP;
END $api_enrollment$;

CREATE FUNCTION zasp_authorization80_worker.gateway_credential_lock(o text,w text,e text,d text,c text) RETURNS void
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $lock$
DECLARE a jsonb;BEGIN
 PERFORM zasp_authorization80_worker.gateway_organization_lock(o);
 -- The original lookup precedes this possibly blocking lock. Re-evaluate it
 -- afterward, including wall-clock expiry, before acquiring a device lock.
 a:=public.zasp_runtime_gateway_credential_authority(c,'runtime-gateway');
 IF(a->>'organization_id',a->>'workspace_id',a->>'environment_id',a->>'device_id',a->>'credential_id') IS DISTINCT FROM(o,w,e,d,c)
 OR NOT COALESCE((a->>'expires_at')::timestamptz>clock_timestamp(),false)
 THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='gateway writer credential changed';END IF;
END $lock$;

DO $writers$ DECLARE p record;d text;needle text;replacement text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN(
 'zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text)',
 'zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea)',
 'zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)',
 'zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway writer owner changed';END IF;
  d:=p.definition;
  IF p.signature='zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text)' THEN
   needle:='PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),candidate_scope.organization_id,candidate_scope.workspace_id,candidate_scope.environment_id,candidate_scope.device_id),0));';
   replacement:='PERFORM zasp_authorization80_worker.gateway_organization_lock(candidate_scope.organization_id);'||E'\n '||needle||E'\n PERFORM zasp_authorization80_worker.gateway_organization_lock(candidate_scope.organization_id);';
  ELSE
   needle:='PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,device_value),0));';
   replacement:='PERFORM zasp_authorization80_worker.gateway_credential_lock(organization_value,workspace_value,environment_value,device_value,credential_value);'||E'\n '||needle||E'\n PERFORM zasp_authorization80_worker.gateway_credential_lock(organization_value,workspace_value,environment_value,device_value,credential_value);';
  END IF;
  -- The organization row is already held, so repeating its check cannot
  -- reverse lock order. A separate device advisory holder can still outlive
  -- credential expiry or login registration; reject before reads or writes.
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway writer advisory anchor changed';END IF;
  d:=replace(d,needle,replacement);
  IF p.signature='zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text)' THEN
   needle:='token_row.expires_at<=transaction_timestamp()';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway enrollment expiry anchor changed';END IF;
   d:=replace(d,needle,'token_row.expires_at<=clock_timestamp()');
  END IF;
  EXECUTE d;
 END LOOP;
END $writers$;

-- Retained fingerprints see only the exact saved predecessor definitions.
-- Independent worker catalog facts still bind every live replacement and ACL.
DO $projection$ DECLARE d text;needle text;p record;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_runtime_data_plane_live_fingerprint()','zasp_security_agent_live_fingerprint()','zasp_security_agent_session_isolation_live_fingerprint()','zasp_recovery_execution_live_fingerprint()') LOOP
  d:=p.definition;
  IF p.signature='zasp_runtime_data_plane_live_fingerprint()' THEN
   needle:='FUNCTION public.zasp_runtime_data_plane_live_fingerprint()';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway15 fingerprint header changed';END IF;
   d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.gateway_projected15()');
   needle:='pg_get_functiondef(procedure_value.oid)';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway15 fingerprint definition changed';END IF;
   d:=replace(d,needle,$saved$CASE WHEN procedure_value.oid IN('public.zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text)'::regprocedure,'public.zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea)'::regprocedure,'public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_runtime_issue_gateway_enrollment(text,text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamp with time zone)'::regprocedure,'public.zasp_runtime_revoke_gateway_enrollment(text,text,text,text,text)'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=procedure_value.oid::regprocedure::text) ELSE pg_get_functiondef(procedure_value.oid) END$saved$);
  ELSIF p.signature='zasp_security_agent_live_fingerprint()' THEN
   -- Release18 includes the live24 fingerprint function BODY, not its output.
   -- Project only that exact wrapper and this replacement's self definition.
   needle:='FUNCTION public.zasp_security_agent_live_fingerprint()';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway18 fingerprint header changed';END IF;
   d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.gateway_projected18()');
   needle:='pg_get_functiondef(procedure.oid)';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway18 fingerprint definition changed';END IF;
   d:=replace(d,needle,$saved$CASE WHEN procedure.oid IN('public.zasp_security_agent_live_fingerprint()'::regprocedure,'public.zasp_security_agent_session_isolation_live_fingerprint()'::regprocedure,'public.zasp_security_agent_budgets_function_identity(oid)'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=procedure.oid::regprocedure::text) ELSE pg_get_functiondef(procedure.oid) END$saved$);
  ELSIF p.signature='zasp_security_agent_session_isolation_live_fingerprint()' THEN
   -- Release24 independently hashes the changed event writer in addition to
   -- the inherited15 chain. Preserve every other live category and attribute.
   needle:='FUNCTION public.zasp_security_agent_session_isolation_live_fingerprint()';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway24 fingerprint header changed';END IF;
   d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.gateway_projected24()');
   needle:='pg_get_functiondef(procedure.oid)';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway24 fingerprint definition changed';END IF;
   d:=replace(d,needle,$saved$CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=procedure.oid::regprocedure::text) ELSE pg_get_functiondef(procedure.oid) END$saved$);
  ELSE
   needle:='FUNCTION public.zasp_recovery_execution_live_fingerprint()';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway27 fingerprint header changed';END IF;
   d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.gateway_projected27()');
   needle:='pg_get_functiondef(procedure.oid)';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway27 fingerprint definition changed';END IF;
   d:=replace(d,needle,$saved$CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=procedure.oid::regprocedure::text) ELSE pg_get_functiondef(procedure.oid) END$saved$);
  END IF;
  EXECUTE d;
 END LOOP;
END $projection$;

-- Retained53 budget fingerprint copies share this exact identity helper. Keep
-- its existing readiness-pin normalization and all other live definitions.
DO $budget_identity$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_security_agent_budgets_function_identity(oid)' AND owner_name='zasp_discovery_authority';
 needle:='SELECT CASE WHEN function_value=';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='gateway budget identity anchor changed';END IF;
 d:=replace(d,needle,$saved$SELECT CASE WHEN function_value IN('public.zasp_security_agent_live_fingerprint()'::regprocedure,'public.zasp_security_agent_session_isolation_live_fingerprint()'::regprocedure,'public.zasp_security_agent_budgets_function_identity(oid)'::regprocedure)
 THEN CASE WHEN zasp_authorization80_worker.catalog_ready() THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=function_value::regprocedure::text) ELSE '' END
 WHEN function_value=$saved$);
 EXECUTE d;
END $budget_identity$;

CREATE OR REPLACE FUNCTION public.zasp_runtime_data_plane_live_fingerprint() RETURNS text
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.gateway_projected15() ELSE '' END
$fingerprint$;
CREATE OR REPLACE FUNCTION public.zasp_recovery_execution_live_fingerprint() RETURNS text
 LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.gateway_projected27() ELSE '' END
$fingerprint$;
CREATE OR REPLACE FUNCTION public.zasp_security_agent_session_isolation_live_fingerprint() RETURNS text
 LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.gateway_projected24() ELSE '' END
$fingerprint$;
CREATE OR REPLACE FUNCTION public.zasp_security_agent_live_fingerprint() RETURNS text
 LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.gateway_projected18() ELSE '' END
$fingerprint$;
