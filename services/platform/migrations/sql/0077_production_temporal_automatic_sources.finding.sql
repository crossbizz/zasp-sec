-- The old public writer and the global audit/export gate stay byte-identical.
-- This is an invoker-security copy, not a new table-writing privilege.
INSERT INTO zasp_temporal77.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid='public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'::regprocedure;
CREATE FUNCTION zasp_temporal77.risk_api_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(zasp_temporal77.ready(c,f)
 AND public.zasp_discovery_principal_ready('zasp_discovery_api')
 AND public.zasp_audit_export_policy_state_ready()
 AND public.zasp_audit_export_worker_security_ready()
 AND public.zasp_audit_export_source_acl_ready()
 AND public.zasp_audit_export_workflow_acl_ready(),false)
$ready$;
CREATE FUNCTION zasp_temporal77.require_risk_ready() RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
BEGIN
 IF NOT zasp_temporal77.risk_api_ready('-- automatic77 checksum','-- automatic77 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='automatic finding authority unavailable';END IF;
END $guard$;
DO $copy$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal77.predecessor_functions
 WHERE signature='zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)'
 AND owner_name='zasp_discovery_authority'
 AND acl='{=X/zasp_discovery_authority,zasp_discovery_authority=X/zasp_discovery_authority,zasp_discovery_api=X/zasp_discovery_authority}'
 AND encode(digest(convert_to(definition,'UTF8'),'sha256'),'hex')='b5366f9c295a2b46844dd6b04458cb706cef5e422f2c53c55b487b62bebbfdec';
 IF position('SECURITY DEFINER' IN d)>0 THEN RAISE EXCEPTION 'automatic finding invoker predecessor changed';END IF;
 d:=replace(d,'FUNCTION public.zasp_risk_mutate(', 'FUNCTION zasp_temporal77.risk_mutate(');
 needle:='public.zasp_audit_exports_require_ready()';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>3 THEN RAISE EXCEPTION 'automatic finding audit predecessor changed';END IF;
 d:=replace(d,needle,'zasp_temporal77.require_risk_ready()');
 needle:='later."version">60';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'automatic finding version predecessor changed';END IF;
 EXECUTE replace(d,needle,'later."version">61');
END $copy$;
