-- The installer independently evaluated the compiled source19 query before
-- this capture. No live fingerprint is promoted to a new expected identity.
CREATE TABLE zasp_authorization80_identity.predecessor(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
INSERT INTO zasp_authorization80_identity.predecessor(definition,owner_name,acl)
 SELECT pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid='public.zasp_identity_admin_reconcile_deprovision(text,text,text,text,bytea,text)'::regprocedure;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_identity.predecessor FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80_identity.immutable();

-- identity retained deprovision

CREATE FUNCTION zasp_authorization80_identity.projected19() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $projection$
-- identity projected19 query
$projection$;

CREATE OR REPLACE FUNCTION public.zasp_identity_admin_reconcile_deprovision(project_value text,event_value text,organization_reference_value text,member_value text,event_digest_value bytea,audit_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $closed$
DECLARE permit jsonb;
BEGIN
 SELECT body INTO permit FROM zasp_authorization80_identity.permits WHERE pid=pg_backend_pid() AND tx=pg_current_xact_id() AND principal=session_user;
 IF NOT COALESCE(permit->>'purpose'='deprovision' AND permit->>'project'=project_value AND permit->>'event_id'=event_value AND permit->>'organization'=organization_reference_value AND permit->>'member'=member_value AND permit->>'body_digest'=encode(event_digest_value,'hex') AND permit->>'audit_id'=audit_value,false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='verified identity deprovision required';END IF;
 RETURN zasp_authorization80_identity.retained_deprovision(project_value,event_value,organization_reference_value,member_value,event_digest_value,audit_value);
END $closed$;
