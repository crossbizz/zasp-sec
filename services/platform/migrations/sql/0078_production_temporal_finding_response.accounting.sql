-- Every family continues to count unknown78 provider usage, even after the
-- finding run is cancelled or made terminal. No lease expiry releases debt.
INSERT INTO zasp_temporal78.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN('zasp_temporal73.unresolved(text,text,text,text)'::regprocedure,'zasp_temporal73.fingerprint()'::regprocedure);
DO $copies$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal73.unresolved(text,text,text,text)';
 EXECUTE replace(d,'FUNCTION zasp_temporal73.unresolved(','FUNCTION zasp_temporal78.predecessor73_unresolved(');
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal73.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal73.fingerprint()','FUNCTION zasp_temporal78.predecessor73_fingerprint()');
 needle:='pg_get_functiondef(p.oid)';
 --73 inherits68's one schema-function catalog branch. It has no second
 -- effective-predecessor branch like77; reject any unexpected recipe.
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding73 projection predecessor changed';END IF;
 EXECUTE replace(d,needle,$projection$CASE WHEN p.oid IN('zasp_temporal73.unresolved(text,text,text,text)'::regprocedure,'zasp_temporal73.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal78.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);
END $copies$;
CREATE OR REPLACE FUNCTION zasp_temporal73.unresolved(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $unresolved$
 SELECT zasp_temporal78.predecessor73_unresolved(o,w,e,r) OR EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL AND x.released_at IS NULL)
$unresolved$;
CREATE OR REPLACE FUNCTION zasp_temporal73.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_temporal78.catalog_ready() THEN zasp_temporal78.predecessor73_fingerprint() ELSE NULL END
$fingerprint$;

CREATE FUNCTION zasp_temporal78.serialize_revocation() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $revocation$
BEGIN
 PERFORM 1 FROM zasp_temporal78.service_grants WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version) FOR UPDATE;
 RETURN NEW;
END $revocation$;
CREATE TRIGGER serialize_grant BEFORE INSERT ON zasp_temporal78.grant_revocations FOR EACH ROW EXECUTE FUNCTION zasp_temporal78.serialize_revocation();
