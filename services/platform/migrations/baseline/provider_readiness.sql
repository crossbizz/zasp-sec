-- Use the shorter readiness path only for its reviewed predicate definitions.
-- Hashes include definition, owner and ACL. A later reviewed release that
-- changes a leaf automatically runs the original path until it is requalified.
-- Each call checks live database rows, current reader roles and catalog state
-- in its own statement. No verdict or permission is cached.
CREATE OR REPLACE FUNCTION zasp_authorization80.release_readiness_predicates_match()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $pins$
 SELECT count(*)=12 AND bool_and(procedure_oid IS NOT NULL) AND
 encode(sha256(convert_to(string_agg(signature||chr(31)||pg_get_functiondef(procedure_oid)||chr(31)||p.proowner::regrole::text||chr(31)||COALESCE(p.proacl::text,'default'),chr(30) ORDER BY signature COLLATE "C"),'UTF8')),'hex')='03f11d8a7a225fc0bf9367830d8c84f3199984f84a63699d29a1f55061220c54'
 FROM (SELECT signature,to_regprocedure(signature) AS procedure_oid FROM (VALUES
 ('public.zasp_sa_multistep_readiness(text,text)'),
 ('zasp_authorization79.reader()'),
 ('zasp_authorization79.ready(text)'),
 ('zasp_authorization79.worker()'),
 ('zasp_authorization80.runtime_audit_ready()'),
 ('zasp_authorization80.runtime_identity_ready()'),
 ('zasp_authorization80.runtime_profile_ready()'),
 ('zasp_authorization80_audit.catalog_ready()'),
 ('zasp_authorization80_identity.catalog_ready()'),
 ('zasp_authorization80_temporal.catalog_ready()'),
 ('zasp_temporal68.current_ready()'),
 ('zasp_temporal68.ready(text,text)')
 ) AS dependencies(signature)) leaf LEFT JOIN pg_proc p ON p.oid=procedure_oid
$pins$;
ALTER FUNCTION zasp_authorization80.release_readiness_predicates_match() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.release_readiness_predicates_match() FROM PUBLIC;

CREATE OR REPLACE FUNCTION zasp_authorization80.ready(c text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
BEGIN
 IF c IS DISTINCT FROM 'd7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd' THEN RETURN false; END IF;
 IF zasp_authorization80.release_readiness_predicates_match() AND (SELECT count(*)=1 FROM zasp_authorization80.runtime_profile) AND EXISTS(
  SELECT FROM zasp_authorization80.runtime_profile r WHERE r.singleton AND
  (r.name,r.identity_mode,r.audit_mode)=('canonical61-temporal78-authorization79-80-v1','source19-canonical61-identity-v1','source52-canonical61-audit-v1')
 ) THEN
  RETURN EXISTS(SELECT FROM zasp_authorization80.registration WHERE checksum=c)
  AND EXISTS(SELECT FROM zasp_authorization79.registration WHERE checksum='8b358e304b2eedaed7a4148f317f6d21d9c624ccc39105ca6199265ae661a987')
  AND to_regnamespace('zasp_temporal78') IS NOT NULL
  AND to_regclass('zasp_authorization80_temporal.registration') IS NOT NULL
  AND to_regclass('zasp_authorization80_audit.registration') IS NOT NULL
  AND to_regprocedure('zasp_authorization80_audit.catalog_ready()') IS NOT NULL
  AND to_regprocedure('zasp_authorization80_temporal.catalog_ready()') IS NOT NULL
  AND EXISTS(SELECT FROM pg_proc WHERE oid=to_regprocedure('zasp_authorization80_identity.catalog_ready()')
    AND proowner='zasp_discovery_authority'::regrole AND prosecdef AND proconfig=ARRAY['search_path=pg_catalog, public']
    AND provolatile='s' AND prolang=(SELECT oid FROM pg_language WHERE lanname='sql')
    AND proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}')
  AND zasp_baseline.intact();
 END IF;
 RETURN EXISTS(SELECT 1 FROM zasp_authorization80.registration WHERE checksum=c AND zasp_baseline.intact())
  AND zasp_authorization80.runtime_profile_ready() AND zasp_authorization80.runtime_audit_ready() AND zasp_authorization80.runtime_identity_ready()
  AND zasp_authorization79.ready('8b358e304b2eedaed7a4148f317f6d21d9c624ccc39105ca6199265ae661a987')
  AND public.zasp_sa_multistep_readiness('033bf2ffa9d4a60121d4f20436ff7de36d1421b62f849254a09048caf75998e6','6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92');
END $ready$;
-- ready() admits a successful verification only when the same sealed catalog
-- is intact including the native identity helper.
CREATE OR REPLACE FUNCTION zasp_authorization80_identity.structural_ready(c text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog, public AS $id$
 SELECT c='a5f37dc064798027b5cee8fddad4bd40a3ec2dc3b7bce49e6771cfce4c88eeea' AND EXISTS(SELECT 1 FROM zasp_authorization80_identity.registration WHERE checksum=c)
 AND (zasp_authorization80.release_readiness_predicates_match() OR zasp_authorization80_identity.catalog_ready())
 AND zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd')
 AND EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE identity_mode='source19-canonical61-identity-v1' AND audit_mode='source52-canonical61-audit-v1')
 AND EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE checksum='2e7b7922aa1c6bf9e677d3c1c0b7a8ed8e13890705ec4991e5ec38a21edc4ad6')
$id$;

-- An authorization80-ready profile always requires the auth79 registration and
-- intact seal. Check current login eligibility once, preserving the four typed
-- principals from auth79.reader() and every row-level/permission decision.
DO $fold$
DECLARE fn regprocedure; f text;after text; old_expr text:='NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready(''d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd'')';
 new_expr text:='NOT zasp_authorization80.ready(''d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd'') OR NOT (CASE WHEN zasp_authorization80.release_readiness_predicates_match() THEN public.zasp_discovery_principal_ready(''zasp_discovery_api'') OR public.zasp_discovery_principal_ready(''zasp_outbox_worker'') OR public.zasp_security_agent_principal_ready(''zasp_security_agent_api'') OR public.zasp_security_agent_principal_ready(''zasp_security_agent_worker'') ELSE zasp_authorization79.reader() END)';
BEGIN
 FOREACH fn IN ARRAY ARRAY['zasp_authorization80.fence(text)'::regprocedure,'zasp_authorization80.resolve(text,text,text,text,text,text)'::regprocedure] LOOP
  f:=pg_get_functiondef(fn); IF position(new_expr IN f)>0 THEN CONTINUE;END IF;
  after:=replace(f,old_expr,new_expr);IF after=f THEN RAISE EXCEPTION 'authorization fence guard changed';END IF;EXECUTE after;
 END LOOP;
END $fold$;
