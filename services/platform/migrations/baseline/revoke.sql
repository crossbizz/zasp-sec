-- Removes the temporary privileges grant.sql recorded. A role that now owns a
-- schema keeps CREATE on it: that is the owner's own privilege, and revoking
-- it would leave the owner unable to create in its own schema. The operator
-- keeps one membership, in zasp_discovery_authority, which roles.sql grants.
DO $revoke$
DECLARE r record;
BEGIN
  FOR r IN SELECT g.role_name, g.schema_name FROM zasp_baseline_temporary_grants g
           JOIN pg_catalog.pg_namespace n ON n.nspname = g.schema_name
           JOIN pg_catalog.pg_roles owner ON owner.oid = n.nspowner
           WHERE owner.rolname <> g.role_name ORDER BY 1, 2 LOOP
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I', r.schema_name, r.role_name);
  END LOOP;
  FOR r IN SELECT o.role_name::name AS role_name
           FROM unnest(string_to_array(current_setting('zasp_baseline.owners'), ',')) AS o(role_name)
           WHERE o.role_name <> 'zasp_discovery_authority' ORDER BY 1 LOOP
    EXECUTE format('REVOKE %I FROM zasp_operator', r.role_name);
  END LOOP;
END $revoke$;
