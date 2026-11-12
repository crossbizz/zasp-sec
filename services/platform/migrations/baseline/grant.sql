-- Temporary privileges for the ownership pass. Runs inside the installation
-- transaction after every object exists, still owned by the operator.
-- Requires the transaction-local setting zasp_baseline.owners: the
-- comma-separated roles the artifact assigns ownership to.
--
-- Handing an object to a role needs two things the finished catalog does not
-- have: the operator must be a member of the role, and the role needs CREATE
-- on the object's schema. Only privileges that are actually missing are
-- granted, and each one is recorded so revoke.sql removes exactly those.
CREATE TEMPORARY TABLE zasp_baseline_temporary_grants (role_name name NOT NULL, schema_name name NOT NULL) ON COMMIT DROP;
DO $grant$
DECLARE r record;
BEGIN
  FOR r IN SELECT o.role_name::name AS role_name, n.nspname AS schema_name
           FROM unnest(string_to_array(current_setting('zasp_baseline.owners'), ',')) AS o(role_name)
           CROSS JOIN pg_catalog.pg_namespace n
           WHERE (n.nspname = 'public' OR n.nspname LIKE 'zasp\_%')
             AND NOT pg_catalog.has_schema_privilege(o.role_name::name, n.oid, 'CREATE')
           ORDER BY 1, 2 LOOP
    EXECUTE format('GRANT CREATE ON SCHEMA %I TO %I', r.schema_name, r.role_name);
    INSERT INTO zasp_baseline_temporary_grants VALUES (r.role_name, r.schema_name);
  END LOOP;
  FOR r IN SELECT o.role_name::name AS role_name
           FROM unnest(string_to_array(current_setting('zasp_baseline.owners'), ',')) AS o(role_name)
           WHERE o.role_name <> 'zasp_discovery_authority' ORDER BY 1 LOOP
    EXECUTE format('GRANT %I TO zasp_operator WITH INHERIT TRUE, SET TRUE', r.role_name);
  END LOOP;
END $grant$;
