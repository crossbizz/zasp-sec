-- Baseline integrity schema.
--
-- The historical releases verified one another by hashing each other's
-- function bodies and comparing catalog fingerprints with constants recorded
-- when each release was written. A baseline has one catalog, installed at
-- once, so those checks reduce to one question: is the catalog still the one
-- that was installed? zasp_baseline.intact() answers it.
CREATE SCHEMA zasp_baseline;

-- A non-superuser that creates a role is given an ADMIN-only membership in it
-- by the bootstrap superuser (always role 10) and cannot revoke it. Readiness
-- predicates read memberships through this view so that automatic grant is not
-- mistaken for a membership someone chose to make. Where the creator also
-- holds an explicit membership, the two rows are shown as the single row a
-- superuser installation has.
CREATE VIEW zasp_baseline.role_memberships AS
  SELECT m.oid, m.roleid, m.member, m.grantor,
         m.admin_option OR EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members c
           WHERE c.roleid = m.roleid AND c.member = m.member
             AND c.grantor = 10 AND c.admin_option AND NOT c.inherit_option AND NOT c.set_option
         ) AS admin_option,
         m.inherit_option, m.set_option
  FROM pg_catalog.pg_auth_members m
  WHERE NOT (m.grantor = 10 AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option);

-- Extension functions are outside the digests: on managed PostgreSQL they
-- belong to the cluster superuser and change with extension upgrades.
--
-- One row, written once by seal(). `content` is a digest of every definition,
-- owner and privilege in the product schemas and of the product roles:
-- functions (body, arguments and defaults, strictness, volatility, cost,
-- security, settings), relations, columns, constraints, indexes, triggers,
-- rewrite rules, policies, sequences, types, default privileges, roles and
-- memberships.
-- `marker` is a cheap digest of the same catalog rows' versions; it lets
-- intact() answer without hashing every function body.
CREATE TABLE zasp_baseline.seal (
  singleton boolean PRIMARY KEY CHECK (singleton),
  artifact text NOT NULL CHECK (artifact ~ '^[a-f0-9]{64}$'),
  content text NOT NULL CHECK (content ~ '^[a-f0-9]{64}$'),
  marker text NOT NULL,
  sealed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE FUNCTION zasp_baseline.content() RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  WITH scope(oid) AS MATERIALIZED (SELECT n.oid FROM pg_namespace n WHERE n.nspname = 'public' OR n.nspname LIKE 'zasp\_%'),
  facts(v) AS (
    SELECT concat_ws('|', 'schema', n.nspname, n.nspowner::regrole::text, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(COALESCE(n.nspacl, acldefault('n', n.nspowner))) AS i))
      FROM pg_namespace n WHERE n.oid IN (SELECT oid FROM scope)
    UNION ALL
    SELECT concat_ws('|', 'function', p.oid::regprocedure::text, p.proowner::regrole::text, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(COALESCE(p.proacl, acldefault('f', p.proowner))) AS i),
                     p.prosecdef, p.provolatile, p.proleakproof, p.proconfig::text, l.lanname,
                     p.prokind, p.proisstrict, p.proretset, p.proparallel, p.procost, p.prorows,
                     pg_get_function_arguments(p.oid), pg_get_function_result(p.oid), p.prosrc)
      FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang WHERE p.pronamespace IN (SELECT oid FROM scope) AND NOT EXISTS (SELECT 1 FROM pg_depend x WHERE x.classid = 'pg_proc'::regclass AND x.objid = p.oid AND x.deptype = 'e')
    UNION ALL
    SELECT concat_ws('|', 'relation', c.oid::regclass::text, c.relkind, c.relowner::regrole::text, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(COALESCE(c.relacl, acldefault(CASE c.relkind WHEN 'S' THEN 's' ELSE 'r' END::"char", c.relowner))) AS i),
                     c.relrowsecurity, c.relforcerowsecurity, c.relpersistence, c.reloptions::text,
                     CASE WHEN c.relkind IN ('v', 'm') THEN pg_get_viewdef(c.oid) END,
                     CASE WHEN c.relkind = 'i' THEN pg_get_indexdef(c.oid) END)
      FROM pg_class c WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT concat_ws('|', 'column', a.attrelid::regclass::text, a.attname, format_type(a.atttypid, a.atttypmod),
                     a.attnotnull, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(a.attacl) AS i), a.attgenerated, a.attidentity, pg_get_expr(d.adbin, d.adrelid))
      FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
      LEFT JOIN pg_attrdef d ON (d.adrelid, d.adnum) = (a.attrelid, a.attnum)
      WHERE c.relnamespace IN (SELECT oid FROM scope) AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0 AND NOT a.attisdropped
    UNION ALL
    SELECT concat_ws('|', 'constraint', k.conrelid::regclass::text, k.conname, pg_get_constraintdef(k.oid))
      FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
      WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT concat_ws('|', 'trigger', t.tgrelid::regclass::text, t.tgname, t.tgenabled, pg_get_triggerdef(t.oid))
      FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
      WHERE c.relnamespace IN (SELECT oid FROM scope) AND NOT t.tgisinternal
    UNION ALL
    SELECT concat_ws('|', 'rule', w.ev_class::regclass::text, w.rulename, w.ev_type, w.ev_enabled, w.is_instead, pg_get_ruledef(w.oid))
      FROM pg_rewrite w JOIN pg_class c ON c.oid = w.ev_class WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT concat_ws('|', 'sequence', q.seqrelid::regclass::text, format_type(q.seqtypid, NULL), q.seqstart, q.seqincrement, q.seqmax, q.seqmin, q.seqcache, q.seqcycle)
      FROM pg_sequence q JOIN pg_class c ON c.oid = q.seqrelid WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT concat_ws('|', 'policy', p.polrelid::regclass::text, p.polname, p.polcmd, p.polpermissive,
                     p.polroles::regrole[]::text, pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid))
      FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT concat_ws('|', 'type', t.oid::regtype::text, t.typtype, t.typowner::regrole::text, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(COALESCE(t.typacl, acldefault('T', t.typowner))) AS i),
                     format_type(t.typbasetype, t.typtypmod), t.typnotnull)
      FROM pg_type t WHERE t.typnamespace IN (SELECT oid FROM scope) AND t.typtype IN ('d', 'e')
    UNION ALL
    SELECT concat_ws('|', 'default-acl', d.defaclrole::regrole::text, d.defaclnamespace::regnamespace::text, d.defaclobjtype, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(d.defaclacl) AS i))
      FROM pg_default_acl d WHERE d.defaclnamespace = 0 OR d.defaclnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT concat_ws('|', 'role', r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
                     r.rolreplication, r.rolbypassrls, r.rolconfig::text)
      FROM pg_roles r WHERE r.rolname LIKE 'zasp\_%'
    UNION ALL
    SELECT concat_ws('|', 'membership', m.roleid::regrole::text, m.member::regrole::text, m.admin_option, m.inherit_option, m.set_option)
      FROM zasp_baseline.role_memberships m
      WHERE m.roleid::regrole::text LIKE 'zasp\_%' OR m.member::regrole::text LIKE 'zasp\_%'
  )
  SELECT encode(sha256(convert_to(COALESCE(string_agg(md5(v), '' ORDER BY md5(v)), ''), 'UTF8')), 'hex') FROM facts
$$;

CREATE FUNCTION zasp_baseline.marker() RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  WITH scope(oid) AS MATERIALIZED (SELECT n.oid FROM pg_namespace n WHERE n.nspname = 'public' OR n.nspname LIKE 'zasp\_%'),
  versions(v) AS (
    SELECT 'n' || n.oid || '.' || n.xmin::text FROM pg_namespace n WHERE n.oid IN (SELECT oid FROM scope)
    UNION ALL
    SELECT 'f' || p.oid || '.' || p.xmin::text FROM pg_proc p WHERE p.pronamespace IN (SELECT oid FROM scope) AND NOT EXISTS (SELECT 1 FROM pg_depend x WHERE x.classid = 'pg_proc'::regclass AND x.objid = p.oid AND x.deptype = 'e')
    UNION ALL
    SELECT 'c' || c.oid || '.' || c.xmin::text FROM pg_class c
      WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT 'a' || a.attrelid || '.' || a.attnum || '.' || a.xmin::text FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
      WHERE c.relnamespace IN (SELECT oid FROM scope) AND a.attnum > 0
    UNION ALL
    SELECT 'd' || d.oid || '.' || d.xmin::text FROM pg_attrdef d JOIN pg_class c ON c.oid = d.adrelid WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT 'k' || k.oid || '.' || k.xmin::text FROM pg_constraint k WHERE k.connamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT 'y' || t.oid || '.' || t.xmin::text FROM pg_type t WHERE t.typnamespace IN (SELECT oid FROM scope) AND t.typtype IN ('d', 'e')
    UNION ALL
    SELECT 't' || t.oid || '.' || t.xmin::text FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT 'p' || p.oid || '.' || p.xmin::text FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT 'q' || q.seqrelid || '.' || q.xmin::text FROM pg_sequence q JOIN pg_class c ON c.oid = q.seqrelid WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT 'w' || w.oid || '.' || w.xmin::text FROM pg_rewrite w JOIN pg_class c ON c.oid = w.ev_class WHERE c.relnamespace IN (SELECT oid FROM scope)
    UNION ALL
    SELECT 'l' || d.oid || '.' || d.xmin::text FROM pg_default_acl d
    UNION ALL
    SELECT 'r' || concat_ws('.', r.oid, r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin, r.rolreplication, r.rolbypassrls, r.rolconfig::text)
      FROM pg_roles r WHERE r.rolname LIKE 'zasp\_%'
    UNION ALL
    SELECT 'm' || concat_ws('.', m.roleid, m.member, m.grantor, m.admin_option, m.inherit_option, m.set_option) FROM pg_auth_members m
      WHERE EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid IN (m.roleid, m.member) AND r.rolname LIKE 'zasp\_%')
  )
  SELECT md5(COALESCE(string_agg(v, ',' ORDER BY v), '')) FROM versions
$$;

-- True while the catalog is the sealed one. The marker comparison is the fast
-- path. When only row versions moved (VACUUM FULL, REINDEX, a restore) the
-- content digest decides, so maintenance cannot take the product down.
CREATE FUNCTION zasp_baseline.intact() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT COALESCE((
    SELECT CASE WHEN s.marker = zasp_baseline.marker() THEN true ELSE s.content = zasp_baseline.content() END
    FROM zasp_baseline.seal s WHERE s.singleton
  ), false)
$$;

-- seal() records the installed catalog. The installer calls it once, in the
-- installation transaction, through the schema authority. Afterwards it only refreshes the marker, and only
-- when the content digest still matches, so it can never bless a changed
-- catalog.
CREATE FUNCTION zasp_baseline.seal(artifact_value text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE recorded zasp_baseline.seal%ROWTYPE; live text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('zasp-baseline-seal', 0));
  live := zasp_baseline.content();
  SELECT * INTO recorded FROM zasp_baseline.seal WHERE singleton;
  IF NOT FOUND THEN
    IF artifact_value IS NULL OR artifact_value !~ '^[a-f0-9]{64}$' THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'baseline artifact checksum rejected';
    END IF;
    INSERT INTO zasp_baseline.seal(singleton, artifact, content, marker) VALUES (true, artifact_value, live, zasp_baseline.marker());
    RETURN true;
  END IF;
  IF recorded.artifact IS DISTINCT FROM artifact_value OR recorded.content IS DISTINCT FROM live THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'baseline catalog differs from the sealed catalog';
  END IF;
  UPDATE zasp_baseline.seal SET marker = zasp_baseline.marker() WHERE singleton;
  RETURN true;
END $$;

-- accept() re-seals after a reviewed schema change. Only the schema authority
-- can run it; the operator reaches it through its authority membership.
CREATE FUNCTION zasp_baseline.accept(artifact_value text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF artifact_value IS NULL OR artifact_value !~ '^[a-f0-9]{64}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'baseline artifact checksum rejected';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('zasp-baseline-seal', 0));
  DELETE FROM zasp_baseline.seal WHERE singleton;
  INSERT INTO zasp_baseline.seal(singleton, artifact, content, marker)
    VALUES (true, artifact_value, zasp_baseline.content(), zasp_baseline.marker());
  RETURN true;
END $$;

CREATE FUNCTION zasp_baseline.state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT COALESCE((SELECT jsonb_build_object('sealed', true, 'artifact', s.artifact, 'intact', zasp_baseline.intact(), 'sealed_at', s.sealed_at)
                   FROM zasp_baseline.seal s WHERE s.singleton), jsonb_build_object('sealed', false, 'intact', false))
$$;

ALTER TABLE zasp_baseline.seal ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON SCHEMA zasp_baseline FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA zasp_baseline FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zasp_baseline FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_baseline TO PUBLIC;
GRANT SELECT ON zasp_baseline.role_memberships TO PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_baseline.intact(), zasp_baseline.state(), zasp_baseline.marker(), zasp_baseline.content() TO PUBLIC;
