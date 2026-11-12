-- Structural facts of the product catalog: every schema, relation, column,
-- constraint, index, trigger, policy, function signature, owner, privilege,
-- role and membership. Function bodies and their language are left out
-- because the baseline rewrites the historical self-verification inside them
-- (rules.sql), which turns some PL/pgSQL checks into SQL ones.
-- generate.sh runs this on the superuser installation and on the baseline
-- and requires the two outputs to be identical. :memberships names the
-- relation memberships are read from.
--
-- Three things are normalised because a dump and restore changes how they are
-- stored without changing what they mean: an ACL that equals the owner's
-- default is stored as NULL and ACL entries are re-added in another order; expressions are re-parsed, which regroups
-- parentheses and prints the implicit "AS text" column alias of a cast in
-- UNION branches; and extension functions (pgcrypto) belong to the cluster
-- superuser when a non-superuser creates a trusted extension.
WITH scope(oid) AS MATERIALIZED (
  SELECT n.oid FROM pg_namespace n WHERE (n.nspname = 'public' OR n.nspname LIKE 'zasp\_%') AND n.nspname <> 'zasp_baseline'
), facts(v) AS (
  SELECT concat_ws('|', 'schema', n.nspname, n.nspowner::regrole::text, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(COALESCE(n.nspacl, acldefault('n', n.nspowner))) AS i)) FROM pg_namespace n WHERE n.oid IN (SELECT oid FROM scope)
  UNION ALL
  SELECT concat_ws('|', 'function', p.oid::regprocedure::text, p.proowner::regrole::text, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(COALESCE(p.proacl, acldefault('f', p.proowner))) AS i), p.prosecdef, p.provolatile,
                   p.proleakproof, p.proconfig::text, p.prokind, p.proisstrict, p.proretset, p.proparallel,
                   translate(pg_get_function_arguments(p.oid), '()', ''), pg_get_function_result(p.oid))
    FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang WHERE p.pronamespace IN (SELECT oid FROM scope) AND NOT EXISTS (SELECT 1 FROM pg_depend x WHERE x.classid = 'pg_proc'::regclass AND x.objid = p.oid AND x.deptype = 'e')
  UNION ALL
  SELECT concat_ws('|', 'relation', c.oid::regclass::text, c.relkind, c.relowner::regrole::text, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(COALESCE(c.relacl, acldefault(CASE c.relkind WHEN 'S' THEN 's' ELSE 'r' END::"char", c.relowner))) AS i), c.relrowsecurity,
                   c.relforcerowsecurity, c.reloptions::text,
                   CASE WHEN c.relkind IN ('v', 'm') THEN replace(translate(regexp_replace(pg_get_viewdef(c.oid), '\s+', ' ', 'g'), '()', ''), ' AS text', '') END,
                   CASE WHEN c.relkind = 'i' THEN pg_get_indexdef(c.oid) END)
    FROM pg_class c WHERE c.relnamespace IN (SELECT oid FROM scope)
  UNION ALL
  SELECT concat_ws('|', 'column', a.attrelid::regclass::text, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(a.attacl) AS i),
                   a.attgenerated, a.attidentity, translate(regexp_replace(pg_get_expr(d.adbin, d.adrelid), '\s+', ' ', 'g'), '()', ''))
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid LEFT JOIN pg_attrdef d ON (d.adrelid, d.adnum) = (a.attrelid, a.attnum)
    WHERE c.relnamespace IN (SELECT oid FROM scope) AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0 AND NOT a.attisdropped
  UNION ALL
  SELECT concat_ws('|', 'constraint', k.conrelid::regclass::text, k.conname, translate(regexp_replace(pg_get_constraintdef(k.oid), '\s+', ' ', 'g'), '()', ''))
    FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid WHERE c.relnamespace IN (SELECT oid FROM scope)
  UNION ALL
  SELECT concat_ws('|', 'trigger', t.tgrelid::regclass::text, t.tgname, t.tgenabled, pg_get_triggerdef(t.oid))
    FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE c.relnamespace IN (SELECT oid FROM scope) AND NOT t.tgisinternal
  UNION ALL
  SELECT concat_ws('|', 'rule', w.ev_class::regclass::text, w.rulename, w.ev_type, w.ev_enabled, w.is_instead)
    FROM pg_rewrite w JOIN pg_class c ON c.oid = w.ev_class WHERE c.relnamespace IN (SELECT oid FROM scope)
  UNION ALL
  SELECT concat_ws('|', 'sequence', q.seqrelid::regclass::text, format_type(q.seqtypid, NULL), q.seqstart, q.seqincrement, q.seqmax, q.seqmin, q.seqcache, q.seqcycle)
    FROM pg_sequence q JOIN pg_class c ON c.oid = q.seqrelid WHERE c.relnamespace IN (SELECT oid FROM scope)
  UNION ALL
  SELECT concat_ws('|', 'policy', p.polrelid::regclass::text, p.polname, p.polcmd, p.polpermissive, p.polroles::regrole[]::text,
                   translate(regexp_replace(pg_get_expr(p.polqual, p.polrelid), '\s+', ' ', 'g'), '()', ''), translate(regexp_replace(pg_get_expr(p.polwithcheck, p.polrelid), '\s+', ' ', 'g'), '()', ''))
    FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid WHERE c.relnamespace IN (SELECT oid FROM scope)
  UNION ALL
  SELECT concat_ws('|', 'type', t.oid::regtype::text, t.typtype, t.typowner::regrole::text, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(COALESCE(t.typacl, acldefault('T', t.typowner))) AS i), format_type(t.typbasetype, t.typtypmod), t.typnotnull)
    FROM pg_type t WHERE t.typnamespace IN (SELECT oid FROM scope) AND t.typtype IN ('d', 'e')
  UNION ALL
  SELECT concat_ws('|', 'default-acl', d.defaclrole::regrole::text, d.defaclnamespace::regnamespace::text, d.defaclobjtype, (SELECT string_agg(i::text, ',' ORDER BY i::text) FROM unnest(d.defaclacl) AS i)) FROM pg_default_acl d
  UNION ALL
  SELECT concat_ws('|', 'role', r.rolname, r.rolinherit, r.rolcanlogin, r.rolreplication, r.rolconfig::text)
    FROM pg_roles r WHERE r.rolname LIKE 'zasp\_%' AND r.rolname <> 'zasp_operator'
  UNION ALL
  SELECT concat_ws('|', 'membership', m.roleid::regrole::text, m.member::regrole::text, m.admin_option, m.inherit_option, m.set_option)
    FROM :memberships m WHERE m.roleid::regrole::text LIKE 'zasp\_%' OR m.member::regrole::text LIKE 'zasp\_%'
)
SELECT v FROM facts ORDER BY v;
