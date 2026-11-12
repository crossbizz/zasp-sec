-- Generator-time rewrite rules. They run once, when the baseline artifact is
-- built, never at install time.
--
-- The historical layers verify one another by hashing each other's function
-- definitions and comparing catalog fingerprints with constants recorded when
-- each release was written. A baseline has one catalog, installed at once, so
-- those cross-checks reduce to one question: is the catalog still the one that
-- was installed? Each rule below rewrites a family of functions to ask that.
-- Every rule must match at least one function, so a change in the historical
-- chain that a rule no longer covers stops the generator.
DO $rules$
DECLARE f record; definition text; rewritten text; constants text[]; matched integer;
BEGIN
  -- R2: per-layer catalog checks.
  matched := 0;
  FOR f IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
           WHERE n.nspname LIKE 'zasp\_%' AND n.nspname<>'zasp_baseline' AND p.proname='catalog_ready' AND p.pronargs=0 AND p.prorettype='bool'::regtype LOOP
    definition := pg_get_functiondef(f.oid);
    rewritten := regexp_replace(definition, 'LANGUAGE \w+', 'LANGUAGE sql');
    rewritten := regexp_replace(rewritten, 'AS \$function\$.*\$function\$', 'AS $function$ SELECT zasp_baseline.intact() $function$');
    EXECUTE rewritten;
    matched := matched + 1;
  END LOOP;
  IF matched = 0 THEN RAISE EXCEPTION 'baseline rewrite rule 1 matched no function'; END IF;
  -- R3: layer readiness keeps the identity the caller must present and
  -- replaces the cross-layer hashing with the integrity check.
  matched := 0;
  FOR f IN SELECT p.oid, p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
           WHERE n.nspname LIKE 'zasp\_%' AND n.nspname<>'zasp_baseline' AND p.proname='ready' AND p.pronargs=2 AND p.prorettype='bool'::regtype LOOP
    constants := regexp_match(f.prosrc, 'c\s*=\s*''([a-f0-9]{64})''\s+AND\s+f\s*=\s*''([a-f0-9]{64})''');
    IF constants IS NULL THEN CONTINUE; END IF;
    definition := pg_get_functiondef(f.oid);
    rewritten := regexp_replace(definition, 'LANGUAGE \w+', 'LANGUAGE sql');
    rewritten := regexp_replace(rewritten, 'AS \$function\$.*\$function\$',
      format('AS $function$ SELECT COALESCE(c=%L AND f=%L AND zasp_baseline.intact(),false) $function$', constants[1], constants[2]));
    EXECUTE rewritten;
    matched := matched + 1;
  END LOOP;
  IF matched = 0 THEN RAISE EXCEPTION 'baseline rewrite rule 2 matched no function'; END IF;
  -- R4: inline comparisons of a live fingerprint with a recorded constant.
  matched := 0;
  FOR f IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
           WHERE n.nspname LIKE 'zasp\_%' AND n.nspname<>'zasp_baseline' AND p.prosrc ~ '[a-z0-9_.]*fingerprint\(\)\s*=\s*''[a-f0-9]{64}''' LOOP
    definition := pg_get_functiondef(f.oid);
    EXECUTE regexp_replace(definition, '[a-z0-9_.]*fingerprint\(\)\s*=\s*''[a-f0-9]{64}''', 'zasp_baseline.intact()', 'g');
    matched := matched + 1;
  END LOOP;
  IF matched = 0 THEN RAISE EXCEPTION 'baseline rewrite rule 3 matched no function'; END IF;
  -- R5: pins on the exact body of another layer's function. The integrity
  -- check covers every function body, so the pin is redundant.
  matched := 0;
  FOR f IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
           WHERE n.nspname LIKE 'zasp\_%' AND n.nspname<>'zasp_baseline' AND p.prosrc ~ 'digest\(convert_to\([a-z_.]*prosrc' LOOP
    definition := pg_get_functiondef(f.oid);
    EXECUTE regexp_replace(definition, 'encode\(digest\(convert_to\([a-z_.]*prosrc,''UTF8''\),''sha256''\),''hex''\)\s*=\s*''[a-f0-9]{64}''', 'zasp_baseline.intact()', 'g');
    matched := matched + 1;
  END LOOP;
  IF matched = 0 THEN RAISE EXCEPTION 'baseline rewrite rule 4 matched no function'; END IF;
  matched := 0;
  FOR f IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
           WHERE n.nspname LIKE 'zasp\_%' AND n.nspname<>'zasp_baseline' AND p.prosrc ~ 'AND prosrc=''' LOOP
    definition := pg_get_functiondef(f.oid);
    EXECUTE regexp_replace(definition, 'AND prosrc=''(''''|[^''])*''', 'AND zasp_baseline.intact()', 'g');
    matched := matched + 1;
  END LOOP;
  IF matched = 0 THEN RAISE EXCEPTION 'baseline rewrite rule 5 matched no function'; END IF;
  -- R6: comparisons of a registration's recorded fingerprint with the live one.
  matched := 0;
  FOR f IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
           WHERE n.nspname LIKE 'zasp\_%' AND n.nspname<>'zasp_baseline' AND p.prosrc ~ 'fingerprint\s*=\s*zasp_[a-z0-9_]+\.fingerprint\(\)' LOOP
    definition := pg_get_functiondef(f.oid);
    EXECUTE regexp_replace(definition, '(\m[a-z]+\.)?fingerprint\s*=\s*zasp_[a-z0-9_]+\.fingerprint\(\)', 'zasp_baseline.intact()', 'g');
    matched := matched + 1;
  END LOOP;
  IF matched = 0 THEN RAISE EXCEPTION 'baseline rewrite rule 6 matched no function'; END IF;
  -- R8: the worker startup gate. The historical profile shipped it closed
  -- ("AND false") while its planning, test, discovery and policy consumers
  -- were being written. They are part of this catalog, so the gate follows
  -- the catalog's integrity.
  definition := pg_get_functiondef('zasp_authorization80_worker.runtime_ready()'::regprocedure);
  IF position('zasp_temporal78.current_ready() AND false' IN definition) = 0 THEN
    RAISE EXCEPTION 'baseline rewrite rule for the worker gate matched nothing';
  END IF;
  EXECUTE replace(definition, 'zasp_temporal78.current_ready() AND false', 'zasp_temporal78.current_ready() AND zasp_baseline.intact()');
END $rules$;
