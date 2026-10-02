-- Historical audit bytes remain immutable. Re-render only proven equal
-- timestamp instants in the expected row, then retain the original full JSON
-- comparison. Unknown fields, missing fields and all non-time values still
-- participate in that comparison.
CREATE FUNCTION zasp_authorization80_worker.planner_receipt_row(captured jsonb,actual jsonb,kind text) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,public AS $receipt_row$
DECLARE names text[];name text;rendered jsonb:=actual;pattern text:='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?[+-][0-9]{2}:[0-9]{2}$';
BEGIN
 IF jsonb_typeof(captured) IS DISTINCT FROM 'object' OR jsonb_typeof(actual) IS DISTINCT FROM 'object' THEN RETURN NULL;END IF;
 names:=CASE kind WHEN 'job' THEN ARRAY['budget_started_at','budget_deadline_at'] WHEN 'reservation' THEN ARRAY['reserved_at','settled_at','released_at'] ELSE NULL END;
 IF names IS NULL THEN RETURN NULL;END IF;
 FOREACH name IN ARRAY names LOOP
  IF (captured?name) IS DISTINCT FROM(actual?name) THEN RETURN NULL;END IF;
  IF NOT(actual?name) THEN CONTINUE;END IF;
  IF actual->name='null'::jsonb THEN
   IF captured->name IS DISTINCT FROM 'null'::jsonb THEN RETURN NULL;END IF;
  ELSE
   IF jsonb_typeof(captured->name) IS DISTINCT FROM 'string' OR jsonb_typeof(actual->name) IS DISTINCT FROM 'string'
    OR NOT(captured->>name ~ pattern) OR NOT(actual->>name ~ pattern)
    OR (captured->>name)::timestamptz IS DISTINCT FROM(actual->>name)::timestamptz THEN RETURN NULL;END IF;
   rendered:=jsonb_set(rendered,ARRAY[name],captured->name);
  END IF;
 END LOOP;
 RETURN rendered;
EXCEPTION WHEN data_exception THEN RETURN NULL;
END $receipt_row$;

-- Transient signed facts need one representation across pooled sessions.
-- This hashes the complete job, normalizing only its two typed timestamp
-- columns. Context/provider strings and every other field stay unchanged.
CREATE FUNCTION zasp_authorization80_worker.planner_job_digest(j jsonb) RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public SET timezone='UTC' AS $job_digest$
 SELECT encode(digest(convert_to(COALESCE((j||jsonb_build_object('budget_started_at',(j->>'budget_started_at')::timestamptz,'budget_deadline_at',(j->>'budget_deadline_at')::timestamptz))::text,'null'),'UTF8'),'sha256'),'hex')
$job_digest$;

-- Capture original function identities before modifying any consumer. The
-- installer has already verified the exact predecessor graph. Its projections
-- preserve those identities while the worker catalog hashes live replacements.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT p.oid::regprocedure::text,pg_get_functiondef(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,'') FROM pg_proc p
 WHERE p.oid=ANY(ARRAY[
 'zasp_temporal68.planning_terminal_valid(text,text,text,text)'::regprocedure,'zasp_temporal68.late_usage_valid(text,text,text,text)'::regprocedure,
 'zasp_temporal74.planning_terminal_valid(text,text,text,text)'::regprocedure,'zasp_temporal74.late_usage_valid(text,text,text,text)'::regprocedure,
 'zasp_temporal78.planning_terminal_valid(text,text,text,text)'::regprocedure,'zasp_temporal78.late_usage_valid(text,text,text,text)'::regprocedure]);
DO $portable_validators$ DECLARE source record;d text;needle text;replacement text;namespace text;kind text;BEGIN
 FOREACH namespace IN ARRAY ARRAY['zasp_temporal68','zasp_temporal74','zasp_temporal78'] LOOP
  FOREACH kind IN ARRAY ARRAY['planning_terminal_valid','late_usage_valid'] LOOP
   SELECT * INTO STRICT source FROM zasp_authorization80_worker.predecessor_functions WHERE signature=namespace||'.'||kind||'(text,text,text,text)';
   IF source.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='planner receipt predecessor owner changed';END IF;
   d:=source.definition;
   needle:='to_jsonb(j)';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='planner job receipt predecessor changed';END IF;
   d:=replace(d,needle,$job$zasp_authorization80_worker.planner_receipt_row(a.body->'job',to_jsonb(j),'job')$job$);
   IF kind='planning_terminal_valid' THEN
    needle:='to_jsonb(p)';
    IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='planner reservation receipt predecessor changed';END IF;
    d:=replace(d,needle,$reservation$zasp_authorization80_worker.planner_receipt_row(a.body->'reservation',to_jsonb(p),'reservation')$reservation$);
    -- jsonb_build_object coerces SQL NULL to JSON null. A rejected helper
    -- result must never become equal to a malformed captured null row.
    needle:=' AND a.body=jsonb_build_object(';
    IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='planner terminal body predecessor changed';END IF;
    d:=replace(d,needle,$guard$ AND zasp_authorization80_worker.planner_receipt_row(a.body->'job',to_jsonb(j),'job') IS NOT NULL
  AND (p.run_id IS NULL OR zasp_authorization80_worker.planner_receipt_row(a.body->'reservation',to_jsonb(p),'reservation') IS NOT NULL)
  AND a.body=jsonb_build_object($guard$);
   ELSE
    needle:=$original$to_jsonb(p)-ARRAY['settled_at','output_digest','prompt_tokens','completion_tokens','total_tokens','cost_nano_credits']$original$;
    replacement:=$original$zasp_authorization80_worker.planner_receipt_row(original-ARRAY['settled_at','output_digest','prompt_tokens','completion_tokens','total_tokens','cost_nano_credits'],to_jsonb(p)-ARRAY['settled_at','output_digest','prompt_tokens','completion_tokens','total_tokens','cost_nano_credits'],'reservation')$original$;
    IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='planner original charge receipt predecessor changed';END IF;
    d:=replace(d,needle,replacement);
    needle:=$later$l.body->'reservation'=to_jsonb(p)$later$;
    IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='planner later charge receipt predecessor changed';END IF;
    d:=replace(d,needle,$later$l.body->'reservation'=zasp_authorization80_worker.planner_receipt_row(l.body->'reservation',to_jsonb(p),'reservation')$later$);
   END IF;
   EXECUTE d;
  END LOOP;
 END LOOP;
END $portable_validators$;
