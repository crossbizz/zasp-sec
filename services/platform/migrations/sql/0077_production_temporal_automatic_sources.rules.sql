-- A persisted rule is versioned intent. It is not admission authority.
CREATE FUNCTION zasp_temporal77.rule_text(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $text$
 SELECT COALESCE(jsonb_typeof(v)='string' AND octet_length(v#>>'{}') BETWEEN 1 AND 64 AND (v#>>'{}')!~'[[:cntrl:]]|^[[:space:]]|[[:space:]]$',false)
$text$;
CREATE FUNCTION zasp_temporal77.rule_integer(v jsonb,maximum integer) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $integer$
 SELECT CASE WHEN jsonb_typeof(v)='number' AND v::text~'^[1-9][0-9]{0,5}$' THEN v::text::integer BETWEEN 1 AND maximum ELSE false END
$integer$;
CREATE FUNCTION zasp_temporal77.rules_valid(b jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $rules$
DECLARE r jsonb;n jsonb;k text;
BEGIN
 IF jsonb_typeof(b) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF NOT b ? 'trigger_rules' THEN RETURN true;END IF;
 r:=b->'trigger_rules';
 IF jsonb_typeof(r) IS DISTINCT FROM 'object' OR octet_length(r::text)>2048 OR NOT zasp_temporal77.rule_integer(r->'version',1) THEN RETURN false;END IF;
 IF r->>'mode'='manual' THEN RETURN zasp_sa_multistep_prior.closed(r,ARRAY['version','mode']);END IF;
 k:=CASE b->>'trigger_kind' WHEN 'finding' THEN 'finding' WHEN 'attack_path' THEN 'attack_path' WHEN 'runtime_decision' THEN 'runtime' ELSE '' END;
 IF r->>'mode' IS DISTINCT FROM 'automatic' OR NOT zasp_sa_multistep_prior.closed(r,ARRAY['version','mode','cooldown_seconds',k]) OR NOT zasp_temporal77.rule_integer(r->'cooldown_seconds',86400) THEN RETURN false;END IF;
 n:=r->k;
 IF k='finding' THEN RETURN COALESCE(zasp_sa_multistep_prior.closed(n,ARRAY['family','minimum_severity']) AND zasp_temporal77.rule_text(n->'family') AND n->>'family'=b->>'trigger_source' AND n->>'minimum_severity' IN('low','medium','high','critical'),false);END IF;
 IF k='attack_path' THEN RETURN COALESCE(zasp_sa_multistep_prior.closed(n,ARRAY['state']) AND n->>'state' IN('potential','observed','verified') AND n->>'state'=b->>'trigger_source',false);END IF;
 IF k='runtime' THEN RETURN COALESCE(zasp_sa_multistep_prior.closed(n,ARRAY['decision','action','count','window_seconds']||CASE WHEN n ? 'risk' THEN ARRAY['risk'] ELSE ARRAY[]::text[] END) AND n->>'decision' IN('allow','monitor','block') AND zasp_temporal77.rule_text(n->'action') AND zasp_temporal77.rule_integer(n->'count',100) AND zasp_temporal77.rule_integer(n->'window_seconds',86400) AND (NOT n ? 'risk' OR n->>'risk' IN('low','medium','high','critical')),false);END IF;
 RETURN false;
END $rules$;

-- Staged adapter support is explicit. Potential/runtime and other responder
-- families remain unavailable; human admission never gains service provenance.
CREATE FUNCTION zasp_temporal77.rules_capable(b jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $capability$
 SELECT NOT b ? 'trigger_rules' OR COALESCE(
 b->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) AND b->>'verification_kind'='test_run'
 AND (b->'trigger_rules'->>'mode'='manual' OR b->>'trigger_kind'='finding' OR b->>'trigger_kind'='attack_path' AND b->>'trigger_source' IN('observed','verified')),false)
$capability$;
CREATE FUNCTION zasp_temporal77.definition_guard() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
BEGIN
 IF NOT NEW.body ? 'trigger_rules' THEN RETURN NEW;END IF;
 IF NOT zasp_temporal77.ready('-- automatic77 checksum','-- automatic77 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='automatic trigger authority unavailable';END IF;
 IF NOT zasp_temporal77.rules_valid(NEW.body) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='automatic trigger rules rejected';END IF;
 IF NEW.activation<>'draft' AND NOT zasp_temporal77.rules_capable(NEW.body) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='automatic trigger action/source capability unavailable';END IF;
 RETURN NEW;
END $guard$;
CREATE TRIGGER zasp_temporal77_definition_guard BEFORE INSERT OR UPDATE ON public.zasp_security_agent_definitions FOR EACH ROW EXECUTE FUNCTION zasp_temporal77.definition_guard();
DO $existing$ BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions WHERE body ? 'trigger_rules' AND (NOT zasp_temporal77.rules_valid(body) OR activation<>'draft')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='preexisting trigger configuration requires disabled valid draft';END IF;
END $existing$;
