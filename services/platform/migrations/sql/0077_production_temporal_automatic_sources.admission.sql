-- Permanent occurrence decisions are distinct from mutable cooldown state.
-- Neither table owns delivery, retry timers or execution leases.
CREATE TABLE zasp_temporal77.occurrences(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,definition_id text NOT NULL,event_id text NOT NULL,
 definition_version bigint NOT NULL,definition_digest bytea NOT NULL CHECK(octet_length(definition_digest)=32),
 disposition text NOT NULL CHECK(disposition IN('admitted','cooldown','consumed')),run_id text,
 snapshot jsonb NOT NULL,snapshot_digest bytea NOT NULL CHECK(snapshot_digest=digest(convert_to(snapshot::text,'UTF8'),'sha256')),
 decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,event_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,event_id) REFERENCES zasp_temporal77.source_events(organization_id,workspace_id,environment_id,event_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK((disposition='cooldown')=(run_id IS NULL))
);
CREATE TABLE zasp_temporal77.cooldowns(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,definition_id text NOT NULL,pattern_key bytea NOT NULL CHECK(octet_length(pattern_key)=32),
 admitted_at timestamptz NOT NULL,admitted_until timestamptz NOT NULL CHECK(admitted_until>admitted_at),
 PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,pattern_key)
);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['occurrences','cooldowns'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal77.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal77.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal77.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal77.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
 END LOOP;
END $tables$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal77.occurrences FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

-- A rule-blind75 or retained selector cannot admit configured automatic work.
-- Existing API human authority remains responsible for human admission.
CREATE FUNCTION zasp_temporal77.run_guard() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
DECLARE d public.zasp_security_agent_definitions%ROWTYPE;BEGIN
 SELECT * INTO d FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version);
 IF NOT d.body ? 'trigger_rules' THEN RETURN NEW;END IF;
 IF NOT zasp_temporal77.ready('-- automatic77 checksum','-- automatic77 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='automatic admission catalog unavailable';END IF;
 IF public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RETURN NEW;END IF;
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') OR NOT EXISTS(
  SELECT 1 FROM zasp_temporal77.occurrences a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version,a.run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version,NEW.run_id)
  AND a.disposition='admitted' AND a.definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256')
 ) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='configured automatic occurrence decision required';END IF;
 RETURN NEW;
END $guard$;
CREATE TRIGGER zasp_temporal77_occurrence_guard BEFORE INSERT ON public.zasp_security_agent_runs FOR EACH ROW EXECUTE FUNCTION zasp_temporal77.run_guard();

CREATE FUNCTION zasp_temporal77.admit_occurrence(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $admit$
DECLARE ref jsonb:=q->'ref';o text:=ref->>'organization_id';w text:=ref->>'workspace_id';e text:=ref->>'environment_id';d text:=ref->>'definition_id';id_value text:=q->>'event_id';
 def public.zasp_security_agent_definitions%ROWTYPE;s zasp_temporal77.source_events%ROWTYPE;prior zasp_temporal77.occurrences%ROWTYPE;legacy public.zasp_security_agent_trigger_receipts%ROWTYPE;
 grant_value jsonb;matched jsonb;until_value timestamptz;now_value timestamptz;disposition_value text;run_value text;result_value jsonb;
BEGIN
 PERFORM zasp_temporal77.require_executor();
 IF NOT COALESCE(zasp_sa_multistep_prior.closed(q,ARRAY['ref','revision','event_id']) AND zasp_sa_multistep_prior.closed(ref,ARRAY['organization_id','workspace_id','environment_id','definition_id'])
 AND public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(id_value)
 AND jsonb_typeof(q->'revision')='number' AND q->>'revision'~'^[1-9][0-9]{0,6}$' AND (q->>'revision')::bigint<=1000000,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='automatic occurrence scope rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('test-selector75-configuration',0));
 IF NOT EXISTS(SELECT 1 FROM zasp_temporal75.configuration WHERE revision=(q->>'revision')::bigint AND enabled AND revision=(SELECT max(revision) FROM zasp_temporal75.configuration)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic selector configuration changed';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT * INTO def FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic definition scope denied';END IF;
 IF def.deleted_at IS NOT NULL OR def.activation NOT IN('supervised','autonomous') OR def.body->>'autonomy' IS DISTINCT FROM def.activation OR def.body->'enabled' IS DISTINCT FROM 'true'::jsonb
 OR def.body->'trigger_rules'->>'mode' IS DISTINCT FROM 'automatic' THEN RETURN jsonb_build_object('disposition','ignored');END IF;
 IF NOT zasp_temporal77.rules_valid(def.body) OR NOT zasp_temporal77.rules_capable(def.body) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic adapter unavailable';END IF;
 grant_value:=zasp_temporal74.authorize(o,w,e,d,def.version);
 SELECT * INTO s FROM zasp_temporal77.source_events WHERE(organization_id,workspace_id,environment_id,event_id)=(o,w,e,id_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic source scope denied';END IF;
 SELECT * INTO prior FROM zasp_temporal77.occurrences WHERE(organization_id,workspace_id,environment_id,definition_id,event_id)=(o,w,e,d,id_value);
 IF FOUND THEN RETURN jsonb_strip_nulls(jsonb_build_object('disposition','replayed','run_id',prior.run_id,'original_disposition',prior.disposition));END IF;
 -- Registered finding/path writers lock their parent before replacing children.
 IF s.source_kind='finding' THEN PERFORM 1 FROM public.zasp_risk_findings WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,s.source_id) FOR SHARE;
 ELSIF s.source_kind='attack_path' THEN PERFORM 1 FROM public.zasp_risk_attack_paths WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,s.source_id) FOR SHARE;
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime automatic adapter unavailable';END IF;
 now_value:=clock_timestamp();matched:=zasp_temporal77.source_match(o,w,e,id_value,def.body,now_value);
 IF matched IS NULL THEN RETURN jsonb_build_object('disposition','ignored');END IF;
 -- Pre77 receipts permanently consumed the same scoped source occurrence.
 -- Never send these through75's same-definition-version replay branch.
 SELECT tr.* INTO legacy FROM public.zasp_security_agent_trigger_receipts tr JOIN public.zasp_security_agent_runs r ON(r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.definition_id)=(tr.organization_id,tr.workspace_id,tr.environment_id,tr.run_id,tr.definition_id)
 WHERE(tr.organization_id,tr.workspace_id,tr.environment_id,tr.definition_id,tr.trigger_id,tr.trigger_version,tr.trigger_kind)=(o,w,e,d,s.source_id,s.source_version,s.source_kind) FOR SHARE OF tr,r;
 IF FOUND THEN disposition_value:='consumed';run_value:=legacy.run_id;
 ELSE
  SELECT admitted_until INTO until_value FROM zasp_temporal77.cooldowns WHERE(organization_id,workspace_id,environment_id,definition_id,pattern_key)=(o,w,e,d,decode(matched->>'cooldown_key','hex'));
  IF until_value IS NOT NULL AND now_value<until_value THEN disposition_value:='cooldown';
  ELSE
   disposition_value:='admitted';
   run_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',concat_ws(chr(31),d,def.version,s.source_kind,s.source_id,s.source_version));
  END IF;
 END IF;
 INSERT INTO zasp_temporal77.occurrences(organization_id,workspace_id,environment_id,definition_id,event_id,definition_version,definition_digest,disposition,run_id,snapshot,snapshot_digest)
 VALUES(o,w,e,d,id_value,def.version,digest(convert_to(def.body::text,'UTF8'),'sha256'),disposition_value,run_value,matched->'evidence',decode(matched->>'digest','hex'));
 IF disposition_value='admitted' THEN
  result_value:=zasp_temporal75.admit_body(o,w,e,d,def.version,s.source_kind,s.source_id,s.source_version,run_value,grant_value->>'principal_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_audit',run_value),public.zasp_discovery_canonical_id(o,w,e,'security_agent_correlation',run_value),true);
  IF result_value->'created' IS DISTINCT FROM 'true'::jsonb OR result_value->>'id' IS DISTINCT FROM run_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='automatic admission changed';END IF;
  INSERT INTO zasp_temporal77.cooldowns VALUES(o,w,e,d,decode(matched->>'cooldown_key','hex'),now_value,now_value+make_interval(secs=>(def.body->'trigger_rules'->>'cooldown_seconds')::integer))
   ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,pattern_key) DO UPDATE SET admitted_at=EXCLUDED.admitted_at,admitted_until=EXCLUDED.admitted_until;
 END IF;
 PERFORM zasp_temporal74.authorize(o,w,e,d,def.version);
 IF zasp_temporal77.source_match(o,w,e,id_value,def.body,clock_timestamp()) IS DISTINCT FROM matched THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='automatic source changed after admission';END IF;
 RETURN jsonb_strip_nulls(jsonb_build_object('disposition',disposition_value,'run_id',run_value));
END $admit$;
