-- Indexed pending delivery avoids walking acknowledged lifetime history. These
-- rows carry only attempt order, never a claim, lease, timer or completion flag.
CREATE TABLE zasp_temporal77.source_pending(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,event_id text NOT NULL,last_attempt_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,event_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,event_id) REFERENCES zasp_temporal77.source_events(organization_id,workspace_id,environment_id,event_id)
);
CREATE INDEX source_pending_order ON zasp_temporal77.source_pending(last_attempt_at,organization_id,workspace_id,environment_id,event_id);
CREATE TABLE zasp_temporal77.source_acceptances(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,event_id text NOT NULL,workflow_id text NOT NULL,accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,event_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,event_id) REFERENCES zasp_temporal77.source_events(organization_id,workspace_id,environment_id,event_id),
 CHECK(workflow_id='automatic-source/v1/'||organization_id||'/'||workspace_id||'/'||environment_id||'/'||event_id)
);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['source_pending','source_acceptances'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal77.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal77.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal77.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal77.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
 END LOOP;
END $tables$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal77.source_acceptances FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE FUNCTION zasp_temporal77.enqueue_source() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $enqueue$
BEGIN
 IF TG_TABLE_SCHEMA<>'zasp_temporal77' OR TG_TABLE_NAME<>'source_events' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic source enqueue target rejected';END IF;
 INSERT INTO zasp_temporal77.source_pending VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.event_id,NEW.captured_at);
 RETURN NEW;
END $enqueue$;
CREATE TRIGGER source_pending AFTER INSERT ON zasp_temporal77.source_events FOR EACH ROW EXECUTE FUNCTION zasp_temporal77.enqueue_source();

CREATE FUNCTION zasp_temporal77.pending_sources(limit_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $pending$
BEGIN
 PERFORM zasp_temporal77.require_executor();
 IF limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 25 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='automatic delivery page bound rejected';END IF;
 IF (SELECT enabled FROM zasp_temporal75.configuration ORDER BY revision DESC LIMIT 1) IS DISTINCT FROM true THEN RETURN '[]'::jsonb;END IF;
 RETURN (SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'event_id',event_id) ORDER BY last_attempt_at,organization_id,workspace_id,environment_id,event_id),'[]'::jsonb)
  FROM(SELECT * FROM zasp_temporal77.source_pending ORDER BY last_attempt_at,organization_id,workspace_id,environment_id,event_id LIMIT limit_value) pending);
END $pending$;

CREATE FUNCTION zasp_temporal77.attempt_source(o text,w text,e text,id_value text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $attempt$
BEGIN
 PERFORM zasp_temporal77.require_executor();
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(id_value),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='automatic delivery reference rejected';END IF;
 UPDATE zasp_temporal77.source_pending SET last_attempt_at=greatest(last_attempt_at,clock_timestamp()) WHERE(organization_id,workspace_id,environment_id,event_id)=(o,w,e,id_value);
 IF FOUND OR EXISTS(SELECT 1 FROM zasp_temporal77.source_acceptances WHERE(organization_id,workspace_id,environment_id,event_id)=(o,w,e,id_value)) THEN RETURN true;END IF;
 RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic delivery source absent';
END $attempt$;

-- The application calls this only after exact durable Temporal acceptance.
-- This receipt attests acceptance, not completion of dispatch or any responder.
CREATE FUNCTION zasp_temporal77.ack_source(o text,w text,e text,id_value text,workflow_value text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ack$
BEGIN
 PERFORM zasp_temporal77.require_executor();
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(id_value)
 AND workflow_value='automatic-source/v1/'||o||'/'||w||'/'||e||'/'||id_value,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='automatic acceptance identity rejected';END IF;
 PERFORM 1 FROM zasp_temporal77.source_pending WHERE(organization_id,workspace_id,environment_id,event_id)=(o,w,e,id_value) FOR UPDATE;
 IF FOUND THEN
  INSERT INTO zasp_temporal77.source_acceptances(organization_id,workspace_id,environment_id,event_id,workflow_id) VALUES(o,w,e,id_value,workflow_value) ON CONFLICT DO NOTHING;
  DELETE FROM zasp_temporal77.source_pending WHERE(organization_id,workspace_id,environment_id,event_id)=(o,w,e,id_value);
  RETURN true;
 END IF;
 IF EXISTS(SELECT 1 FROM zasp_temporal77.source_acceptances WHERE(organization_id,workspace_id,environment_id,event_id,workflow_id)=(o,w,e,id_value,workflow_value)) THEN RETURN true;END IF;
 RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic acceptance source absent';
END $ack$;
