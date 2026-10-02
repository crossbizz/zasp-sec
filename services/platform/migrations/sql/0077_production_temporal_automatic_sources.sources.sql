-- Immutable canonical references only. The committed source and its children
-- are resolved by matching; an AFTER row trigger cannot prove final payloads.
CREATE TABLE zasp_temporal77.source_events(
 organization_id text NOT NULL CHECK(public.zasp_valid_product_id(organization_id)),
 workspace_id text NOT NULL CHECK(public.zasp_valid_product_id(workspace_id)),
 environment_id text NOT NULL CHECK(public.zasp_valid_product_id(environment_id)),
 event_id text NOT NULL CHECK(public.zasp_valid_product_id(event_id)),
 source_kind text NOT NULL CHECK(source_kind IN('finding','attack_path','runtime_decision')),
 source_id text NOT NULL CHECK(public.zasp_valid_product_id(source_id)),
 source_version bigint NOT NULL CHECK(source_version>0),source_at timestamptz NOT NULL,
 captured_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,event_id),
 UNIQUE(organization_id,workspace_id,environment_id,source_kind,source_id,source_version)
);
ALTER TABLE zasp_temporal77.source_events OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal77.source_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal77.source_events FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal77.source_events USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal77.source_events FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE FUNCTION zasp_temporal77.put_source(o text,w text,e text,k text,id_value text,v bigint,at_value timestamptz) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $put$
DECLARE inserted integer;BEGIN
 INSERT INTO zasp_temporal77.source_events(organization_id,workspace_id,environment_id,event_id,source_kind,source_id,source_version,source_at)
 VALUES(o,w,e,public.zasp_discovery_canonical_id(o,w,e,'automatic_source_v1',concat_ws(chr(31),k,id_value,v)),k,id_value,v,at_value)
 ON CONFLICT(organization_id,workspace_id,environment_id,source_kind,source_id,source_version) DO NOTHING;
 GET DIAGNOSTICS inserted=ROW_COUNT;RETURN inserted=1;
END $put$;

CREATE FUNCTION zasp_temporal77.capture_source() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $capture$
DECLARE kind_value text;id_value text;version_value bigint;at_value timestamptz;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_OP NOT IN('INSERT','UPDATE') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic source capture context rejected';END IF;
 IF TG_TABLE_NAME='zasp_risk_findings' THEN kind_value:='finding';id_value:=NEW.id;version_value:=NEW.version;at_value:=NEW.updated_at;
 ELSIF TG_TABLE_NAME='zasp_risk_attack_paths' THEN kind_value:='attack_path';id_value:=NEW.id;version_value:=NEW.version;at_value:=NEW.updated_at;
 ELSIF TG_TABLE_NAME='zasp_runtime_gateway_events' AND TG_OP='INSERT' THEN kind_value:='runtime_decision';id_value:=NEW.event_id;version_value:=NEW.sequence;at_value:=NEW.occurred_at;
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic source capture relation rejected';END IF;
 PERFORM zasp_temporal77.put_source(NEW.organization_id,NEW.workspace_id,NEW.environment_id,kind_value,id_value,version_value,at_value);
 -- A legitimate discovery transaction updates finding.path_id without another
 -- version increment. Do not overwrite the occurrence or digest its transient
 -- row image. No network calls, matcher, or admission/budget locks belong here.
 RETURN NEW;
END $capture$;
CREATE TRIGGER zasp_temporal77_finding_source AFTER INSERT OR UPDATE ON public.zasp_risk_findings FOR EACH ROW EXECUTE FUNCTION zasp_temporal77.capture_source();
CREATE TRIGGER zasp_temporal77_path_source AFTER INSERT OR UPDATE ON public.zasp_risk_attack_paths FOR EACH ROW EXECUTE FUNCTION zasp_temporal77.capture_source();
CREATE TRIGGER zasp_temporal77_runtime_source AFTER INSERT ON public.zasp_runtime_gateway_events FOR EACH ROW EXECUTE FUNCTION zasp_temporal77.capture_source();

-- No eager data rewrite during schema installation. Bounded worker catch-up
-- creates these same canonical references from original source timestamps and
-- retains a durable cursor; activation never manufactures an occurrence ID.
