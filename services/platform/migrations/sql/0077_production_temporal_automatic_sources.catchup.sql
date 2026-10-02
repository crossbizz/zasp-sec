-- This cursor is only bounded source discovery progress. It has no lease,
-- execution state, retry timer, definition consumption or admission authority.
CREATE TABLE zasp_temporal77.source_scan(
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 source_kind text NOT NULL DEFAULT 'finding' CHECK(source_kind IN('finding','attack_path','runtime_decision')),
 after_o text NOT NULL DEFAULT '',after_w text NOT NULL DEFAULT '',after_e text NOT NULL DEFAULT '',after_id text NOT NULL DEFAULT '',
 runtime_at timestamptz,runtime_active boolean NOT NULL DEFAULT false,
 CHECK((after_o,after_w,after_e,after_id)=('','','','') OR public.zasp_valid_product_id(after_o) AND public.zasp_valid_product_id(after_w) AND public.zasp_valid_product_id(after_e) AND (public.zasp_valid_product_id(after_id) OR source_kind='runtime_decision' AND after_id='')),
 CHECK(source_kind='runtime_decision' OR runtime_at IS NULL AND NOT runtime_active),
 CHECK(runtime_at IS NULL OR runtime_active AND public.zasp_valid_product_id(after_id))
);
ALTER TABLE zasp_temporal77.source_scan OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal77.source_scan ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal77.source_scan FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal77.source_scan USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
INSERT INTO zasp_temporal77.source_scan DEFAULT VALUES;

CREATE FUNCTION zasp_temporal77.require_executor() RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $principal$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='automatic source requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal77.ready('-- automatic77 checksum','-- automatic77 fingerprint') OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic source executor rejected';END IF;
END $principal$;

-- Reuse the existing27 scope/occurred_at DESC/event_id ASC index. Separate
-- same-time and older-time seeks preserve its mixed-direction ordering without
-- scanning the prefix again or sorting an unbounded equal-time population.
CREATE FUNCTION zasp_temporal77.runtime_page(o text,w text,e text,after_at timestamptz,after_id text,floor_value timestamptz,now_value timestamptz,limit_value integer) RETURNS SETOF public.zasp_runtime_gateway_events LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $page$
DECLARE n integer:=0;BEGIN
 IF limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime source page bound rejected';END IF;
 IF after_at IS NOT NULL THEN
  RETURN QUERY SELECT v.* FROM public.zasp_runtime_gateway_events v WHERE(v.organization_id,v.workspace_id,v.environment_id)=(o,w,e)
   AND v.occurred_at=after_at AND v.event_id>after_id AND v.occurred_at BETWEEN floor_value AND now_value ORDER BY v.event_id LIMIT limit_value;
  GET DIAGNOSTICS n=ROW_COUNT;
 END IF;
 IF n<limit_value THEN
  RETURN QUERY SELECT v.* FROM public.zasp_runtime_gateway_events v WHERE(v.organization_id,v.workspace_id,v.environment_id)=(o,w,e)
   AND v.occurred_at<COALESCE(after_at,'infinity'::timestamptz) AND v.occurred_at BETWEEN floor_value AND now_value
   ORDER BY v.occurred_at DESC,v.event_id ASC LIMIT limit_value-n;
 END IF;
END $page$;

CREATE FUNCTION zasp_temporal77.scan_sources(limit_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $scan$
DECLARE cursor_value zasp_temporal77.source_scan%ROWTYPE;item record;table_value text;id_column text;version_column text;time_column text;
 scanned_value integer:=0;captured_value integer:=0;wrapped_value boolean:=false;now_value timestamptz:=clock_timestamp();
BEGIN
 PERFORM zasp_temporal77.require_executor();
 IF limit_value IS NULL OR limit_value NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='automatic source scan bound rejected';END IF;
 SELECT * INTO STRICT cursor_value FROM zasp_temporal77.source_scan WHERE singleton FOR UPDATE;
 IF cursor_value.source_kind='runtime_decision' THEN
  IF NOT cursor_value.runtime_active THEN
   SELECT organization_id,workspace_id,environment_id INTO cursor_value.after_o,cursor_value.after_w,cursor_value.after_e
    FROM public.zasp_gateway_devices WHERE(organization_id,workspace_id,environment_id)>(cursor_value.after_o,cursor_value.after_w,cursor_value.after_e)
    ORDER BY organization_id,workspace_id,environment_id,id LIMIT 1;
   IF NOT FOUND THEN
    UPDATE zasp_temporal77.source_scan SET source_kind='finding',after_o='',after_w='',after_e='',after_id='',runtime_at=NULL,runtime_active=false WHERE singleton;
    RETURN jsonb_build_object('scanned',0,'captured',0,'wrapped',true);
   END IF;
   cursor_value.runtime_active:=true;cursor_value.runtime_at:=NULL;cursor_value.after_id:='';
  END IF;
  FOR item IN SELECT * FROM zasp_temporal77.runtime_page(cursor_value.after_o,cursor_value.after_w,cursor_value.after_e,cursor_value.runtime_at,cursor_value.after_id,now_value-interval '24 hours',now_value,limit_value) LOOP
   scanned_value:=scanned_value+1;
   IF zasp_temporal77.put_source(item.organization_id,item.workspace_id,item.environment_id,'runtime_decision',item.event_id,item.sequence,item.occurred_at) THEN captured_value:=captured_value+1;END IF;
   cursor_value.runtime_at:=item.occurred_at;cursor_value.after_id:=item.event_id;
  END LOOP;
  IF scanned_value<limit_value THEN cursor_value.runtime_active:=false;cursor_value.runtime_at:=NULL;cursor_value.after_id:='';END IF;
  UPDATE zasp_temporal77.source_scan SET after_o=cursor_value.after_o,after_w=cursor_value.after_w,after_e=cursor_value.after_e,after_id=cursor_value.after_id,runtime_at=cursor_value.runtime_at,runtime_active=cursor_value.runtime_active WHERE singleton;
  RETURN jsonb_build_object('scanned',scanned_value,'captured',captured_value,'wrapped',false);
 END IF;
 IF cursor_value.source_kind='finding' THEN table_value:='zasp_risk_findings';id_column:='id';version_column:='version';time_column:='updated_at';
 ELSE table_value:='zasp_risk_attack_paths';id_column:='id';version_column:='version';time_column:='updated_at';END IF;
 -- Fixed relation/column choices above, primary-key tuple seek, bounded rows.
 FOR item IN EXECUTE format('SELECT organization_id,workspace_id,environment_id,%I source_id,%I source_version,%I source_at FROM public.%I WHERE(organization_id,workspace_id,environment_id,%I)>($1,$2,$3,$4) ORDER BY organization_id,workspace_id,environment_id,%I LIMIT $5',id_column,version_column,time_column,table_value,id_column,id_column)
 USING cursor_value.after_o,cursor_value.after_w,cursor_value.after_e,cursor_value.after_id,limit_value LOOP
  scanned_value:=scanned_value+1;
  IF zasp_temporal77.put_source(item.organization_id,item.workspace_id,item.environment_id,cursor_value.source_kind,item.source_id,item.source_version,item.source_at) THEN captured_value:=captured_value+1;END IF;
  cursor_value.after_o:=item.organization_id;cursor_value.after_w:=item.workspace_id;cursor_value.after_e:=item.environment_id;cursor_value.after_id:=item.source_id;
 END LOOP;
 IF scanned_value<limit_value THEN
  cursor_value.source_kind:=CASE cursor_value.source_kind WHEN 'finding' THEN 'attack_path' ELSE 'runtime_decision' END;
  cursor_value.after_o:='';cursor_value.after_w:='';cursor_value.after_e:='';cursor_value.after_id:='';
 END IF;
 UPDATE zasp_temporal77.source_scan SET source_kind=cursor_value.source_kind,after_o=cursor_value.after_o,after_w=cursor_value.after_w,after_e=cursor_value.after_e,after_id=cursor_value.after_id WHERE singleton;
 RETURN jsonb_build_object('scanned',scanned_value,'captured',captured_value,'wrapped',wrapped_value);
END $scan$;
