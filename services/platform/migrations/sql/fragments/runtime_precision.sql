-- Included by the upcoming precision migration; not independently activated.
CREATE FUNCTION public.zasp_runtime_precise_epoch(value text) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog, public AS $epoch$
DECLARE whole_value timestamptz; seconds_value numeric; fraction_value text;
BEGIN
 IF octet_length(value) NOT BETWEEN 20 AND 30 OR value !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{0,8}[1-9])?Z$' THEN RETURN NULL;END IF;
 -- Never cast fractional source time to timestamptz: PostgreSQL would round
 -- nanoseconds to microseconds before validation or occurrence-window matching.
 whole_value := (left(value,19)||'Z')::timestamptz;
 IF to_char(whole_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')<>left(value,19) THEN RETURN NULL;END IF;
 seconds_value := extract(epoch FROM whole_value);
 IF seconds_value<=0 THEN RETURN NULL;END IF;
 IF length(value)>20 THEN
  fraction_value := substring(value FROM 21 FOR length(value)-21);
  seconds_value := seconds_value+('0.'||fraction_value)::numeric;
 END IF;
 RETURN seconds_value;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR invalid_text_representation OR numeric_value_out_of_range THEN RETURN NULL;
END
$epoch$;
ALTER FUNCTION public.zasp_runtime_precise_epoch(text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precise_epoch(text) FROM PUBLIC;

CREATE FUNCTION public.zasp_runtime_precise_lineage_valid(value jsonb,event_time_value text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog, public AS $lineage$
DECLARE key_value text; identifier text; source_value numeric; start_value numeric; wire_value timestamptz;
BEGIN
 IF value IS NULL OR jsonb_typeof(value)<>'object' OR event_time_value IS NULL OR value->>'profile' IS DISTINCT FROM 'kubernetes-container-v2' OR octet_length(value::text)>1280 THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(value) member WHERE member.key NOT IN('profile','cluster_uid','node_uid','boot_id','pod_uid','container_id','process_id','process_start_time','cgroup_id','source_event_time') OR jsonb_typeof(member.value)<>'string' OR member.value='""'::jsonb) THEN RETURN false;END IF;
 FOREACH key_value IN ARRAY ARRAY['cluster_uid','node_uid','boot_id','pod_uid'] LOOP
  identifier:=value->>key_value;
  IF NOT COALESCE(identifier ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND identifier<>'00000000-0000-0000-0000-000000000000',false) THEN RETURN false;END IF;
 END LOOP;
 IF NOT COALESCE(value->>'container_id' ~ '^(containerd|docker|cri-o)://[0-9a-f]{64}$' AND right(value->>'container_id',64)<>repeat('0',64),false) THEN RETURN false;END IF;
 source_value:=zasp_runtime_precise_epoch(value->>'source_event_time');
 IF source_value IS NULL OR octet_length(event_time_value)<>24 OR event_time_value !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' THEN RETURN false;END IF;
 -- Display time is deliberately millisecond precision. Its full canonical
 -- spelling is checked separately from the nanosecond source-time contract.
 wire_value:=event_time_value::timestamptz;
 IF to_char(wire_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')<>event_time_value OR trunc(source_value,3)<>extract(epoch FROM wire_value) THEN RETURN false;END IF;
 IF (value ? 'process_id') IS DISTINCT FROM (value ? 'process_start_time') THEN RETURN false;END IF;
 IF value ? 'process_id' THEN
  IF value->>'process_id' !~ '^[1-9][0-9]{0,9}$' OR (value->>'process_id')::numeric>4294967295 THEN RETURN false;END IF;
  start_value:=zasp_runtime_precise_epoch(value->>'process_start_time');
  IF start_value IS NULL OR start_value>source_value THEN RETURN false;END IF;
 END IF;
 IF value ? 'cgroup_id' AND (value->>'cgroup_id' !~ '^[1-9][0-9]{0,19}$' OR (value->>'cgroup_id')::numeric>18446744073709551615) THEN RETURN false;END IF;
 RETURN true;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END
$lineage$;
ALTER FUNCTION public.zasp_runtime_precise_lineage_valid(jsonb,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_precise_lineage_valid(jsonb,text) FROM PUBLIC;
