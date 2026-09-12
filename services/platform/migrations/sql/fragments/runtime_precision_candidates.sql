-- The future migration must pin this fragment and replace the inherited
-- schema50 readiness checks with its complete precision readiness contract.
-- No worker EXECUTE grant is made here. This is not an activation mechanism.
DO $precise_freeze$
DECLARE definition text;needle text;replacement text;expected integer;
BEGIN
 IF NOT COALESCE(public.zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=50),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint')),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precision predecessor unavailable';END IF;
 SELECT pg_get_functiondef('public.zasp_runtime_freeze_sandbox_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)'::regprocedure) INTO STRICT definition;
 FOR needle,replacement,expected IN SELECT * FROM (VALUES
  ('FUNCTION public.zasp_runtime_freeze_sandbox_candidates(', 'FUNCTION public.zasp_runtime_freeze_precise_candidates(', 1),
  ('implementation_value=''runtime-correlation-v3''', 'implementation_value=''runtime-correlation-v4''', 1),
  ('''runtime-candidate-snapshot-v2''', '''runtime-candidate-snapshot-v3''', 2),
  ('SELECT * INTO STRICT index_row', 'IF domain_row.source_kind<>''tetragon'' OR domain_row.runtime_sensor_id IS DISTINCT FROM domain_row.source_sensor_id OR batch_row.payload_schema_version<>''runtime-event-v2'' THEN RAISE EXCEPTION USING ERRCODE=''22023'',MESSAGE=''runtime precise archive schema rejected'';END IF;
 SELECT * INTO STRICT index_row', 1),
  ('IF batch_row.state<>''processing''', 'IF index_row.implementation_version<>''runtime-index-v2'' OR batch_row.state<>''processing''', 1),
  ('stage,state,effect_digest,result_reference,result_version_id)', 'stage,implementation_version,state,effect_digest,result_reference,result_version_id)', 1),
  ('''archive'',''succeeded'',archive_digest_value', '''archive'',''runtime-archive-v2'',''succeeded'',archive_digest_value', 1),
  ('receipt->>''implementation_version''=''runtime-index-v1''', 'receipt->>''implementation_version''=''runtime-index-v2''', 1),
  ('AND archive->>''source''=domain_row.source_kind', 'AND archive->>''version''=''runtime-archive-v2'' AND archive->>''source''=domain_row.source_kind', 1),
  ('zasp_runtime_candidate_lineage_valid(event_value->''observed_lineage'',(event_value->>''event_time'')::timestamptz)', 'zasp_runtime_precise_lineage_valid(event_value->''observed_lineage'',event_value->>''event_time'')', 1),
  ('(value->>''event_time'')::timestamptz event_time FROM jsonb_array_elements', '(value->>''event_time'')::timestamptz event_time,zasp_runtime_precise_epoch(value#>>''{observed_lineage,source_event_time}'') source_epoch FROM jsonb_array_elements', 1),
  ('AND observation.event_time BETWEEN target.event_time-interval ''5 minutes'' AND target.event_time+interval ''5 minutes''',
   'AND observation.event_time BETWEEN target.event_time-interval ''5 minutes'' AND target.event_time+interval ''5 minutes''+interval ''1 millisecond''
    AND abs(extract(epoch FROM observation.event_time)-target.source_epoch)<=300', 1)
 ) AS changes(needle,replacement,expected) LOOP
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>expected THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime precise freeze predecessor rejected';END IF;
  definition:=replace(definition,needle,replacement);
 END LOOP;
 EXECUTE definition;
END
$precise_freeze$;
ALTER FUNCTION public.zasp_runtime_freeze_precise_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_freeze_precise_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) FROM PUBLIC;
