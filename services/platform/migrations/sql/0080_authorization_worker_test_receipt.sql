-- A closed completed read. No caller chooses native pins or an operation.
CREATE FUNCTION zasp_authorization80_worker.test74_receipt_request(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $request$
DECLARE k text;BEGIN
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker receipt principal rejected';END IF;
 IF octet_length(q::text)>4096 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','parent_run_id','test_run_id','step_id','effect_key','generation','category','input_digest','request_digest'])
 OR q->'generation' IS DISTINCT FROM '1'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker receipt request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','parent_run_id','test_run_id','step_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker receipt scope rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['effect_key','input_digest','request_digest'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(q->>k~'^[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker receipt digest rejected';END IF;
 END LOOP;
 IF jsonb_typeof(q->'category') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker receipt category rejected';END IF;
 RETURN jsonb_build_object('organization_id',q->'organization_id','workspace_id',q->'workspace_id','environment_id',q->'environment_id','run_id',q->'test_run_id','effect_key',q->'effect_key','operation','complete','payload',jsonb_build_object('category',q->'category','request_digest',q->'request_digest'),'checksum','-- worker test checksum','fingerprint','-- worker test fingerprint');
END $request$;

-- Only the private receipt reader calls this helper. Its entry and exit retain
-- full catalog validation under the schema lock; parent identity is still
-- checked on both sides of the row lock, without repeating catalog scans.
DO $receipt_parent$ DECLARE d text;needle text;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.test74_captured_parent(text,text,text,text,text,text)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_authorization80_worker.test74_captured_parent(','FUNCTION zasp_authorization80_worker.test74_receipt_parent(');
 needle:='NOT zasp_temporal74.current_ready() OR ';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt parent readiness changed';END IF;
 EXECUTE replace(d,needle,'');
END $receipt_parent$;

DO $reader$ DECLARE d text;needle text;replacement text;start_at integer;end_at integer;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.test74_complete(jsonb)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_authorization80_worker.test74_complete(q jsonb)','FUNCTION zasp_authorization80_worker.test74_receipt_read(q jsonb)');
 needle:=$old$zasp_temporal74.ready(q->>'checksum',q->>'fingerprint')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt pins changed';END IF;
 d:=replace(d,needle,$new$(q->>'checksum'='-- worker test checksum' AND q->>'fingerprint'='-- worker test fingerprint')$new$);
 needle:='parent_value:=zasp_authorization80_worker.test74_captured_parent(o,w,e,link.run_id,child_id,key_value);';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt parent changed';END IF;
 d:=replace(d,needle,'parent_value:=zasp_authorization80_worker.test74_receipt_parent(o,w,e,link.run_id,child_id,key_value);');
 needle:='new_start boolean:=false;';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt declarations changed';END IF;
 d:=replace(d,needle,needle||'reference_value jsonb;facts_value jsonb;captured_value zasp_authorization80_worker.test_associations%ROWTYPE;owner_value zasp_temporal74.run_owners%ROWTYPE;journal_value jsonb;');
 needle:=$old$PERFORM zasp_authorization80_worker.require_test74_completion(q->>'operation',q);$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt entry changed';END IF;
 d:=replace(d,needle,'reference_value:=q;q:=zasp_authorization80_worker.test74_receipt_request(q);');
 needle:=$old$ELSE ARRAY['category','request_digest','http_status','response_digest','protected','credential_version_digest'] END$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt payload changed';END IF;
 d:=replace(d,needle,$new$ELSE ARRAY['category','request_digest'] END$new$);
 needle:=$old$  IF op='start' AND j.state IS DISTINCT FROM 'completed' THEN$old$;
 replacement:=$old$  result_value:=jsonb_build_object('state',j.state,$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 OR(length(d)-length(replace(d,replacement,'')))/length(replacement)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt dispatch changed';END IF;
 start_at:=strpos(d,needle);end_at:=strpos(d,replacement);
 IF end_at<=start_at THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt dispatch order changed';END IF;
 d:=substring(d FROM 1 FOR start_at-1)||$guard$
  IF j.test_run_id IS NULL OR j.state IS DISTINCT FROM 'completed' OR j.attempt IS DISTINCT FROM 1 OR j.http_status IS DISTINCT FROM 200 OR j.protected IS NULL OR j.completed_at IS NULL
   OR octet_length(j.response_digest) IS DISTINCT FROM 32 OR octet_length(j.credential_version_digest) IS DISTINCT FROM 32 OR j.credential_version_digest=decode(repeat('0',64),'hex')
   OR (link.run_id,link.step_id,encode(j.input_digest,'hex')) IS DISTINCT FROM(reference_value->>'parent_run_id',reference_value->>'step_id',reference_value->>'input_digest') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker completed receipt absent or changed';END IF;
$guard$||substring(d FROM end_at);
 -- The reader has no journal write dispatch left, including unreachable writes.
 IF strpos(d,'INSERT INTO')>0 OR strpos(d,'UPDATE zasp_temporal74.invocations')>0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt contains mutation';END IF;
 needle:=' RETURN jsonb_build_object(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt return changed';END IF;
 d:=replace(d,needle,$facts$
 SELECT * INTO STRICT owner_value FROM zasp_temporal74.run_owners WHERE(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id)=(o,w,e,link.run_id,link.step_id,child_id);
 facts_value:=zasp_authorization80_worker.test74_native_facts(true,jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',link.run_id,'definition_version',owner_value.definition_version,'input_digest',owner_value.input_digest),true);
 captured_value:=jsonb_populate_record(NULL::zasp_authorization80_worker.test_associations,facts_value);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_associations a WHERE a=captured_value) OR captured_value.target_digest IS DISTINCT FROM encode(digest(convert_to(resolution::text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker receipt capture changed';END IF;
 journal_value:=(to_jsonb(j)-ARRAY['started_at','completed_at'])||jsonb_build_object('started_at',to_char(j.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 facts_value:=facts_value||jsonb_build_object('receipt_phase','receipt','request_digest',encode(digest(convert_to(reference_value::text,'UTF8'),'sha256'),'hex'),'child_run_id',child_id,'step_id',link.step_id,'effect_key',j.effect_key,'generation',1,'snapshot_digest',encode(f.snapshot_digest,'hex'),'input_digest',encode(j.input_digest,'hex'),'manifest_digest',encode(digest(convert_to(prepared.manifest::text,'UTF8'),'sha256'),'hex'),'body_digest',encode(digest(prepared.body,'sha256'),'hex'),'journal_digest',encode(digest(convert_to(journal_value::text,'UTF8'),'sha256'),'hex'));
 result_value:=jsonb_build_object($facts$);
 needle:='END $function$';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt function ending changed';END IF;
 d:=replace(d,needle,$return$
 result_value:=result_value||jsonb_build_object('input_digest',encode(j.input_digest,'hex'),'generation',1,'captured_resolution_digest',captured_value.target_digest);
 RETURN jsonb_build_object('facts',facts_value,'receipt',result_value);
END $function$$return$);
 EXECUTE d;
END $reader$;

CREATE FUNCTION zasp_authorization80_worker.test74_receipt_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $source$
BEGIN
 IF phase IS DISTINCT FROM 'receipt' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker receipt phase rejected';END IF;
 RETURN zasp_authorization80_worker.test74_receipt_read(q)->'facts';
END $source$;
DO $fence$ DECLARE d text;needle text;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.require_test74_completion(text,jsonb)'::regprocedure);
 d:=replace(replace(d,'require_test74_completion','require_test74_receipt'),'test74_completion_source','test74_receipt_source');
 needle:=$old$('complete')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt fence phase changed';END IF;
 d:=replace(d,needle,$new$('receipt')$new$);
 needle:='RETURNS void';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt fence return changed';END IF;
 d:=replace(d,needle,'RETURNS jsonb');
 needle:='DECLARE envelope json;';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt fence declaration changed';END IF;
 d:=replace(d,needle,'DECLARE receipt_value jsonb;envelope json;');
 needle:=$old$source_value:=zasp_authorization80_worker.test74_receipt_source(phase,q);$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt fence source changed';END IF;
 d:=replace(d,needle,$new$receipt_value:=zasp_authorization80_worker.test74_receipt_read(q);source_value:=receipt_value->'facts';$new$);
 needle:=$old$IF proof->'facts' IS DISTINCT FROM source_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker planning source changed';END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker receipt fence equality changed';END IF;
 -- Only the freshly read, locked receipt can be returned, after the inherited
 -- final time fence and exact signed-facts comparison. No second native read.
 EXECUTE replace(d,needle,needle||$new$RETURN receipt_value->'receipt';$new$);
END $fence$;
CREATE FUNCTION zasp_authorization80_worker.test74_receipt(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $receipt$
BEGIN
 RETURN zasp_authorization80_worker.require_test74_receipt('receipt',q);
END $receipt$;
