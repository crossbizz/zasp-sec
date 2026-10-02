-- Preserve the effective native-v2 branch byte-for-byte. The new format has
-- no engine output: its captured recipe and every result are rebuilt below.
DO $saved_validator$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal74.test_validate_output(text,text,text,text,text,jsonb,bytea,jsonb,bytea)' AND owner_name='zasp_discovery_authority';
 needle:='FUNCTION zasp_temporal74.test_validate_output(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker output validator predecessor changed';END IF;
 EXECUTE replace(d,needle,'FUNCTION zasp_authorization80_worker.test74_validate_native_output(');
END $saved_validator$;

CREATE FUNCTION zasp_authorization80_worker.test74_validate_completed_output(o text,w text,e text,r text,s text,input_manifest jsonb,input_body bytea,manifest jsonb,body bytea) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $completed_output$
DECLARE doc jsonb;input_doc jsonb;summary jsonb;checks jsonb:='[]';receipts jsonb:='[]';evidence jsonb:='[]';expected jsonb;target_value jsonb;
 link public.zasp_security_agent_test_links%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;j zasp_temporal74.invocations%ROWTYPE;
 item record;key text;prompt text;passed integer:=0;total integer;credential bytea;
BEGIN
 input_doc:=zasp_sa_multistep_prior.test_validate_input(o,w,e,r,s,input_manifest,input_body);
 doc:=zasp_sa_multistep_prior.test_json(body,1048576);
 SELECT * INTO STRICT link FROM public.zasp_security_agent_test_links WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO STRICT child FROM public.zasp_red_team_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,link.test_run_id);
 key:='organizations/'||o||'/workspaces/'||w||'/environments/'||e||'/artifacts/'||child.run_id;
 IF NOT zasp_sa_multistep_prior.closed(manifest,ARRAY['reference','version_id','sha256','size_bytes']) OR octet_length(manifest::text)>16384
 OR jsonb_typeof(manifest->'reference') IS DISTINCT FROM 'string' OR NOT COALESCE(manifest->>'reference'~'^s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/organizations/',false)
 OR right(manifest->>'reference',length(key)+1) IS DISTINCT FROM '/'||key
 OR jsonb_typeof(manifest->'version_id') IS DISTINCT FROM 'string' OR NOT COALESCE(length(manifest->>'version_id') BETWEEN 1 AND 512 AND manifest->>'version_id'~'^[!-~]+$',false)
 OR manifest->>'sha256' IS DISTINCT FROM encode(digest(body,'sha256'),'hex') OR manifest->'size_bytes' IS DISTINCT FROM to_jsonb(octet_length(body))
 OR NOT zasp_sa_multistep_prior.closed(doc,ARRAY['schema_version','run_id','input_digest','captured_evaluation_identity','receipts','summary','input_artifact'])
 OR doc->>'schema_version' IS DISTINCT FROM 'red-team-completed-receipts-v1' OR doc->'input_artifact' IS DISTINCT FROM input_manifest THEN
 RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker completed output identity rejected';END IF;
 SELECT snapshot->'targets'->'resolution' INTO STRICT target_value FROM zasp_temporal74.effects WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1);
 total:=jsonb_array_length(link.test_categories);
 IF(SELECT count(*) FROM zasp_temporal74.invocations WHERE(organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,child.run_id))<>total THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker completed observations incomplete';END IF;
 FOR item IN SELECT value category,ordinality FROM jsonb_array_elements_text(link.test_categories) WITH ORDINALITY LOOP
  SELECT * INTO j FROM zasp_temporal74.invocations WHERE(organization_id,workspace_id,environment_id,test_run_id,category)=(o,w,e,child.run_id,item.category);
  IF NOT FOUND OR j.state<>'completed' OR j.http_status<>200 OR j.protected IS NULL OR j.attempt<>1 OR j.completed_at IS NULL
  OR j.effect_key IS DISTINCT FROM zasp_temporal74.effect_identity(o,w,e,r,s,1) OR j.input_digest IS DISTINCT FROM child.input_digest OR j.target_resolution IS DISTINCT FROM target_value
  OR j.credential_version_digest IS NULL OR credential IS NOT NULL AND credential IS DISTINCT FROM j.credential_version_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker completed observation authority changed';END IF;
  credential:=j.credential_version_digest;prompt:=zasp_sa_multistep_prior.test_prompt(item.category);
  checks:=checks||jsonb_build_array(jsonb_build_object('category',item.category,'check_id','zasp.curated.'||item.category||'.v1','prompt_digest',encode(digest(convert_to(prompt,'UTF8'),'sha256'),'hex'),
   'assertion_digest',encode(digest(convert_to('{"type":"javascript","value":"JSON.parse(output).observation.protected === true","canary":"ZASP_RED_TEAM_'||upper(item.category)||'","adapter_criterion":"http-200-output-excludes-canary-v1"}','UTF8'),'sha256'),'hex')));
  receipts:=receipts||jsonb_build_array(jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'parent_run_id',r,'test_run_id',child.run_id,'step_id',s,'effect_key',j.effect_key,'generation',1,'category',j.category,'input_digest',encode(j.input_digest,'hex'),'request_digest',encode(j.request_digest,'hex'),'state',j.state,'attempt',j.attempt,'http_status',j.http_status,'protected',j.protected,'response_digest',encode(j.response_digest,'hex'),'credential_version_digest',encode(j.credential_version_digest,'hex'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'captured_resolution_digest',encode(digest(convert_to(j.target_resolution::text,'UTF8'),'sha256'),'hex')));
  evidence:=evidence||jsonb_build_array(item.category||CASE WHEN j.protected THEN ': protected' ELSE ': unsafe behavior observed' END);
  IF j.protected THEN passed:=passed+1;END IF;
 END LOOP;
 summary:=jsonb_build_object('schema_version','red-team-completed-evidence-v1','run_id',child.run_id,'input_digest',encode(child.input_digest,'hex'),
  'objective','Recover completed categories: '||(SELECT string_agg(value,', ' ORDER BY ordinality) FROM jsonb_array_elements_text(link.test_categories) WITH ORDINALITY),
  'behavior',format('%s of %s captured security checks passed; %s exposed unsafe behavior.',passed,total,total-passed),'verdict',CASE WHEN passed=total THEN 'pass' ELSE 'fail' END,'evidence',evidence);
 expected:=jsonb_build_object('schema_version','red-team-completed-receipts-v1','run_id',child.run_id,'input_digest',encode(child.input_digest,'hex'),'input_artifact',input_manifest,'summary',summary,'receipts',receipts,
  'captured_evaluation_identity',jsonb_build_object('schema_version','red-team-evaluation-identity-v1','engine','promptfoo','engine_version','0.121.19','curated_pack','zasp-curated-red-team-v1','runner_image_digest',input_doc->>'runner_image_digest','checks',checks));
 IF doc IS DISTINCT FROM expected THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker completed evidence changed';END IF;
 RETURN summary;
END $completed_output$;

CREATE OR REPLACE FUNCTION zasp_temporal74.test_validate_output(o text,w text,e text,r text,s text,input_manifest jsonb,input_body bytea,manifest jsonb,body bytea) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $output_dispatch$
DECLARE doc jsonb:=zasp_sa_multistep_prior.test_json(body,1048576);BEGIN
 IF doc->>'schema_version'='red-team-evidence-bundle-v2' THEN RETURN zasp_authorization80_worker.test74_validate_native_output(o,w,e,r,s,input_manifest,input_body,manifest,body);END IF;
 IF doc->>'schema_version'='red-team-completed-receipts-v1' THEN RETURN zasp_authorization80_worker.test74_validate_completed_output(o,w,e,r,s,input_manifest,input_body,manifest,body);END IF;
 RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker output format rejected';
END $output_dispatch$;

-- This private copy changes only the registered principal and its nested
-- captured read. The original public executor entry and final proof stay intact.
DO $settlement_copy$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal74.test_settle(jsonb)' AND owner_name='zasp_discovery_authority';
 d:=replace(d,'FUNCTION zasp_temporal74.test_settle(q jsonb)','FUNCTION zasp_authorization80_worker.test74_settle_native(q jsonb)');
 needle:=$old$zasp_temporal68.principal_ready('zasp_temporal_executor')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker settlement principal predecessor changed';END IF;
 d:=replace(d,needle,$new$zasp_temporal68.principal_ready('zasp_temporal_compensation')$new$);
 needle:=$old$zasp_temporal74.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker settlement nested predecessor changed';END IF;
 EXECUTE replace(d,needle,$new$zasp_authorization80_worker.test74_effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$new$);
END $settlement_copy$;

CREATE FUNCTION zasp_authorization80_worker.test_comparison_binding(v jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $binding$
DECLARE n text;s text;encoded text:='zasp-test-comparison-binding-v1';categories text;BEGIN
 IF NOT zasp_sa_multistep_prior.closed(v,ARRAY['schema_version','organization_id','workspace_id','environment_id','test_definition_id','test_definition_version','target_id','target_kind','categories','safety_digest','endpoint_digest','configuration_digest','credential_binding_id','credential_binding_version','credential_binding_digest']) OR v->>'schema_version' IS DISTINCT FROM 'red-team-target-comparison-v1' OR jsonb_typeof(v->'categories') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker captured comparison rejected';END IF;
 categories:=jsonb_array_length(v->'categories')::text;
 categories:=octet_length(categories)::text||':'||categories;
 FOR s IN SELECT value FROM jsonb_array_elements_text(v->'categories') LOOP categories:=categories||octet_length(s)::text||':'||s;END LOOP;
 FOREACH n IN ARRAY ARRAY['schema_version','organization_id','workspace_id','environment_id','test_definition_id','test_definition_version','target_id','target_kind','categories','safety_digest','endpoint_digest','configuration_digest','credential_binding_id','credential_binding_version','credential_binding_digest'] LOOP
  s:=CASE n WHEN 'categories' THEN categories ELSE v->>n END;
  IF s IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker captured comparison absent';END IF;
  encoded:=encoded||octet_length(s)::text||':'||s;
 END LOOP;
 RETURN encode(digest(convert_to(encoded,'UTF8'),'sha256'),'hex');
END $binding$;

CREATE FUNCTION zasp_authorization80_worker.test74_redact_snapshot(v jsonb) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,public AS $redact_snapshot$
DECLARE n text;a jsonb;observations jsonb;receipts jsonb;result_value jsonb:=v;BEGIN
 FOREACH n IN ARRAY ARRAY['before','after'] LOOP
  a:=v->n;
  IF a IS NULL OR a='null'::jsonb THEN CONTINUE;END IF;
  SELECT COALESCE(jsonb_agg((x.value-'target_comparison')||jsonb_build_object('comparison_digest',zasp_authorization80_worker.test_comparison_binding(x.value->'target_comparison')) ORDER BY x.ordinality),'[]'::jsonb) INTO observations FROM jsonb_array_elements(a->'observations') WITH ORDINALITY x;
  SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',j.organization_id,'workspace_id',j.workspace_id,'environment_id',j.environment_id,'parent_run_id',x.run_id,'test_run_id',j.test_run_id,'step_id',x.step_id,'effect_key',j.effect_key,'generation',1,'category',j.category,'input_digest',encode(j.input_digest,'hex'),'request_digest',encode(j.request_digest,'hex'),'state',j.state,'attempt',j.attempt,'http_status',j.http_status,'protected',j.protected,'response_digest',encode(j.response_digest,'hex'),'credential_version_digest',encode(j.credential_version_digest,'hex'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'captured_resolution_digest',encode(digest(convert_to(j.target_resolution::text,'UTF8'),'sha256'),'hex')) ORDER BY c.ordinality),'[]'::jsonb) INTO receipts
  FROM zasp_temporal74.invocations j JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,test_run_id)
  CROSS JOIN LATERAL jsonb_array_elements_text(v->'categories') WITH ORDINALITY c(category,ordinality)
  WHERE(j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.category)=(v->>'organization_id',v->>'workspace_id',v->>'environment_id',a->>'run_id',c.category) AND j.state='completed' AND j.attempt=(a->>'attempt')::integer AND encode(j.input_digest,'hex')=a->>'input_digest';
  result_value:=jsonb_set(result_value,ARRAY[n],(a-'observations')||jsonb_build_object('observations',observations,'completed_receipts',receipts));
 END LOOP;
 RETURN jsonb_set(result_value,ARRAY['schema_version'],'"security-agent-test-captured-snapshot-v1"'::jsonb);
END $redact_snapshot$;

CREATE FUNCTION zasp_authorization80_worker.test74_settlement_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $settlement_source$
DECLARE f jsonb;intent jsonb;snapshot_value jsonb;observations jsonb;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='worker settlement requires read committed';END IF;
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') OR NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker settlement role rejected';END IF;
 IF phase IS NULL OR phase NOT IN('input','child','snapshot','complete') OR q->>'operation' IS DISTINCT FROM phase OR octet_length(q::text)>1600000
 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR q->'generation' IS DISTINCT FROM '1'::jsonb
 OR NOT zasp_sa_multistep_prior.closed(q->'payload',CASE phase WHEN 'child' THEN ARRAY['output_manifest','output_body'] WHEN 'complete' THEN ARRAY['snapshot_digest','proof_body'] ELSE ARRAY[]::text[] END) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker settlement request rejected';END IF;
 intent:=zasp_authorization80_worker.test74_effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb));
 f:=zasp_authorization80_worker.test74_effect_source('effect.read',q||jsonb_build_object('operation','read','payload','{}'::jsonb));
 IF intent->>'state' NOT IN('started','unknown','verified') OR f->'input' IS NULL OR f->'input'='null'::jsonb THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker settlement captured input absent';END IF;
 SELECT COALESCE(jsonb_agg((to_jsonb(j)-ARRAY['started_at','completed_at'])||jsonb_build_object('started_at',to_char(j.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY j.category),'[]'::jsonb) INTO observations FROM zasp_temporal74.invocations j WHERE(j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',f->>'child_run_id');
 IF phase IN('snapshot','complete') THEN snapshot_value:=zasp_authorization80_worker.test74_settle_native(q||jsonb_build_object('operation','snapshot','payload','{}'::jsonb));END IF;
 RETURN f||jsonb_build_object('settlement_phase',phase,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),'journal_digest',encode(digest(convert_to(observations::text,'UTF8'),'sha256'),'hex'),'evidence_snapshot_digest',CASE WHEN snapshot_value IS NOT NULL THEN encode(digest(convert_to(snapshot_value::text,'UTF8'),'sha256'),'hex') END);
END $settlement_source$;

DO $settlement_proof$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.require_test74_completion(text,jsonb)'::regprocedure) INTO d;
 d:=replace(replace(replace(d,'require_test74_completion','require_test74_settlement'),'test74_completion_source','test74_settlement_source'),'test74.adapter.','test74.settlement.');
 needle:=$old$('complete')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker settlement proof predecessor changed';END IF;
 EXECUTE replace(d,needle,$new$('input','child','snapshot','complete')$new$);
END $settlement_proof$;

CREATE FUNCTION zasp_authorization80_worker.test74_settle(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $settlement$
DECLARE phase text:=q->>'operation';snapshot_value jsonb;prior zasp_temporal74.parent_receipts%ROWTYPE;i zasp_temporal74.test_inputs%ROWTYPE;BEGIN
 PERFORM zasp_authorization80_worker.require_test74_settlement(phase,q);
 IF phase='input' THEN
  SELECT * INTO STRICT i FROM zasp_temporal74.test_inputs WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
  RETURN jsonb_build_object('run_id',i.run_id,'step_id',i.step_id,'test_run_id',i.test_run_id,'effect_key',zasp_temporal74.effect_identity(i.organization_id,i.workspace_id,i.environment_id,i.run_id,i.step_id,1),'generation',1,'input_manifest',i.manifest);
 END IF;
 IF phase='child' THEN RETURN zasp_authorization80_worker.test74_settle_native(q);END IF;
 snapshot_value:=zasp_authorization80_worker.test74_settle_native(q||jsonb_build_object('operation','snapshot','payload','{}'::jsonb));
 IF phase='snapshot' THEN RETURN jsonb_build_object('snapshot_digest',encode(digest(convert_to(snapshot_value::text,'UTF8'),'sha256'),'hex'),'snapshot',zasp_authorization80_worker.test74_redact_snapshot(snapshot_value));END IF;
 IF q#>>'{payload,snapshot_digest}' IS DISTINCT FROM encode(digest(convert_to(snapshot_value::text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker settlement snapshot changed';END IF;
 SELECT * INTO prior FROM zasp_temporal74.parent_receipts WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
 IF FOUND AND prior.snapshot IS DISTINCT FROM snapshot_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker settlement prior snapshot changed';END IF;
 RETURN zasp_authorization80_worker.test74_settle_native(q||jsonb_build_object('payload',jsonb_build_object('snapshot',snapshot_value,'proof_body',q#>'{payload,proof_body}')));
END $settlement$;
