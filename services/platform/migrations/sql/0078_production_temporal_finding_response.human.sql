CREATE FUNCTION zasp_temporal78.family(o text,w text,e text,d text,a text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $family$
DECLARE b jsonb;s public.zasp_authorized_scopes%ROWTYPE;BEGIN
 IF NOT zasp_temporal78.current_ready() OR NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding human family unavailable';END IF;
 s:=zasp_sa_multistep_prior.lock_scope(o,w,e,a);
 IF s.principal_id IS NULL OR NOT COALESCE(s.permissions?'view',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding human scope denied';END IF;
 SELECT body INTO b FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding human scope denied';END IF;
 IF b->'allowed_actions'='["update_finding_response"]'::jsonb AND b->'max_steps'='1'::jsonb THEN PERFORM zasp_temporal78.manager(o,w,e,a);RETURN true;END IF;
 RETURN false;
END $family$;

CREATE FUNCTION zasp_temporal78.human_current(o text,w text,e text,d text,v bigint,a text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $human$
DECLARE b public.zasp_security_agent_definitions%ROWTYPE;BEGIN
 PERFORM zasp_temporal78.manager(o,w,e,a);
 SELECT * INTO b FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) AND deleted_at IS NULL FOR SHARE;
 IF b.definition_id IS NULL OR NOT zasp_temporal78.capable(b.body) OR b.activation NOT IN('supervised','autonomous') OR b.body->>'autonomy' IS DISTINCT FROM b.activation OR b.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR NOT COALESCE(b.body->'environment_ids'?e,false)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions h WHERE(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version,h.activation,h.definition)=(o,w,e,d,v,b.activation,b.body) AND h.definition_digest=digest(convert_to(b.body::text,'UTF8'),'sha256'))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding human definition changed';END IF;
 PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,'update_finding_response');
 RETURN b.body;
END $human$;

CREATE FUNCTION zasp_temporal78.human_authorize(o text,w text,e text,r text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $authority$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;BEGIN
 SELECT * INTO x FROM zasp_temporal78.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 IF x.source_kind IS DISTINCT FROM 'human78' OR rr.run_id IS NULL
  OR NOT EXISTS(SELECT 1 FROM zasp_temporal66.run_owners c JOIN zasp_temporal65.commands m USING(organization_id,workspace_id,environment_id,run_id)
   JOIN public.zasp_security_agent_request_receipts p ON(p.organization_id,p.workspace_id,p.environment_id,p.receipt_id)=(m.organization_id,m.workspace_id,m.environment_id,m.event_id)
   JOIN public.zasp_security_agent_audit a ON(a.organization_id,a.workspace_id,a.environment_id,a.audit_id)=(p.organization_id,p.workspace_id,p.environment_id,p.audit_id)
   WHERE(c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.execution_owner,c.definition_version,c.input_digest,m.kind,m.execution_owner,m.definition_version,m.input_digest)=(o,w,e,r,'legacy',x.definition_version,x.input_digest,'start','legacy',x.definition_version,x.input_digest)
    AND p.operation='runSecurityAgent' AND p.principal_id=rr.requested_by AND p.resource_id=x.definition_id AND p.expected_version=x.definition_version
    AND p.intent_digest=digest(convert_to(p.intent::text,'UTF8'),'sha256') AND p.intent->>'trigger_id'=x.trigger_id AND p.intent->'trigger_version'=to_jsonb(x.trigger_version)
    AND p.response->>'id'=r AND a.run_id=r AND a.actor_id=rr.requested_by AND a.event_kind='run_queued' AND encode(a.event_digest,'hex')=x.input_digest)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding human provenance changed';END IF;
 PERFORM zasp_temporal78.human_current(o,w,e,x.definition_id,x.definition_version,rr.requested_by);
END $authority$;

CREATE FUNCTION zasp_temporal78.finding_snapshot(o text,w text,e text,t text,v bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public SET timezone TO 'UTC' AS $snapshot$
DECLARE src public.zasp_risk_findings%ROWTYPE;BEGIN
 SELECT * INTO src FROM public.zasp_risk_findings WHERE(organization_id,workspace_id,environment_id,id,version,status)=(o,w,e,t,v,'open') FOR SHARE;
 IF src.id IS NULL OR NOT public.zasp_risk_finding_visible(src) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding human source changed';END IF;
 RETURN jsonb_build_object('kind','finding','source',to_jsonb(src),
 'evidence',(SELECT COALESCE(jsonb_agg(to_jsonb(child) ORDER BY position),'[]'::jsonb) FROM public.zasp_risk_finding_evidence child WHERE(organization_id,workspace_id,environment_id,finding_id)=(o,w,e,t)),
 'factors',(SELECT COALESCE(jsonb_agg(to_jsonb(child) ORDER BY position),'[]'::jsonb) FROM public.zasp_risk_finding_factors child WHERE(organization_id,workspace_id,environment_id,finding_id)=(o,w,e,t)));
END $snapshot$;

CREATE FUNCTION zasp_temporal78.resource(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $resource$
DECLARE o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';d text:=q->>'definition_id';a text:=q->>'actor_id';r text:=q->>'run_id';t text:=q->>'trigger_id';key_value text:=q->>'idempotency_key';v bigint;tv bigint;k text;
 b jsonb;snapshot_value jsonb;trigger_hash bytea;intent_value jsonb;intent_hash bytea;result_value jsonb;step_value text;created boolean:=false;prior public.zasp_security_agent_request_receipts%ROWTYPE;tr public.zasp_security_agent_trigger_receipts%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='finding human admission requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.current_ready() OR NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding human admission unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','definition_id','actor_id','idempotency_key','definition_version','run_id','trigger_kind','trigger_id','audit_id','correlation_id','receipt_id']||CASE WHEN q?'trigger_version' OR q?'trigger_source' THEN ARRAY['trigger_version','trigger_source'] ELSE ARRAY[]::text[] END) OR octet_length(q::text)>8192 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding human request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','definition_id','actor_id','run_id','trigger_id','audit_id','correlation_id','receipt_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding human identifier rejected';END IF;
 END LOOP;
 IF NOT zasp_temporal78.family(o,w,e,d,a) THEN RETURN NULL;END IF;
 IF NOT COALESCE(q->>'trigger_kind'='finding' AND jsonb_typeof(q->'definition_version')='number' AND q->>'definition_version'~'^[1-9][0-9]{0,6}$' AND (q->>'definition_version')::bigint<=1000000
  AND jsonb_typeof(q->'trigger_version')='number' AND q->>'trigger_version'~'^[1-9][0-9]{0,15}$' AND (q->>'trigger_version')::bigint<=9007199254740991
  AND jsonb_typeof(q->'trigger_source')='string' AND jsonb_typeof(q->'idempotency_key')='string' AND length(key_value) BETWEEN 16 AND 128 AND key_value~'^[A-Za-z0-9][A-Za-z0-9._:-]*$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding human source contract rejected';END IF;
 v:=(q->>'definition_version')::bigint;tv:=(q->>'trigger_version')::bigint;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,a,'runSecurityAgent',key_value),0));
 b:=zasp_temporal78.human_current(o,w,e,d,v,a);
 IF q->>'trigger_source' IS DISTINCT FROM b->>'trigger_source' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding human family changed';END IF;
 intent_value:=jsonb_build_object('definition_id',d,'expected_version',v,'trigger_kind','finding','trigger_id',t,'trigger_version',tv,'trigger_source',q->>'trigger_source');intent_hash:=digest(convert_to(intent_value::text,'UTF8'),'sha256');
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,a,'runSecurityAgent',key_value);
 IF FOUND THEN
  IF (prior.resource_id,prior.expected_version,prior.intent,prior.intent_digest) IS DISTINCT FROM(d,v,intent_value,intent_hash) OR prior.expires_at<=clock_timestamp()
   OR NOT EXISTS(SELECT 1 FROM zasp_temporal78.run_owners x JOIN zasp_temporal66.run_owners c USING(organization_id,workspace_id,environment_id,run_id) WHERE(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.definition_id,x.definition_version,x.trigger_id,x.trigger_version)=(o,w,e,prior.response->>'id',d,v,t,tv) AND(c.execution_owner,c.definition_version,c.input_digest)=('legacy',x.definition_version,x.input_digest))
  THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='finding human replay conflict';END IF;
  RETURN prior.response||jsonb_build_object('replayed',true);
 END IF;
 snapshot_value:=zasp_temporal78.finding_snapshot(o,w,e,t,tv);
 IF snapshot_value->'source'->>'rule' IS DISTINCT FROM b->>'trigger_source' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding human source family changed';END IF;
 trigger_hash:=digest(convert_to(jsonb_build_object('kind','finding','id',t,'version',tv)::text,'UTF8'),'sha256');
 SELECT * INTO tr FROM public.zasp_security_agent_trigger_receipts WHERE(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_version)=(o,w,e,d,t,tv) FOR SHARE;
 IF FOUND THEN
  SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,tr.run_id) FOR SHARE;
  IF rr.run_id IS NULL OR rr.definition_version<>v OR rr.requested_by<>a OR tr.trigger_kind<>'finding' OR tr.trigger_digest IS DISTINCT FROM trigger_hash
   OR NOT EXISTS(SELECT 1 FROM zasp_temporal78.run_owners x JOIN zasp_temporal66.run_owners c USING(organization_id,workspace_id,environment_id,run_id) WHERE(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.source_kind,x.definition_version,x.input_digest)=(o,w,e,rr.run_id,'human78',v,encode(trigger_hash,'hex')) AND(c.execution_owner,c.definition_version,c.input_digest)=('legacy',v,x.input_digest))
  THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='finding human occurrence already owned';END IF;
 ELSE
  step_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0');
  INSERT INTO zasp_temporal78.run_owners VALUES(o,w,e,r,d,v,'human78',t,tv,encode(trigger_hash,'hex'),snapshot_value,digest(convert_to(snapshot_value::text,'UTF8'),'sha256'),'update_finding_response',step_value,'security-agent-finding/v1/'||o||'/'||w||'/'||e||'/'||r,clock_timestamp());
  INSERT INTO public.zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) VALUES(o,w,e,d,t,'finding',tv,trigger_hash,r);
  INSERT INTO public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES(o,w,e,r,d,v,t,a,'queued') RETURNING * INTO rr;
  --66's legacy tag excludes the generic ordered dispatcher.78 is the real
  -- workflow owner, protected by its own restrictive RLS and lease backstop.
  -- Never update/transfer a preexisting compatibility owner.
  INSERT INTO zasp_temporal66.run_owners VALUES(o,w,e,r,'legacy',v,encode(trigger_hash,'hex'));
  INSERT INTO zasp_temporal78.commands VALUES(o,w,e,r,1,'start');
  INSERT INTO zasp_temporal78.start_deliveries(organization_id,workspace_id,environment_id,run_id) VALUES(o,w,e,r);
  created:=true;
 END IF;
 result_value:=jsonb_build_object('id',rr.run_id,'agent_id',d,'state',rr.state,'evidence_ids',jsonb_build_array(t),'definition_version',v,'version',rr.version,'replayed',NOT created,'audit_id',q->>'audit_id','correlation_id',q->>'correlation_id','receipt_id',q->>'receipt_id');
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,q->>'audit_id',q->>'correlation_id',rr.run_id,a,CASE WHEN created THEN 'run_queued' ELSE 'run_deduplicated' END,trigger_hash,jsonb_build_object('run_id',rr.run_id,'definition_id',d,'definition_version',v,'trigger_kind','finding','trigger_id',t,'trigger_version',tv,'automatic',false,'action','update_finding_response'));
 INSERT INTO public.zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id) VALUES(o,w,e,a,'runSecurityAgent',key_value,d,v,intent_value,intent_hash,result_value,q->>'audit_id',q->>'correlation_id',q->>'receipt_id');
 PERFORM zasp_temporal78.human_current(o,w,e,d,v,a);
 IF NOT zasp_temporal78.current_ready() OR zasp_temporal78.finding_snapshot(o,w,e,t,tv) IS DISTINCT FROM snapshot_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding human commit changed';END IF;
 RETURN result_value;
END $resource$;

CREATE FUNCTION zasp_temporal78.ownership_guard() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
DECLARE row_value jsonb:=to_jsonb(NEW);owned boolean;BEGIN
 owned:=zasp_temporal78.is_owned(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id);
 IF owned AND(row_value->>'lease_owner' IS NOT NULL OR row_value->>'lease_token' IS NOT NULL OR row_value->>'lease_expires_at' IS NOT NULL OR row_value->>'state'='leased') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding owner rejects legacy lease';END IF;
 IF TG_TABLE_NAME='zasp_security_agent_runs' AND TG_OP='INSERT' THEN
  IF NEW.state<>'simulated' AND zasp_temporal78.definition_migrated(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id)
   AND(NOT owned OR NOT zasp_temporal78.current_ready()) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding owner required before admission';END IF;
 END IF;
 RETURN NEW;
END $guard$;
CREATE TRIGGER zasp_temporal78_ownership BEFORE INSERT OR UPDATE ON public.zasp_security_agent_runs FOR EACH ROW EXECUTE FUNCTION zasp_temporal78.ownership_guard();
CREATE TRIGGER zasp_temporal78_ownership BEFORE INSERT OR UPDATE ON public.zasp_security_agent_effects FOR EACH ROW EXECUTE FUNCTION zasp_temporal78.ownership_guard();
