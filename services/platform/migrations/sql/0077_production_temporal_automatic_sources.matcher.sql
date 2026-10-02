-- Private source evidence, not execution authorization. Both event dispatch and
-- current-source catch-up call this matcher inside their admission transaction.
CREATE INDEX source_window ON zasp_temporal77.source_events(organization_id,workspace_id,environment_id,source_kind,source_at,event_id);

CREATE FUNCTION zasp_temporal77.runtime_candidate(o text,w text,e text,id_value text,r jsonb,at_value timestamptz) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $candidate$
 SELECT jsonb_build_object('event_id',v.event_id,'device_id',v.device_id,'sequence',v.sequence,'evaluation',a.evaluation,'request_digest',encode(a.request_digest,'hex'))
 FROM public.zasp_runtime_gateway_events v
 JOIN zasp_temporal77.runtime_evaluations a USING(organization_id,workspace_id,environment_id,event_id)
 JOIN public.zasp_gateway_devices d ON(d.organization_id,d.workspace_id,d.environment_id,d.id)=(v.organization_id,v.workspace_id,v.environment_id,v.device_id)
 JOIN public.zasp_gateway_credentials c ON(c.organization_id,c.workspace_id,c.environment_id,c.device_id,c.id)=(v.organization_id,v.workspace_id,v.environment_id,v.device_id,v.credential_id)
 WHERE(v.organization_id,v.workspace_id,v.environment_id,v.event_id)=(o,w,e,id_value)
 AND v.occurred_at BETWEEN at_value-make_interval(secs=>(r->>'window_seconds')::integer) AND at_value
 AND v.decision=r->>'decision' AND a.evaluation->>'action'=r->>'action'
 AND (NOT r?'risk' OR a.evaluation->>'risk'=r->>'risk')
 AND a.legacy_digest=v.request_digest AND zasp_temporal77.evaluation_valid(a.evaluation,v.decision,v.policy_ids,v.classification)
 AND d.state='active' AND c.format_version=1 AND c.audience='runtime-gateway' AND c.revoked_at IS NULL AND c.expires_at>at_value
 AND NOT EXISTS(SELECT 1 FROM public.zasp_gateway_credentials newer WHERE(newer.organization_id,newer.workspace_id,newer.environment_id,newer.device_id)=(o,w,e,v.device_id) AND newer.credential_generation>c.credential_generation)
$candidate$;

CREATE FUNCTION zasp_temporal77.source_match(o text,w text,e text,event_value text,b jsonb,at_value timestamptz) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public SET timezone TO 'UTC' AS $match$
DECLARE s zasp_temporal77.source_events%ROWTYPE;r jsonb;f public.zasp_risk_findings%ROWTYPE;p public.zasp_risk_attack_paths%ROWTYPE;
 evidence_value jsonb;anchor jsonb;pattern jsonb;digest_value bytea;trigger_value text;identity_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(event_value) AND at_value IS NOT NULL,false)
 OR NOT zasp_temporal77.rules_valid(b) OR b->'trigger_rules'->>'mode' IS DISTINCT FROM 'automatic' THEN RETURN NULL;END IF;
 SELECT * INTO s FROM zasp_temporal77.source_events WHERE(organization_id,workspace_id,environment_id,event_id)=(o,w,e,event_value);
 IF NOT FOUND OR s.source_kind IS DISTINCT FROM b->>'trigger_kind' THEN RETURN NULL;END IF;
 r:=b->'trigger_rules';trigger_value:=s.source_id;
 IF s.source_kind='finding' THEN
  SELECT * INTO f FROM public.zasp_risk_findings WHERE(organization_id,workspace_id,environment_id,id,version)=(o,w,e,s.source_id,s.source_version);
  IF NOT FOUND OR f.status<>'open' OR f.rule IS DISTINCT FROM r->'finding'->>'family'
   OR NOT public.zasp_risk_finding_visible(f)
   OR array_position(ARRAY['low','medium','high','critical'],f.severity)<array_position(ARRAY['low','medium','high','critical'],r->'finding'->>'minimum_severity') THEN RETURN NULL;END IF;
  identity_value:=jsonb_build_object('kind','finding','id',f.id,'version',f.version);
  evidence_value:=jsonb_build_object('kind','finding','source',to_jsonb(f),
   'evidence',(SELECT COALESCE(jsonb_agg(to_jsonb(child) ORDER BY position),'[]'::jsonb) FROM public.zasp_risk_finding_evidence child WHERE(organization_id,workspace_id,environment_id,finding_id)=(o,w,e,f.id)),
   'factors',(SELECT COALESCE(jsonb_agg(to_jsonb(child) ORDER BY position),'[]'::jsonb) FROM public.zasp_risk_finding_factors child WHERE(organization_id,workspace_id,environment_id,finding_id)=(o,w,e,f.id)));
  pattern:=jsonb_build_array('finding',f.id);
 ELSIF s.source_kind='attack_path' THEN
  SELECT * INTO p FROM public.zasp_risk_attack_paths WHERE(organization_id,workspace_id,environment_id,id,version)=(o,w,e,s.source_id,s.source_version);
  IF NOT FOUND OR p.state IS DISTINCT FROM r->'attack_path'->>'state' OR NOT public.zasp_risk_attack_path_valid(p) THEN RETURN NULL;END IF;
  identity_value:=jsonb_build_object('kind','attack_path','id',p.id,'version',p.version,'state',p.state);
  evidence_value:=jsonb_build_object('kind','attack_path','source',to_jsonb(p),
   'nodes',(SELECT COALESCE(jsonb_agg(to_jsonb(child) ORDER BY position),'[]'::jsonb) FROM public.zasp_risk_attack_path_nodes child WHERE(organization_id,workspace_id,environment_id,path_id)=(o,w,e,p.id)),
   'evidence',(SELECT COALESCE(jsonb_agg(to_jsonb(child) ORDER BY position),'[]'::jsonb) FROM public.zasp_risk_attack_path_evidence child WHERE(organization_id,workspace_id,environment_id,path_id)=(o,w,e,p.id)),
   'break_options',(SELECT COALESCE(jsonb_agg(to_jsonb(child) ORDER BY rank),'[]'::jsonb) FROM public.zasp_risk_break_options child WHERE(organization_id,workspace_id,environment_id,path_id)=(o,w,e,p.id)));
  pattern:=jsonb_build_array('attack_path',p.id);
 ELSE
  r:=r->'runtime';anchor:=zasp_temporal77.runtime_candidate(o,w,e,s.source_id,r,at_value);
  IF anchor IS NULL OR (anchor->>'sequence')::bigint<>s.source_version THEN RETURN NULL;END IF;
  SELECT jsonb_agg(candidate ORDER BY source_at,event_id) INTO evidence_value FROM(
   SELECT candidate,occurrence.source_at,occurrence.event_id FROM zasp_temporal77.source_events occurrence
   CROSS JOIN LATERAL(SELECT zasp_temporal77.runtime_candidate(o,w,e,occurrence.source_id,r,at_value) candidate) matched
   WHERE(occurrence.organization_id,occurrence.workspace_id,occurrence.environment_id,occurrence.source_kind)=(o,w,e,'runtime_decision')
   AND occurrence.source_at BETWEEN at_value-make_interval(secs=>(r->>'window_seconds')::integer) AND at_value
   AND candidate->'evaluation'->>'agent_id'=anchor->'evaluation'->>'agent_id'
   AND candidate->'evaluation'->>'session_id'=anchor->'evaluation'->>'session_id'
   ORDER BY occurrence.source_at,occurrence.event_id LIMIT (r->>'count')::integer
  ) matches;
  IF COALESCE(jsonb_array_length(evidence_value),0)<(r->>'count')::integer THEN RETURN NULL;END IF;
  pattern:=jsonb_build_array('runtime_decision',anchor->'evaluation'->>'agent_id',anchor->'evaluation'->>'session_id',r->>'action',r->>'decision');
  evidence_value:=jsonb_build_object('kind','runtime_decision','anchor',anchor,'events',evidence_value);
 END IF;
 digest_value:=digest(convert_to(evidence_value::text,'UTF8'),'sha256');
 RETURN jsonb_build_object('event_id',s.event_id,'kind',s.source_kind,'trigger_id',trigger_value,'version',s.source_version,'digest',encode(digest_value,'hex'),'cooldown_key',encode(digest(convert_to(pattern::text,'UTF8'),'sha256'),'hex'),'evidence',evidence_value)
  || CASE WHEN identity_value IS NOT NULL THEN jsonb_build_object('legacy_trigger_digest',encode(digest(convert_to(identity_value::text,'UTF8'),'sha256'),'hex')) ELSE '{}'::jsonb END;
END $match$;
