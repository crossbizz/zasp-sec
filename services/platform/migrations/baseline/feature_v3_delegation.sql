-- Runtime receipts contain the token digest only. The token itself confers authority.
CREATE TABLE IF NOT EXISTS public.delegation_receipts (
 sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 credential_id text NOT NULL, agent_id text NOT NULL, parent_task_id text NOT NULL,
 token_digest text NOT NULL CHECK(token_digest='' OR token_digest ~ '^[0-9a-f]{64}$'),
 operation_id text NOT NULL, status text NOT NULL CHECK(status IN ('issued','verified','denied','delegation_unverified')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(organization_id,workspace_id,environment_id,credential_id)
 REFERENCES public.zasp_workload_bindings(organization_id,workspace_id,environment_id,credential_id)
);
ALTER TABLE public.delegation_receipts ADD COLUMN IF NOT EXISTS hop jsonb;
ALTER TABLE public.delegation_receipts ADD COLUMN IF NOT EXISTS parent_digest text
 CHECK (parent_digest IS NULL OR parent_digest ~ '^[0-9a-f]{64}$');
CREATE INDEX IF NOT EXISTS delegation_receipts_for_binding ON public.delegation_receipts(organization_id,workspace_id,environment_id,credential_id,sequence_id DESC);
CREATE INDEX IF NOT EXISTS delegation_issued_by_digest ON public.delegation_receipts(organization_id,workspace_id,environment_id,token_digest,sequence_id) WHERE status='issued';
CREATE INDEX IF NOT EXISTS delegation_receipts_by_task ON public.delegation_receipts(organization_id,workspace_id,environment_id,parent_task_id,sequence_id);
ALTER TABLE public.delegation_receipts OWNER TO zasp_discovery_authority;
ALTER TABLE public.delegation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.delegation_receipts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.delegation_receipts FROM PUBLIC;
DO $rls$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='delegation_receipts' AND policyname='receipt_authority') THEN
  CREATE POLICY receipt_authority ON public.delegation_receipts TO zasp_discovery_authority USING (true) WITH CHECK (true);
 END IF;
END $rls$;

CREATE OR REPLACE FUNCTION zasp_authorization80.delegation_receipt(o text,w text,e text,actor text,op text,agent text,task text,digest text,result text,link text,grant_hop jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE proof jsonb; accepted_hop jsonb; required_permission text := CASE WHEN op='createWorkloadActionDecision' THEN 'decide_actions' ELSE 'use_gateway' END;
BEGIN
 IF op IS NULL OR op NOT IN ('createWorkloadActionDecision','issueRuntimeDelegation','verifyRuntimeDelegation','callMCPGateway','closeMCPGatewaySession','createGatewayChatCompletion','createGatewayResponse','createGatewayMessage') THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='unsupported delegation operation';
 END IF;
 proof:=zasp_authorization80.product_request(o,w,e,actor,op,required_permission,'environment',e,false,false,false,true);
 IF proof->>'credential_kind' IS DISTINCT FROM '2' OR NOT coalesce(proof->'pat_ceiling'?required_permission,false)
  OR NOT EXISTS(SELECT FROM public.zasp_workload_bindings b JOIN public.zasp_inventory_entities i ON
    (i.organization_id,i.workspace_id,i.environment_id,i.id,i.product_kind,i.state)=(o,w,e,agent,'agent','active')
    WHERE (b.organization_id,b.workspace_id,b.environment_id,b.agent_id,b.credential_id)=(o,w,e,agent,proof->>'credential_id'))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='active bound workload required'; END IF;
 IF task IS NULL OR task!~'^([A-Za-z0-9][A-Za-z0-9_.:/-]{0,127})?$' OR result IS NULL OR ((op='issueRuntimeDelegation')<>(result='issued'))
    OR (result IN ('issued','verified') AND (task='' OR digest='')) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid delegation receipt'; END IF;
 IF result='issued' THEN
  IF jsonb_typeof(grant_hop) IS DISTINCT FROM 'object' OR grant_hop->>'parent_agent_id' IS DISTINCT FROM agent OR NOT COALESCE(
     public.zasp_valid_product_id(grant_hop->>'child_agent_id') AND grant_hop->>'child_agent_id'<>agent AND
     jsonb_typeof(grant_hop->'allowed_operations')='array' AND jsonb_array_length(grant_hop->'allowed_operations') BETWEEN 1 AND 32 AND
     jsonb_typeof(grant_hop->'allowed_resources')='array' AND jsonb_array_length(grant_hop->'allowed_resources') BETWEEN 1 AND 32 AND
     (grant_hop->>'depth')::int BETWEEN 1 AND (grant_hop->>'max_depth')::int AND (grant_hop->>'max_depth')::int BETWEEN 1 AND 8 AND
     (((grant_hop->>'depth')::int=1 AND link='') OR ((grant_hop->>'depth')::int>1 AND link~'^[0-9a-f]{64}$')) AND
     (grant_hop-ARRAY['parent_agent_id','child_agent_id','depth','max_depth','expires_at','allowed_operations','allowed_resources'])='{}'::jsonb
     AND (grant_hop->>'expires_at')::bigint>0 AND pg_column_size(grant_hop)<16384,false)
  THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid delegation hop'; END IF;
 ELSIF grant_hop IS NOT NULL OR link IS DISTINCT FROM '' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unexpected delegation hop'; END IF;
 IF result='issued' THEN accepted_hop:=grant_hop;
 ELSIF result='verified' THEN
  SELECT r.hop INTO accepted_hop FROM public.delegation_receipts r
   WHERE (r.organization_id,r.workspace_id,r.environment_id,r.token_digest,r.parent_task_id,r.status)=(o,w,e,digest,task,'issued')
   AND r.hop->>'child_agent_id'=agent ORDER BY r.sequence_id LIMIT 1;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='matching issuance required'; END IF;
 END IF;
 IF accepted_hop IS NOT NULL THEN
  IF NOT EXISTS(SELECT FROM public.zasp_inventory_entities i WHERE (i.organization_id,i.workspace_id,i.environment_id,i.id,i.product_kind,i.state)=(o,w,e,accepted_hop->>'child_agent_id','agent','active')) THEN
   RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='active child required'; END IF;
  -- When a reviewer has declared the parent's or child's V2 purpose, each
  -- tool operation must resolve to an approved inventory tool at the same scope.
  IF EXISTS (WITH reviewed AS (
    SELECT DISTINCT ON (v.agent_id) v.allowed_tool_ids FROM public.zasp_agent_purpose_versions v
    WHERE (v.organization_id,v.workspace_id,v.environment_id)=(o,w,e) AND v.agent_id IN (accepted_hop->>'parent_agent_id',accepted_hop->>'child_agent_id')
    ORDER BY v.agent_id,v.revision DESC
   )
   SELECT FROM reviewed p CROSS JOIN jsonb_array_elements_text(accepted_hop->'allowed_operations') action(name)
   WHERE NOT EXISTS(SELECT FROM public.zasp_inventory_entities t WHERE
    (t.organization_id,t.workspace_id,t.environment_id,t.product_kind,t.state)=(o,w,e,'tool','active') AND p.allowed_tool_ids?t.id
    AND (t.id=action.name OR t.stable_fields->>'name'=action.name))) THEN
   RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='operation outside reviewed purpose'; END IF;
 END IF;
 INSERT INTO public.delegation_receipts(organization_id,workspace_id,environment_id,credential_id,agent_id,parent_task_id,token_digest,operation_id,status,parent_digest,hop)
 VALUES(o,w,e,proof->>'credential_id',agent,task,digest,op,result,nullif(link,''),grant_hop);
 PERFORM zasp_authorization80.product_settled(proof);
 RETURN 'true'::jsonb;
END $fn$;
ALTER FUNCTION zasp_authorization80.delegation_receipt(text,text,text,text,text,text,text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.delegation_receipt(text,text,text,text,text,text,text,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.delegation_receipt(text,text,text,text,text,text,text,text,text,text,jsonb) TO zasp_discovery_api;

-- Only receipts owned by this administrator-selected workload open a chain.
-- Each ancestor must match its signed digest, task, agent, depth and tenant.
CREATE OR REPLACE FUNCTION zasp_authorization80.workload_delegations(o text,w text,e text,actor text,cred text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $read$
DECLARE proof jsonb; agent text;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,actor,'getWorkloadDelegations','manage_api_tokens','environment',e,false,true,false,false);
 IF proof#>>'{path_parameters,id}' IS DISTINCT FROM cred THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload credential path required'; END IF;
 SELECT b.agent_id INTO agent FROM public.zasp_workload_bindings b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.credential_id)=(o,w,e,cred);
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 RETURN (WITH RECURSIVE page AS MATERIALIZED (
   SELECT r.* FROM public.delegation_receipts r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.credential_id)=(o,w,e,cred)
   ORDER BY r.sequence_id DESC LIMIT 26
  ), selected AS (SELECT * FROM page ORDER BY sequence_id DESC LIMIT 25),
  chain(receipt,task,hop,parent_digest) AS (
   SELECT r.sequence_id,r.parent_task_id,g.hop,g.parent_digest FROM selected r CROSS JOIN LATERAL (
    SELECT v.hop,v.parent_digest FROM public.delegation_receipts v
    WHERE (v.organization_id,v.workspace_id,v.environment_id,v.token_digest,v.parent_task_id,v.status)=(o,w,e,r.token_digest,r.parent_task_id,'issued')
     AND ((r.status='issued' AND v.sequence_id=r.sequence_id) OR (r.status='verified' AND v.hop->>'child_agent_id'=agent))
    ORDER BY v.sequence_id LIMIT 1) g
   UNION ALL
   SELECT c.receipt,c.task,g.hop,g.parent_digest FROM chain c CROSS JOIN LATERAL (
    SELECT a.hop,a.parent_digest FROM public.delegation_receipts a
    WHERE (a.organization_id,a.workspace_id,a.environment_id,a.token_digest,a.parent_task_id,a.status)=(o,w,e,c.parent_digest,c.task,'issued')
     AND a.hop->>'child_agent_id'=c.hop->>'parent_agent_id' AND (a.hop->>'depth')::int=(c.hop->>'depth')::int-1
    ORDER BY a.sequence_id LIMIT 1) g WHERE c.parent_digest IS NOT NULL AND (c.hop->>'depth')::int>1
  )
  SELECT jsonb_build_object('credential_id',cred,'agent_id',agent,'truncated',(SELECT count(*)>25 FROM page),
   'items',coalesce(jsonb_agg(jsonb_build_object('id',r.sequence_id::text,'parent_task_id',r.parent_task_id,'status',r.status,'observed_at',r.created_at,
    'grants',coalesce((SELECT jsonb_agg(c.hop ORDER BY (c.hop->>'depth')::int) FROM chain c WHERE c.receipt=r.sequence_id),'[]'::jsonb))
   ORDER BY r.sequence_id DESC),'[]'::jsonb)) FROM selected r);
END $read$;
ALTER FUNCTION zasp_authorization80.workload_delegations(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.workload_delegations(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.workload_delegations(text,text,text,text,text) TO zasp_discovery_api;
