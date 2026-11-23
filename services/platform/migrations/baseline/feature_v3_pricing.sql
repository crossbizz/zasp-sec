-- Retain historical prices and account IDs. The approved unit names the
-- accounting ledger. A price alone grants no model access.
ALTER TABLE zasp_sa_multistep_prior.pricing_accounts DROP CONSTRAINT IF EXISTS pricing_accounts_provider_check;
ALTER TABLE zasp_sa_multistep_prior.pricing_accounts ADD CONSTRAINT pricing_accounts_provider_check
 CHECK(provider IN ('openrouter','zasp_vpc_slm','bedrock_privatelink','vertex_privatelink','byoc_vllm'));

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_pricing_unit(provider text,unit text) RETURNS boolean
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $unit$
 SELECT (provider='openrouter' AND unit='openrouter_credit') OR
 (provider IN ('zasp_vpc_slm','bedrock_privatelink','vertex_privatelink','byoc_vllm') AND unit='model_credit')
$unit$;
ALTER FUNCTION zasp_authorization80.ai_pricing_unit(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.ai_pricing_unit(text,text) FROM PUBLIC;

-- Change only the provider selectors in the pinned V2 validation functions.
-- The original credential, CAS, expiry, pricing digest and audit fences apply.
DO $pricing_upgrade$
DECLARE change record; def text;
BEGIN
 FOR change IN SELECT * FROM (VALUES
 ('zasp_sa_multistep_prior.pricing_policy_valid(jsonb)',
  $a$p->>'provider'<>'openrouter' OR p->>'cost_unit'<>'openrouter_credit'$a$,
  $a$NOT zasp_authorization80.ai_pricing_unit(p->>'provider',p->>'cost_unit')$a$),
 ('zasp_authorization80.security_agent_pricing_binding(text,text,text,text,text)',
  $a$provider_value='openrouter' AND length(model_value)$a$,
  $a$provider_value IN ('openrouter','zasp_vpc_slm','bedrock_privatelink','vertex_privatelink','byoc_vllm') AND length(model_value)$a$),
 ('zasp_sa_multistep_prior.pricing_admin(text,text,jsonb)',
  $a$credential_prefix:='secret_ref_planner/'$a$,
  $a$IF op<>'disable' AND p->>'provider'='openrouter' AND NOT EXISTS(
   SELECT FROM public.zasp_environments env WHERE (env.organization_id,env.workspace_id,env.id)=(o,w,e) AND env.environment_class IN ('development','test')
  ) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='public router pricing is limited to development and test'; END IF;
  credential_prefix:='secret_ref_planner/'$a$),
 ('zasp_sa_multistep_prior.pricing_lookup(text,text,jsonb)',
  $a$IF NOT public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value) THEN$a$,
  $a$IF q->>'provider'='openrouter' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='legacy public planner is disabled'; END IF;
  IF NOT public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value) THEN$a$)
 ) v(signature,needle,replacement) LOOP
  def:=pg_get_functiondef(change.signature::regprocedure);
  IF position(change.replacement IN def)>0 THEN CONTINUE; END IF;
  IF (length(def)-length(replace(def,change.needle,'')))/length(change.needle)<>1 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='unexpected pricing predecessor'; END IF;
  EXECUTE replace(def,change.needle,change.replacement);
 END LOOP;
END $pricing_upgrade$;
