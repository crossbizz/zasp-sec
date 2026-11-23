-- Immutable, actor-owned inputs for explicit backup and restore retries. Actual
-- recovery is still submitted through its own fresh-authenticated operations.
CREATE TABLE IF NOT EXISTS public.zasp_recovery_intents (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,principal_id text NOT NULL,
 id text NOT NULL CHECK(public.zasp_valid_product_id(id)),parameters jsonb NOT NULL CHECK(jsonb_typeof(parameters)='object' AND octet_length(parameters::text)<=512),
 expires_at timestamptz NOT NULL DEFAULT (now()+interval '90 days'),
 PRIMARY KEY(organization_id,workspace_id,environment_id,principal_id,id)
);
ALTER TABLE public.zasp_recovery_intents OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_recovery_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_recovery_intents FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_recovery_intents FROM PUBLIC;
DO $protect$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='zasp_recovery_intents' AND policyname='recovery_intent_authority') THEN
  CREATE POLICY recovery_intent_authority ON public.zasp_recovery_intents TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $protect$;
CREATE OR REPLACE FUNCTION zasp_authorization80.recovery_intent(o text,w text,e text,a text,i text,op text,params jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $intent$
DECLARE proof jsonb; stored jsonb; write_op boolean:=op='putRecoveryIntent';
BEGIN
 IF op IS NULL OR op NOT IN('getRecoveryIntent','putRecoveryIntent') THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 proof:=zasp_authorization80.product_request(o,w,e,a,op,CASE WHEN write_op THEN 'manage_identity' ELSE 'view' END,'environment',e,false,true,write_op,write_op);
 IF proof#>>'{path_parameters,id}' IS DISTINCT FROM i OR NOT public.zasp_valid_product_id(i) THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 IF write_op THEN
  IF params IS NULL OR jsonb_typeof(params)<>'object' OR NOT public.zasp_valid_product_id(params->>'backup_id') OR params->>'kind' IS NULL
   OR NOT (CASE params->>'kind' WHEN 'backup' THEN (params-ARRAY['kind','backup_id','retention_days']='{}'::jsonb AND params->>'backup_id'=i AND jsonb_typeof(params->'retention_days')='number' AND params->>'retention_days'~'^(?:[7-9]|[1-8][0-9]|90)$')
    WHEN 'restore' THEN (params-ARRAY['kind','backup_id','target_environment']='{}'::jsonb AND params->>'backup_id'<>i AND jsonb_typeof(params->'target_environment')='string' AND params->>'target_environment'~'^[a-z][a-z0-9-]{0,62}$' AND params->>'target_environment' NOT IN('production',e)) ELSE false END) IS TRUE
  THEN RAISE EXCEPTION USING ERRCODE='22023'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws('/',o,w,e,a,'recovery-intents'),0));
  DELETE FROM public.zasp_recovery_intents WHERE (organization_id,workspace_id,environment_id,principal_id)=(o,w,e,a) AND expires_at<=now();
  SELECT parameters INTO stored FROM public.zasp_recovery_intents WHERE (organization_id,workspace_id,environment_id,principal_id,id)=(o,w,e,a,i);
  IF FOUND THEN
   IF stored IS DISTINCT FROM params THEN RETURN '"conflict"'; END IF;
  ELSE
   IF (SELECT count(*) FROM public.zasp_recovery_intents WHERE (organization_id,workspace_id,environment_id,principal_id)=(o,w,e,a))>=256 THEN RETURN '"limit"'; END IF;
   INSERT INTO public.zasp_recovery_intents(organization_id,workspace_id,environment_id,principal_id,id,parameters) VALUES(o,w,e,a,i,params) RETURNING parameters INTO stored;
  END IF;
  PERFORM zasp_authorization80.product_settled(proof);
 ELSE
  SELECT parameters INTO stored FROM public.zasp_recovery_intents WHERE (organization_id,workspace_id,environment_id,principal_id,id)=(o,w,e,a,i) AND expires_at>now();
 END IF;
 IF stored IS NULL THEN RETURN 'null'; END IF;
 RETURN jsonb_build_object('id',i,'parameters',stored);
END $intent$;
ALTER FUNCTION zasp_authorization80.recovery_intent(text,text,text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.recovery_intent(text,text,text,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.recovery_intent(text,text,text,text,text,text,jsonb) TO zasp_discovery_api;
