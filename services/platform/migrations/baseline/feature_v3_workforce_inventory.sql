-- Native agents retain their actual registration authority. Locked declarations
-- are derived only from the versioned Studio or built-in agent definition.
CREATE TABLE IF NOT EXISTS public.zasp_workforce_inventory (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 id text NOT NULL,source text NOT NULL CHECK(source IN('built_in','studio')),revision bigint NOT NULL CHECK(revision>0),
 name text NOT NULL,purpose jsonb NOT NULL,active boolean NOT NULL,updated_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,id,source)
);
CREATE TABLE IF NOT EXISTS public.zasp_workforce_finding_receipts (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 agent_id text NOT NULL,revision bigint NOT NULL,finding_id text NOT NULL,finding_version bigint NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,agent_id,revision,finding_id,finding_version),
 FOREIGN KEY(organization_id,workspace_id,environment_id,agent_id,revision) REFERENCES public.zasp_custom_security_agent_revisions
);
DO $tables$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['zasp_workforce_inventory','zasp_workforce_finding_receipts'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',t);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',t);
  IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname='workforce_authority') THEN
   EXECUTE format('CREATE POLICY workforce_authority ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',t);
  END IF;
 END LOOP;
END $tables$;

CREATE OR REPLACE FUNCTION zasp_authorization80.workforce_register(o text,w text,e text,i text,src text,v bigint,d jsonb,enabled boolean,updated timestamptz) RETURNS void
LANGUAGE sql SET search_path=pg_catalog,public AS $reg$
 INSERT INTO public.zasp_workforce_inventory AS a(organization_id,workspace_id,environment_id,id,source,revision,name,purpose,active,updated_at)
 VALUES(o,w,e,i,src,v,coalesce(nullif(d->>'name',''),'Security agent'),
  CASE WHEN src='studio' THEN jsonb_build_object('mission',d->>'mission','trigger',d->>'trigger','read_tools',d->'read_tools','proposal',d->'proposal','require_approval',true,'max_steps',d->'max_steps','budget_nano_credits',d->'budget_nano_credits')
  ELSE jsonb_build_object('mission',coalesce(d->>'name','Registered security workflow'),'trigger',coalesce(d->>'trigger_kind','manual'),'read_tools','[]'::jsonb,'allowed_actions',coalesce(d->'allowed_actions','[]'::jsonb),'autonomy',d->>'autonomy','max_steps',d->'max_steps') END,
  enabled,updated)
 ON CONFLICT(organization_id,workspace_id,environment_id,id,source) DO UPDATE SET
 revision=excluded.revision,name=excluded.name,purpose=excluded.purpose,active=excluded.active,updated_at=excluded.updated_at WHERE a.revision<=excluded.revision
$reg$;
CREATE OR REPLACE FUNCTION zasp_authorization80.workforce_registration() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $registration$
BEGIN
 IF TG_TABLE_SCHEMA<>'public' THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 IF TG_TABLE_NAME='zasp_custom_security_agent_revisions' AND TG_OP='INSERT' THEN
  PERFORM zasp_authorization80.workforce_register(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.id,'studio',NEW.revision,NEW.definition,true,NEW.updated_at);
 ELSIF TG_TABLE_NAME='zasp_security_agent_definitions' THEN
  IF TG_OP='DELETE' THEN DELETE FROM public.zasp_workforce_inventory WHERE (organization_id,workspace_id,environment_id,id,source)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.definition_id,'built_in');
  ELSE PERFORM zasp_authorization80.workforce_register(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,'built_in',NEW.version,NEW.body,NEW.deleted_at IS NULL,NEW.updated_at);
  END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 RETURN NULL;
END $registration$;
CREATE OR REPLACE TRIGGER workforce_studio_registered AFTER INSERT ON public.zasp_custom_security_agent_revisions FOR EACH ROW EXECUTE FUNCTION zasp_authorization80.workforce_registration();
CREATE OR REPLACE TRIGGER workforce_builtin_registered AFTER INSERT OR UPDATE OR DELETE ON public.zasp_security_agent_definitions FOR EACH ROW EXECUTE FUNCTION zasp_authorization80.workforce_registration();

SELECT zasp_authorization80.workforce_register(organization_id,workspace_id,environment_id,definition_id,'built_in',version,body,deleted_at IS NULL,updated_at) FROM public.zasp_security_agent_definitions;
SELECT zasp_authorization80.workforce_register(organization_id,workspace_id,environment_id,id,'studio',revision,definition,true,updated_at) FROM
 (SELECT DISTINCT ON(organization_id,workspace_id,environment_id,id) * FROM public.zasp_custom_security_agent_revisions ORDER BY organization_id,workspace_id,environment_id,id,revision DESC) latest;

-- Opening or reopening a finding records a bounded, read-only observation for
-- each matching immutable revision; proposed actions retain their approval gate.
CREATE OR REPLACE FUNCTION zasp_authorization80.workforce_finding_opened() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $opened$
BEGIN
 IF TG_RELID<>'public.zasp_risk_findings'::regclass THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 IF NEW.status<>'open' OR (TG_OP='UPDATE' AND OLD.status='open') THEN RETURN NULL; END IF;
 INSERT INTO public.zasp_workforce_finding_receipts(organization_id,workspace_id,environment_id,agent_id,revision,finding_id,finding_version)
 SELECT a.organization_id,a.workspace_id,a.environment_id,a.id,a.revision,NEW.id,NEW.version FROM public.zasp_workforce_inventory a
 WHERE (a.organization_id,a.workspace_id,a.environment_id,a.source,a.active,a.purpose->>'trigger')=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,'studio',true,'finding_opened')
 ON CONFLICT DO NOTHING;
 RETURN NULL;
END $opened$;
CREATE OR REPLACE TRIGGER workforce_finding_opened AFTER INSERT OR UPDATE OF status ON public.zasp_risk_findings FOR EACH ROW EXECUTE FUNCTION zasp_authorization80.workforce_finding_opened();

CREATE OR REPLACE FUNCTION zasp_authorization80.workforce_page(o text,w text,e text,after_key text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $page$
DECLARE p jsonb:=zasp_authorization80.context(); result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listWorkforceInventory'],'view',true);
 IF p->'collection' IS DISTINCT FROM 'true'::jsonb OR n IS NULL OR n NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 IF after_key IS NOT NULL AND after_key !~ '^pid_[0-9a-f-]{36}[.](built_in|studio)$' THEN RAISE EXCEPTION USING ERRCODE='22023'; END IF;
 WITH candidates AS MATERIALIZED (
  SELECT a.*,a.id||'.'||a.source AS page_key FROM public.zasp_workforce_inventory a
  WHERE (a.organization_id,a.workspace_id,a.environment_id,a.active)=(o,w,e,true)
   AND (after_key IS NULL OR a.id||'.'||a.source>after_key)
   AND CASE WHEN a.source='studio' THEN zasp_authorization80.allowed(o,w,e,'environment',e) ELSE zasp_authorization80.allowed(o,w,e,'security_agent',a.id) END
  ORDER BY a.id,a.source LIMIT n+1
 ), visible AS (
  SELECT c.*, (SELECT count(*) FROM public.zasp_workforce_finding_receipts x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.agent_id,x.revision)=(o,w,e,c.id,c.revision)) AS trigger_receipts
  FROM candidates c ORDER BY c.id,c.source LIMIT n
 )
 SELECT jsonb_build_object('items',coalesce(jsonb_agg(jsonb_build_object('id',id,'source',source,'revision',revision,'name',name,'mission',purpose->>'mission','trigger',purpose->>'trigger',
 'read_tools',purpose->'read_tools','actions',CASE WHEN source='studio' THEN CASE WHEN purpose->>'proposal'='none' THEN '[]'::jsonb ELSE jsonb_build_array(purpose->>'proposal') END ELSE purpose->'allowed_actions' END,
 'trigger_receipts',trigger_receipts,'updated_at',updated_at) ORDER BY id,source),'[]'::jsonb),'next_cursor',CASE WHEN (SELECT count(*) FROM candidates)>n THEN max(page_key) END) INTO result FROM visible;
 RETURN result;
END $page$;

DO $grants$ DECLARE f regprocedure; BEGIN
 FOREACH f IN ARRAY ARRAY['zasp_authorization80.workforce_register(text,text,text,text,text,bigint,jsonb,boolean,timestamptz)'::regprocedure,
 'zasp_authorization80.workforce_registration()'::regprocedure,'zasp_authorization80.workforce_finding_opened()'::regprocedure,'zasp_authorization80.workforce_page(text,text,text,text,integer)'::regprocedure] LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f); EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
 IF f::text LIKE '%workforce_page%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',f); END IF;
 END LOOP;
END $grants$;
