CREATE TABLE IF NOT EXISTS public.zasp_addon_offline_observations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 addon_version_id text NOT NULL,manifest_digest text NOT NULL,evidence_id text NOT NULL CHECK(public.zasp_valid_product_id(evidence_id)),
 scanner text NOT NULL CHECK(scanner IN('cisco_skill_scanner','nvidia_skillspector','gvisor_tetragon')),profile_digest text NOT NULL CHECK(profile_digest~'^sha256:[a-f0-9]{64}$'),
 indicators jsonb NOT NULL CHECK(jsonb_typeof(indicators)='array' AND jsonb_array_length(indicators)<=4),
 observed_at timestamptz NOT NULL,expires_at timestamptz NOT NULL CHECK(expires_at>observed_at AND expires_at<=observed_at+interval '7 days'),receipt_digest text NOT NULL CHECK(receipt_digest~'^sha256:[a-f0-9]{64}$'),
 PRIMARY KEY(organization_id,workspace_id,environment_id,evidence_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,addon_version_id) REFERENCES public.zasp_addon_versions(organization_id,workspace_id,environment_id,id)
);
CREATE INDEX IF NOT EXISTS zasp_addon_offline_observations_version ON public.zasp_addon_offline_observations(organization_id,workspace_id,environment_id,addon_version_id,scanner,observed_at DESC);
ALTER TABLE public.zasp_addon_offline_observations OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_addon_offline_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_addon_offline_observations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_addon_offline_observations FROM PUBLIC;
DO $policy$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='zasp_addon_offline_observations' AND policyname='scan_authority') THEN
 CREATE POLICY scan_authority ON public.zasp_addon_offline_observations TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $policy$;
-- Only the operator's dedicated importer can submit attested data. No API or
-- general-purpose worker role receives this function at installation.
CREATE OR REPLACE FUNCTION public.zasp_import_addon_observation(r jsonb,d text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $import$
DECLARE o text:=r->>'organization_id';w text:=r->>'workspace_id';e text:=r->>'environment_id';i text:=r->>'addon_version_id'; ev text:=r->>'evidence_id'; allowed jsonb;
BEGIN
 IF r->>'schema_version' IS DISTINCT FROM 'zasp-offline-addon-observation.v1' OR (r->>'observed_at')::timestamptz>now() OR (r->>'expires_at')::timestamptz<=now()
 OR NOT EXISTS(SELECT FROM public.zasp_addon_versions v WHERE (v.organization_id,v.workspace_id,v.environment_id,v.id,v.manifest_digest)=(o,w,e,i,r->>'manifest_digest'))
 OR coalesce(zasp_authorization80.ai_data_limits(o,w,e,false)->>'collection_mode','') NOT IN ('metadata_only','extended')
 THEN RETURN false; END IF;
 IF r->>'scanner'='gvisor_tetragon' AND r->>'isolation'='egress_denied' THEN allowed:='["honeytoken_read","honeytoken_egress_denied","unexpected_process","filesystem_write"]';
 ELSIF r->>'scanner' IN('cisco_skill_scanner','nvidia_skillspector') AND r->>'isolation'='offline_static' THEN allowed:='["instruction_override","credential_reference","network_reference","broad_permissions"]';
 ELSE RETURN false; END IF;
 IF jsonb_typeof(r->'indicators') IS DISTINCT FROM 'array' OR NOT (allowed @> (r->'indicators')) THEN RETURN false; END IF;
 INSERT INTO public.zasp_addon_offline_observations VALUES(o,w,e,i,r->>'manifest_digest',ev,r->>'scanner',r->>'scanner_profile_digest',r->'indicators',(r->>'observed_at')::timestamptz,(r->>'expires_at')::timestamptz,d) ON CONFLICT DO NOTHING;
 RETURN EXISTS(SELECT FROM public.zasp_addon_offline_observations a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.evidence_id,a.receipt_digest)=(o,w,e,ev,d));
END $import$;
ALTER FUNCTION public.zasp_import_addon_observation(jsonb,text) OWNER TO zasp_operator;
REVOKE ALL ON FUNCTION public.zasp_import_addon_observation(jsonb,text) FROM PUBLIC;


CREATE OR REPLACE FUNCTION zasp_authorization80.addon_observations(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $obs$
 SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY scanner),'[]'::jsonb) FROM(
 SELECT DISTINCT ON(a.scanner) a.scanner,a.profile_digest,a.evidence_id,a.indicators,a.observed_at,a.expires_at
 FROM public.zasp_addon_offline_observations a JOIN public.zasp_addon_versions v ON
 (a.organization_id,a.workspace_id,a.environment_id,a.addon_version_id,a.manifest_digest)=(v.organization_id,v.workspace_id,v.environment_id,v.id,v.manifest_digest)
 WHERE (a.organization_id,a.workspace_id,a.environment_id,a.addon_version_id)=(o,w,e,i) AND a.expires_at>now()
 ORDER BY a.scanner,a.observed_at DESC,a.evidence_id DESC) t
$obs$;
CREATE OR REPLACE FUNCTION zasp_authorization80.addon_version_with_observations(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $get$
DECLARE base jsonb;
BEGIN
 base:=zasp_authorization80.addon_version_get(o,w,e,i);
 IF base IS NULL OR base='null'::jsonb THEN RETURN 'null'::jsonb; END IF;
 RETURN base||jsonb_build_object('offline_observations',zasp_authorization80.addon_observations(o,w,e,i));
END $get$;
ALTER FUNCTION zasp_authorization80.addon_observations(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.addon_observations(text,text,text,text) FROM PUBLIC;
ALTER FUNCTION zasp_authorization80.addon_version_with_observations(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.addon_version_with_observations(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.addon_version_with_observations(text,text,text,text) TO zasp_discovery_api;
