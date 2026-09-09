DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version>40)
 OR NOT public.zasp_production_runtime_sessions_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=40),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_sessions_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session reads prerequisite rejected';
 END IF;
END
$guard$;

-- Backfill and trigger installation share one write exclusion boundary.
LOCK TABLE public.zasp_runtime_session_events IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE public.zasp_runtime_session_summaries (
 organization_id text NOT NULL CHECK(zasp_valid_product_id(organization_id)),
 workspace_id text NOT NULL CHECK(zasp_valid_product_id(workspace_id)),
 environment_id text NOT NULL CHECK(zasp_valid_product_id(environment_id)),
 id text NOT NULL CHECK(id='unattributed' OR zasp_valid_product_id(id)),
 first_event_at timestamptz NOT NULL CHECK(isfinite(first_event_at)),
 last_event_at timestamptz NOT NULL CHECK(isfinite(last_event_at) AND last_event_at>=first_event_at),
 projected_at timestamptz NOT NULL CHECK(isfinite(projected_at)),
 event_count bigint NOT NULL CHECK(event_count>0),
 exact_count bigint NOT NULL CHECK(exact_count>=0),
 strong_count bigint NOT NULL CHECK(strong_count>=0),
 probable_count bigint NOT NULL CHECK(probable_count>=0),
 unattributed_count bigint NOT NULL CHECK(unattributed_count>=0),
 minimum_agent_id text CHECK(minimum_agent_id IS NULL OR zasp_valid_product_id(minimum_agent_id)),
 maximum_agent_id text CHECK(maximum_agent_id IS NULL OR zasp_valid_product_id(maximum_agent_id)),
 PRIMARY KEY(organization_id,workspace_id,environment_id,id),
 CHECK(event_count=exact_count+strong_count+probable_count+unattributed_count),
 CHECK((id='unattributed' AND minimum_agent_id IS NULL AND maximum_agent_id IS NULL AND exact_count+strong_count=0) OR (id<>'unattributed' AND minimum_agent_id IS NOT NULL AND maximum_agent_id IS NOT NULL AND probable_count+unattributed_count=0))
);
ALTER TABLE public.zasp_runtime_session_summaries OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_session_summaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_session_summaries FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_runtime_session_summaries_authority ON public.zasp_runtime_session_summaries TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON public.zasp_runtime_session_summaries FROM PUBLIC;
CREATE INDEX zasp_runtime_session_investigation_events_idx ON public.zasp_runtime_session_events(organization_id,workspace_id,environment_id,(COALESCE(session_id,'unattributed')),event_time,event_id);

INSERT INTO public.zasp_runtime_session_summaries
 SELECT organization_id,workspace_id,environment_id,COALESCE(session_id,'unattributed'),
 min(event_time),max(event_time),max(projected_at),count(*),
 count(*) FILTER(WHERE confidence='exact'),count(*) FILTER(WHERE confidence='strong'),
 count(*) FILTER(WHERE confidence='probable'),count(*) FILTER(WHERE confidence='unattributed'),
 min(agent_id),max(agent_id)
 FROM public.zasp_runtime_session_events GROUP BY organization_id,workspace_id,environment_id,COALESCE(session_id,'unattributed');

CREATE FUNCTION public.zasp_runtime_session_maintain_summary() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $projection$
DECLARE key_value text;
BEGIN
 IF TG_OP='UPDATE' THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session events are immutable';
 ELSIF TG_OP='INSERT' THEN
  INSERT INTO zasp_runtime_session_summaries AS current_summary VALUES(
   NEW.organization_id,NEW.workspace_id,NEW.environment_id,COALESCE(NEW.session_id,'unattributed'),
   NEW.event_time,NEW.event_time,NEW.projected_at,1,
   (NEW.confidence='exact')::integer,(NEW.confidence='strong')::integer,
   (NEW.confidence='probable')::integer,(NEW.confidence='unattributed')::integer,NEW.agent_id,NEW.agent_id)
  ON CONFLICT(organization_id,workspace_id,environment_id,id) DO UPDATE SET
   first_event_at=LEAST(current_summary.first_event_at,EXCLUDED.first_event_at),
   last_event_at=GREATEST(current_summary.last_event_at,EXCLUDED.last_event_at),
   projected_at=GREATEST(current_summary.projected_at,EXCLUDED.projected_at),
   event_count=current_summary.event_count+1,
   exact_count=current_summary.exact_count+EXCLUDED.exact_count,
   strong_count=current_summary.strong_count+EXCLUDED.strong_count,
   probable_count=current_summary.probable_count+EXCLUDED.probable_count,
   unattributed_count=current_summary.unattributed_count+EXCLUDED.unattributed_count,
   minimum_agent_id=LEAST(current_summary.minimum_agent_id,EXCLUDED.minimum_agent_id),
   maximum_agent_id=GREATEST(current_summary.maximum_agent_id,EXCLUDED.maximum_agent_id);
 ELSE
  key_value:=COALESCE(OLD.session_id,'unattributed');
  -- Serialize against INSERT projection before calculating remaining evidence.
  PERFORM 1 FROM zasp_runtime_session_summaries
   WHERE (organization_id,workspace_id,environment_id,id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,key_value) FOR UPDATE;
  DELETE FROM zasp_runtime_session_summaries
   WHERE (organization_id,workspace_id,environment_id,id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id,key_value);
  INSERT INTO zasp_runtime_session_summaries
   SELECT organization_id,workspace_id,environment_id,COALESCE(session_id,'unattributed'),
   min(event_time),max(event_time),max(projected_at),count(*),
   count(*) FILTER(WHERE confidence='exact'),count(*) FILTER(WHERE confidence='strong'),
   count(*) FILTER(WHERE confidence='probable'),count(*) FILTER(WHERE confidence='unattributed'),min(agent_id),max(agent_id)
   FROM zasp_runtime_session_events
   WHERE (organization_id,workspace_id,environment_id)=(OLD.organization_id,OLD.workspace_id,OLD.environment_id)
    AND COALESCE(session_id,'unattributed')=key_value
   GROUP BY organization_id,workspace_id,environment_id,COALESCE(session_id,'unattributed');
 END IF;
 RETURN NULL;
END
$projection$;
ALTER FUNCTION public.zasp_runtime_session_maintain_summary() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_maintain_summary() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_session_summary_projection AFTER INSERT OR UPDATE OR DELETE ON public.zasp_runtime_session_events
 FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_session_maintain_summary();

CREATE FUNCTION public.zasp_runtime_session_summary_json(summary_value public.zasp_runtime_session_summaries) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $summary$
 SELECT jsonb_build_object('kind',CASE WHEN summary_value.id='unattributed' THEN 'unattributed' ELSE 'runtime' END,
 'id',summary_value.id,'workspace_id',summary_value.workspace_id,'environment_id',summary_value.environment_id,
 'agent_id',CASE WHEN summary_value.minimum_agent_id=summary_value.maximum_agent_id THEN summary_value.minimum_agent_id ELSE NULL END,
 'principal_id',NULL,'first_event_at',summary_value.first_event_at,'last_event_at',summary_value.last_event_at,
 'projected_at',summary_value.projected_at,'event_count',summary_value.event_count,
 'confidence_counts',jsonb_build_object('exact',summary_value.exact_count,'strong',summary_value.strong_count,'probable',summary_value.probable_count,'unattributed',summary_value.unattributed_count))
$summary$;
ALTER FUNCTION public.zasp_runtime_session_summary_json(public.zasp_runtime_session_summaries) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_summary_json(public.zasp_runtime_session_summaries) FROM PUBLIC;

CREATE FUNCTION public.zasp_runtime_session_read_authorized(organization_value text,workspace_value text,environment_value text,principal_value text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $authorization$
BEGIN
 RETURN COALESCE(zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(principal_value)
 AND zasp_discovery_principal_ready('zasp_discovery_api')
 AND zasp_production_runtime_session_reads_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=41),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_session_reads_fingerprint'))
 AND EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes(principal_value,organization_value) scope_value
  WHERE (scope_value.organization_id,scope_value.workspace_id,scope_value.environment_id)=(organization_value,workspace_value,environment_value) AND scope_value.permissions ? 'investigate_sessions'),false);
END
$authorization$;
ALTER FUNCTION public.zasp_runtime_session_read_authorized(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_read_authorized(text,text,text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_runtime_session_page(organization_value text,workspace_value text,environment_value text,principal_value text,after_value text,limit_value integer,agent_value text,from_value timestamptz,to_value timestamptz) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $page$
DECLARE result_value jsonb;
BEGIN
 IF num_nulls(after_value,limit_value,agent_value)>0 OR limit_value NOT BETWEEN 1 AND 101
 OR (after_value<>'' AND after_value<>'unattributed' AND NOT zasp_valid_product_id(after_value))
 OR (agent_value<>'' AND NOT zasp_valid_product_id(agent_value))
 OR (from_value IS NOT NULL AND NOT isfinite(from_value)) OR (to_value IS NOT NULL AND NOT isfinite(to_value))
 OR (from_value IS NOT NULL AND to_value IS NOT NULL AND from_value>to_value) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session query rejected';
 END IF;
 IF NOT zasp_runtime_session_read_authorized(organization_value,workspace_value,environment_value,principal_value) THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY id),'[]'::jsonb)) INTO result_value FROM (
  SELECT summary_value.id,zasp_runtime_session_summary_json(summary_value) item FROM zasp_runtime_session_summaries summary_value
  WHERE (summary_value.organization_id,summary_value.workspace_id,summary_value.environment_id)=(organization_value,workspace_value,environment_value)
   AND (after_value='' OR summary_value.id>after_value)
   AND ((agent_value='' AND from_value IS NULL AND to_value IS NULL) OR EXISTS(
    SELECT 1 FROM zasp_runtime_session_events event_value
    WHERE (event_value.organization_id,event_value.workspace_id,event_value.environment_id)=(organization_value,workspace_value,environment_value)
     AND COALESCE(event_value.session_id,'unattributed')=summary_value.id
     AND (agent_value='' OR event_value.agent_id=agent_value)
     AND (from_value IS NULL OR event_value.event_time>=from_value) AND (to_value IS NULL OR event_value.event_time<=to_value)))
  ORDER BY summary_value.id LIMIT limit_value
 ) page_value;
 RETURN result_value;
END
$page$;

CREATE FUNCTION public.zasp_runtime_session_get(organization_value text,workspace_value text,environment_value text,principal_value text,id_value text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $detail$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(id_value='unattributed' OR zasp_valid_product_id(id_value),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session target rejected';END IF;
 IF NOT zasp_runtime_session_read_authorized(organization_value,workspace_value,environment_value,principal_value) THEN RETURN NULL;END IF;
 SELECT zasp_runtime_session_summary_json(summary_value) INTO result_value FROM zasp_runtime_session_summaries summary_value
 WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,id_value);
 RETURN result_value;
END
$detail$;

CREATE FUNCTION public.zasp_runtime_session_event_page(organization_value text,workspace_value text,environment_value text,principal_value text,id_value text,after_time_value timestamptz,after_id_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $events$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(id_value='unattributed' OR zasp_valid_product_id(id_value),false) OR num_nulls(after_id_value,limit_value)>0
 OR limit_value NOT BETWEEN 1 AND 101 OR (after_time_value IS NULL)<>(after_id_value='')
 OR (after_time_value IS NOT NULL AND (NOT isfinite(after_time_value) OR NOT zasp_valid_product_id(after_id_value))) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime session event query rejected';
 END IF;
 IF NOT zasp_runtime_session_read_authorized(organization_value,workspace_value,environment_value,principal_value)
 OR NOT EXISTS(SELECT 1 FROM zasp_runtime_session_summaries WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,id_value)) THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY event_time,event_id),'[]'::jsonb)) INTO result_value FROM (
  SELECT event_time,event_id,jsonb_build_object('id',event_id,'session_id',session_id,'agent_id',agent_id,
   'class',CASE WHEN event_class='process' THEN 'runtime' ELSE event_class END,'action',action,
   'label',title,'evidence_id',evidence_id,'source',source,'confidence',confidence,'at',event_time,'projected_at',projected_at) item
  FROM zasp_runtime_session_events WHERE (organization_id,workspace_id,environment_id)=(organization_value,workspace_value,environment_value)
   AND COALESCE(session_id,'unattributed')=id_value
   AND (after_time_value IS NULL OR (event_time,event_id)>(after_time_value,after_id_value))
  ORDER BY event_time,event_id LIMIT limit_value
 ) page_value;
 RETURN result_value;
END
$events$;
ALTER FUNCTION public.zasp_runtime_session_page(text,text,text,text,text,integer,text,timestamptz,timestamptz) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_session_get(text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_session_event_page(text,text,text,text,text,timestamptz,text,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_session_page(text,text,text,text,text,integer,text,timestamptz,timestamptz),public.zasp_runtime_session_get(text,text,text,text,text),public.zasp_runtime_session_event_page(text,text,text,text,text,timestamptz,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_session_page(text,text,text,text,text,integer,text,timestamptz,timestamptz),public.zasp_runtime_session_get(text,text,text,text,text),public.zasp_runtime_session_event_page(text,text,text,text,text,timestamptz,text,integer) TO zasp_discovery_api;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 40','later_release."version" > 41'),'later."version">40','later."version">41'),'later."version" > 40','later."version" > 41');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime session reads compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_runtime_session_reads_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_sessions_security_ready()
 AND EXISTS(SELECT 1 FROM pg_class WHERE oid='public.zasp_runtime_session_summaries'::regclass AND relrowsecurity AND relforcerowsecurity AND relowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority'))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE((SELECT relacl FROM pg_class WHERE oid='public.zasp_runtime_session_summaries'::regclass),acldefault('r',(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority')))) acl WHERE acl.grantee<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace
  WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_session_maintain_summary','zasp_runtime_session_summary_json','zasp_runtime_session_read_authorized','zasp_runtime_session_page','zasp_runtime_session_get','zasp_runtime_session_event_page')
  AND (procedure.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT procedure.prosecdef OR NOT COALESCE(procedure.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']
   OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>procedure.proowner AND NOT (acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api') AND procedure.proname IN('zasp_runtime_session_page','zasp_runtime_session_get','zasp_runtime_session_event_page')))))
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_events'::regclass AND tgname='zasp_runtime_session_summary_projection' AND tgenabled='O' AND tgfoid='public.zasp_runtime_session_maintain_summary()'::regprocedure)
$security$;
CREATE FUNCTION public.zasp_production_runtime_session_reads_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_sessions_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',procedure.proname,pg_get_function_identity_arguments(procedure.oid),owner.rolname,procedure.prosecdef,COALESCE(procedure.proconfig::text,''),COALESCE(procedure.proacl::text,''),pg_get_functiondef(procedure.oid)) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_runtime_session_reads_readiness','zasp_production_runtime_session_reads_security_ready','zasp_runtime_session_maintain_summary','zasp_runtime_session_summary_json','zasp_runtime_session_read_authorized','zasp_runtime_session_page','zasp_runtime_session_get','zasp_runtime_session_event_page')
 UNION ALL SELECT concat_ws('|','table',relname,relowner::regrole::text,relrowsecurity,relforcerowsecurity,COALESCE(relacl::text,'')) FROM pg_class WHERE oid='public.zasp_runtime_session_summaries'::regclass
 UNION ALL SELECT concat_ws('|','constraint',conname,pg_get_constraintdef(oid),convalidated) FROM pg_constraint WHERE conrelid='public.zasp_runtime_session_summaries'::regclass
 UNION ALL SELECT concat_ws('|','column',attname,format_type(atttypid,atttypmod),attnotnull) FROM pg_attribute WHERE attrelid='public.zasp_runtime_session_summaries'::regclass AND attnum>0 AND NOT attisdropped
 UNION ALL SELECT concat_ws('|','policy',policyname,roles::text,cmd,qual,with_check) FROM pg_policies WHERE schemaname='public' AND tablename='zasp_runtime_session_summaries'
 UNION ALL SELECT concat_ws('|','index',indexname,indexdef) FROM pg_indexes WHERE schemaname='public' AND tablename='zasp_runtime_session_summaries'
 UNION ALL SELECT concat_ws('|','trigger',tgname,tgenabled,pg_get_triggerdef(oid)) FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_events'::regclass AND NOT tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_session_reads_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=41 AND name='production_runtime_session_reads' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>41) AND zasp_production_runtime_session_reads_security_ready() AND zasp_production_runtime_session_reads_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_session_reads_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_session_reads_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_session_reads_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_session_reads_security_ready(),public.zasp_production_runtime_session_reads_live_fingerprint(),public.zasp_production_runtime_session_reads_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_session_reads_readiness(text,text) TO zasp_runtime_coordinator,zasp_discovery_api;

ALTER FUNCTION public.zasp_production_runtime_sessions_readiness(text,text) RENAME TO zasp_production_runtime_sessions_readiness_v40;
CREATE FUNCTION public.zasp_production_runtime_sessions_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=40 AND name='production_runtime_sessions' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_sessions_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_session_reads_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=41),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_session_reads_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_sessions_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_sessions_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_sessions_readiness(text,text) TO zasp_runtime_coordinator;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_session_reads_fingerprint', 'f7ab24a108da3edb743e164646f0db64119dd505f50723cde3a4635565b96d4f');
