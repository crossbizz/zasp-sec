CREATE SCHEMA zasp_sensor_coverage_v1 AUTHORIZATION zasp_discovery_authority;
-- node coverage authority definitions
REVOKE ALL ON SCHEMA zasp_sensor_coverage_v1 FROM PUBLIC;
CREATE TABLE zasp_sensor_coverage_v1.registration(singleton boolean NOT NULL DEFAULT true,checksum text NOT NULL,rawseal text NOT NULL,CONSTRAINT registration_pkey PRIMARY KEY(singleton),CONSTRAINT registration_singleton_ck CHECK(singleton),CONSTRAINT registration_checksum_ck CHECK(checksum ~ '^[a-f0-9]{64}$'),CONSTRAINT registration_rawseal_ck CHECK(rawseal ~ '^[a-f0-9]{64}$'));
ALTER TABLE zasp_sensor_coverage_v1.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_sensor_coverage_v1.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_sensor_coverage_v1.registration FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_sensor_coverage_v1.registration FROM PUBLIC,zasp_discovery_api,zasp_runtime_ingest;
CREATE POLICY authority ON zasp_sensor_coverage_v1.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TABLE zasp_sensor_coverage_v1.accepted_observations(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,sensor_id text NOT NULL,sequence bigint NOT NULL,state_uid text NOT NULL,storage_epoch bigint NOT NULL,request_digest bytea NOT NULL,source_observed_at text NOT NULL,expires_at text NOT NULL,source_epoch numeric NOT NULL,expires_epoch numeric NOT NULL,resolved_at timestamp with time zone NOT NULL,sensor_version bigint NOT NULL,token_id text NOT NULL,token_generation bigint NOT NULL,wire bytea NOT NULL,observation jsonb NOT NULL,recorded_tx xid8 NOT NULL DEFAULT pg_current_xact_id(),CONSTRAINT accepted_observations_pkey PRIMARY KEY(organization_id,workspace_id,environment_id,sensor_id),CONSTRAINT accepted_observations_sequence_ck CHECK(sequence>0),CONSTRAINT accepted_observations_epoch_ck CHECK(storage_epoch>0),CONSTRAINT accepted_observations_digest_ck CHECK(octet_length(request_digest)=32),CONSTRAINT accepted_observations_expires_ck CHECK(expires_epoch>source_epoch),CONSTRAINT accepted_observations_version_ck CHECK(sensor_version>0),CONSTRAINT accepted_observations_generation_ck CHECK(token_generation>0),CONSTRAINT accepted_observations_wire_min_ck CHECK(octet_length(wire)>0),CONSTRAINT accepted_observations_wire_max_ck CHECK(octet_length(wire)<=16777216),CONSTRAINT accepted_observations_observation_ck CHECK(jsonb_typeof(observation)='object'));
ALTER TABLE zasp_sensor_coverage_v1.accepted_observations OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_sensor_coverage_v1.accepted_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_sensor_coverage_v1.accepted_observations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_sensor_coverage_v1.accepted_observations FROM PUBLIC,zasp_discovery_api,zasp_runtime_ingest;
CREATE POLICY authority ON zasp_sensor_coverage_v1.accepted_observations TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TABLE zasp_sensor_coverage_v1.resolved_attempts(organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,sensor_id text NOT NULL,sequence bigint NOT NULL,state_uid text NOT NULL,storage_epoch bigint NOT NULL,request_digest bytea NOT NULL,source_observed_at text NOT NULL,expires_at text NOT NULL,source_epoch numeric NOT NULL,expires_epoch numeric NOT NULL,resolved_at timestamp with time zone NOT NULL,sensor_version bigint NOT NULL,token_id text NOT NULL,token_generation bigint NOT NULL,disposition text NOT NULL,CONSTRAINT resolved_attempts_pkey PRIMARY KEY(organization_id,workspace_id,environment_id,sensor_id),CONSTRAINT resolved_attempts_sequence_ck CHECK(sequence>0),CONSTRAINT resolved_attempts_epoch_ck CHECK(storage_epoch>0),CONSTRAINT resolved_attempts_digest_ck CHECK(octet_length(request_digest)=32),CONSTRAINT resolved_attempts_expires_ck CHECK(expires_epoch>source_epoch),CONSTRAINT resolved_attempts_version_ck CHECK(sensor_version>0),CONSTRAINT resolved_attempts_generation_ck CHECK(token_generation>0),CONSTRAINT resolved_attempts_disposition_ck CHECK(disposition IN ('accepted','expired_not_committed')));
ALTER TABLE zasp_sensor_coverage_v1.resolved_attempts OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_sensor_coverage_v1.resolved_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_sensor_coverage_v1.resolved_attempts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_sensor_coverage_v1.resolved_attempts FROM PUBLIC,zasp_discovery_api,zasp_runtime_ingest;
CREATE POLICY authority ON zasp_sensor_coverage_v1.resolved_attempts TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE FUNCTION zasp_sensor_coverage_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS (
 SELECT concat_ws('|','schema',nspowner,nspacl::text) FROM pg_namespace WHERE nspname='zasp_sensor_coverage_v1'
 UNION ALL SELECT concat_ws('|','type',t.oid,t.typname,t.typowner,t.typacl::text,t.typtype,t.typcategory,t.typrelid,t.typelem,t.typarray,t.typbasetype,t.typisdefined,t.typnotnull,t.typndims,t.typcollation,t.typinput,t.typoutput,t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typsubscript,t.typlen,t.typbyval,t.typalign,t.typstorage,t.typdelim,t.typdefaultbin::text,t.typdefault) FROM pg_type t WHERE t.typnamespace='zasp_sensor_coverage_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_sensor_coverage_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_sensor_coverage_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_sensor_coverage_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE c.relnamespace='zasp_sensor_coverage_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',i.indexrelid::regclass::text,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_sensor_coverage_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_sensor_coverage_v1'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','policy',p.polrelid,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_sensor_coverage_v1'::regnamespace
 ) SELECT encode(public.digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_sensor_coverage_v1.immutable_registration() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='node coverage registration is immutable';END
$$;
CREATE TRIGGER immutable_registration BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_sensor_coverage_v1.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_sensor_coverage_v1.immutable_registration();
CREATE FUNCTION zasp_sensor_coverage_v1.raw_seal_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE manifest constant text:=$coverage_manifest$-- node coverage manifest$coverage_manifest$;part jsonb;field jsonb;f record;t record;expected integer;expr text;BEGIN
 IF(SELECT count(*) FROM zasp_sensor_coverage_v1.registration)<>1 OR NOT EXISTS(SELECT 1 FROM zasp_sensor_coverage_v1.registration WHERE singleton AND checksum='-- node coverage checksum' AND rawseal=zasp_sensor_coverage_v1.fingerprint()) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_proc WHERE pronamespace='zasp_sensor_coverage_v1'::regnamespace)<>10 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_sensor_coverage_v1'::regnamespace AND relkind='r')<>3 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_sensor_coverage_v1'::regnamespace AND relkind='i')<>3 OR EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='zasp_sensor_coverage_v1'::regnamespace AND relkind NOT IN('r','i')) THEN RETURN false;END IF;
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'own') LOOP
  SELECT p.*,l.lanname INTO STRICT f FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=(part->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR f.prokind<>'f' OR f.proretset OR f.proisstrict OR f.proleakproof OR f.proparallel<>'u' OR f.provariadic<>0 OR f.pronargdefaults<>0 OR f.proallargtypes IS NOT NULL OR f.proargmodes IS NOT NULL OR f.proargnames IS DISTINCT FROM ARRAY(SELECT jsonb_array_elements_text(part->'argnames')) AND NOT(part->'argnames'='[]'::jsonb AND f.proargnames IS NULL) OR f.lanname<>part->>'language' OR f.provolatile::text<>part->>'volatility' OR f.prorettype<>(part->>'returns')::regtype THEN RETURN false;END IF;
  IF encode(public.digest(convert_to(replace(replace(f.prosrc,'-- node coverage checksum','-- node coverage '||'checksum'),manifest,'-- node coverage '||'manifest'),'UTF8'),'sha256'),'hex')<>part->>'source' THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>f.proowner AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE a.grantee=role_name::regrole)) OR NOT has_function_privilege(f.proowner,f.oid,'EXECUTE') OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE NOT has_function_privilege(role_name,f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'tables') LOOP
  SELECT * INTO STRICT t FROM pg_class WHERE oid=('zasp_sensor_coverage_v1.'||(part->>'name'))::regclass;
  IF t.relowner<>'zasp_discovery_authority'::regrole OR NOT t.relrowsecurity OR NOT t.relforcerowsecurity OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable) OR(SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='authority' AND polpermissive AND polcmd='*' AND polroles=ARRAY['zasp_discovery_authority'::regrole::oid] AND pg_get_expr(polqual,polrelid)='true' AND pg_get_expr(polwithcheck,polrelid)='true') THEN RETURN false;END IF;
  IF(SELECT count(*) FROM pg_attribute WHERE attrelid=t.oid AND attnum>0 AND NOT attisdropped)<>jsonb_array_length(part->'columns') THEN RETURN false;END IF;
  expected:=0;FOR field IN SELECT value FROM jsonb_array_elements(part->'columns') LOOP
   expected:=expected+1;
   IF NOT EXISTS(SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=t.oid AND a.attnum=expected AND a.attname=field->>'name' AND format_type(a.atttypid,a.atttypmod)=field->>'type' AND a.attnotnull AND NOT a.attisdropped AND a.attacl IS NULL AND a.attidentity='' AND a.attgenerated='' AND CASE WHEN field ? 'default_expression' THEN pg_get_expr(d.adbin,d.adrelid)=field->>'default_expression' WHEN(field->>'default')::boolean THEN pg_get_expr(d.adbin,d.adrelid)='true' ELSE d.oid IS NULL END) THEN RETURN false;END IF;
  END LOOP;
  IF(SELECT count(*) FROM pg_constraint WHERE conrelid=t.oid AND contype<>'n')<>1+jsonb_array_length(part->'checks') OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=t.oid AND contype='p' AND convalidated AND array_to_string(conkey,',')=part->>'pk') OR EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=t.oid AND k.contype='n' AND(cardinality(k.conkey) IS DISTINCT FROM 1 OR NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum=k.conkey[1] AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull))) THEN RETURN false;END IF;
  FOR field IN SELECT value FROM jsonb_array_elements(part->'checks') LOOP
   SELECT pg_get_expr(conbin,conrelid) INTO STRICT expr FROM pg_constraint WHERE conrelid=t.oid AND conname=field->>'name' AND contype='c' AND convalidated;
   -- Each fixed CHECK is a single atomic comparison; no boolean regrouping is
   -- normalized. IN's catalog ANY-array spelling is handled separately.
   IF field->>'name'='resolved_attempts_disposition_ck' THEN
    IF expr IS DISTINCT FROM $disposition_expr$(disposition = ANY (ARRAY['accepted'::text, 'expired_not_committed'::text]))$disposition_expr$ THEN RETURN false;END IF;
   ELSIF translate(regexp_replace(expr,'::text','','g'),E' \n\t()','') IS DISTINCT FROM translate(field->>'expression',E' \n\t()','') THEN RETURN false;END IF;
  END LOOP;
  IF(SELECT count(*) FROM pg_index WHERE indrelid=t.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid=t.oid AND indisprimary AND indisunique AND indisvalid AND indisready AND indislive AND replace(indkey::text,' ',',')=part->>'pk') THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_type c JOIN pg_type a ON a.oid=c.typarray WHERE c.oid=t.reltype AND c.typnamespace=t.relnamespace AND c.typrelid=t.oid AND c.typtype='c' AND c.typcategory='C' AND c.typname=part->>'name' AND c.typowner=t.relowner AND c.typacl IS NULL AND c.typelem=0 AND c.typbasetype=0 AND c.typisdefined AND NOT c.typnotnull AND c.typndims=0 AND c.typdefault IS NULL AND c.typdefaultbin IS NULL AND a.typnamespace=t.relnamespace AND a.typname='_'||(part->>'name') AND a.typowner=t.relowner AND a.typacl IS NULL AND a.typtype='b' AND a.typcategory='A' AND a.typelem=c.oid AND a.typrelid=0 AND a.typarray=0 AND a.typbasetype=0 AND a.typisdefined AND NOT a.typnotnull AND a.typndims=0 AND a.typdefault IS NULL AND a.typdefaultbin IS NULL) THEN RETURN false;END IF;
 END LOOP;
 IF(SELECT count(*) FROM pg_type WHERE typnamespace='zasp_sensor_coverage_v1'::regnamespace)<>6 OR(SELECT count(*) FROM pg_trigger x JOIN pg_class t ON t.oid=x.tgrelid WHERE t.relnamespace='zasp_sensor_coverage_v1'::regnamespace AND NOT x.tgisinternal)<>1 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='zasp_sensor_coverage_v1.registration'::regclass AND tgname='immutable_registration' AND tgenabled='O' AND tgtype=58 AND tgnargs=0 AND tgfoid='zasp_sensor_coverage_v1.immutable_registration()'::regprocedure) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_sensor_coverage_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT(a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE') OR a.grantee IN('zasp_discovery_api'::regrole,'zasp_runtime_ingest'::regrole) AND a.privilege_type='USAGE'))) OR NOT has_schema_privilege('zasp_discovery_api','zasp_sensor_coverage_v1','USAGE') OR NOT has_schema_privilege('zasp_runtime_ingest','zasp_sensor_coverage_v1','USAGE') THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_operator WHERE oprnamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_collation WHERE collnamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_conversion WHERE connamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_opclass WHERE opcnamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_opfamily WHERE opfnamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_config WHERE cfgnamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_dict WHERE dictnamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_parser WHERE prsnamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_ts_template WHERE tmplnamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_statistic_ext WHERE stxnamespace='zasp_sensor_coverage_v1'::regnamespace) OR EXISTS(SELECT 1 FROM pg_extension WHERE extnamespace='zasp_sensor_coverage_v1'::regnamespace) THEN RETURN false;END IF;
 RETURN true;EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_sensor_coverage_v1.effective_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE manifest constant text:=$coverage_manifest$-- node coverage manifest$coverage_manifest$;part jsonb;f record;BEGIN
 -- Trusted compiled parent bodies and exact owner/ACL frames are independent of
 -- registration's captured live seal. No parent or dynamic data is cached.
 FOR part IN SELECT value FROM jsonb_array_elements(manifest::jsonb->'parents') LOOP
  SELECT p.* INTO STRICT f FROM pg_proc p WHERE p.oid=(part->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR f.prosecdef IS DISTINCT FROM(part->>'secdef')::boolean OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR encode(public.digest(convert_to(f.prosrc,'UTF8'),'sha256'),'hex')<>part->>'source' OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>f.proowner AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE a.grantee=role_name::regrole)) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(part->'roles') role_name WHERE NOT has_function_privilege(role_name,f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 RETURN COALESCE(zasp_sensor_coverage_v1.raw_seal_ready()
 AND zasp_authorization79.ready('-- node coverage parent79') AND zasp_authorization80.ready('-- node coverage parent80') AND zasp_authorization80_temporal.ready()
 AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum='-- node coverage worker')
 AND zasp_authorization80_runtime.catalog_ready() AND zasp_authorization80_runtime.current_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum='-- node coverage runtime')
 AND zasp_authorization80.sensor_source_ready() AND(SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='-- node coverage audit mode' AND identity_mode='-- node coverage identity mode') FROM zasp_authorization80.runtime_profile)
 -- node coverage selected parent predicate
 ,false);EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_sensor_coverage_v1.caller_ready(purpose text,pin text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(pin='-- node coverage checksum' AND zasp_sensor_coverage_v1.effective_ready() AND CASE purpose WHEN 'ingest' THEN public.zasp_discovery_principal_ready('zasp_runtime_ingest') WHEN 'human-read' THEN public.zasp_discovery_principal_ready('zasp_discovery_api') ELSE false END,false)
$$;
CREATE FUNCTION zasp_sensor_coverage_v1.require_live_token(locator bytea,secret bytea,audience text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE auth jsonb;BEGIN
 IF NOT zasp_sensor_coverage_v1.caller_ready('ingest','-- node coverage checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='node coverage ingest unavailable';END IF;
 auth:=zasp_authorization80_runtime.runtime_authenticate_sensor(locator,secret,audience);
 IF audience IS DISTINCT FROM 'event-ingest' OR auth->>'sensor_kind' IS DISTINCT FROM 'tetragon' THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='node coverage token rejected';END IF;
 -- Same original sensor advisory/token/sensor locks were acquired by native15.
 -- Obtain the exact rows explicitly before doing the final wall-clock test.
 PERFORM 1 FROM public.zasp_sensor_tokens token JOIN public.zasp_sensors sensor ON(sensor.organization_id,sensor.workspace_id,sensor.environment_id,sensor.id)=(token.organization_id,token.workspace_id,token.environment_id,token.sensor_id)
 WHERE(token.organization_id,token.workspace_id,token.environment_id,token.sensor_id,token.id,token.token_generation)=(auth->>'organization_id',auth->>'workspace_id',auth->>'environment_id',auth->>'sensor_id',auth->>'token_id',(auth->>'token_generation')::bigint) FOR UPDATE OF token,sensor;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='node coverage token unavailable';END IF;
 IF zasp_sensor_coverage_v1.caller_ready('ingest','-- node coverage checksum') IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='node coverage authority changed';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_sensor_tokens token JOIN public.zasp_sensors sensor ON(sensor.organization_id,sensor.workspace_id,sensor.environment_id,sensor.id)=(token.organization_id,token.workspace_id,token.environment_id,token.sensor_id)
 WHERE(token.organization_id,token.workspace_id,token.environment_id,token.sensor_id,token.id,token.token_generation)=(auth->>'organization_id',auth->>'workspace_id',auth->>'environment_id',auth->>'sensor_id',auth->>'token_id',(auth->>'token_generation')::bigint)
 AND token.format_version=1 AND token.audience=$3 AND token.revoked_at IS NULL AND token.expires_at>clock_timestamp() AND token.sensor_version_at_issue=sensor.version AND sensor.version=(auth->>'sensor_version')::bigint AND sensor.state IN('pending','active','degraded')
 AND NOT EXISTS(SELECT 1 FROM public.zasp_sensor_tokens newer WHERE(newer.organization_id,newer.workspace_id,newer.environment_id,newer.sensor_id)=(token.organization_id,token.workspace_id,token.environment_id,token.sensor_id) AND newer.token_generation>token.token_generation)) THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='node coverage token expired';END IF;
 RETURN auth;
END
$$;
CREATE FUNCTION zasp_sensor_coverage_v1.validate_wire(wire bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE original json;v jsonb;s jsonb;target jsonb;n jsonb;report jsonb;raw_report json;item jsonb;stack jsonb[];part jsonb;key text;ts text;instant numeric;identity_instant numeric;measured_instant numeric;source_instant numeric;minimum_instant numeric;minimum_text text;prior text:='';report_key text;caps jsonb:='["file","network","process"]';kernel text:='unknown';rate numeric:=0;drops numeric:=0;all_btf boolean:=true;all_healthy boolean:=true;time_pattern constant text:='^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{0,8}[1-9])?Z$';uuid_pattern constant text:='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';name_pattern constant text:='^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$';BEGIN
 IF wire IS NULL OR octet_length(wire) NOT BETWEEN 1 AND 16777216 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage wire';END IF;
 original:=convert_from(wire,'UTF8')::json;
 IF NOT zasp_authorization80.unique_json(original,0) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='duplicate node coverage wire member';END IF;
 v:=original::jsonb;stack:=ARRAY[v];
 WHILE cardinality(stack)>0 LOOP
  part:=stack[cardinality(stack)];stack:=stack[1:cardinality(stack)-1];
  IF jsonb_typeof(part)='null' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='null node coverage wire member';
  ELSIF jsonb_typeof(part)='object' THEN FOR item IN SELECT value FROM jsonb_each(part) LOOP stack:=array_append(stack,item);END LOOP;
  ELSIF jsonb_typeof(part)='array' THEN FOR item IN SELECT value FROM jsonb_array_elements(part) LOOP stack:=array_append(stack,item);END LOOP;END IF;
 END LOOP;
 IF jsonb_typeof(v)<>'object' OR NOT v ?& ARRAY['sequence','status','capabilities','kernel','btf','event_rate','drops','coverage_schema','state_uid','storage_epoch','selection','target_digest','inventory_observed_at','source_observed_at','ttl_seconds','sensor_daemonset_uid','tetragon_daemonset_uid','selected_nodes','reports'] OR v-ARRAY['sequence','status','capabilities','kernel','btf','event_rate','drops','coverage_schema','state_uid','storage_epoch','selection','target_digest','inventory_observed_at','source_observed_at','ttl_seconds','sensor_daemonset_uid','tetragon_daemonset_uid','selected_nodes','reports']<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage envelope';END IF;
 FOREACH key IN ARRAY ARRAY['sequence','storage_epoch','ttl_seconds','event_rate','drops'] LOOP
  IF jsonb_typeof(v->key)<>'number' OR v->>key!~'^(0|[1-9][0-9]*)$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage integer';END IF;
 END LOOP;
 IF(v->>'sequence')::numeric NOT BETWEEN 1 AND 9223372036854775807 OR(v->>'storage_epoch')::numeric NOT BETWEEN 1 AND 9223372036854775807 OR(v->>'ttl_seconds')::numeric NOT BETWEEN 6 AND 300 OR(v->>'event_rate')::numeric>1000000000 OR(v->>'drops')::numeric>1000000000 OR jsonb_typeof(v->'btf')<>'boolean' OR jsonb_typeof(v->'capabilities')<>'array' OR jsonb_typeof(v->'selected_nodes')<>'array' OR jsonb_typeof(v->'reports')<>'array' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage bounds';END IF;
 FOREACH key IN ARRAY ARRAY['coverage_schema','status','kernel','state_uid','target_digest','sensor_daemonset_uid','tetragon_daemonset_uid','inventory_observed_at','source_observed_at'] LOOP IF jsonb_typeof(v->key)<>'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage string';END IF;END LOOP;
 IF v->>'coverage_schema'<>'zasp-node-coverage-retained-v1' OR v->>'status' NOT IN('healthy','degraded') OR octet_length(v->>'kernel') NOT BETWEEN 1 AND 128 OR v->>'kernel'<>btrim(v->>'kernel') OR v->>'kernel'~'[[:cntrl:]]' OR v->>'target_digest'!~'^[0-9a-f]{64}$' OR jsonb_array_length(v->'selected_nodes') NOT BETWEEN 1 AND 1000 OR jsonb_array_length(v->'reports')>1000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage facts';END IF;
 FOREACH key IN ARRAY ARRAY['state_uid','sensor_daemonset_uid','tetragon_daemonset_uid'] LOOP IF v->>key!~uuid_pattern OR v->>key='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage UID';END IF;END LOOP;
 s:=v->'selection';
 IF jsonb_typeof(s)<>'object' OR NOT s ?& ARRAY['source_profile','cluster_uid','enrollment_binding','match_labels','sensor','tetragon'] OR s-ARRAY['source_profile','cluster_uid','enrollment_binding','match_labels','sensor','tetragon']<>'{}'::jsonb OR octet_length((original->'selection')::text)>65536 OR jsonb_typeof(s->'source_profile')<>'string' OR s->>'source_profile' NOT IN('tetragon-local-stream-v2','tetragon-local-stream-v3') OR jsonb_typeof(s->'cluster_uid')<>'string' OR s->>'cluster_uid'!~uuid_pattern OR s->>'cluster_uid'='00000000-0000-0000-0000-000000000000' OR jsonb_typeof(s->'enrollment_binding')<>'string' OR s->>'enrollment_binding'!~'^[0-9a-f]{64}$' OR jsonb_typeof(s->'match_labels')<>'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage selection';END IF;
 IF(SELECT count(*) FROM jsonb_object_keys(s->'match_labels')) NOT BETWEEN 1 AND 8 OR EXISTS(SELECT 1 FROM jsonb_each(s->'match_labels') pair WHERE octet_length(pair.key)>253 OR array_length(string_to_array(pair.key,'/'),1)>2 OR split_part(pair.key,'/',array_length(string_to_array(pair.key,'/'),1))!~'^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$' OR pair.key LIKE '%/%' AND split_part(pair.key,'/',1)!~name_pattern OR jsonb_typeof(pair.value)<>'string' OR pair.value#>>'{}'!~'^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage selector';END IF;
 FOREACH key IN ARRAY ARRAY['sensor','tetragon'] LOOP
  target:=s->key;
  IF jsonb_typeof(target)<>'object' OR NOT target ?& ARRAY['namespace','name','release','release_namespace','image','service_account','container'] OR target-ARRAY['namespace','name','release','release_namespace','image','service_account','container']<>'{}'::jsonb OR EXISTS(SELECT 1 FROM jsonb_each(target) f WHERE jsonb_typeof(f.value)<>'string') OR target->>'namespace' IS DISTINCT FROM target->>'release_namespace' OR octet_length(target->>'image')>512 OR target->>'image'!~'^[-A-Za-z0-9./:]+@sha256:[0-9a-f]{64}$' OR EXISTS(SELECT 1 FROM jsonb_each_text(target) f WHERE f.key<>'image' AND f.value!~name_pattern) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage target';END IF;
 END LOOP;
 IF v->>'sensor_daemonset_uid'=v->>'tetragon_daemonset_uid' OR(s#>>'{sensor,namespace}',s#>>'{sensor,name}')=(s#>>'{tetragon,namespace}',s#>>'{tetragon,name}') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='node coverage target collision';END IF;
 FOR n IN SELECT value FROM jsonb_array_elements(v->'selected_nodes') LOOP
  IF jsonb_typeof(n)<>'object' OR NOT n ?& ARRAY['node_name','node_uid','boot_id'] OR n-ARRAY['node_name','node_uid','boot_id']<>'{}'::jsonb OR EXISTS(SELECT 1 FROM jsonb_each(n) f WHERE jsonb_typeof(f.value)<>'string') OR octet_length(n::text)>1024 OR n->>'node_name'!~name_pattern OR n->>'node_uid'!~uuid_pattern OR n->>'boot_id'!~uuid_pattern OR n->>'node_uid'='00000000-0000-0000-0000-000000000000' OR n->>'boot_id'='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid selected node identity';END IF;
  report_key:=n->>'node_uid'||'/'||(n->>'boot_id');IF report_key COLLATE "C"<=prior COLLATE "C" THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unordered selected node identity';END IF;prior:=report_key;
 END LOOP;
 IF(SELECT count(DISTINCT value->>'node_name') FROM jsonb_array_elements(v->'selected_nodes'))<>jsonb_array_length(v->'selected_nodes') OR(SELECT count(DISTINCT value->>'node_uid') FROM jsonb_array_elements(v->'selected_nodes'))<>jsonb_array_length(v->'selected_nodes') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='duplicate selected node identity';END IF;
 minimum_text:=v->>'inventory_observed_at';
 -- Parse whole seconds and decimal fractions separately. PostgreSQL timestamps
 -- round to microseconds; exact numeric epochs preserve original nanoseconds.
 FOREACH ts IN ARRAY ARRAY[v->>'inventory_observed_at',v->>'source_observed_at'] LOOP
  IF ts!~time_pattern THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage timestamp';END IF;
  instant:=extract(epoch FROM (substring(ts FROM 1 FOR 19)||'Z')::timestamptz)+CASE WHEN length(ts)>20 THEN ('0.'||substring(ts FROM 21 FOR length(ts)-21))::numeric ELSE 0 END;
  IF instant>extract(epoch FROM clock_timestamp())+5 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='future node coverage timestamp';END IF;
  IF ts=v->>'inventory_observed_at' THEN minimum_instant:=instant;END IF;IF ts=v->>'source_observed_at' THEN source_instant:=instant;END IF;
 END LOOP;
 prior:='';
 FOR raw_report IN SELECT value FROM json_array_elements(original->'reports') LOOP
  report:=raw_report::jsonb;
  IF jsonb_typeof(report)<>'object' OR NOT report ?& ARRAY['schema','enrollment_binding','cluster_uid','node_name','node_uid','boot_id','reporter_pod_name','reporter_pod_uid','tetragon_pod_name','tetragon_pod_uid','generation_id','source_profile','identity_observed_at','measured_at','status','capabilities','kernel','btf','event_rate','drops'] OR report-ARRAY['schema','enrollment_binding','cluster_uid','node_name','node_uid','boot_id','reporter_pod_name','reporter_pod_uid','tetragon_pod_name','tetragon_pod_uid','generation_id','source_profile','identity_observed_at','measured_at','status','capabilities','kernel','btf','event_rate','drops']<>'{}'::jsonb OR octet_length(raw_report::text)>8192 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage report';END IF;
  FOREACH key IN ARRAY ARRAY['schema','enrollment_binding','cluster_uid','node_name','node_uid','boot_id','reporter_pod_name','reporter_pod_uid','tetragon_pod_name','tetragon_pod_uid','generation_id','source_profile','identity_observed_at','measured_at','status','kernel'] LOOP IF jsonb_typeof(report->key)<>'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid report string';END IF;END LOOP;
  IF report->>'schema'<>'zasp-node-coverage-v2' OR(report->>'enrollment_binding',report->>'cluster_uid',report->>'source_profile') IS DISTINCT FROM(s->>'enrollment_binding',s->>'cluster_uid',s->>'source_profile') OR report->>'status' NOT IN('healthy','degraded') OR octet_length(report->>'kernel') NOT BETWEEN 1 AND 128 OR jsonb_typeof(report->'btf')<>'boolean' OR jsonb_typeof(report->'capabilities')<>'array' OR jsonb_array_length(report->'capabilities') NOT BETWEEN 1 AND 3 OR EXISTS(SELECT 1 FROM jsonb_array_elements(report->'capabilities') c WHERE jsonb_typeof(c)<>'string' OR c#>>'{}' NOT IN('file','network','process')) OR(SELECT count(DISTINCT c) FROM jsonb_array_elements_text(report->'capabilities') c)<>jsonb_array_length(report->'capabilities') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid report facts';END IF;
  FOREACH key IN ARRAY ARRAY['node_uid','boot_id','reporter_pod_uid','tetragon_pod_uid','generation_id'] LOOP IF report->>key!~uuid_pattern OR report->>key='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid report UID';END IF;END LOOP;
  FOREACH key IN ARRAY ARRAY['node_name','reporter_pod_name','tetragon_pod_name'] LOOP IF report->>key!~name_pattern THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid report name';END IF;END LOOP;
  report_key:=report->>'node_uid'||'/'||(report->>'boot_id');
  IF report_key COLLATE "C"<=prior COLLATE "C" OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v->'selected_nodes') node WHERE(node->>'node_name',node->>'node_uid',node->>'boot_id')=(report->>'node_name',report->>'node_uid',report->>'boot_id')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='report selected identity mismatch';END IF;prior:=report_key;
  FOREACH key IN ARRAY ARRAY['event_rate','drops'] LOOP IF jsonb_typeof(report->key)<>'number' OR report->>key!~'^(0|[1-9][0-9]*)$' OR(report->>key)::numeric>1000000000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid report count';END IF;END LOOP;
  FOREACH key IN ARRAY ARRAY['identity_observed_at','measured_at'] LOOP
   ts:=report->>key;IF ts!~time_pattern THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid report timestamp';END IF;
   instant:=extract(epoch FROM(substring(ts FROM 1 FOR 19)||'Z')::timestamptz)+CASE WHEN length(ts)>20 THEN ('0.'||substring(ts FROM 21 FOR length(ts)-21))::numeric ELSE 0 END;
   IF instant>extract(epoch FROM clock_timestamp())+5 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='future report timestamp';END IF;
   IF key='identity_observed_at' THEN identity_instant:=instant;ELSE measured_instant:=instant;END IF;
   IF instant<minimum_instant THEN minimum_instant:=instant;minimum_text:=ts;END IF;
  END LOOP;
  IF identity_instant>measured_instant+5 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='node coverage report identity clock mismatch';END IF;
  IF kernel='unknown' THEN kernel:=report->>'kernel';ELSIF kernel IS DISTINCT FROM report->>'kernel' THEN kernel:='mixed';END IF;
  SELECT COALESCE(jsonb_agg(cap ORDER BY cap),'[]'::jsonb) INTO caps FROM jsonb_array_elements_text(caps) cap WHERE report->'capabilities' ? cap;
  rate:=least(1000000000,rate+(report->>'event_rate')::numeric);drops:=least(1000000000,drops+(report->>'drops')::numeric);all_btf:=all_btf AND(report->>'btf')::boolean;all_healthy:=all_healthy AND report->>'status'='healthy';
 END LOOP;
 IF jsonb_array_length(v->'reports')=0 OR jsonb_array_length(caps)=0 THEN caps:='["process"]'::jsonb;all_btf:=false;END IF;
 IF source_instant IS DISTINCT FROM minimum_instant OR v->>'source_observed_at' IS DISTINCT FROM minimum_text OR v->'capabilities' IS DISTINCT FROM caps OR(v->>'event_rate')::numeric<>rate OR(v->>'drops')::numeric<>drops OR v->>'kernel' IS DISTINCT FROM kernel THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='node coverage aggregate mismatch';END IF;
 IF v->>'status'='healthy' AND(jsonb_array_length(v->'reports')<>jsonb_array_length(v->'selected_nodes') OR NOT all_healthy OR NOT all_btf OR drops<>0 OR caps<>'["file","network","process"]'::jsonb OR kernel='mixed' OR NOT(v->>'btf')::boolean) OR(v->>'btf')::boolean AND(NOT all_btf OR NOT all_healthy OR drops<>0 OR caps<>'["file","network","process"]'::jsonb OR jsonb_array_length(v->'reports')<>jsonb_array_length(v->'selected_nodes')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unproved healthy node coverage aggregate';END IF;
 RETURN v;
EXCEPTION WHEN invalid_text_representation OR invalid_datetime_format OR datetime_field_overflow OR character_not_in_repertoire OR numeric_value_out_of_range THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid node coverage encoding';END
$$;

CREATE FUNCTION zasp_sensor_coverage_v1.record_heartbeat(locator bytea,secret bytea,audience text,wire bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v jsonb;auth jsonb;final_auth jsonb;o text;w text;e text;i text;seq bigint;digest_value bytea;native_sequence bigint;accepted zasp_sensor_coverage_v1.accepted_observations%ROWTYPE;resolved zasp_sensor_coverage_v1.resolved_attempts%ROWTYPE;source_time numeric;expiry numeric;expiry_text text;stamp timestamptz;disposition_value text;receipt jsonb;prior_replay boolean:=false;enrollment text;BEGIN
 v:=zasp_sensor_coverage_v1.validate_wire(wire);
 auth:=zasp_sensor_coverage_v1.require_live_token(locator,secret,audience);
 o:=auth->>'organization_id';w:=auth->>'workspace_id';e:=auth->>'environment_id';i:=auth->>'sensor_id';seq:=(v->>'sequence')::bigint;digest_value:=public.digest(wire,'sha256');
 enrollment:=encode(public.digest(convert_to('zasp.sensor-enrollment.v1','UTF8')||decode('00','hex')||convert_to(o,'UTF8')||decode('00','hex')||convert_to(w,'UTF8')||decode('00','hex')||convert_to(e,'UTF8')||decode('00','hex')||convert_to(i,'UTF8'),'sha256'),'hex');
 IF v#>>'{selection,enrollment_binding}' IS DISTINCT FROM enrollment THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='node coverage enrollment mismatch';END IF;
 SELECT * INTO accepted FROM zasp_sensor_coverage_v1.accepted_observations a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.sensor_id)=(o,w,e,i);
 SELECT * INTO resolved FROM zasp_sensor_coverage_v1.resolved_attempts r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.sensor_id)=(o,w,e,i);
 SELECT heartbeat.sequence INTO native_sequence FROM public.zasp_sensor_heartbeats heartbeat WHERE(heartbeat.organization_id,heartbeat.workspace_id,heartbeat.environment_id,heartbeat.sensor_id)=(o,w,e,i);
 IF accepted.state_uid IS NOT NULL AND accepted.state_uid IS DISTINCT FROM v->>'state_uid' OR resolved.state_uid IS NOT NULL AND resolved.state_uid IS DISTINCT FROM v->>'state_uid' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='node coverage storage identity changed';END IF;
 -- Only an exact retained terminal is replayable. A missing overwritten receipt
 -- never proves that a lower sequence was not previously accepted.
 IF resolved.sequence=seq THEN
  IF resolved.request_digest<>digest_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='node coverage sequence conflict';END IF;
  disposition_value:=resolved.disposition;stamp:=resolved.resolved_at;expiry_text:=resolved.expires_at;prior_replay:=true;
 ELSIF accepted.sequence=seq THEN
  IF accepted.request_digest<>digest_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='node coverage sequence conflict';END IF;
  disposition_value:='accepted';stamp:=accepted.resolved_at;expiry_text:=accepted.expires_at;prior_replay:=true;
 ELSE
  IF seq<=greatest(COALESCE(native_sequence,0),COALESCE(accepted.sequence,0),COALESCE(resolved.sequence,0)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='node coverage sequence superseded';END IF;
  source_time:=extract(epoch FROM(substring(v->>'source_observed_at' FROM 1 FOR 19)||'Z')::timestamptz)+CASE WHEN length(v->>'source_observed_at')>20 THEN('0.'||substring(v->>'source_observed_at' FROM 21 FOR length(v->>'source_observed_at')-21))::numeric ELSE 0 END;
  expiry:=source_time+(v->>'ttl_seconds')::integer;
  expiry_text:=to_char(((substring(v->>'source_observed_at' FROM 1 FOR 19)||'Z')::timestamptz+make_interval(secs=>(v->>'ttl_seconds')::integer)) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')||substring(v->>'source_observed_at' FROM 20);
  stamp:=clock_timestamp();
  IF expiry>extract(epoch FROM stamp) THEN
   PERFORM zasp_authorization80_runtime.runtime_sensor_heartbeat(locator,secret,audience,seq,v->>'status',v->'capabilities',v->>'kernel',(v->>'btf')::boolean,(v->>'event_rate')::bigint,(v->>'drops')::bigint);
   disposition_value:='accepted';
   IF expiry<=extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='node coverage source expired during acceptance';END IF;
   INSERT INTO zasp_sensor_coverage_v1.accepted_observations VALUES(o,w,e,i,seq,v->>'state_uid',(v->>'storage_epoch')::bigint,digest_value,v->>'source_observed_at',expiry_text,source_time,expiry,stamp,(auth->>'sensor_version')::bigint,auth->>'token_id',(auth->>'token_generation')::bigint,wire,v,pg_current_xact_id())
   ON CONFLICT(organization_id,workspace_id,environment_id,sensor_id) DO UPDATE SET sequence=excluded.sequence,state_uid=excluded.state_uid,storage_epoch=excluded.storage_epoch,request_digest=excluded.request_digest,source_observed_at=excluded.source_observed_at,expires_at=excluded.expires_at,source_epoch=excluded.source_epoch,expires_epoch=excluded.expires_epoch,resolved_at=excluded.resolved_at,sensor_version=excluded.sensor_version,token_id=excluded.token_id,token_generation=excluded.token_generation,wire=excluded.wire,observation=excluded.observation,recorded_tx=excluded.recorded_tx;
  ELSE disposition_value:='expired_not_committed';END IF;
  INSERT INTO zasp_sensor_coverage_v1.resolved_attempts VALUES(o,w,e,i,seq,v->>'state_uid',(v->>'storage_epoch')::bigint,digest_value,v->>'source_observed_at',expiry_text,source_time,expiry,stamp,(auth->>'sensor_version')::bigint,auth->>'token_id',(auth->>'token_generation')::bigint,disposition_value)
  ON CONFLICT(organization_id,workspace_id,environment_id,sensor_id) DO UPDATE SET sequence=excluded.sequence,state_uid=excluded.state_uid,storage_epoch=excluded.storage_epoch,request_digest=excluded.request_digest,source_observed_at=excluded.source_observed_at,expires_at=excluded.expires_at,source_epoch=excluded.source_epoch,expires_epoch=excluded.expires_epoch,resolved_at=excluded.resolved_at,sensor_version=excluded.sensor_version,token_id=excluded.token_id,token_generation=excluded.token_generation,disposition=excluded.disposition;
 END IF;
 final_auth:=zasp_sensor_coverage_v1.require_live_token(locator,secret,audience);
 IF final_auth IS DISTINCT FROM auth THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='node coverage token changed';END IF;
 IF NOT prior_replay AND disposition_value='accepted' AND expiry<=extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='node coverage source expired after acceptance wait';END IF;
 RETURN jsonb_build_object('sensor_id',i,'sequence',seq,'request_digest',encode(digest_value,'hex'),'disposition',disposition_value,'resolved_at',to_char(stamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')||CASE WHEN extract(microseconds FROM stamp)::bigint%1000000=0 THEN '' ELSE '.'||rtrim(to_char(stamp AT TIME ZONE 'UTC','US'),'0') END||'Z','source_observed_at',v->>'source_observed_at','expires_at',expiry_text,'replayed',prior_replay);
END
$$;
CREATE FUNCTION zasp_sensor_coverage_v1.confirm_receipt(locator bytea,secret bytea,audience text,attempt_sequence bigint,request_digest bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE auth jsonb;final_auth jsonb;r record;BEGIN
 IF attempt_sequence IS NULL OR attempt_sequence<1 OR request_digest IS NULL OR octet_length(request_digest)<>32 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='node coverage receipt confirmation rejected';END IF;
 auth:=zasp_sensor_coverage_v1.require_live_token(locator,secret,audience);
 SELECT d.sequence,d.request_digest,d.disposition,d.resolved_at,d.source_observed_at,d.expires_at INTO r FROM(
 SELECT a.sequence,a.request_digest,'accepted'::text disposition,a.resolved_at,a.source_observed_at,a.expires_at FROM zasp_sensor_coverage_v1.accepted_observations a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.sensor_id,a.sequence,a.request_digest)=(auth->>'organization_id',auth->>'workspace_id',auth->>'environment_id',auth->>'sensor_id',attempt_sequence,$5)
 UNION ALL SELECT a.sequence,a.request_digest,a.disposition,a.resolved_at,a.source_observed_at,a.expires_at FROM zasp_sensor_coverage_v1.resolved_attempts a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.sensor_id,a.sequence,a.request_digest)=(auth->>'organization_id',auth->>'workspace_id',auth->>'environment_id',auth->>'sensor_id',attempt_sequence,$5)) d ORDER BY d.disposition LIMIT 1;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='node coverage terminal receipt unavailable';END IF;
 final_auth:=zasp_sensor_coverage_v1.require_live_token(locator,secret,audience);
 IF final_auth IS DISTINCT FROM auth THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='node coverage confirmation authority changed';END IF;
 -- Only a new acceptance in THIS transaction is source-clock constrained. A
 -- durable accepted replay from a prior transaction remains historical proof.
 IF r.disposition='accepted' AND EXISTS(SELECT 1 FROM zasp_sensor_coverage_v1.accepted_observations a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.sensor_id,a.sequence,a.request_digest)=(auth->>'organization_id',auth->>'workspace_id',auth->>'environment_id',auth->>'sensor_id',attempt_sequence,$5) AND a.recorded_tx=pg_current_xact_id() AND a.expires_epoch<=extract(epoch FROM clock_timestamp())) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='node coverage source expired before confirmation';END IF;
 -- Presentation-only replayed is deliberately not a durable authority field.
 -- The same-transaction adapter compares every stable field and preserves its
 -- original record response replay flag only after confirmed COMMIT.
 RETURN jsonb_build_object('sensor_id',auth->>'sensor_id','sequence',r.sequence,'request_digest',encode(r.request_digest,'hex'),'disposition',r.disposition,'resolved_at',to_char(r.resolved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')||CASE WHEN extract(microseconds FROM r.resolved_at)::bigint%1000000=0 THEN '' ELSE '.'||rtrim(to_char(r.resolved_at AT TIME ZONE 'UTC','US'),'0') END||'Z','source_observed_at',r.source_observed_at,'expires_at',r.expires_at,'replayed',true);
END
$$;
CREATE FUNCTION zasp_sensor_coverage_v1.sensor_coverage(o text,w text,e text,sensor_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb;revision jsonb;base jsonb;accepted zasp_sensor_coverage_v1.accepted_observations%ROWTYPE;native_sequence bigint;current_version bigint;current_state text;state_value text:='unavailable';receipt jsonb:=NULL;BEGIN
 IF NOT zasp_sensor_coverage_v1.caller_ready('human-read','-- node coverage checksum') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='node coverage read unavailable';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['getSensorCoverage'],'view',false,NULL);
 IF NOT zasp_authorization80.sensor_authorized(o,w,e,'getSensorCoverage',sensor_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='node coverage sensor denied';END IF;
 proof:=zasp_authorization80.context();revision:=proof->'revision';PERFORM zasp_authorization80.identity_fence(proof);
 PERFORM zasp_authorization79.revalidate(o,(revision->>'desired')::bigint,(revision->>'generation')::bigint,revision->>'store_id',revision->>'model_id');
 base:=zasp_authorization80.sensor_coverage(o,w,e,sensor_id);
 SELECT * INTO accepted FROM zasp_sensor_coverage_v1.accepted_observations a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.sensor_id)=(o,w,e,$4);
 IF FOUND THEN
  SELECT s.version,s.state INTO current_version,current_state FROM public.zasp_sensors s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.id)=(o,w,e,$4);
  SELECT h.sequence INTO native_sequence FROM public.zasp_sensor_heartbeats h WHERE(h.organization_id,h.workspace_id,h.environment_id,h.sensor_id)=(o,w,e,$4);
  state_value:=CASE WHEN current_state NOT IN('pending','active','degraded') OR current_version IS DISTINCT FROM accepted.sensor_version THEN 'enrollment_revoked' WHEN native_sequence IS DISTINCT FROM accepted.sequence THEN 'source_superseded' WHEN accepted.expires_epoch<=extract(epoch FROM clock_timestamp()) THEN 'source_expired' ELSE 'source_current' END;
  receipt:=jsonb_build_object('sequence',accepted.sequence,'request_digest',encode(accepted.request_digest,'hex'),'received_at',to_char(accepted.resolved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')||CASE WHEN extract(microseconds FROM accepted.resolved_at)::bigint%1000000=0 THEN '' ELSE '.'||rtrim(to_char(accepted.resolved_at AT TIME ZONE 'UTC','US'),'0') END||'Z','source_observed_at',accepted.source_observed_at,'expires_at',accepted.expires_at,'observation',accepted.observation);
 END IF;
 PERFORM zasp_authorization79.revalidate(o,(revision->>'desired')::bigint,(revision->>'generation')::bigint,revision->>'store_id',revision->>'model_id');PERFORM zasp_authorization80.identity_fence(proof);
 IF proof IS DISTINCT FROM zasp_authorization80.context() OR NOT zasp_sensor_coverage_v1.caller_ready('human-read','-- node coverage checksum') OR NOT zasp_authorization80.sensor_authorized(o,w,e,'getSensorCoverage',sensor_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='node coverage read authority changed';END IF;
 RETURN base||jsonb_build_object('node_observation',jsonb_build_object('schema','zasp-node-observation-read-v1','state',state_value,'receipt',receipt));
END
$$;
DO $coverage_owners$
DECLARE p record;BEGIN
 FOR p IN SELECT p.oid::regprocedure identity FROM pg_proc p WHERE p.pronamespace='zasp_sensor_coverage_v1'::regnamespace LOOP
  EXECUTE 'ALTER FUNCTION '||p.identity||' OWNER TO zasp_discovery_authority';
  EXECUTE 'REVOKE ALL ON FUNCTION '||p.identity||' FROM PUBLIC,zasp_discovery_api,zasp_runtime_ingest';
 END LOOP;
END
$coverage_owners$;
GRANT USAGE ON SCHEMA zasp_sensor_coverage_v1 TO zasp_discovery_api,zasp_runtime_ingest;
GRANT EXECUTE ON FUNCTION zasp_sensor_coverage_v1.caller_ready(text,text) TO zasp_discovery_api,zasp_runtime_ingest;
GRANT EXECUTE ON FUNCTION zasp_sensor_coverage_v1.record_heartbeat(bytea,bytea,text,bytea),zasp_sensor_coverage_v1.confirm_receipt(bytea,bytea,text,bigint,bytea) TO zasp_runtime_ingest;
GRANT EXECUTE ON FUNCTION zasp_sensor_coverage_v1.sensor_coverage(text,text,text,text) TO zasp_discovery_api;
