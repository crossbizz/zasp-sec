-- Application Check attestation. Only the registered migration principal can
-- provision the purpose-derived verifier; the API cannot mint decision proofs.
CREATE TABLE zasp_authorization80.verifier(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),version text NOT NULL CHECK(version~'^[a-f0-9]{64}$'),key bytea NOT NULL CHECK(octet_length(key)=32));
ALTER TABLE zasp_authorization80.verifier OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_authorization80.verifier ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_authorization80.verifier FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_authorization80.verifier TO zasp_discovery_authority USING(true) WITH CHECK(true);

CREATE FUNCTION zasp_authorization80.register_verifier(v text,k bytea) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE changed boolean; org text;
BEGIN
 IF NOT zasp_authorization80.ready('-- authorization80 checksum')
 OR NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')
 OR NOT pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
 OR NOT COALESCE(octet_length(k)=32 AND v=encode(public.digest(k,'sha256'),'hex'),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization verifier registration rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-authorization80-verifier',0));
 SELECT NOT EXISTS(SELECT 1 FROM zasp_authorization80.verifier WHERE version=v AND key=k) INTO changed;
 IF changed THEN
  -- Lock revisions before changing verifier material, matching current fences.
  FOR org IN SELECT id FROM public.zasp_organizations ORDER BY id LOOP PERFORM zasp_authorization79.touch(org);END LOOP;
  INSERT INTO zasp_authorization80.verifier(version,key) VALUES(v,k) ON CONFLICT(singleton) DO UPDATE SET version=EXCLUDED.version,key=EXCLUDED.key;
 END IF;
 RETURN true;
END $$;

CREATE FUNCTION zasp_authorization80.key_ready(v text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_authorization80.ready('-- authorization80 checksum') AND EXISTS(SELECT 1 FROM zasp_authorization80.verifier WHERE version=v)
$$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.key_ready(text) TO zasp_discovery_api,zasp_security_agent_api;

CREATE FUNCTION zasp_authorization80.unique_json(v json,depth integer DEFAULT 0) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $$
DECLARE child json;
BEGIN
 IF depth>32 THEN RETURN false;END IF;
 IF json_typeof(v)='object' THEN
  IF (SELECT count(*)<>count(DISTINCT key) FROM json_each(v)) THEN RETURN false;END IF;
  FOR child IN SELECT value FROM json_each(v) LOOP IF NOT zasp_authorization80.unique_json(child,depth+1) THEN RETURN false;END IF;END LOOP;
 ELSIF json_typeof(v)='array' THEN
  FOR child IN SELECT value FROM json_array_elements(v) LOOP IF NOT zasp_authorization80.unique_json(child,depth+1) THEN RETURN false;END IF;END LOOP;
 END IF;
 RETURN true;
END $$;

CREATE FUNCTION zasp_authorization80.verify_attestation(envelope text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE outer_value json;body_bytes bytea;body_json json;proof jsonb;k bytea;now_ms bigint:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
BEGIN
 IF envelope IS NULL OR octet_length(envelope)>12*1024*1024 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization attestation rejected';END IF;
 outer_value:=envelope::json;
 IF json_typeof(outer_value)<>'object' OR NOT zasp_authorization80.unique_json(outer_value)
 OR (SELECT count(*) FROM json_each(outer_value))<>3
 OR EXISTS(SELECT 1 FROM json_each(outer_value) WHERE key NOT IN('body','version','mac') OR json_typeof(value)<>'string')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization attestation rejected';END IF;
 SELECT key INTO k FROM zasp_authorization80.verifier WHERE version=outer_value->>'version';
 body_bytes:=decode(outer_value->>'body','base64');
 IF NOT COALESCE(k IS NOT NULL AND octet_length(body_bytes) BETWEEN 1 AND 8*1024*1024
 AND outer_value->>'mac'=encode(public.hmac(convert_to('zasp-authorization-attestation-v1','UTF8')||decode('00','hex')||body_bytes,k,'sha256'),'hex'),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization attestation rejected';END IF;
 -- Parse the exact authenticated bytes, not a parallel unsigned allowed list.
 body_json:=convert_from(body_bytes,'UTF8')::json;
 IF json_typeof(body_json)<>'object' OR NOT zasp_authorization80.unique_json(body_json) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization attestation rejected';END IF;
 proof:=body_json::jsonb;
 IF NOT COALESCE(proof->>'attestation_domain'='zasp-authorization-attestation-v1' AND proof->>'key_version'=outer_value->>'version'
 AND (proof->>'issued_at')::bigint<=now_ms+5000 AND (proof->>'expires_at')::bigint>now_ms
 AND (proof->>'expires_at')::bigint-(proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization attestation rejected';END IF;
 RETURN proof;
EXCEPTION WHEN data_exception THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization attestation rejected';
END $$;

CREATE FUNCTION zasp_authorization80.context_seal(p jsonb) RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT encode(public.hmac(convert_to(jsonb_build_array('zasp-authorization-context-v1',session_user,pg_current_xact_id_if_assigned()::text,p)::text,'UTF8'),key,'sha256'),'hex') FROM zasp_authorization80.verifier WHERE version=p->>'key_version'
$$;

CREATE FUNCTION zasp_authorization80.context() RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;seal text;
BEGIN
 p:=NULLIF(current_setting('zasp.authorization80',true),'')::jsonb;
 seal:=NULLIF(current_setting('zasp.authorization80_seal',true),'');
 IF p IS NULL OR seal IS NULL OR pg_current_xact_id_if_assigned() IS NULL OR seal IS DISTINCT FROM zasp_authorization80.context_seal(p)
 OR NOT COALESCE((p->>'expires_at')::bigint>floor(extract(epoch FROM clock_timestamp())*1000)::bigint,false) THEN RETURN NULL;END IF;
 RETURN p;
EXCEPTION WHEN data_exception THEN RETURN NULL;
END $$;
