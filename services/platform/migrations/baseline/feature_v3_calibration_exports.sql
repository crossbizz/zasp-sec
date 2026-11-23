-- Freeze redacted observations at request time. The worker writes only this
-- bounded snapshot to a versioned, KMS-encrypted ClassExport key.
CREATE TABLE IF NOT EXISTS public.zasp_calibration_exports (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,id text NOT NULL,actor text NOT NULL,idem text NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN('queued','writing','ready','failed')),
 requested_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL DEFAULT now()+interval '1 day',
 samples integer NOT NULL CHECK(samples BETWEEN 0 AND 2048), snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='array' AND octet_length(snapshot::text)<=1048576),
 attempts integer NOT NULL DEFAULT 0,lease uuid,lease_until timestamptz,object_version text,object_sha text,size_bytes integer,
 PRIMARY KEY(organization_id,workspace_id,environment_id,id),UNIQUE(organization_id,workspace_id,environment_id,actor,idem),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_data_controls
);
CREATE TABLE IF NOT EXISTS public.zasp_calibration_grants (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,export_id text NOT NULL,
 actor text NOT NULL,session_id text NOT NULL,digest text NOT NULL,expires_at timestamptz NOT NULL,consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(organization_id,workspace_id,environment_id,export_id,actor,session_id,digest),
 FOREIGN KEY(organization_id,workspace_id,environment_id,export_id) REFERENCES public.zasp_calibration_exports ON DELETE CASCADE
);
DO $protect$ DECLARE tbl text; BEGIN FOREACH tbl IN ARRAY ARRAY['zasp_calibration_exports','zasp_calibration_grants'] LOOP
 EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',tbl);
 EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tbl);
 EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tbl);
 EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tbl);
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename=tbl AND policyname='calibration_owner') THEN
 EXECUTE format('CREATE POLICY calibration_owner ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',tbl);END IF;
 END LOOP;END $protect$;

CREATE OR REPLACE FUNCTION zasp_authorization80.calibration_export(o text,w text,e text,a text,x text,op text,k text,d text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $export$
DECLARE p jsonb;j public.zasp_calibration_exports%ROWTYPE;frozen jsonb; deadline timestamptz; session_key text; read_op text;
BEGIN
 IF op NOT IN('createCalibrationExport','getCalibrationExport','createCalibrationDownloadGrant','read','consume') OR op IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501';END IF;
 read_op:=CASE WHEN op IN('read','consume') THEN 'downloadCalibrationExport' ELSE op END;
 p:=zasp_authorization80.product_request(o,w,e,a,read_op,'view_compliance','environment',e,false,op NOT IN('read','consume'),op IN('createCalibrationExport','createCalibrationDownloadGrant'),op<>'getCalibrationExport');
 IF op<>'createCalibrationExport' AND p#>>'{path_parameters,id}' IS DISTINCT FROM x THEN RAISE EXCEPTION USING ERRCODE='42501';END IF;
 IF op='createCalibrationExport' THEN
  IF k IS NULL OR k!~'^[A-Za-z0-9_.:-]{16,128}$' THEN RETURN '"invalid"';END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws('/',o,w,e,'calibration-export'),0));
  SELECT * INTO j FROM public.zasp_calibration_exports WHERE (organization_id,workspace_id,environment_id,actor,idem)=(o,w,e,a,k);
  IF NOT FOUND THEN
   IF (SELECT count(*) FROM public.zasp_calibration_exports WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND expires_at>now())>=32 THEN RETURN '"limit"';END IF;
   SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.evaluated_at,t.decision_id,t.rule_id),'[]') INTO frozen FROM
   (SELECT s.decision_id,s.rule_id,s.threat_probability,s.evaluated_at,f.label FROM public.semantic_evaluations s LEFT JOIN public.analyst_feedback f USING(organization_id,workspace_id,environment_id,decision_id,rule_id)
    WHERE (s.organization_id,s.workspace_id,s.environment_id)=(o,w,e) AND s.evaluated_at>=now()-interval '30 days' ORDER BY evaluated_at DESC,decision_id,rule_id LIMIT 2048)t;
   INSERT INTO public.zasp_calibration_exports(organization_id,workspace_id,environment_id,id,actor,idem,samples,snapshot) VALUES(o,w,e,x,a,k,jsonb_array_length(frozen),frozen) RETURNING * INTO j;
  END IF;
 ELSE
  SELECT * INTO j FROM public.zasp_calibration_exports WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,x) AND (actor=a OR (op IN('read','consume') AND p->>'credential_kind'='2')) AND expires_at>now() FOR SHARE;
  IF NOT FOUND THEN RETURN 'null';END IF;
 END IF;
 IF j.status IN('writing','queued') AND (j.expires_at<=now() OR (j.attempts>=3 AND j.lease_until<=now())) THEN j.status:='failed'; END IF;
 IF op IN('createCalibrationExport','getCalibrationExport') THEN
  IF op='createCalibrationExport' THEN PERFORM zasp_authorization80.product_settled(p); END IF;
  RETURN jsonb_build_object('id',j.id,'environment_id',e,'samples',j.samples,'status',j.status,'requested_at',j.requested_at,'expires_at',j.expires_at);
 END IF;
 session_key:=p->>'credential_id';
 IF session_key IS NULL OR d IS NULL OR d!~'^[a-f0-9]{64}$' OR j.status<>'ready' THEN RETURN '"unavailable"';END IF;
 IF op='createCalibrationDownloadGrant' THEN
  deadline:=least(j.expires_at,now()+interval '1 minute');
  INSERT INTO public.zasp_calibration_grants VALUES(o,w,e,x,a,session_key,d,deadline,false);
  PERFORM zasp_authorization80.product_settled(p);
  RETURN jsonb_build_object('expires_at',deadline);
 END IF;
 IF NOT EXISTS(SELECT FROM public.zasp_calibration_grants g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.export_id,g.actor,g.digest)=(o,w,e,x,j.actor,d) AND (g.session_id=session_key OR p->>'credential_kind'='2') AND NOT g.consumed AND g.expires_at>now()) THEN RETURN '"unavailable"';END IF;
 IF op='consume' THEN
  UPDATE public.zasp_calibration_grants g SET consumed=true WHERE (g.organization_id,g.workspace_id,g.environment_id,g.export_id,g.actor,g.digest)=(o,w,e,x,j.actor,d) AND (g.session_id=session_key OR p->>'credential_kind'='2') AND NOT g.consumed AND g.expires_at>now();
  IF NOT FOUND THEN RETURN '"unavailable"';END IF;
 END IF;
 PERFORM zasp_authorization80.product_settled(p);
 RETURN jsonb_build_object('version',j.object_version,'sha256',j.object_sha,'size',j.size_bytes);
END $export$;

CREATE OR REPLACE FUNCTION public.zasp_calibration_export_worker(token uuid,version_id text,sha text,n integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $writer$
DECLARE j public.zasp_calibration_exports%ROWTYPE;
BEGIN
 PERFORM public.zasp_compliance_require(expected_checksum,expected_fingerprint,'zasp_compliance_worker');
 IF token IS NULL THEN
  WITH next AS (SELECT organization_id,workspace_id,environment_id,id FROM public.zasp_calibration_exports
   WHERE expires_at>now() AND attempts<3 AND (status='queued' OR (status='writing' AND lease_until<=now())) ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP LOCKED)
  UPDATE public.zasp_calibration_exports x SET status='writing',attempts=attempts+1,lease=gen_random_uuid(),lease_until=now()+interval '1 minute'
   FROM next WHERE (x.organization_id,x.workspace_id,x.environment_id,x.id)=(next.organization_id,next.workspace_id,next.environment_id,next.id) RETURNING x.* INTO j;
  IF NOT FOUND THEN RETURN 'null'; END IF;
  RETURN jsonb_build_object('organization_id',j.organization_id,'workspace_id',j.workspace_id,'environment_id',j.environment_id,'id',j.id,'lease',j.lease,'snapshot',j.snapshot);
 END IF;
 IF version_id IS NULL OR length(version_id) NOT BETWEEN 1 AND 1024 OR sha IS NULL OR sha!~'^[a-f0-9]{64}$' OR n IS NULL OR n NOT BETWEEN 1 AND 1048576 THEN RETURN 'false'; END IF;
 UPDATE public.zasp_calibration_exports SET status='ready',object_version=version_id,object_sha=sha,size_bytes=n,lease=NULL,lease_until=NULL,snapshot='[]'
 WHERE status='writing' AND lease=token AND lease_until>now() AND expires_at>now();
 RETURN to_jsonb(FOUND);
END $writer$;
ALTER FUNCTION zasp_authorization80.calibration_export(text,text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_calibration_export_worker(uuid,text,text,integer,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.calibration_export(text,text,text,text,text,text,text,text),public.zasp_calibration_export_worker(uuid,text,text,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.calibration_export(text,text,text,text,text,text,text,text) TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION public.zasp_calibration_export_worker(uuid,text,text,integer,text,text) TO zasp_compliance_worker;
