-- Preserve the installed62 ABI and mutation history; add only current human
-- approval authority. These three live definitions remain worker-fingerprinted.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_ordered_public62.api(text,text,jsonb)'::regprocedure,'zasp_ordered_public62.mutate(text,text,jsonb)'::regprocedure,'zasp_ordered_public62.fingerprint()'::regprocedure);

CREATE FUNCTION zasp_authorization80_worker.require_ordered62_approval(q jsonb,current_value boolean) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $approval$
DECLARE p jsonb:=zasp_authorization80.context();o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';actor text:=q->>'actor_id';
 id_value text:=CASE WHEN q->>'operation'='classify' THEN q->>'resource_id' ELSE q->>'approval_id' END;approval public.zasp_security_agent_approvals%ROWTYPE;authenticated timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR current_value IS NULL OR p IS NULL
 OR NOT zasp_authorization80_worker.catalog_ready() OR NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api'),false)
 OR NOT COALESCE((q->>'operation' IN('decide_resource','decide') OR(q->>'operation'='classify' AND q->>'resource_kind'='approval'))
 AND zasp_authorization80.read_request(o,w,e,ARRAY['decideSecurityAgentApproval'],'manage_workflows',true,actor)
 AND p->'collection'='false'::jsonb AND p->'fresh_auth'='true'::jsonb AND p#>>'{path_parameters,id}'=id_value
 AND jsonb_array_length(p->'targets')=1 AND jsonb_array_length(p->'allowed')=1
 AND zasp_authorization80.allowed(o,w,e,'security_agent_approval',id_value),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current ordered approval required';END IF;
 IF current_value THEN
  -- The outer entry takes this before budget/admission/run locks. Rechecks
  -- before transition preserve exact current revision, never a tolerated range.
  PERFORM 1 FROM zasp_authorization79.organizations x WHERE x.organization_id=o
   AND(x.desired,x.applied,x.generation,x.store_id,x.model_id)=((p#>>'{revision,desired}')::bigint,(p#>>'{revision,applied}')::bigint,(p#>>'{revision,generation}')::bigint,p#>>'{revision,store_id}',p#>>'{revision,model_id}') FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered approval revision changed';END IF;
 END IF;
 SELECT * INTO approval FROM public.zasp_security_agent_approvals WHERE(organization_id,workspace_id,environment_id,approval_id)=(o,w,e,id_value) FOR SHARE;
 IF NOT FOUND OR(q->>'operation'='decide' AND q->>'run_id' IS DISTINCT FROM approval.run_id)
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'targets') t WHERE(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'kind',t->>'id',COALESCE(NULLIF(t->>'source_id',''),t->>'id'))=(o,w,e,'security_agent_approval',id_value,id_value)
 AND(NOT current_value OR(t->>'version')::bigint=approval.version))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered approval target changed';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 IF q->>'operation'<>'classify' THEN
  SELECT authenticated_at INTO authenticated FROM public.zasp_product_sessions WHERE(session_id,token_digest)=(p->>'credential_id',decode(p->>'credential_digest','hex'));
  IF authenticated IS NULL OR jsonb_typeof(q->'fresh_auth_at') IS DISTINCT FROM 'string' OR(q->>'fresh_auth_at')::timestamptz IS DISTINCT FROM authenticated THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered approval freshness changed';END IF;
 END IF;
 -- Nested transition may wait after the pre-write check. Expiry here rolls
 -- back all local writes; no provider or gateway IO occurs in this transaction.
 IF p IS DISTINCT FROM zasp_authorization80.context() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered approval proof expired';END IF;
END $approval$;

CREATE FUNCTION zasp_authorization80_worker.ordered62_replace(d text,needle text,replacement text) RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $replace$
BEGIN
 IF d IS NULL OR needle IS NULL OR length(needle)=0 OR replacement IS NULL OR(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered62 predecessor changed';END IF;
 RETURN replace(d,needle,replacement);
END $replace$;

DO $ordered_human$ DECLARE d text;needle text;guard text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_ordered_public62.api(text,text,jsonb)' AND owner_name='zasp_discovery_authority' AND acl='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_security_agent_api=X/zasp_discovery_authority}';
 guard:=$gate$ IF op IN('decide_resource','decide') OR(op='classify' AND q->>'resource_kind'='approval') THEN PERFORM zasp_authorization80_worker.require_ordered62_approval(q,true);END IF;$gate$;
 needle:=$lock$ PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));$lock$;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,guard||E'\n'||needle);
 needle:=' RETURN result_value;';
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,replace(guard,'(q,true)','(q,false)')||E'\n'||needle);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_ordered_public62.mutate(text,text,jsonb)' AND owner_name='zasp_discovery_authority' AND acl='{zasp_discovery_authority=X/zasp_discovery_authority}';
 guard:=$gate$ IF op='decide' THEN PERFORM zasp_authorization80_worker.require_ordered62_approval(q,true);END IF;$gate$;
 needle:=$admitted$ admitted:=EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r));$admitted$;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,guard||E'\n'||needle);
 needle:='   transition_result:=zasp_temporal67.api_transition(';
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,guard||E'\n'||needle);
 needle:=$return$ RETURN result_value||jsonb_build_object('replayed',replayed);$return$;
 d:=zasp_authorization80_worker.ordered62_replace(d,needle,replace(guard,'(q,true)','(q,false)')||E'\n'||needle);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_ordered_public62.fingerprint()' AND owner_name='zasp_discovery_authority' AND acl='{zasp_discovery_authority=X/zasp_discovery_authority}';
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_ordered_public62.fingerprint()','FUNCTION zasp_authorization80_worker.projected62()');
 d:=zasp_authorization80_worker.ordered62_replace(d,'pg_get_functiondef(p.oid)',$projection$CASE WHEN p.oid IN('zasp_ordered_public62.api(text,text,jsonb)'::regprocedure,'zasp_ordered_public62.mutate(text,text,jsonb)'::regprocedure,'zasp_ordered_public62.fingerprint()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);
 EXECUTE d;
END $ordered_human$;

CREATE OR REPLACE FUNCTION zasp_ordered_public62.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- worker catalog body digest' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum') AND zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.projected62() ELSE NULL END
$fingerprint$;
