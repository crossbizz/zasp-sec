-- The lock-only role needs EXECUTE on a policy helper, not parent visibility
-- for its adapter login.66 hashes this helper's ACL. Preserve the exact
-- predecessor hash through a two-object projection guarded by the complete
-- registered74 catalog, including the actual helper ACL and wrapper body.
INSERT INTO zasp_temporal74.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal66.legacy_visible(text,text,text,text)'::regprocedure,'zasp_temporal66.fingerprint()'::regprocedure);
DO $projection$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal66.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal66.fingerprint()', 'FUNCTION zasp_temporal74.owner66_fingerprint()');
 -- pg_get_functiondef retains SQL source spelling. Fail if that exact source
 -- no longer has the single function-ACL and function-definition expressions.
 needle:='COALESCE(p.proacl::text,'''')';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 OR (length(d)-length(replace(d,'pg_get_functiondef(p.oid)','')))/length('pg_get_functiondef(p.oid)')<>1 THEN RAISE EXCEPTION 'single-test66 projection predecessor changed';END IF;
 d:=replace(d,needle,$new$CASE WHEN p.oid='zasp_temporal66.legacy_visible(text,text,text,text)'::regprocedure THEN (SELECT acl FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal66.legacy_visible(text,text,text,text)') ELSE COALESCE(p.proacl::text,'') END$new$);
 d:=replace(d,'pg_get_functiondef(p.oid)',$new$CASE WHEN p.oid='zasp_temporal66.fingerprint()'::regprocedure THEN (SELECT definition FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal66.fingerprint()') ELSE pg_get_functiondef(p.oid) END$new$);
 EXECUTE d;
END $projection$;
ALTER FUNCTION zasp_temporal74.owner66_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_temporal74.owner66_fingerprint() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_temporal66.legacy_visible(text,text,text,text),zasp_temporal74.visible(text,text,text,text) TO zasp_temporal74_parent_lock;

CREATE OR REPLACE FUNCTION zasp_temporal66.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN (SELECT count(*)=1 FROM zasp_temporal74.registration)
  AND EXISTS(SELECT 1 FROM zasp_temporal74.registration WHERE checksum='-- test74 checksum' AND fingerprint='-- test74 fingerprint')
  AND zasp_temporal74.fingerprint()='-- test74 fingerprint'
 THEN zasp_temporal74.owner66_fingerprint() ELSE NULL END
$fingerprint$;

--65 predates the shipped cancelled approval variant. Extend only that state
-- for a persisted74 parent; all original audit/intent/approver checks remain.
INSERT INTO zasp_temporal74.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal65.capture()'::regprocedure,'zasp_temporal65.fingerprint()'::regprocedure);
DO $cancelled_approval$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal65.capture()';
 needle:='a.state IN(''approved'',''rejected'')';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'single-test65 decision predecessor changed';END IF;
 d:=replace(d,needle,$new$(a.state IN('approved','rejected') OR a.state='cancelled'
  AND public.zasp_security_agent_principal_ready('zasp_security_agent_api') AND zasp_temporal74.current_ready()
  AND NEW.response->>'state'='cancelled' AND NEW.response->>'id'=a.approval_id AND NEW.response->>'run_id'=rr.run_id AND NEW.response->>'step_id'=a.step_id
  AND NEW.intent=jsonb_build_object('approval_id',a.approval_id,'expected_version',NEW.expected_version,'decision','cancelled')
  AND audit_row.event_kind='approval_decided' AND audit_row.step_id=a.step_id AND audit_row.event_digest=NEW.intent_digest
  AND audit_row.body=jsonb_build_object('approval_id',a.approval_id,'run_id',rr.run_id,'decision','cancelled','version',NEW.expected_version+1)
  AND rr.state='cancelled' AND rr.completed_at IS NOT NULL AND rr.lease_owner IS NULL AND rr.lease_token IS NULL AND rr.lease_expires_at IS NULL AND a.plan_hash=rr.plan_hash
  AND EXISTS(SELECT 1 FROM zasp_temporal74.run_owners x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.definition_id,x.definition_version)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,a.step_id,rr.definition_id,rr.definition_version)))$new$);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal65.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal65.fingerprint()', 'FUNCTION zasp_temporal74.outbox65_fingerprint()');
 needle:='pg_get_functiondef(p.oid)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'single-test65 fingerprint predecessor changed';END IF;
 EXECUTE replace(d,needle,$new$CASE WHEN p.oid IN('zasp_temporal65.capture()'::regprocedure,'zasp_temporal65.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal74.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$new$);
END $cancelled_approval$;
ALTER FUNCTION zasp_temporal74.outbox65_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_temporal74.outbox65_fingerprint() FROM PUBLIC;
CREATE OR REPLACE FUNCTION zasp_temporal65.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN (SELECT count(*)=1 FROM zasp_temporal74.registration)
  AND EXISTS(SELECT 1 FROM zasp_temporal74.registration WHERE checksum='-- test74 checksum' AND fingerprint='-- test74 fingerprint')
  AND zasp_temporal74.fingerprint()='-- test74 fingerprint'
 THEN zasp_temporal74.outbox65_fingerprint() ELSE NULL END
$fingerprint$;
