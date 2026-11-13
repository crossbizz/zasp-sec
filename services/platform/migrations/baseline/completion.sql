-- Product completion on top of the activated baseline.
--
-- The historical chain moved about half of the product onto the current
-- authorization model (zasp_authorization80: every product statement is an
-- authorized function executed inside a fenced transaction). The read
-- surfaces below were never moved, so under the current model the API refused
-- them. This file adds what those surfaces need. The only existing function
-- bodies it changes are zasp_authorization80.resolve and parent_targets
-- (section F), which keep every rule and check readiness once per call.
--
-- generate.sh applies this file to the superuser installation, as the
-- PostgreSQL superuser, in one transaction, after activation.sql. Every
-- object names its owner and its grantees explicitly; nothing is granted to
-- PUBLIC and no role is created. The file is re-runnable.
--
-- An existing installation applies it the same way and then re-seals the
-- catalog: SET ROLE zasp_discovery_authority; SELECT zasp_baseline.accept(...).

-- ---------------------------------------------------------------------------
-- A. Typed inventory for new Environments.
--
-- zasp_authorization80.inventory_page (and the typed inventory reads behind
-- it) serve an Environment only once its inventory scope is in phase
-- 'cutover'. The chain cut scopes over by an operator procedure
-- (zasp_inventory_backfill_scope, then zasp_inventory_cutover_scope) meant for
-- Environments that carried legacy generic inventory payloads. Nothing ran it
-- for an Environment created afterwards, so every new Environment refused its
-- inventory lists with 'authorization inventory page rejected'.
--
-- A new Environment has no legacy inventory, so the chain's own procedure
-- proves the (empty) equivalence and cuts it over at creation. The trigger
-- covers every creation path: bootstrap, zasp_authorization80.create_workspace
-- and zasp_authorization80.create_environment. Discovery writes typed
-- inventory (zasp_discovery_apply_snapshot) independently of the phase, so
-- discovered entities appear on the authorized lists.
CREATE OR REPLACE FUNCTION public.zasp_inventory_environment_cutover() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $environment_cutover$
BEGIN
 IF TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_RELID<>'public.zasp_environments'::regclass THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='inventory environment cutover contract rejected';
 END IF;
 -- A scope that is already cut over (a state row that outlived a deleted
 -- Environment of the same ID) needs nothing and must not fail the insert.
 IF COALESCE(public.zasp_inventory_scope_state(NEW.organization_id,NEW.workspace_id,NEW.id)->>'phase','')='cutover' THEN
  RETURN NULL;
 END IF;
 PERFORM public.zasp_inventory_backfill_scope(NEW.organization_id,NEW.workspace_id,NEW.id);
 PERFORM public.zasp_inventory_cutover_scope(NEW.organization_id,NEW.workspace_id,NEW.id);
 RETURN NULL;
END $environment_cutover$;
ALTER FUNCTION public.zasp_inventory_environment_cutover() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_inventory_environment_cutover() FROM PUBLIC;

DROP TRIGGER IF EXISTS zasp_inventory_environment_cutover ON public.zasp_environments;
CREATE TRIGGER zasp_inventory_environment_cutover AFTER INSERT ON public.zasp_environments
 FOR EACH ROW EXECUTE FUNCTION public.zasp_inventory_environment_cutover();

-- Environments created before this file was applied. An Environment whose
-- legacy and typed inventory disagree stops here, as the procedure intends.
DO $existing_environments$
DECLARE scope record;
BEGIN
 FOR scope IN SELECT x.organization_id,x.workspace_id,x.id FROM public.zasp_environments x
  WHERE COALESCE(public.zasp_inventory_scope_state(x.organization_id,x.workspace_id,x.id)->>'phase','') <> 'cutover'
  ORDER BY x.organization_id,x.workspace_id,x.id LOOP
  IF COALESCE(public.zasp_inventory_scope_state(scope.organization_id,scope.workspace_id,scope.id)->>'phase','expanded')='expanded' THEN
   PERFORM public.zasp_inventory_backfill_scope(scope.organization_id,scope.workspace_id,scope.id);
  END IF;
  PERFORM public.zasp_inventory_cutover_scope(scope.organization_id,scope.workspace_id,scope.id);
 END LOOP;
END $existing_environments$;

-- ---------------------------------------------------------------------------
-- Authorized reads. Every function below follows its zasp_authorization80
-- neighbours (inventory_page, workflow_page, risk_page, receipt_page,
-- get_data_controls):
--   * it is SECURITY DEFINER, owned by zasp_discovery_authority, with a fixed
--     search_path, and executable only by the API role that serves the route;
--   * it returns data only inside a fenced transaction: require_read /
--     read_request compare the organization, workspace, environment,
--     operation and permission arguments with the attested proof that
--     zasp_authorization80.fence() verified for this transaction;
--   * every returned row passes zasp_authorization80.allowed() for its own
--     resource kind, or, for scope-level reads, the scope target itself does;
--   * page sizes are bounded.
-- Nothing here reads a caller-supplied organization outside the proof.

-- ---------------------------------------------------------------------------
-- B. Security Agent catalog, runs and approvals.
--
-- Capability readiness. The chain's zasp_sa_attack_lab_readiness and
-- zasp_sa_export_readiness require exactly 60 rows in zasp_schema_versions.
-- Release 61 (production_security_agent_multistep) did not re-pin them, so on
-- the 61-release baseline both are false for ever and the Security Agent
-- catalog reported 'provider unavailable'. These two functions state the same
-- capability for the current catalog: the release row and its recorded
-- identity, the role shape the release requires, and the current
-- authorization release, whose readiness is the catalog integrity check
-- (zasp_baseline.intact(), through zasp_authorization80.ready) plus the
-- multistep release that superseded the 60-release pins.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_attack_lab_ready(c text,f text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $attack_lab_ready$
 SELECT COALESCE(c='e0f037ec8948a4d574ae33f37e9554d9ff6539785b7d601d7c96685a66c01776' AND f='f44bc966ef77ab523a80ace71b59defbe709c1fdbefd69ccfc40cacaf16d7ba8'
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=57 AND name='production_security_agent_attack_lab' AND checksum=c)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_attack_lab_checksum' AND value=c)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_attack_lab_fingerprint' AND value=f)
 AND public.zasp_sa_attack_lab_role_ready()
 AND zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd')
 AND(public.zasp_discovery_principal_ready('zasp_discovery_api') OR public.zasp_security_agent_principal_ready('zasp_security_agent_api')),false)
$attack_lab_ready$;

CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_export_ready(c text,f text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $export_ready$
 SELECT COALESCE(c='5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985' AND f='8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f'
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=58 AND name='production_security_agent_exports' AND checksum=c)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_exports_checksum' AND value=c)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_exports_fingerprint' AND value=f)
 AND public.zasp_sa_export_principal_ready('zasp_security_agent_api')
 AND zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd'),false)
$export_ready$;

-- Security Agent definitions (GET /security-agents). The chain's
-- workflow_page('security_agent') reads zasp_workflow_records, which holds no
-- Security Agent; the definitions live in zasp_security_agent_definitions,
-- the source the resolver registers for kind 'security_agent'.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_page(o text,w text,e text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_page$
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listSecurityAgents'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR(a IS NOT NULL AND NOT public.zasp_valid_product_id(a)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 RETURN(WITH candidates AS(SELECT d.definition_id AS id,d.body FROM public.zasp_security_agent_definitions d WHERE(d.organization_id,d.workspace_id,d.environment_id)=(o,w,e) AND d.deleted_at IS NULL AND(a IS NULL OR d.definition_id>a) AND zasp_authorization80.allowed(o,w,e,'security_agent',d.definition_id) ORDER BY d.definition_id LIMIT n+1),visible AS(SELECT * FROM candidates ORDER BY id LIMIT n)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(body ORDER BY id) FROM visible),'[]'::jsonb),'next_id',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END));
END $security_agent_page$;

-- Execution controls (GET /security-agent-execution-controls): browser
-- session only, manage_identity on the current Environment. The payload is
-- the chain's own detail plus the eight action switches of the export release.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_execution_controls(o text,w text,e text,actor text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $execution_controls$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE(zasp_authorization80.read_request(o,w,e,ARRAY['getSecurityAgentExecutionControls'],'manage_identity',true,actor) AND zasp_authorization80.allowed(o,w,e,'environment',e),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current read purpose required';END IF;
 result:=public.zasp_security_agent_execution_control_detail(o,w,e);
 RETURN jsonb_set(result,'{actions}',(SELECT jsonb_agg(jsonb_build_object('target','action','action_key',k,'enabled',COALESCE(c.execution_enabled,false),'version',COALESCE(c.version,0)) ORDER BY k)
  FROM unnest(ARRAY['create_evidence_export','create_temporary_policy','isolate_session','rerun_test','revoke_integration_connection','run_test','start_attack_lab','update_finding_response']) k
  LEFT JOIN public.zasp_security_agent_kill_switches c ON(c.organization_id,c.workspace_id,c.environment_id,c.action_key)=(o,w,e,k)));
END $execution_controls$;

-- Runs (GET /security-agent-runs). Same selection, order, keyset and item
-- shape as the chain's zasp_security_agent_run_page, restricted to allowed runs.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_run_page(o text,w text,e text,definition_value text,state_value text,before_created_value timestamptz,before_id_value text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_run_page$
DECLARE items_value jsonb;next_created_value timestamptz;next_id_value text;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listSecurityAgentRuns'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100
  OR(definition_value IS NOT NULL AND NOT public.zasp_valid_product_id(definition_value))
  OR(state_value IS NOT NULL AND state_value NOT IN('queued','planning','waiting_approval','running','verifying','contained','remediated','needs_human','failed','inconclusive','cancelled'))
  OR(before_created_value IS NULL)<>(before_id_value IS NULL) OR(before_id_value IS NOT NULL AND NOT public.zasp_valid_product_id(before_id_value))
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent run page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 WITH candidates AS(
  SELECT run.*,row_number() OVER(ORDER BY run.created_at DESC,run.run_id DESC) AS ordinal
  FROM public.zasp_security_agent_runs run
  WHERE(run.organization_id,run.workspace_id,run.environment_id)=(o,w,e)
   AND run.state<>'simulated' AND(definition_value IS NULL OR run.definition_id=definition_value) AND(state_value IS NULL OR run.state=state_value)
   AND(before_created_value IS NULL OR(run.created_at,run.run_id)<(before_created_value,before_id_value))
   AND zasp_authorization80.allowed(o,w,e,'security_agent_run',run.run_id)
  ORDER BY run.created_at DESC,run.run_id DESC LIMIT n+1
 )
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',run_id,'agent_id',definition_id,'state',state,'evidence_ids',public.zasp_sa_manual_evidence(o,w,e,run_id,trigger_id),'definition_version',definition_version,'version',version)||public.zasp_sa_manual_fields(o,w,e,run_id) ORDER BY created_at DESC,run_id DESC) FILTER(WHERE ordinal<=n),'[]'::jsonb),
        max(created_at) FILTER(WHERE ordinal=n AND(SELECT count(*) FROM candidates)>n),
        max(run_id) FILTER(WHERE ordinal=n AND(SELECT count(*) FROM candidates)>n)
 INTO items_value,next_created_value,next_id_value FROM candidates;
 RETURN jsonb_build_object('items',items_value,'next_created_at',CASE WHEN next_created_value IS NULL THEN NULL ELSE to_char(next_created_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,'next_id',next_id_value);
END $security_agent_run_page$;

-- Approvals (GET /security-agent-approvals). The page is produced by the
-- chain's newest actor-bound reader, zasp_temporal78.approval_page, which
-- keeps its own release, principal and viewer checks. This function adds the
-- current read purpose and removes every approval the proof does not allow,
-- so a page can be shorter than requested; the keyset cursor is the reader's.
CREATE OR REPLACE FUNCTION zasp_authorization80.security_agent_approval_page(o text,w text,e text,state_value text,run_value text,before_created_value timestamptz,before_id_value text,n integer,actor text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $security_agent_approval_page$
DECLARE page_value jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listSecurityAgentApprovals'],'view',false,actor);
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization security agent approval page rejected';END IF;
 page_value:=zasp_temporal78.approval_page(o,w,e,state_value,run_value,before_created_value,before_id_value,n,actor);
 IF jsonb_typeof(page_value->'items') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization security agent approval page unavailable';END IF;
 RETURN jsonb_set(page_value,'{items}',COALESCE((SELECT jsonb_agg(item.value ORDER BY item.ordinality) FROM jsonb_array_elements(page_value->'items') WITH ORDINALITY item(value,ordinality)
  WHERE zasp_authorization80.allowed(o,w,e,'security_agent_approval',COALESCE(item.value->'detail'->>'id',item.value->>'id'))),'[]'::jsonb));
END $security_agent_approval_page$;

-- ---------------------------------------------------------------------------
-- C. Tests, test runs and Attack Lab runs. Same selection, order, cursor and
-- item shape as zasp_red_team_list_definitions, zasp_red_team_list_runs and
-- zasp_attack_lab_list_runs, restricted to allowed rows.
CREATE OR REPLACE FUNCTION zasp_authorization80.test_page(o text,w text,e text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $test_page$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listTests'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR(a IS NOT NULL AND NOT public.zasp_valid_product_id(a)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization test page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(public.zasp_red_team_definition_json(definition_row) ORDER BY definition_id),'[]'::jsonb),'next_cursor',CASE WHEN count(*)=n THEN max(definition_id) END) INTO result
 FROM(SELECT * FROM public.zasp_red_team_definitions d WHERE(d.organization_id,d.workspace_id,d.environment_id)=(o,w,e) AND(a IS NULL OR d.definition_id>a) AND zasp_authorization80.allowed(o,w,e,'test',d.definition_id) ORDER BY d.definition_id LIMIT n) definition_row;
 RETURN result;
END $test_page$;

CREATE OR REPLACE FUNCTION zasp_authorization80.test_run_page(o text,w text,e text,before_value timestamptz,before_id_value text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $test_run_page$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listTestRuns'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR(before_value IS NULL AND before_id_value IS NOT NULL) OR(before_value IS NOT NULL AND NOT COALESCE(public.zasp_valid_product_id(before_id_value),false)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization test run page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 WITH visible AS(SELECT * FROM public.zasp_red_team_runs r WHERE(r.organization_id,r.workspace_id,r.environment_id)=(o,w,e) AND(before_value IS NULL OR(r.queued_at,r.run_id)<(before_value,before_id_value)) AND zasp_authorization80.allowed(o,w,e,'test_run',r.run_id) ORDER BY r.queued_at DESC,r.run_id DESC LIMIT n),
 cursor_row AS(SELECT queued_at,run_id FROM visible ORDER BY queued_at,run_id LIMIT 1)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(public.zasp_red_team_run_json(run_row) ORDER BY queued_at DESC,run_id DESC) FROM visible run_row),'[]'::jsonb),'next_cursor',CASE WHEN(SELECT count(*) FROM visible)=n THEN(SELECT jsonb_build_object('queued_at',to_char(queued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'id',run_id) FROM cursor_row) END) INTO result;
 RETURN result;
END $test_run_page$;

CREATE OR REPLACE FUNCTION zasp_authorization80.attack_lab_run_page(o text,w text,e text,before_value timestamptz,before_id_value text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $attack_lab_run_page$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listAttackLabRuns'],'view');
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR(before_value IS NULL AND before_id_value IS NOT NULL) OR(before_value IS NOT NULL AND NOT COALESCE(public.zasp_valid_product_id(before_id_value),false)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization attack lab run page rejected';END IF;
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization security agent principal rejected';END IF;
 WITH visible AS(SELECT * FROM public.zasp_attack_lab_runs r WHERE(r.organization_id,r.workspace_id,r.environment_id)=(o,w,e) AND(before_value IS NULL OR(r.queued_at,r.run_id)<(before_value,before_id_value)) AND zasp_authorization80.allowed(o,w,e,'attack_lab_run',r.run_id) ORDER BY r.queued_at DESC,r.run_id DESC LIMIT n),
 cursor_row AS(SELECT queued_at,run_id FROM visible ORDER BY queued_at,run_id LIMIT 1)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(public.zasp_attack_lab_run_json(run_row) ORDER BY queued_at DESC,run_id DESC) FROM visible run_row),'[]'::jsonb),'next_cursor',CASE WHEN(SELECT count(*) FROM visible)=n THEN(SELECT jsonb_build_object('queued_at',to_char(queued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'id',run_id) FROM cursor_row) END) INTO result;
 RETURN result;
END $attack_lab_run_page$;

-- ---------------------------------------------------------------------------
-- D. Organization and identity administration reads. Browser session only.
-- zasp_authorization80_identity had the mutations but no read.

-- GET /organization: view on the Organization of the proof.
CREATE OR REPLACE FUNCTION zasp_authorization80.organization(o text,w text,e text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $organization$
DECLARE result jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_discovery_principal_ready('zasp_discovery_api') AND zasp_authorization80.read_request(o,w,e,ARRAY['getOrganization'],'view',true) AND zasp_authorization80.allowed(o,w,e,'organization',o),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current read purpose required';END IF;
 SELECT jsonb_build_object('id',x.id,'name',x.name,'domain',x.domain,'version',x.version) INTO result FROM public.zasp_organizations x WHERE x.id=o;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='organization missing';END IF;
 RETURN result;
END $organization$;

-- Shared admission of the identity administration reads: the verified
-- identity release, the actor of the proof, manage_identity, and the target
-- the operation's policy names (the Organization's identity, or the current
-- Environment).
CREATE OR REPLACE FUNCTION zasp_authorization80.require_identity_read(op text,o text,w text,e text,actor text) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $require_identity_read$
BEGIN
 IF NOT COALESCE(zasp_authorization80_identity.api_ready()
  AND op IN('listMembers','listGroupMappings','listSSOConnections','listSCIMConnections')
  AND zasp_authorization80.read_request(o,w,e,ARRAY[op],'manage_identity',true,actor)
  AND CASE WHEN op='listGroupMappings' THEN zasp_authorization80.allowed(o,w,e,'environment',e) ELSE zasp_authorization80.allowed(o,w,e,'organization_identity',o) END,false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked identity administration read required';END IF;
END $require_identity_read$;

-- GET /admin/members.
CREATE OR REPLACE FUNCTION zasp_authorization80.member_page(o text,w text,e text,actor text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $member_page$
BEGIN
 PERFORM zasp_authorization80.require_identity_read('listMembers',o,w,e,actor);
 IF NOT COALESCE(n BETWEEN 1 AND 101 AND a IS NOT NULL AND(a='' OR public.zasp_valid_product_id(a)),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization member page rejected';END IF;
 RETURN(SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY item->>'id'),'[]'::jsonb)) FROM(
  SELECT jsonb_build_object('id',m.principal_id,'organization_id',m.organization_id,'organization_reference',m.organization_reference,'member_reference',m.member_reference,'role',m.role,'active',m.active,'version',m.version) AS item
  FROM public.zasp_identity_memberships m WHERE m.organization_id=o AND(a='' OR m.principal_id>a) ORDER BY m.principal_id LIMIT n) page);
END $member_page$;

-- GET /admin/group-mappings. The proof authorizes manage_identity on the
-- current Environment, and updateGroupMappings writes mappings for that
-- Environment, so the page lists that Environment's mappings.
CREATE OR REPLACE FUNCTION zasp_authorization80.group_mapping_page(o text,w text,e text,actor text,a text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $group_mapping_page$
BEGIN
 PERFORM zasp_authorization80.require_identity_read('listGroupMappings',o,w,e,actor);
 IF NOT COALESCE(n BETWEEN 1 AND 101 AND a IS NOT NULL AND octet_length(a)<=512,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authorization group mapping page rejected';END IF;
 RETURN(SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY item->>'group_reference'),'[]'::jsonb)) FROM(
  SELECT jsonb_build_object('group_reference',g.group_reference,'role',g.role,'workspace_id',g.workspace_id,'environment_id',g.environment_id,'version',g.version) AS item
  FROM public.zasp_group_mappings g WHERE(g.organization_id,g.workspace_id,g.environment_id)=(o,w,e) AND(a='' OR g.group_reference>a) ORDER BY g.group_reference LIMIT n) page);
END $group_mapping_page$;

-- The identity provider's reference for the Organization, which the SSO and
-- SCIM connection lists send to the provider. Same rule as the chain's
-- zasp_identity_admin_provider_organization (an active organization or
-- security administrator), under the checked read.
CREATE OR REPLACE FUNCTION zasp_authorization80.identity_provider_organization(o text,w text,e text,actor text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $identity_provider_organization$
DECLARE reference text;op text;
BEGIN
 op:=zasp_authorization80.context()->>'operation_id';
 IF op IS NULL OR op NOT IN('listSSOConnections','listSCIMConnections') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='checked identity administration read required';END IF;
 PERFORM zasp_authorization80.require_identity_read(op,o,w,e,actor);
 SELECT m.organization_reference INTO reference FROM public.zasp_identity_memberships m
 WHERE(m.organization_id,m.principal_id)=(o,actor) AND m.active AND m.role IN('organization_admin','security_admin');
 IF NOT FOUND OR reference IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='identity provider organization missing';END IF;
 RETURN to_jsonb(reference);
END $identity_provider_organization$;

-- ---------------------------------------------------------------------------
-- E. Audit events. The audit page (zasp_authorization80.audit_page) existed.
-- Its readiness also asks whether the single-test release (zasp_temporal74)
-- is valid, through zasp_temporal74.api_ready, which only the Security Agent
-- API role may execute and which is true only for that role. The product API
-- role serves the audit page, so its readiness could never pass. This states
-- the same release validity for either API role; it grants nothing in
-- zasp_temporal74.
CREATE OR REPLACE FUNCTION zasp_authorization80.test_release_ready(c text,f text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $test_release_ready$
 SELECT COALESCE(zasp_temporal74.ready(c,f)
 AND(public.zasp_discovery_principal_ready('zasp_discovery_api') OR public.zasp_security_agent_principal_ready('zasp_security_agent_api')),false)
$test_release_ready$;

-- ---------------------------------------------------------------------------
-- Ownership and privileges, as the neighbouring functions have them.
DO $privileges$
DECLARE f record;
BEGIN
 FOR f IN SELECT * FROM(VALUES
  ('zasp_authorization80.security_agent_attack_lab_ready(text,text)','zasp_discovery_api,zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_export_ready(text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_page(text,text,text,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_execution_controls(text,text,text,text)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_run_page(text,text,text,text,text,timestamptz,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.security_agent_approval_page(text,text,text,text,text,timestamptz,text,integer,text)','zasp_security_agent_api'),
  ('zasp_authorization80.test_page(text,text,text,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.test_run_page(text,text,text,timestamptz,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.attack_lab_run_page(text,text,text,timestamptz,text,integer)','zasp_security_agent_api'),
  ('zasp_authorization80.organization(text,text,text)','zasp_discovery_api'),
  ('zasp_authorization80.require_identity_read(text,text,text,text,text)',NULL),
  ('zasp_authorization80.member_page(text,text,text,text,text,integer)','zasp_discovery_api'),
  ('zasp_authorization80.group_mapping_page(text,text,text,text,text,integer)','zasp_discovery_api'),
  ('zasp_authorization80.identity_provider_organization(text,text,text,text)','zasp_discovery_api'),
  ('zasp_authorization80.test_release_ready(text,text)','zasp_discovery_api,zasp_security_agent_api')
 ) v(signature,grantees) LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature::regprocedure);
  IF f.grantees IS NOT NULL THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %s',f.signature::regprocedure,f.grantees);END IF;
 END LOOP;
END $privileges$;

-- ---------------------------------------------------------------------------
-- F. Candidate resolution checks readiness once per call.
--
-- zasp_authorization80.resolve verified the release (reader() and ready())
-- on entry, and every nested resolution repeated it: a mixed collection
-- ('*') resolves 23 kinds, and an audit collection resolves '*' for every
-- Environment of the Organization, so one request evaluated the same
-- readiness about 70 times (16 s for three empty Environments; the audit
-- route never answered inside its deadline). The catalog cannot change
-- between those evaluations in a way the first one would not also see.
--
-- resolve keeps its signature, grants and entry check, and then calls
-- resolve_inner: the same body, verbatim, without the check, whose nested
-- resolutions stay inside it. Only resolve_inner's owner can execute it.
-- parent_targets is reachable without resolve (from parent_allowed, inside a
-- fenced read), so its collection branch performs the check itself before it
-- uses resolve_inner. Its per-object branches still call the checked resolve.
-- No candidate, target or permission rule changes.
DO $resolve_once$
DECLARE d text;
 guard text:=$g$ IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization resolver rejected';END IF;$g$;
 nested text:=$n$result:=result||zasp_authorization80.resolve(o,scope_value.workspace_id,scope_value.id,'*',NULL);$n$;
 branch text:=$b$ IF i IS NULL THEN$b$;
BEGIN
 IF to_regprocedure('zasp_authorization80.resolve_inner(text,text,text,text,text,text)') IS NOT NULL THEN RETURN;END IF;
 SELECT pg_get_functiondef('zasp_authorization80.resolve(text,text,text,text,text,text)'::regprocedure) INTO STRICT d;
 IF (length(d)-length(replace(d,guard,'')))/length(guard)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization resolver predecessor changed';END IF;
 EXECUTE replace(replace(d,guard,''),'zasp_authorization80.resolve(','zasp_authorization80.resolve_inner(');
 SELECT pg_get_functiondef('zasp_authorization80.parent_targets(text,text,text,text,text,text)'::regprocedure) INTO STRICT d;
 IF (length(d)-length(replace(d,nested,'')))/length(nested)<>1 OR (length(d)-length(replace(d,branch,'')))/length(branch)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authorization parent resolver predecessor changed';END IF;
 EXECUTE replace(replace(d,nested,replace(nested,'zasp_authorization80.resolve(','zasp_authorization80.resolve_inner(')),branch,branch||E'\n '||guard);
END $resolve_once$;

CREATE OR REPLACE FUNCTION zasp_authorization80.resolve(o text,w text,e text,k text,i text DEFAULT NULL,selector text DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $resolve$
BEGIN
 IF NOT zasp_authorization79.reader() OR NOT zasp_authorization80.ready('d7fbda32a2b3b9ea0ffbd4f7c7a7967a9d4fba2f6573f49e8386e9586a18a1fd') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authorization resolver rejected';END IF;
 RETURN zasp_authorization80.resolve_inner(o,w,e,k,i,selector);
END $resolve$;
ALTER FUNCTION zasp_authorization80.resolve_inner(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.resolve_inner(text,text,text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_outbox_worker,zasp_security_agent_worker;


-- ---------------------------------------------------------------------------
-- G. Worker startup gate and AWS identity classification.
--
-- Every worker mode asks zasp_authorization80_worker.runtime_ready() at
-- startup unless it uses the runtime profile check. The chain granted that
-- question only to the Temporal, discovery and scheduler roles, so every other
-- worker mode (outbox publishers, projections, Security Agent, Red Team,
-- Attack Lab, policy deployment, recovery, exports, compliance) refused to
-- start on any database. The function returns one boolean about catalog
-- integrity and reads no tenant data.
DO $worker_gate$
DECLARE worker text;
BEGIN
 FOREACH worker IN ARRAY ARRAY[
  'zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_audit_export_outbox','zasp_audit_export_worker',
  'zasp_compliance_cleanup','zasp_compliance_worker','zasp_outbox_worker','zasp_policy_deployment_worker',
  'zasp_projection_graph_worker','zasp_projection_risk_worker','zasp_projection_search_worker',
  'zasp_recovery_outbox_worker','zasp_recovery_worker','zasp_red_team_outbox_worker','zasp_red_team_worker',
  'zasp_security_agent_action_worker','zasp_security_agent_attack_lab_reconciler','zasp_security_agent_worker'] LOOP
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=worker) THEN
   EXECUTE format('GRANT USAGE ON SCHEMA zasp_authorization80_worker TO %I',worker);
   EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.runtime_ready() TO %I',worker);
  END IF;
 END LOOP;
END $worker_gate$;

-- An AWS IAM role is a non-human identity. The chain classified every AWS
-- kind as an asset, and assets have no list route, so nothing an AWS
-- discovery run found could be listed.
UPDATE public.zasp_inventory_identity_rules SET product_kind='identity',rule_version=rule_version+1
 WHERE provider='aws' AND source_kind='aws_role' AND product_kind='asset';
