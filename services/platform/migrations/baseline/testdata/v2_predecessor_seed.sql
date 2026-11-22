-- Restore a small, deterministic historical dataset into the disposable old
-- baseline. As with a data-only restore, don't fire creation/permit triggers.
-- Subsequent authentication and authorization use unmodified service logins.
SET LOCAL session_replication_role = replica;
DO $fixture$
DECLARE
  tenant integer;
  prefix text; org text; ws text; env text; actor text;
BEGIN
  FOR tenant IN 1..2 LOOP
    prefix := 'pid_85a0000' || tenant || '-0000-4000-8000-00000000000';
    org := prefix || '1'; ws := prefix || '2'; env := prefix || '3'; actor := prefix || '4';
    INSERT INTO zasp_organizations(id,name,domain)
      VALUES(org,'Upgrade tenant ' || tenant,'upgrade-' || tenant || '.invalid');
    INSERT INTO zasp_workspaces(id,organization_id,name) VALUES(ws,org,'Engineering');
    INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class)
      VALUES(org,ws,env,'Staging','staging');
    INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active,version)
      VALUES(actor,org,'org-upgrade-' || tenant,'member-upgrade-' || tenant,'security_admin',true,3);
    INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default)
      VALUES(actor,org,ws,env,'Staging','["view"]',true);
    INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at,version)
      VALUES(digest('upgrade-rehearsal-ephemeral-credential-' || tenant,'sha256'),prefix || '5','Deploy reader',actor,org,ws,env,'["view"]',now()+interval '1 day',2);
    INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at)
      VALUES(digest('synthetic-upgrade-browser-session-credential-' || tenant,'sha256'),'session-upgrade-' || tenant,actor,org,ws,env,
        '["view"]',repeat('c',32),now(),now()+interval '2 hours');
    INSERT INTO zasp_gateway_policies(organization_id,workspace_id,environment_id,unapproved_servers,denied_tool_risks,requests_per_minute,version,updated_by)
      VALUES(org,ws,env,'refuse',ARRAY['write','execute'],50+tenant,4,actor);
    INSERT INTO zasp_guardrail_decisions(organization_id,workspace_id,environment_id,id,principal_id,direction,decision,rules,input_bytes,content_digest,tool_name,policy_version)
      VALUES(org,ws,env,prefix || '6',actor,'input','block','["pii"]',23,digest('fixture-input-' || tenant,'sha256'),'ticket_lookup',4);
    INSERT INTO zasp_compliance_export_scopes(organization_id,workspace_id,environment_id) VALUES(org,ws,env);
    INSERT INTO zasp_compliance_export_jobs(organization_id,workspace_id,environment_id,export_id,principal_id,session_digest,idempotency_key,request,request_digest,policy_revision,mapping_revision)
      VALUES(org,ws,env,prefix || '7',actor,digest('synthetic-upgrade-browser-session-credential-' || tenant,'sha256'),'upgrade-job-' || tenant,
        '{"framework":"soc2_security"}',digest(convert_to('{"framework":"soc2_security"}'::jsonb::text,'UTF8'),'sha256'),'compliance-limits-v1','product-evidence-v1');
    INSERT INTO zasp_authorization79.organizations(organization_id,desired,applied,generation,store_id,model_id,applied_at,blocked_reason)
      VALUES(org,1,1,1,'01K00000000000000000000001','01K00000000000000000000002',now(),'');
  END LOOP;
END
$fixture$;
