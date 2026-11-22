-- Snapshot every seeded row including primary keys, digests, payloads and
-- relations. Authenticated reads legitimately change the token's last_used_at.
SELECT jsonb_build_array(to_jsonb(o),to_jsonb(w),to_jsonb(e),to_jsonb(m),to_jsonb(s),
         to_jsonb(t)-'last_used_at',to_jsonb(p),to_jsonb(d),to_jsonb(x),to_jsonb(j),to_jsonb(b))::text
FROM zasp_organizations o
JOIN zasp_workspaces w ON w.organization_id=o.id
JOIN zasp_environments e ON (e.organization_id,e.workspace_id)=(o.id,w.id)
JOIN zasp_identity_memberships m ON m.organization_id=o.id
JOIN zasp_authorized_scopes s ON (s.organization_id,s.workspace_id,s.environment_id,s.principal_id)=(o.id,w.id,e.id,m.principal_id)
JOIN zasp_product_api_tokens t ON (t.organization_id,t.workspace_id,t.environment_id,t.principal_id)=(o.id,w.id,e.id,m.principal_id)
JOIN zasp_gateway_policies p ON (p.organization_id,p.workspace_id,p.environment_id)=(o.id,w.id,e.id)
JOIN zasp_guardrail_decisions d ON (d.organization_id,d.workspace_id,d.environment_id,d.principal_id)=(o.id,w.id,e.id,m.principal_id)
JOIN zasp_compliance_export_scopes x ON (x.organization_id,x.workspace_id,x.environment_id)=(o.id,w.id,e.id)
JOIN zasp_compliance_export_jobs j ON (j.organization_id,j.workspace_id,j.environment_id,j.principal_id)=(o.id,w.id,e.id,m.principal_id)
JOIN zasp_product_sessions b ON (b.organization_id,b.workspace_id,b.environment_id,b.principal_id,b.token_digest)=(o.id,w.id,e.id,m.principal_id,j.session_digest)
WHERE o.id IN ('pid_85a00001-0000-4000-8000-000000000001','pid_85a00002-0000-4000-8000-000000000001')
ORDER BY o.id
