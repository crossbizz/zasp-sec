import {readFileSync} from 'node:fs';
const reviewCatalog = JSON.parse(readFileSync(new URL('../../services/platform/compliancemap/data/owasp_agentic_top10-2026.json', import.meta.url), 'utf8'));
// Synthetic Zasp records for isolated browser review. Never loaded by the app.
export const id = n => `pid_${String(n).padStart(8, '0')}-0000-4000-8000-${String(n).padStart(12, '0')}`;
export const pageOf = items => ({ items, page_info: { has_more: false, next_cursor: null } });
const at = '2026-11-15T12:00:00Z';
const capabilities = ['inventory.read','inventory.write','findings.read','attack-paths.read','compliance.read','red-team.read','policies.read','policies.write','security-agents.read','sessions.read','audit.read','integrations.read','integrations.write','sensors.read','sensors.write','identity.manage','api-access.manage','recovery.read','system.read'];
export const bootstrap = { principal: { id: id(4), organization_id: id(1), organization_reference: 'organization-ui-review', member_reference: 'member-ui-review', role: 'security_admin', active: true }, organization_id: id(1), workspace_id: id(2), environment_id: id(3), permissions: ['view','view_audit','view_compliance','manage_workflows','revoke_sessions'], capabilities, csrf_token: 'c'.repeat(32), fresh_auth_expires_at: '2099-01-01T00:00:00Z', correlation_id: id(4) };
const names = ['Support agent', 'Repository reviewer', 'Invoice processing assistant', 'Platform knowledge agent', 'Customer success assistant', 'Operations runbook agent', 'Research assistant', 'Release coordinator', 'Workspace agent with an intentionally long name to inspect truncation and full accessible values', 'Incident triage assistant', 'Developer documentation agent', 'Cloud inventory assistant'];
export const inventory = (kind = 'agent') => names.map((name, index) => ({ id: id((kind === 'tool' ? 1000 : 100) + index), name: kind === 'agent' ? name : `${['Support', 'Platform', 'Cloud', 'Operations'][index % 4]} ${kind} ${index + 1}`, kind, owner: ['security@example.test', 'platform@example.test', ''][index % 3], team: 'Platform', tags: [], evidence_id: id(200), confidence_basis_points: 9500, first_seen: at, last_seen: at, observed_at: at, fresh_until: '2099-01-01T00:00:00Z', freshness_state: 'fresh', version: 1, provider: ['aws','github','gcp','kubernetes'][index % 4], source_kind: kind === 'agent' ? ['bedrock_agent','github_agent_project','vertex_agent','kubernetes_agent'][index % 4] : 'kubernetes_resource', discovery: { method: kind === 'agent' && index % 3 === 0 ? 'declared' : 'provider_api', platform: ['bedrock_agent','github_repository','vertex_ai_agent_engine','kubernetes_workload'][index % 4], signals: [] }, management_state: kind === 'agent' ? index % 3 === 2 ? 'unmanaged' : 'managed' : 'not_applicable', last_activity_at: null, activity_state: kind === 'agent' ? 'unknown' : 'not_applicable' }));
const finding = { id: id(300), source: 'posture', rule: 'unapproved_tool', title: 'Public tool access', severity: 'high', status: 'open', agent_id: id(100), path_id: id(310), evidence_ids: [id(200)], risk_factors: [{ name: 'Public input', evidence_id: id(200) }], version: 1, created_at: at, updated_at: at };
const attackPath = { id: id(310), entry_id: id(100), sink_id: id(101), node_ids: [id(100), id(101)], state: 'verified', evidence_ids: [id(200)], blocked_edge: -1, version: 1, created_at: at, updated_at: at };
const reviewDevice = {
  id: id(701), cohort: 'Support-pilot', state: 'active', version: 1, credential_generation: 1,
  last_seen: at, connection: 'stale', policy_revision: 3, reported_policy_revision: 3,
  acknowledged: true, queued_receipts: 0, dropped_receipts: 0,
};
const workloadToken = {
  id: id(710), name: 'Support tooling workload', principal_id: id(4), workspace_id: id(2), environment_id: id(3),
  permissions: ['decide_actions'], created_at: at, expires_at: '2099-01-01T00:00:00Z',
  last_used_at: null, revoked_at: null, version: 1,
};
const supervisedToken = { ...workloadToken, id: id(715), name: 'Supervised support workload' };
const supervisedSession = {
  credential_id: supervisedToken.id, agent_id: id(100), session_id: id(716),
  source: 'administrator_bound_credential', created_by: id(4), created_at: at,
};
const unboundPath = `/api/v1/runtime/workload-bindings/${workloadToken.id}`;
export function fixtureStatus(url) {
  return url.pathname === unboundPath ? 404 : 200;
}
const policy = { id: 'policy-review', name: 'Review unapproved tool calls', scope: 'environment', trigger: 'tool', conditions: [{ field: 'action', operator: 'equals', value: 'invoke' }], action: 'block', rollout: 'monitor', failure_mode: 'closed' };
const manifest = (key, provider, category, description, auth_mode) => ({ key, provider, category, description, data_types: ['repository'], actions: ['inventory_read'], auth_mode, setup_schema: [{ key: 'authorization_mode', label: 'Authorization mode', type: 'string', required: true, description: 'Provider application' }], access_guidance: 'Grant read-only access to selected resources.', test_semantics: 'Verify provider authorization.' });
const catalog = [manifest('aws','Amazon Web Services','cloud','Discover Bedrock agents, runtimes, roles and data stores through a read-only role.','aws_assume_role'),manifest('gcp','Google Cloud','cloud','Discover Vertex AI agents and service accounts.','credential_reference'),manifest('github','GitHub','developer','Discover agent projects, skills and MCP configuration.','github_app_oauth'),manifest('saas-openai','OpenAI','saas','Read projects, assistants and API key metadata.','nango_connection'),manifest('saas-anthropic','Anthropic','saas','Read workspaces and API key metadata.','nango_connection')];
export function fixture(url, fallback) {
  const path = url.pathname.replace('/api/v1/', '');
  if (['admin/scim-connections','admin/sso-connections','mcp-servers','security-agents','compliance/controls','compliance/evidence'].includes(path)) return pageOf([]);
  if (path === 'compliance/editions') return {items:[{framework:reviewCatalog.framework,edition:reviewCatalog.edition,source_digest:reviewCatalog.source_digest,total_controls:reviewCatalog.entries.length}]};
  if (path === 'compliance/coverage') {
    const {entries, ...source} = reviewCatalog;
    return {...source, total_controls:entries.length,matched_controls:entries.length,collected_at:at,next_after:null,
      summary:{applicable_controls:1,verified_applicable_controls:0,unassessed_controls:9,out_of_scope_controls:0,risks:10,techniques:0,subtechniques:0,mitigations:0},
      items:entries.map(({id:upstream_id,title,kind})=>({control:{...source,upstream_id,title,kind,owner:'Application security',
        scope:'addon_supply_chain',applicability:upstream_id==='ASI04'?'applicable':'unassessed',rationale:'Synthetic Environment review.',status:'active'},
        evidence_counts:upstream_id==='ASI04'?{static_scan:1}:{},last_verified_at:null}))};
  }
  if (path === 'addon-versions') return { items:[{id:id(720),manifest_digest:'sha256:'+'a'.repeat(64),origin:'local',provenance:'reported',ruleset:'zasp-static.v2',findings:[{rule_id:'dependency.unpinned',count:1}],review_state:'pending',revision:0}], next_cursor:null };
  if (path === 'test-probes') {
    const categories = ['prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information','indirect_injection','poisoned_resource','cross_agent_delegation'];
    return { version:'zasp-probe-library-v1',digest:'a'.repeat(64),probe_count:1080,default_sample_size:25,categories:categories.map(category=>({
      category,title:category.replaceAll('_',' '),probe_count:120,techniques:['direct_override'],
      frameworks:[{framework:'owasp_llm_top10_2025',control:'LLM01',title:'Prompt Injection'}],
    }))};
  }
  if (path === 'session/bootstrap') return bootstrap;
  if (path === 'workflow-mutation-receipts') return { items: [] };
  if (path === 'home/summary') return { agent_count: 12, high_risk_paths: 3, verified_changes: 24, blocked_changes: 7, pending_approvals: 2, oldest_approval_age_seconds: 120, needs_human_runs: 1, failed_runs: 0, inconclusive_runs: 1, recent_contained: 3, recent_remediated: 5, healthy: true, attention_required: false };
  for (const [endpoint, kind] of [['agents','agent'], ['tools','tool'], ['identities','identity'], ['runtimes','runtime'], ['assets','asset']]) {
    if (path === endpoint && kind !== 'asset') return pageOf(inventory(kind));
    if (path.startsWith(endpoint + '/') && path.split('/').length === 2) return { summary: inventory(kind).find(row => row.id === path.split('/')[1]), sources: [{ integration_id: id(400), provider: inventory(kind).find(row => row.id === path.split('/')[1]).provider, source: 'kubernetes', source_identifier: 'sha256:' + 'b'.repeat(64), snapshot_id: id(401), generation: 1, evidence_id: id(200), confidence_basis_points: 9500, observed_at: at, fresh_until: '2099-01-01T00:00:00Z', projection_version: 1, winning: true }], evidence: [{ id: id(200), checksum: 'sha256:' + 'a'.repeat(64), media_type: 'application/json', schema_version: 'raw_v1', parser_version: 'parser_v1', tool_version: 'tool_v1', collected_at: at, size_bytes: 128 }] };
  }
  if (/^agents\/[^/]+\/access$/.test(path)) return { agent_id: path.split('/')[1], ai_actions: null, mcp_servers: [], data_stores: [], skills: [], tools: [], tool_kinds: [] };
  if (path === `agents/${id(100)}/capabilities`) return pageOf([{agent_id:id(100),target_id:id(101),target_kind:'identity',
    category:'identity_assume',outcome:'assume',state:'blocked',reachable:true,evidence_ids:[id(200)]}]);
  if (path === `agents/${id(100)}/relationships`) return pageOf([{id:id(210),from_id:id(100),to_id:id(101),type:'uses_identity',evidence_id:id(200)}]);
  if (path === `agents/${id(100)}/sessions`) return pageOf([{id:id(211),agent_id:id(100),started_at:at}]);
  if (path === `agents/${id(100)}/purpose`) return { agent_id: id(100), revision: 2, allowed_tool_ids: [inventory('tool')[0].id], updated_at: at };
  if (path === `agents/${id(100)}/suggestions`) return { agent_id: id(100), purpose_revision: 2, items: [], more: false, last_scan: null };
  if (path === 'findings') return pageOf([finding, { ...finding, id: id(301), title: 'Agent role permits broad resource access', severity: 'critical' }, { ...finding, id: id(302), title: 'Model invocation needs ownership review', severity: 'medium' }]);
  if (path === `findings/${id(300)}`) return finding;
  if (path === 'attack-paths') return pageOf([attackPath]);
  if (path === `attack-paths/${id(310)}`) return attackPath;
  if (path === 'policies') return pageOf([policy]);
  if (path === 'policies/policy-review') return policy;
  if (path === 'policies/policy-review/decisions') return { items: [] };
  if (path === 'integration-catalog') return { items: catalog };
  if (path === 'integrations') return pageOf([{ id: id(400), connector_key: 'github', name: 'Engineering repositories', configuration: { authorization_mode: 'github_app' }, status: 'active', created_at: at, updated_at: at }]);
  if (path === 'admin/roles') return pageOf([{ role: 'security_admin', permissions: ['view','view_audit','manage_workflows'] }, { role: 'read_only_viewer', permissions: ['view'] }]);
  if (path === 'admin/members') return pageOf([{ ...bootstrap.principal, version: 1 }]);
  if (path === 'admin/api-token-policy') return { environment_id: id(3), max_lifetime_days: 90, version: 1, updated_at: at, default_lifetime_days: 1, decision_token_max_lifetime_days: 90, token_max_lifetime_days: 90 };
  if (path === 'admin/api-tokens') return pageOf([workloadToken, supervisedToken]);
  if (path === `runtime/workload-bindings/${supervisedToken.id}`) return supervisedSession;
  if (url.pathname === unboundPath) return { code: 'not_found', message: 'This workload credential has no agent binding.', correlation_id: id(711), retryable: false };
  if (path === 'admin/api-token-reveal-grants') return pageOf([]);
  if (path === 'settings/data-controls') return { environment_id: id(3), environment_class: 'production', collection_mode: 'metadata_only', retention_days: 30, deletion_enabled: true, version: 1 };
  if (path === 'system/status') return { security_plane_healthy: true, optional_degraded: false, fresh_at: at };
  if (path === 'system/components') return { items: ['postgresql','identity-provider'].map(name => ({ id: name, required: true, state: 'healthy', fresh_at: at })) };
  if (path === 'system/version') return { version: '0.1.0' };
  if (path === 'settings/external-data-flows') return { items: [{ id: 'identity-provider', required: true, categories: ['identity_metadata'], enabled: true, health: 'healthy' }] };
  if (path === 'organization') return { id: id(1), name: 'UI review workspace', domain: 'example.test', version: 1 };
  if (path === 'audit-events' || path === 'audit-log') return pageOf([{ id: id(600), workspace_id: id(2), environment_id: id(3), actor_id: id(4), action: 'member.role.update', target_id: id(4), outcome: 'succeeded', metadata: {}, occurred_at: at }]);
  if (path === 'gateway/mcp-servers') return { items: [], gateway_enabled: true };
  if (path === 'gateway/policy') return { environment_id: id(3), unapproved_servers: 'refuse', denied_tool_risks: [], requests_per_minute: 60, version: 1, updated_at: at, gateway_enabled: true };
  if (path === 'gateway/activity') return { items: [], next_cursor: null };
  if (['security-actions','security-agent-templates','gateway/activity','mcp-registry'].includes(path)) return { items: [] };
  if (path === 'devices') return { items: [reviewDevice], next_after_id: null, counts: { expected: 1, enrolled: 1, online: 0, acknowledged: 1 } };
  if (path === `devices/${reviewDevice.id}`) return { ...reviewDevice, reported_adapter: 'macos_claude_ticket', inventory_partitions: 0, observation_count: 0, partition_summaries: [], recent_observations: [] };
  if (path === 'sensors') return pageOf([{ id: id(700), name: 'production-runtime', kind: 'tetragon', mode: 'metadata_only', state: 'active', version: 1, token_expires_at: '2099-01-01T00:00:00Z', last_heartbeat_at: at, created_at: at, updated_at: at }]);
  if (['security-agent-runs', 'security-agent-approvals', 'tests', 'test-runs', 'attack-lab/runs', 'admin/roles'].includes(path)) return { items: [] };
  if (path === 'sessions' && url.searchParams.get('kind') === 'runtime') return { ...pageOf([]), search: { state: 'empty', pending_batches: 0, pending_batches_capped: false, quarantined_batches: 0, quarantined_batches_capped: false, last_indexed_at: null, oldest_pending_at: null, checked_at: at, selector_coverage: 'observed_only' } };
  if (path === 'sessions') return pageOf([{id:'session-review',agent_id:'product-console',principal_id:id(4),
    workspace_id:id(2),environment_id:id(3),state:'active',authenticated_at:at,expires_at:'2099-01-01T00:00:00Z',version:1,events:[]}]);
  if (path === 'sessions/session-review/events') return pageOf([]);
  if (path === 'guardrails/policy') return { environment_id: id(3), version: 1, updated_at: at, rules: ['injection.instruction_override','injection.role_switch','injection.hidden_text','injection.tool_call','pii.email','pii.phone','pii.credit_card','pii.us_ssn','secret.aws_access_key_id','secret.private_key','secret.bearer_token'].map(id => ({ id, category: id.startsWith('injection.') ? 'prompt_injection' : 'sensitive_data', description: 'Matches ' + id, mode: id.startsWith('injection.') ? 'block' : 'redact', default_mode: id.startsWith('injection.') ? 'block' : 'redact', redactable: !id.startsWith('injection.') })) };
  if (path === 'search') {
    const q = (url.searchParams.get('q') || '').toLowerCase();
    const limit = Math.min(100, Number(url.searchParams.get('limit') || 20));
    const items = ['agent', 'asset', 'identity', 'runtime', 'tool'].flatMap(type =>
      inventory(type).map(({id, name}) => ({type, id, name})));
    items.push({type:'finding', id:finding.id, name:finding.title});
    const order = item => [item.type, item.name.toLowerCase(), item.id].join('\u001f');
    return {items: items.filter(item => item.name.toLowerCase().startsWith(q) || item.type === q || item.id === q)
      .sort((a, b) => order(a) < order(b) ? -1 : 1).slice(0, limit)};
  }
  fallback?.(path);
  return pageOf([]);
}
