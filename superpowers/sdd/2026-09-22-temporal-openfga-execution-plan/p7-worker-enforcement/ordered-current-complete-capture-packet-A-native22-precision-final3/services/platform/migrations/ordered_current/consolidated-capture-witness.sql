SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:2','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('fingerprint',(fingerprint::text)) AS fact FROM zasp_authorization80_worker.registration) captured GROUP BY fact
) AS capture_witness_0001
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:31','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('singleton',(singleton),'checksum',(checksum),'fingerprint',(fingerprint)) AS fact FROM zasp_authorization80_runtime.registration) captured GROUP BY fact
) AS capture_witness_0002
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_setup:live-metadata','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('value',((SELECT value FROM zasp_schema_metadata WHERE key='production_security_agent_attack_path_fingerprint'))) AS fact ) captured GROUP BY fact
) AS capture_witness_0003
UNION ALL
SELECT * FROM (
WITH saved AS (
 SELECT s.*,s.signature IN('public.zasp_workflow_mutate_v3(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text)','public.zasp_workflow_replay(text,text,text,text,text,text,jsonb)')
 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b JOIN pg_roles r ON r.rolname=b.principal_name WHERE b.principal_name=s.owner_name AND b.authority_role='zasp_discovery_authority' AND pg_has_role(r.oid,'zasp_discovery_authority','MEMBER')) AS migration_owned
 FROM zasp_sa_export_prior.functions s
 ) SELECT jsonb_build_object('ruleId','public:sa_export:saved-observations','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature),'owner',(CASE WHEN migration_owned THEN '<registered-migration-principal>' ELSE 'owner:'||owner_name END),'acl',(CASE WHEN migration_owned THEN (SELECT jsonb_agg(CASE WHEN a->>'grantee'=owner_name THEN jsonb_build_array('registered-migration-principal',a-'grantee') ELSE jsonb_build_array('literal',a) END ORDER BY n)::text FROM jsonb_array_elements(acl) WITH ORDINALITY x(a,n)) ELSE acl::text END)) AS fact FROM saved) captured GROUP BY fact
) AS capture_witness_0004
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:role:managed-marker','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('role',(r.rolname::text),'managed_here',(shobj_description(r.oid,'pg_authid')=ANY(ARRAY[format('zasp-managed:production-discovery-execution-v1:database:%s:created',(SELECT oid FROM pg_database WHERE datname=current_database())),format('zasp-managed:production-discovery-execution-v1:database:%s:bound',(SELECT oid FROM pg_database WHERE datname=current_database()))]))) AS fact FROM pg_roles r WHERE r.rolname=ANY(ARRAY['zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker'])) captured GROUP BY fact
) AS capture_witness_0005
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:rule','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('provider',(provider::text),'source_kind',(source_kind::text),'row',(to_jsonb(rule))) AS fact FROM zasp_inventory_identity_rules rule) captured GROUP BY fact
) AS capture_witness_0006
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:restore','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('object_kind',(object_kind::text),'object_identity',(object_identity::text),'definition_digest',(encode(definition_digest,'hex'))) AS fact FROM zasp_inventory_legacy_restore) captured GROUP BY fact
) AS capture_witness_0007
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:role:managed-marker','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('role',(role.rolname::text),'managed_here',(shobj_description(role.oid,'pg_authid')=ANY(ARRAY[format('zasp-managed:typed-inventory-cutover-v1:database:%s:created',(SELECT oid FROM pg_database WHERE datname=current_database())),format('zasp-managed:typed-inventory-cutover-v1:database:%s:bound',(SELECT oid FROM pg_database WHERE datname=current_database()))]))) AS fact FROM pg_roles role WHERE role.rolname='zasp_inventory_authority') captured GROUP BY fact
) AS capture_witness_0008
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:runtime-audit:none-namespace','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('namespace_identity',(CASE WHEN (SELECT count(*) FROM zasp_authorization80.runtime_profile)=1 AND rp.singleton AND rp.audit_mode='none' THEN to_regnamespace('zasp_authorization80_audit')::text ELSE NULL END)) AS fact FROM zasp_authorization80.runtime_profile rp WHERE (SELECT count(*) FROM zasp_authorization80.runtime_profile)=1 AND rp.singleton AND rp.audit_mode='none') captured GROUP BY fact
) AS capture_witness_0009
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:runtime-audit:none-trigger-inputs','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_identity',(t.tgrelid::regclass::text),'name',(t.tgname::text)) AS fact FROM zasp_authorization80.runtime_profile rp CROSS JOIN pg_trigger t WHERE (SELECT count(*) FROM zasp_authorization80.runtime_profile)=1 AND rp.singleton AND rp.audit_mode='none' AND t.tgrelid=(CASE WHEN (SELECT count(*) FROM zasp_authorization80.runtime_profile)=1 AND rp.singleton AND rp.audit_mode='none' THEN 'public.zasp_admin_audit' ELSE NULL END)::regclass AND t.tgname='zasp_authorization80_audit_write_guard') captured GROUP BY fact
) AS capture_witness_0010
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:snapshot','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('normalized_acl',(jsonb_build_object('owner',c.relowner::regrole::text,'grants',(SELECT jsonb_agg(jsonb_build_object('grantor',a.grantor::regrole::text,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor::regrole::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,a.privilege_type,a.is_grantable) FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a),'columns',(SELECT jsonb_agg(jsonb_build_object('number',column_row.attnum,'name',column_row.attname,'grants',CASE WHEN column_row.attacl IS NULL THEN 'null'::jsonb ELSE COALESCE((SELECT jsonb_agg(jsonb_build_object('grantor',a.grantor::regrole::text,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor::regrole::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,a.privilege_type,a.is_grantable) FROM aclexplode(column_row.attacl) a),'[]'::jsonb) END) ORDER BY column_row.attnum) FROM pg_attribute column_row WHERE column_row.attrelid=c.oid AND column_row.attnum>0 AND NOT column_row.attisdropped)))) AS fact FROM pg_class c WHERE c.oid='public.zasp_admin_audit'::regclass) captured GROUP BY fact
) AS capture_witness_0011
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:expected','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('normalized_acl',(jsonb_build_object('owner',s.before_state->'owner','columns',s.before_state->'columns','grants',(SELECT jsonb_agg(value ORDER BY value->>'grantor',value->>'grantee',value->>'privilege',(value->>'grantable')::boolean) FROM (
 SELECT value FROM jsonb_array_elements(s.before_state->'grants')
 UNION ALL SELECT jsonb_build_object('grantor',s.before_state->>'owner','grantee','zasp_discovery_authority','privilege','SELECT','grantable',false) WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s.before_state->'grants') g WHERE g->>'grantor'=s.before_state->>'owner' AND g->>'grantee'='zasp_discovery_authority' AND g->>'privilege'='SELECT')
 ) grants)))) AS fact FROM public.zasp_audit_export_source_acl s) captured GROUP BY fact
) AS capture_witness_0012
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-workflow:snapshot','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('normalized_acl',(jsonb_build_object('owner',c.relowner::regrole::text,'grants',(SELECT jsonb_agg(jsonb_build_object('grantor',a.grantor::regrole::text,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor::regrole::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,a.privilege_type,a.is_grantable) FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a),'columns',(SELECT jsonb_agg(jsonb_build_object('number',column_row.attnum,'name',column_row.attname,'grants',CASE WHEN column_row.attacl IS NULL THEN 'null'::jsonb ELSE COALESCE((SELECT jsonb_agg(jsonb_build_object('grantor',a.grantor::regrole::text,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor::regrole::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,a.privilege_type,a.is_grantable) FROM aclexplode(column_row.attacl) a),'[]'::jsonb) END) ORDER BY column_row.attnum) FROM pg_attribute column_row WHERE column_row.attrelid=c.oid AND column_row.attnum>0 AND NOT column_row.attisdropped)))) AS fact FROM pg_class c WHERE c.oid='public.zasp_workflow_audit'::regclass) captured GROUP BY fact
) AS capture_witness_0013
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:schema-metadata:normalization-input','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('key',(key::text),'value',(value::text)) AS fact FROM public.zasp_schema_metadata WHERE key NOT IN('production_audit_exports_checksum','production_audit_exports_fingerprint','production_security_agent_budgets_checksum','production_security_agent_budgets_fingerprint','production_security_agent_run_context_checksum','production_security_agent_run_context_fingerprint','production_security_agent_existing_tests_checksum','production_security_agent_existing_tests_fingerprint','production_compliance_checksum','production_compliance_fingerprint','production_security_agent_attack_lab_checksum','production_security_agent_attack_lab_fingerprint','production_security_agent_exports_checksum','production_security_agent_exports_fingerprint','production_security_agent_webhooks_checksum','production_security_agent_webhooks_fingerprint','production_discovery_schedule_replay_checksum','production_discovery_schedule_replay_fingerprint','production_security_agent_multistep_checksum','production_security_agent_multistep_fingerprint')) captured GROUP BY fact
) AS capture_witness_0014
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:worker-catalog-ready:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text)) AS fact FROM zasp_authorization80_worker.registration WHERE checksum='e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960') captured GROUP BY fact
) AS capture_witness_0015
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal74:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal74.registration) captured GROUP BY fact
) AS capture_witness_0016
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal76:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal76.registration) captured GROUP BY fact
) AS capture_witness_0017
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal77:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal77.registration) captured GROUP BY fact
) AS capture_witness_0018
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal78:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal78.registration) captured GROUP BY fact
) AS capture_witness_0019
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:authorization80-temporal:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_authorization80_temporal.registration) captured GROUP BY fact
) AS capture_witness_0020
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:roles-ready:roles','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('name',(r.rolname::text),'login',(r.rolcanlogin),'inherit',(r.rolinherit),'superuser',(r.rolsuper),'create_db',(r.rolcreatedb),'create_role',(r.rolcreaterole),'replication',(r.rolreplication),'bypass_rls',(r.rolbypassrls)) AS fact FROM pg_roles r WHERE r.rolname IN(SELECT principal_name FROM zasp_temporal72.principals UNION SELECT authority_role FROM zasp_temporal72.principals)) captured GROUP BY fact
) AS capture_witness_0021
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:roles-ready:membership','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('granted_role',(granted.rolname::text),'member_role',(member.rolname::text),'admin_option',(membership.admin_option)) AS fact FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE member.rolname IN(SELECT principal_name FROM zasp_temporal72.principals)) captured GROUP BY fact
) AS capture_witness_0022
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:roles-ready:bindings','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('source',(b.source::text),'principal_name',(b.principal_name::text),'authority_role',(b.authority_role::text)) AS fact FROM (SELECT 'principal-bindings'::text source,principal_name,authority_role FROM public.zasp_discovery_principal_bindings UNION ALL SELECT 'execution-principals'::text source,principal_name,authority_role FROM public.zasp_discovery_execution_principals) b WHERE EXISTS(SELECT 1 FROM zasp_temporal72.principals p WHERE (p.principal_name,p.authority_role)=(b.principal_name,b.authority_role))) captured GROUP BY fact
) AS capture_witness_0023
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal68:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal68.registration) captured GROUP BY fact
) AS capture_witness_0024
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal69:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal69.registration) captured GROUP BY fact
) AS capture_witness_0025
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal70:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal70.registration) captured GROUP BY fact
) AS capture_witness_0026
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal71:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal71.registration) captured GROUP BY fact
) AS capture_witness_0027
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal72:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal72.registration) captured GROUP BY fact
) AS capture_witness_0028
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal73:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal73.registration) captured GROUP BY fact
) AS capture_witness_0029
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:temporal75:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal75.registration) captured GROUP BY fact
) AS capture_witness_0030
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:authorization79:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_authorization79.registration) captured GROUP BY fact
) AS capture_witness_0031
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:authorization80:registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_authorization80.registration) captured GROUP BY fact
) AS capture_witness_0032
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:metadata','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('key',(m.key::text),'value',(m.value::text)) AS fact FROM public.zasp_schema_metadata m WHERE m.key NOT IN('production_audit_exports_checksum','production_audit_exports_fingerprint','production_security_agent_budgets_checksum','production_security_agent_budgets_fingerprint','production_security_agent_run_context_checksum','production_security_agent_run_context_fingerprint','production_security_agent_existing_tests_checksum','production_security_agent_existing_tests_fingerprint','production_compliance_checksum','production_compliance_fingerprint','production_security_agent_attack_lab_checksum','production_security_agent_attack_lab_fingerprint','production_security_agent_exports_checksum','production_security_agent_exports_fingerprint','production_security_agent_webhooks_checksum','production_security_agent_webhooks_fingerprint','production_discovery_schedule_replay_checksum','production_discovery_schedule_replay_fingerprint','production_security_agent_multistep_checksum','production_security_agent_multistep_fingerprint')) captured GROUP BY fact
) AS capture_witness_0033
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:metadata-principal-login','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('principal_name',(r.rolname::text),'login',(r.rolcanlogin)) AS fact FROM pg_roles r WHERE r.rolname IN (SELECT b.principal_name FROM public.zasp_discovery_principal_bindings b WHERE b.authority_role='zasp_discovery_authority')) captured GROUP BY fact
) AS capture_witness_0034
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:metadata-principals','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('principal_name',(b.principal_name::text),'authority_role',(b.authority_role::text)) AS fact FROM public.zasp_discovery_principal_bindings b WHERE b.authority_role='zasp_discovery_authority') captured GROUP BY fact
) AS capture_witness_0035
