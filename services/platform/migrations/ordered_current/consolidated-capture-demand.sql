SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM selected c
) AS capture_demand_0001
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM selected c JOIN pg_constraint k ON k.conrelid=c.oid JOIN pg_trigger t ON t.tgconstraint=k.oid WHERE t.tgisinternal AND k.contype='f'
) AS capture_demand_0002
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_demand_0003
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_demand_0004
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_demand_0005
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_demand_0006
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_demand_0007
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_demand_0008
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_demand_0009
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_demand_0010
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_demand_0011
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:2:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_temporary_policy_targets' AND class.relkind IN('r','i')
) AS capture_demand_0012
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:3:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE attribute.attrelid='public.zasp_security_agent_temporary_policy_targets'::regclass AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_demand_0013
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:4:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_temporary_policy_targets'::regclass
) AS capture_demand_0014
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:5:demand','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index index_value JOIN pg_class index_class ON index_class.oid=index_value.indexrelid WHERE (index_value.indrelid='public.zasp_runtime_gateway_events'::regclass AND index_class.relname='zasp_runtime_gateway_events_session_v24_idx') OR index_value.indrelid='public.zasp_security_agent_temporary_policy_targets'::regclass
) AS capture_demand_0015
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:7:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid='public.zasp_security_agent_definitions'::regclass AND conname='zasp_security_agent_session_isolation_supervised_check'
) AS capture_demand_0016
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:2:demand','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles WHERE rolname IN('zasp_recovery_worker','zasp_recovery_outbox_worker')
) AS capture_demand_0017
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:4:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_recovery_%' AND class.relkind IN('r','i')
) AS capture_demand_0018
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:5:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_recovery_%' AND class.relkind='i'
) AS capture_demand_0019
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:6:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_recovery_%' AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_demand_0020
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:7:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_recovery_%'
) AS capture_demand_0021
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:8:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname='zasp_runtime_gateway_events' AND attribute.attname='policy_ids' AND NOT attribute.attisdropped
) AS capture_demand_0022
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:9:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname='zasp_runtime_gateway_events' AND constraint_value.conname='zasp_runtime_gateway_events_policy_ids_v27_ck'
) AS capture_demand_0023
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:10:demand','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index index_value JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_roles owner ON owner.oid=index_class.relowner WHERE index_value.indrelid='public.zasp_runtime_gateway_events'::regclass AND index_class.relname IN('zasp_runtime_gateway_events_policy_ids_v27_idx','zasp_runtime_gateway_events_policy_history_v27_idx')
) AS capture_demand_0024
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:11:demand','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_recovery_%'
) AS capture_demand_0025
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:12:demand','identity',NULL,'handle','pg_trigger:'||trigger.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger trigger JOIN pg_class class ON class.oid=trigger.tgrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND trigger.tgname LIKE '%_recovery_hold' AND NOT trigger.tgisinternal
) AS capture_demand_0026
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:2:demand','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles WHERE rolname='zasp_policy_deployment_worker'
) AS capture_demand_0027
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:4:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_policy_deployment_%' AND class.relkind IN('r','i')
) AS capture_demand_0028
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:5:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND (class.relname LIKE 'zasp_policy_deployment_%' OR class.relname IN('zasp_security_agent_temporary_policy_targets','zasp_security_agent_session_policy_targets')) AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_demand_0029
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:6:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_policy_deployment_%' AND class.relkind='i'
) AS capture_demand_0030
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:7:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_policy_deployment_%'
) AS capture_demand_0031
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:8:demand','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_policy_deployment_%'
) AS capture_demand_0032
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:9:demand','identity',NULL,'handle','pg_trigger:'||trigger.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger trigger JOIN pg_class class ON class.oid=trigger.tgrelid WHERE trigger.tgname LIKE '%policy_deployment%' OR trigger.tgname LIKE '%policy_sequence' OR trigger.tgname LIKE '%policy_verify'
) AS capture_demand_0033
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:3:demand','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class WHERE oid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass)
) AS capture_demand_0034
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:4:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass)
) AS capture_demand_0035
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:5:demand','identity',NULL,'handle','pg_attribute:'||attrelid::text||':'||attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute WHERE attrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass) AND attnum>0 AND NOT attisdropped
) AS capture_demand_0036
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:6:demand','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_policies WHERE schemaname='public' AND tablename IN('zasp_runtime_session_events','zasp_runtime_session_projection_receipts')
) AS capture_demand_0037
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:7:demand','identity',NULL,'handle',(SELECT 'pg_class:'||capture_class.oid::text||':0' FROM pg_class capture_class JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_class.relname=indexname AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_indexes WHERE schemaname='public' AND tablename IN('zasp_runtime_session_events','zasp_runtime_session_projection_receipts')
) AS capture_demand_0038
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:3:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_claim_session_stage_compatible','zasp_runtime_session_claim_version_guard','zasp_runtime_claim_projection_v2','zasp_runtime_claim_completion_v2')
) AS capture_demand_0039
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:4:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_runtime_session_claim_version'
) AS capture_demand_0040
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:5:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid='public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure
) AS capture_demand_0041
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:6:demand','identity',NULL,'handle','pg_attribute:'||attrelid::text||':'||attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute WHERE attrelid='public.zasp_runtime_session_events'::regclass AND attnum>0 AND NOT attisdropped
) AS capture_demand_0042
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:7:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid IN('public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer)'::regprocedure,'public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text)'::regprocedure)
) AS capture_demand_0043
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:8:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_claim_stage_sandbox_compatible','zasp_runtime_claim_correlation_v3','zasp_runtime_freeze_sandbox_candidates','zasp_production_runtime_sandbox_binding_security_ready','zasp_production_runtime_sandbox_binding_readiness','zasp_production_runtime_correlation_routing_readiness_v49','zasp_production_runtime_candidate_authority_live_fingerprint')
) AS capture_demand_0044
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:4:demand','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class WHERE oid='public.zasp_runtime_sandbox_search_outbox'::regclass
) AS capture_demand_0045
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:5:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid='public.zasp_runtime_sandbox_search_outbox'::regclass
) AS capture_demand_0046
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:6:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.zasp_runtime_sandbox_search_outbox'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0047
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:7:demand','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_policies WHERE schemaname='public' AND tablename='zasp_runtime_sandbox_search_outbox'
) AS capture_demand_0048
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:8:demand','identity',NULL,'handle',(SELECT 'pg_class:'||capture_class.oid::text||':0' FROM pg_class capture_class JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_class.relname=indexname AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_indexes WHERE schemaname='public' AND tablename='zasp_runtime_sandbox_search_outbox'
) AS capture_demand_0049
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:9:demand','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger WHERE tgrelid IN('public.zasp_runtime_session_projection_receipts'::regclass,'public.zasp_runtime_sandbox_search_outbox'::regclass,'public.zasp_runtime_session_search_outbox'::regclass) AND NOT tgisinternal
) AS capture_demand_0050
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM selected c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0051
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM selected c JOIN pg_constraint k ON k.conrelid=c.oid
) AS capture_demand_0052
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM selected c JOIN pg_index i ON i.indrelid=c.oid
) AS capture_demand_0053
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM selected c JOIN pg_policy p ON p.polrelid=c.oid
) AS capture_demand_0054
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_authorization80_temporal'
) AS capture_demand_0055
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace
) AS capture_demand_0056
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0057
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace
) AS capture_demand_0058
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace
) AS capture_demand_0059
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND(c.relnamespace='zasp_authorization80_temporal'::regnamespace OR t.tgname='zasp_authorization79_capture' AND t.tgrelid IN('public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_syncs'::regclass,'public.zasp_inventory_entities'::regclass))
) AS capture_demand_0060
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_ordered_public62'
) AS capture_demand_0061
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_ordered_public62'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0062
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_demand_0063
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_demand_0064
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_demand_0065
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_demand_0066
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal68'
) AS capture_demand_0067
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal68'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0068
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_demand_0069
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_demand_0070
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_demand_0071
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal68'::regnamespace AND NOT(t.tgrelid='zasp_temporal68.deliveries'::regclass AND t.tgname IN('ordered_policy_capture','ordered_policy_no_truncate'))
) AS capture_demand_0072
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal69'
) AS capture_demand_0073
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal69'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0074
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_demand_0075
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_demand_0076
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_demand_0077
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_demand_0078
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal72'
) AS capture_demand_0079
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal72'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0080
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_demand_0081
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_demand_0082
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_demand_0083
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND NOT(t.tgname IN('zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate') AND t.tgrelid IN('zasp_temporal72.runs'::regclass,'zasp_temporal72.schedules'::regclass)) AND c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_demand_0084
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal78'
) AS capture_demand_0085
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal78'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0086
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_demand_0087
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_demand_0088
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_demand_0089
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_demand_0090
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:finding-ownership-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgname='zasp_temporal78_ownership' AND t.tgrelid IN('public.zasp_security_agent_runs'::regclass,'public.zasp_security_agent_effects'::regclass)
) AS capture_demand_0091
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:finding-decision-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgname='zasp_temporal78_control_capture' AND t.tgrelid='public.zasp_security_agent_request_receipts'::regclass
) AS capture_demand_0092
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_authorization79'
) AS capture_demand_0093
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE relnamespace='zasp_authorization79'::regnamespace
) AS capture_demand_0094
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization79'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0095
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization79'::regnamespace
) AS capture_demand_0096
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization79'::regnamespace
) AS capture_demand_0097
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgname='zasp_authorization79_capture'
) AS capture_demand_0098
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal70'
) AS capture_demand_0099
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_demand_0100
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal70'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0101
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_demand_0102
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_demand_0103
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_demand_0104
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_demand_0105
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_demand_0106
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal71'
) AS capture_demand_0107
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_demand_0108
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal71'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0109
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_demand_0110
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_demand_0111
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_demand_0112
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_demand_0113
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_demand_0114
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_risk_projection_current','zasp_discovery_risk_projection_items','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs','zasp_workflow_receipts']) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0115
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value JOIN pg_class c ON c.oid=constraint_value.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (c.relname LIKE 'zasp_discovery_execution_%' OR c.relname IN('zasp_discovery_connection_subjects','zasp_discovery_job_checkpoints','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_risk_projection_current','zasp_discovery_risk_projection_items','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_integration_connections')) AND (constraint_value.conname LIKE 'zasp_execution_%' OR c.relname<>'zasp_integration_connections')
) AS capture_demand_0116
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:index:demand','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace n ON n.oid=table_class.relnamespace WHERE n.nspname='public' AND index_class.relname LIKE 'zasp_execution_%'
) AS capture_demand_0117
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_precision_predecessor'
) AS capture_demand_0118
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conname='zasp_runtime_precision_source_check'
) AS capture_demand_0119
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN('public.zasp_runtime_batch_authorities'::regclass,'public.zasp_runtime_stage_work'::regclass,'public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass,'public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass,'public.zasp_runtime_session_search_outbox'::regclass,'public.zasp_runtime_sandbox_search_outbox'::regclass,'public.zasp_runtime_ingest_reconciliation_work'::regclass,'public.zasp_runtime_ingest_reconciliation_state'::regclass,'public.zasp_discovery_outbox'::regclass,'public.zasp_discovery_outbox_topic_fairness'::regclass,'public.zasp_runtime_deliveries'::regclass) AND NOT t.tgisinternal AND NOT(t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_authorization80_runtime_stage_insert') AND NOT(t.tgrelid='public.zasp_discovery_outbox'::regclass AND t.tgname='zasp_temporal72_outbox_guard')
) AS capture_demand_0120
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal65'
) AS capture_demand_0121
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal65'::regnamespace
) AS capture_demand_0122
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal65'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0123
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal65'::regnamespace
) AS capture_demand_0124
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal65'::regnamespace
) AS capture_demand_0125
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal65'::regnamespace
) AS capture_demand_0126
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgname='zasp_temporal65_capture' AND t.tgrelid='public.zasp_security_agent_request_receipts'::regclass
) AS capture_demand_0127
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal66'
) AS capture_demand_0128
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal66'::regnamespace
) AS capture_demand_0129
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal66'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0130
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal66'::regnamespace
) AS capture_demand_0131
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal66'::regnamespace
) AS capture_demand_0132
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal66'::regnamespace OR p.polname='zasp_temporal66_owner'
) AS capture_demand_0133
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND (c.relnamespace='zasp_temporal66'::regnamespace OR t.tgname IN('zasp_temporal66_lease','zasp_temporal66_capture'))
) AS capture_demand_0134
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal75'
) AS capture_demand_0135
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_demand_0136
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal75'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0137
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_demand_0138
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_demand_0139
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_demand_0140
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_demand_0141
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_demand_0142
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:owner-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_temporal75_owner'
) AS capture_demand_0143
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:owner-policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p WHERE p.polname='zasp_temporal75_owner' AND p.polrelid='public.zasp_security_agent_runs'::regclass
) AS capture_demand_0144
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal67'
) AS capture_demand_0145
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_demand_0146
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal67'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0147
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_demand_0148
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_demand_0149
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_demand_0150
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_demand_0151
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal73'
) AS capture_demand_0152
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_demand_0153
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal73'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0154
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_demand_0155
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_demand_0156
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_demand_0157
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_demand_0158
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_demand_0159
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:capacity-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_temporal73_capacity'
) AS capture_demand_0160
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal76'
) AS capture_demand_0161
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_demand_0162
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal76'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0163
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_demand_0164
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_demand_0165
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_demand_0166
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_demand_0167
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_demand_0168
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:human-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_request_receipts'::regclass AND t.tgname='zasp_temporal76_capture'
) AS capture_demand_0169
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:owner-policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p WHERE p.polname='zasp_temporal76_owner' AND p.polrelid='public.zasp_security_agent_runs'::regclass
) AS capture_demand_0170
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:executor-constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k WHERE k.conrelid='zasp_temporal74.run_owners'::regclass AND k.conname='run_owners_source_kind_check'
) AS capture_demand_0171
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_temporal77'
) AS capture_demand_0172
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_demand_0173
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal77'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0174
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_demand_0175
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_demand_0176
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_demand_0177
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal77'::regnamespace AND NOT(t.tgrelid IN('zasp_temporal77.runtime_evaluations'::regclass,'zasp_temporal77.source_events'::regclass) AND t.tgname IN('zasp_authorization80_worker_runtime_capture','zasp_authorization80_worker_runtime_no_truncate'))
) AS capture_demand_0178
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_demand_0179
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:definition-guard:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_definitions'::regclass AND t.tgname='zasp_temporal77_definition_guard'
) AS capture_demand_0180
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:source-capture:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE (t.tgrelid,t.tgname) IN(('public.zasp_risk_findings'::regclass,'zasp_temporal77_finding_source'),('public.zasp_risk_attack_paths'::regclass,'zasp_temporal77_path_source'),('public.zasp_runtime_gateway_events'::regclass,'zasp_temporal77_runtime_source'))
) AS capture_demand_0181
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:occurrence-guard:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_temporal77_occurrence_guard'
) AS capture_demand_0182
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:role:demand','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles WHERE rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy')
) AS capture_demand_0183
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:table:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_attack_lab_%' AND class.relkind IN('r','i')
) AS capture_demand_0184
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:index:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_attack_lab_%' AND class.relkind='i'
) AS capture_demand_0185
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:column:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_attack_lab_%' AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_demand_0186
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:constraint:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_attack_lab_%'
) AS capture_demand_0187
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:policy:demand','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_attack_lab_%'
) AS capture_demand_0188
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_attack_lab_%'
) AS capture_demand_0189
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_schedule_replay_prior'
) AS capture_demand_0190
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass) AND c.relkind='r'
) AS capture_demand_0191
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE (n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0192
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass
) AS capture_demand_0193
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass
) AS capture_demand_0194
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:column:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
    WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_capability_evidence','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_evidence']) AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_demand_0195
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:constraint:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_capability_evidence','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_evidence'])
) AS capture_demand_0196
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:index:demand','identity',NULL,'handle','pg_class:'||index_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class index_value JOIN pg_namespace namespace ON namespace.oid=index_value.relnamespace WHERE namespace.nspname='public' AND index_value.relname IN('zasp_inventory_entities_kind_page_v14_idx','zasp_inventory_observations_identity_v14_idx','zasp_inventory_capability_evidence_edge_v14_idx')
) AS capture_demand_0197
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:trigger:demand','identity',NULL,'handle','pg_trigger:'||trigger_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger trigger_value JOIN pg_class class ON class.oid=trigger_value.tgrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname='zasp_core_payloads' AND trigger_value.tgname='zasp_core_inventory_write_fence' AND NOT trigger_value.tgisinternal
) AS capture_demand_0198
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:role:demand','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles WHERE rolname IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter')
) AS capture_demand_0199
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:table:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_red_team_%' AND class.relkind IN('r','i')
) AS capture_demand_0200
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:column:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_red_team_%' AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_demand_0201
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:constraint:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_red_team_%'
) AS capture_demand_0202
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:policy:demand','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_red_team_%'
) AS capture_demand_0203
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_red_team_%' OR procedure.proname='zasp_effective_scope_permissions')
) AS capture_demand_0204
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_sa_attack_lab_prior'
) AS capture_demand_0205
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_sa_attack_lab_') AND c.relkind='r'
) AS capture_demand_0206
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE n.nspname='public' AND starts_with(c.relname,'zasp_sa_attack_lab_') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0207
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE starts_with(c.relname,'zasp_sa_attack_lab_')
) AS capture_demand_0208
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE starts_with(c.relname,'zasp_sa_attack_lab_')
) AS capture_demand_0209
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_sa_export_prior'
) AS capture_demand_0210
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_')) AND c.relkind='r'
) AS capture_demand_0211
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE (n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_')) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0212
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_')
) AS capture_demand_0213
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE starts_with(c.relname,'zasp_sa_export_')
) AS capture_demand_0214
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_')
) AS capture_demand_0215
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE NOT t.tgisinternal AND (n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_'))
) AS capture_demand_0216
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_') AND c.relkind IN('r','v','m','p','S')
) AS capture_demand_0217
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_') AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0218
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
) AS capture_demand_0219
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
) AS capture_demand_0220
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
) AS capture_demand_0221
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
 -- FK trigger names contain installation-specific OIDs. Bind their constraint,
 -- both relations, function, event flags and enabled state, on both FK sides.
) AS capture_demand_0222
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
) AS capture_demand_0223
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_sa_webhook_prior'
) AS capture_demand_0224
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))) AND c.relkind='r'
) AS capture_demand_0225
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE (n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0226
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))
) AS capture_demand_0227
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_')
) AS capture_demand_0228
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))
) AS capture_demand_0229
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))
) AS capture_demand_0230
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:role:demand','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles WHERE rolname='zasp_security_agent_webhook_worker'
) AS capture_demand_0231
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:table:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_connector_revocations' AND class.relkind IN('r','i')
) AS capture_demand_0232
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:column:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE attribute.attrelid='public.zasp_security_agent_connector_revocations'::regclass AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_demand_0233
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:table_constraint:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_connector_revocations'::regclass
) AS capture_demand_0234
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:index:demand','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index index_value JOIN pg_class index_class ON index_class.oid=index_value.indexrelid WHERE index_value.indrelid='public.zasp_security_agent_connector_revocations'::regclass
) AS capture_demand_0235
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:policy:demand','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy policy WHERE policy.polrelid='public.zasp_security_agent_connector_revocations'::regclass
) AS capture_demand_0236
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_execution_control_detail','zasp_security_agent_execution_control_detail_v22_restore','zasp_security_agent_mutate_execution_control','zasp_security_agent_mutate_execution_control_v22_restore','zasp_security_agent_schedule_connector_revocation_triggers','zasp_security_agent_schedule_triggers_v23','zasp_security_agent_claim_runs_v23','zasp_security_agent_prepare_connector_revocation_run','zasp_security_agent_prepare_run_v23','zasp_security_agent_dispatch_connector_revocation_run','zasp_security_agent_execute_run_v23','zasp_security_agent_reconcile_connector_revocations','zasp_security_agent_approval_value_v23','zasp_security_agent_run_detail_v23','zasp_security_agent_approval_page_v23','zasp_security_agent_approval_detail_v23','zasp_security_agent_decide_approval_v23','zasp_connector_complete_revocation','zasp_connector_complete_revocation_v22','zasp_security_agent_connector_revocation_security_ready','zasp_workflow_mutate','zasp_risk_mutate'])
) AS capture_demand_0237
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:constraint:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid='public.zasp_security_agent_definitions'::regclass AND conname='zasp_security_agent_connector_revocation_supervised_check'
) AS capture_demand_0238
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:table:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_approval_notifications' AND class.relkind IN('r','i')
) AS capture_demand_0239
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:column:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=class.oid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_approval_notifications' AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_demand_0240
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:constraint:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_approval_notifications'::regclass
) AS capture_demand_0241
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:index:demand','identity',NULL,'handle','pg_class:'||index_metadata.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index index_metadata JOIN pg_class index_value ON index_value.oid=index_metadata.indexrelid WHERE index_metadata.indrelid='public.zasp_security_agent_approval_notifications'::regclass
) AS capture_demand_0242
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:policy:demand','identity',NULL,'handle','pg_policy:'||policy_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy policy_value WHERE policy_value.polrelid='public.zasp_security_agent_approval_notifications'::regclass
) AS capture_demand_0243
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_enqueue_approval_notification','zasp_security_agent_claim_approval_notification','zasp_security_agent_complete_approval_notification','zasp_security_agent_fail_approval_notification','zasp_production_approval_notification_security_ready','zasp_production_approval_notification_readiness','zasp_production_home_attention_readiness'])
) AS capture_demand_0244
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:trigger:demand','identity',NULL,'handle','pg_trigger:'||trigger_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger trigger_value WHERE trigger_value.tgrelid='public.zasp_security_agent_approvals'::regclass AND trigger_value.tgname='zasp_security_agent_enqueue_approval_notification_v30' AND NOT trigger_value.tgisinternal
) AS capture_demand_0245
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:home_attention:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_inventory_home_summary','zasp_inventory_home_summary_v29')
) AS capture_demand_0246
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_setup:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_execution_integration_setup_status','zasp_production_integration_setup_security_ready')
) AS capture_demand_0247
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_integration_webhook_test_public','zasp_integration_webhook_test_reserve','zasp_integration_webhook_test_complete','zasp_integration_webhook_test_status','zasp_production_integration_webhook_security_ready')
) AS capture_demand_0248
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:table:demand','identity',NULL,'handle','pg_class:'||table_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class table_value JOIN pg_roles owner ON owner.oid=table_value.relowner WHERE table_value.oid='public.zasp_integration_webhook_tests'::regclass
) AS capture_demand_0249
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:column:demand','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute LEFT JOIN pg_attrdef default_value ON (default_value.adrelid,default_value.adnum)=(attribute.attrelid,attribute.attnum) WHERE attribute.attrelid='public.zasp_integration_webhook_tests'::regclass AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_demand_0250
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:constraint:demand','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_integration_webhook_tests'::regclass
) AS capture_demand_0251
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:index:demand','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index index_value WHERE index_value.indrelid='public.zasp_integration_webhook_tests'::regclass
) AS capture_demand_0252
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:policy:demand','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy policy WHERE policy.polrelid='public.zasp_integration_webhook_tests'::regclass
) AS capture_demand_0253
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:reconciliation_lane_plan:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_connector_claim_reconciliation','zasp_production_reconciliation_lane_plan_readiness','zasp_production_reconciliation_lane_plan_security_ready')
) AS capture_demand_0254
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_artifacts:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_red_team_artifacts_readiness','zasp_production_red_team_artifacts_security_ready','zasp_red_team_valid_input_artifact','zasp_red_team_finish_run','zasp_red_team_finish_run_v38','zasp_red_team_get_run')
) AS capture_demand_0255
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_artifacts:constraint:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid='public.zasp_red_team_attempts'::regclass
) AS capture_demand_0256
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_artifacts:column:demand','identity',NULL,'handle','pg_attribute:'||attrelid::text||':'||attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute WHERE attrelid='public.zasp_red_team_attempts'::regclass AND attnum>0 AND NOT attisdropped
) AS capture_demand_0257
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_invocation:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_red_team_invocation_security_ready')
) AS capture_demand_0258
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_safety:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_red_team_safety_security_ready')
) AS capture_demand_0259
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:workflow_compatibility:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_workflow_mutate','zasp_risk_mutate')
) AS capture_demand_0260
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:acceptance:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_lookup_acceptance','zasp_production_runtime_acceptance_security_ready','zasp_production_runtime_acceptance_readiness','zasp_production_runtime_candidate_authority_readiness_v47')
) AS capture_demand_0261
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_candidate_lineage_valid','zasp_runtime_candidate_execution_live','zasp_runtime_freeze_candidates','zasp_production_runtime_candidate_authority_security_ready','zasp_production_runtime_candidate_authority_readiness','zasp_production_reconciliation_lane_plan_readiness_v46')
) AS capture_demand_0262
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN('zasp_runtime_candidate_observations','zasp_runtime_candidate_snapshots')
) AS capture_demand_0263
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0264
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:constraint:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass)
) AS capture_demand_0265
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:index:demand','identity',NULL,'handle','pg_class:'||indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index WHERE indrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass)
) AS capture_demand_0266
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:policy:demand','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_policies WHERE schemaname='public' AND tablename IN('zasp_runtime_candidate_observations','zasp_runtime_candidate_snapshots')
) AS capture_demand_0267
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:trigger:demand','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger WHERE tgrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass) AND NOT tgisinternal
) AS capture_demand_0268
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:correlation_routing:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_claim_stage_compatible','zasp_runtime_claim_correlation_v2','zasp_runtime_correlation_claim_version_guard','zasp_production_runtime_correlation_routing_security_ready','zasp_production_runtime_correlation_routing_readiness','zasp_production_runtime_acceptance_readiness_v48')
) AS capture_demand_0269
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:correlation_routing:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_runtime_correlation_claim_version'
) AS capture_demand_0270
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_pairing_immutable','zasp_runtime_bind_batch_domain','zasp_runtime_public_sensor_value','zasp_runtime_public_sensor_value_v44','zasp_runtime_public_create_sensor','zasp_runtime_public_create_sensor_v44','zasp_production_runtime_enrollment_pairing_readiness','zasp_production_runtime_enrollment_pairing_security_ready')
) AS capture_demand_0271
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains')
) AS capture_demand_0272
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:column:demand','identity',NULL,'handle',(SELECT 'pg_attribute:'||capture_attribute.attrelid::text||':'||capture_attribute.attnum::text FROM pg_attribute capture_attribute JOIN pg_class capture_class ON capture_class.oid=capture_attribute.attrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_attribute.attname=column_name AND capture_class.relname=table_name AND capture_ns.nspname=table_schema),'multiplicity',1,'fact','{}'::jsonb) FROM information_schema.columns WHERE table_schema='public' AND table_name IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains')
) AS capture_demand_0273
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:constraint:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_sensor_pairings'::regclass,'public.zasp_runtime_batch_domains'::regclass) OR conname IN('zasp_sensor_kind_identity_v45','zasp_runtime_batch_source_identity_v45')
) AS capture_demand_0274
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:policy:demand','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_policies WHERE schemaname='public' AND tablename IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains')
) AS capture_demand_0275
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:trigger:demand','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger WHERE tgname IN('zasp_runtime_sensor_pairings_immutable','zasp_runtime_batch_domains_immutable','zasp_runtime_batch_domain_insert') AND NOT tgisinternal
) AS capture_demand_0276
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:queue_replay:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_claim_delivery','zasp_runtime_commit_reserved_batch','zasp_production_runtime_queue_replay_security_ready')
) AS capture_demand_0277
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_evidence:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_session_event_get','zasp_production_runtime_session_evidence_readiness','zasp_production_runtime_session_evidence_security_ready')
) AS capture_demand_0278
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_query:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_session_query_status','zasp_runtime_session_query_hydrate','zasp_production_runtime_session_query_readiness','zasp_production_runtime_session_query_security_ready')
) AS capture_demand_0279
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_runtime_session_reads_readiness','zasp_production_runtime_session_reads_security_ready','zasp_runtime_session_maintain_summary','zasp_runtime_session_summary_json','zasp_runtime_session_read_authorized','zasp_runtime_session_page','zasp_runtime_session_get','zasp_runtime_session_event_page')
) AS capture_demand_0280
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:table:demand','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class WHERE oid='public.zasp_runtime_session_summaries'::regclass
) AS capture_demand_0281
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:constraint:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid='public.zasp_runtime_session_summaries'::regclass
) AS capture_demand_0282
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:column:demand','identity',NULL,'handle','pg_attribute:'||attrelid::text||':'||attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute WHERE attrelid='public.zasp_runtime_session_summaries'::regclass AND attnum>0 AND NOT attisdropped
) AS capture_demand_0283
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:policy:demand','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_policies WHERE schemaname='public' AND tablename='zasp_runtime_session_summaries'
) AS capture_demand_0284
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:index:demand','identity',NULL,'handle',(SELECT 'pg_class:'||capture_class.oid::text||':0' FROM pg_class capture_class JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_class.relname=indexname AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_indexes WHERE schemaname='public' AND tablename='zasp_runtime_session_summaries'
) AS capture_demand_0285
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:trigger:demand','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_events'::regclass AND NOT tgisinternal
) AS capture_demand_0286
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_runtime_session_search_%' OR procedure.proname IN('zasp_production_runtime_session_search_readiness','zasp_production_runtime_session_search_security_ready'))
) AS capture_demand_0287
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:table:demand','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class WHERE oid='public.zasp_runtime_session_search_outbox'::regclass
) AS capture_demand_0288
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:constraint:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid='public.zasp_runtime_session_search_outbox'::regclass
) AS capture_demand_0289
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:column:demand','identity',NULL,'handle','pg_attribute:'||attribute_value.attrelid::text||':'||attribute_value.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute attribute_value LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute_value.attrelid AND default_value.adnum=attribute_value.attnum WHERE attribute_value.attrelid='public.zasp_runtime_session_search_outbox'::regclass AND attribute_value.attnum>0 AND NOT attribute_value.attisdropped
) AS capture_demand_0290
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:policy:demand','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_policies WHERE schemaname='public' AND tablename='zasp_runtime_session_search_outbox'
) AS capture_demand_0291
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:index:demand','identity',NULL,'handle',(SELECT 'pg_class:'||capture_class.oid::text||':0' FROM pg_class capture_class JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_class.relname=indexname AND capture_ns.nspname=schemaname),'multiplicity',1,'fact','{}'::jsonb) FROM pg_indexes WHERE schemaname='public' AND tablename='zasp_runtime_session_search_outbox'
) AS capture_demand_0292
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:trigger:demand','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_projection_receipts'::regclass AND NOT tgisinternal
) AS capture_demand_0293
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM selected c JOIN pg_trigger t ON t.tgrelid=c.oid JOIN pg_proc p ON p.oid=t.tgfoid WHERE NOT t.tgisinternal AND NOT(
 (t.tgrelid IN('public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_gateway','zasp_authorization80_worker_ordered_no_truncate'))
 OR(t.tgrelid IN('public.zasp_workflow_records'::regclass,'public.zasp_security_agent_temporary_policy_targets'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_policy','zasp_authorization80_worker_ordered_policy_no_truncate')))
 AND NOT(t.tgrelid IN('public.zasp_inventory_entities'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_source_observations'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_target','zasp_authorization80_worker_ordered_no_truncate')) AND NOT(t.tgname IN('zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate') AND t.tgrelid IN('public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_connection_subjects'::regclass,'public.zasp_connector_credentials'::regclass) OR t.tgname='zasp_authorization80_worker_discovery_admission' AND t.tgrelid='public.zasp_workflow_idempotency'::regclass) AND NOT(t.tgname IN('zasp_authorization80_worker_target_capture','zasp_authorization80_worker_target_no_truncate') AND t.tgrelid IN('public.zasp_inventory_entities'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_source_observations'::regclass)) AND NOT(t.tgname='zasp_authorization79_capture' AND t.tgrelid IN('public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_syncs'::regclass,'public.zasp_inventory_entities'::regclass))
) AS capture_demand_0294
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_temporal'::regnamespace OR p.oid IN('zasp_temporal72.fingerprint()'::regprocedure,'zasp_temporal72.domain_catalog()'::regprocedure,'zasp_temporal68.ready(text,text)'::regprocedure,'zasp_temporal68.fingerprint()'::regprocedure,'zasp_authorization79.capture()'::regprocedure)
) AS capture_demand_0295
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_ordered_public62'::regnamespace
) AS capture_demand_0296
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal68'::regnamespace
) AS capture_demand_0297
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal69'::regnamespace
) AS capture_demand_0298
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal72'::regnamespace
) AS capture_demand_0299
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:precision-handoff:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.oid='public.zasp_production_runtime_precision_live_fingerprint()'::regprocedure
) AS capture_demand_0300
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:bulk-handoff:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.oid IN('public.zasp_execution_claim_jobs(text,text,integer,integer)'::regprocedure,'public.zasp_execution_live_fingerprint()'::regprocedure,'public.zasp_discovery_schedule_replay_function_identity(oid)'::regprocedure)
) AS capture_demand_0301
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal78'::regnamespace
) AS capture_demand_0302
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:effective-predecessor:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%' OR signature LIKE 'zasp_temporal73.%' OR signature IN('zasp_temporal74.visible(text,text,text,text)','zasp_temporal76.executor74_fingerprint()','zasp_temporal76.fingerprint()'))
) AS capture_demand_0303
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE pronamespace='zasp_authorization79'::regnamespace
) AS capture_demand_0304
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:view:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE relnamespace='zasp_authorization79'::regnamespace AND relkind='v'
) AS capture_demand_0305
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:6:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_runtime_gateway_record_event','zasp_runtime_gateway_record_event_v23_restore','zasp_security_agent_execution_control_detail','zasp_security_agent_execution_control_detail_v23_restore','zasp_security_agent_mutate_execution_control','zasp_security_agent_mutate_execution_control_v23_restore','zasp_security_agent_schedule_session_isolation_triggers','zasp_security_agent_schedule_triggers_v24','zasp_security_agent_run_v24','zasp_security_agent_prepare_session_isolation_run','zasp_security_agent_prepare_run_v24','zasp_security_agent_dispatch_session_isolation_run','zasp_security_agent_execute_run_v24','zasp_security_agent_claim_session_policy_effects','zasp_security_agent_heartbeat_session_policy_effect','zasp_security_agent_store_session_policy_target','zasp_security_agent_read_session_policy_target','zasp_security_agent_finish_session_policy_effect','zasp_security_agent_approval_value_v24','zasp_security_agent_run_detail_v24','zasp_security_agent_approval_page_v24','zasp_security_agent_approval_detail_v24','zasp_security_agent_decide_approval_v24','zasp_security_agent_session_isolation_security_ready','zasp_workflow_mutate','zasp_risk_mutate'])
) AS capture_demand_0306
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:13:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_recovery_%' OR procedure.proname IN('zasp_policy_id_array_valid','zasp_runtime_gateway_record_event_v27','zasp_policy_list_runtime_decisions'))
) AS capture_demand_0307
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:10:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_policy_deployment_%' OR procedure.proname IN('zasp_security_agent_store_temporary_policy_target','zasp_security_agent_store_session_policy_target','zasp_security_agent_expire_approvals_v28'))
) AS capture_demand_0308
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:2:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_runtime_sessions_readiness','zasp_production_runtime_sessions_security_ready','zasp_runtime_finish_stage','zasp_runtime_finish_stage_v39','zasp_runtime_finish_session_projection')
) AS capture_demand_0309
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:1:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid IN('public.zasp_runtime_sandbox_search_enqueue()'::regprocedure,'public.zasp_runtime_legacy_search_insert_guard()'::regprocedure,'public.zasp_production_runtime_sandbox_search_security_ready()'::regprocedure,'public.zasp_production_runtime_sandbox_search_live_fingerprint()'::regprocedure)
) AS capture_demand_0310
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:2:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid IN('public.zasp_runtime_sandbox_query_status(text,text,text,text)'::regprocedure,'public.zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[])'::regprocedure)
) AS capture_demand_0311
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:3:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_sandbox_search_worker_ready','zasp_runtime_sandbox_search_mutation_guard','zasp_runtime_sandbox_search_claim','zasp_runtime_sandbox_search_heartbeat','zasp_runtime_sandbox_search_finish')
) AS capture_demand_0312
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal70'::regnamespace
) AS capture_demand_0313
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal71'::regnamespace
) AS capture_demand_0314
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal65'::regnamespace
) AS capture_demand_0315
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal66'::regnamespace
) AS capture_demand_0316
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal75'::regnamespace
) AS capture_demand_0317
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal67'::regnamespace
) AS capture_demand_0318
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal73'::regnamespace
) AS capture_demand_0319
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal76'::regnamespace
) AS capture_demand_0320
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:executor-function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.oid IN('zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.fingerprint()'::regprocedure)
) AS capture_demand_0321
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_sa_attack_lab_prior' OR n.nspname='public' AND starts_with(p.proname,'zasp_sa_attack_lab_')
) AS capture_demand_0322
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND (starts_with(p.proname,'zasp_sa_export_') OR starts_with(p.proname,'zasp_sa_manual_'))
) AS capture_demand_0323
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND starts_with(p.proname,'zasp_sa_multistep_')
) AS capture_demand_0324
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (starts_with(p.proname,'zasp_sa_webhook_') OR p.proname LIKE '%security_agent_webhook%')
) AS capture_demand_0325
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_temporal77'::regnamespace
) AS capture_demand_0326
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:effective-policy-boundary:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.oid IN('zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'::regprocedure,'zasp_temporal67.base_fingerprint()'::regprocedure,'zasp_temporal67.fingerprint()'::regprocedure)
) AS capture_demand_0327
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_schedule_replay_prior' OR p.oid IN(SELECT signature::regprocedure FROM zasp_schedule_replay_prior.functions) OR n.nspname='public' AND starts_with(p.proname,'zasp_discovery_schedule_replay_')
) AS capture_demand_0328
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','ready78:saved-current:routines:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.oid IN(SELECT to_regprocedure(signature) FROM zasp_temporal72.predecessor_functions)
) AS capture_demand_0329
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:4:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_authorization80_worker'
) AS capture_demand_0330
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:5:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_worker'::regnamespace OR p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions)
) AS capture_demand_0331
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:6:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace
) AS capture_demand_0332
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:7:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0333
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:8:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace
) AS capture_demand_0334
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:9:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace
) AS capture_demand_0335
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:10:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_authorization80_worker'::regnamespace
) AS capture_demand_0336
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:15:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_authorization80_runtime'
) AS capture_demand_0337
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:16:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_runtime'::regnamespace OR p.oid IN(SELECT to_regprocedure(signature) FROM zasp_authorization80_runtime.predecessor_functions WHERE signature LIKE '%guard()') OR p.oid='public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure
) AS capture_demand_0338
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:17:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
) AS capture_demand_0339
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:18:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0340
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:19:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
) AS capture_demand_0341
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:20:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
) AS capture_demand_0342
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:21:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
) AS capture_demand_0343
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:22:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND(c.relnamespace='zasp_authorization80_runtime'::regnamespace OR t.tgfoid IN(SELECT to_regprocedure(signature) FROM zasp_authorization80_runtime.predecessor_functions WHERE signature LIKE '%guard()'))
) AS capture_demand_0344
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:23:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_authorization80_runtime_stage_insert'
) AS capture_demand_0345
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:24:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='public.zasp_runtime_stage_work'::regclass
) AS capture_demand_0346
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:25:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a WHERE a.attrelid='public.zasp_runtime_stage_work'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0347
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:26:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p WHERE p.polrelid='public.zasp_runtime_stage_work'::regclass
) AS capture_demand_0348
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:32:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_authorization80_runtime_stage_insert'
) AS capture_demand_0349
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:33:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN('public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass,'public.zasp_runtime_session_summaries'::regclass,'public.zasp_runtime_gateway_events'::regclass,'zasp_temporal77.runtime_evaluations'::regclass,'zasp_temporal77.source_events'::regclass) AND t.tgname IN('zasp_authorization80_worker_runtime_capture','zasp_authorization80_worker_runtime_no_truncate')
) AS capture_demand_0350
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:34:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid IN(SELECT signature::regclass FROM zasp_authorization80_worker.predecessor_views)
) AS capture_demand_0351
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:35:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace AND c.relkind='v'
) AS capture_demand_0352
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:36:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname IN('zasp_authorization80_worker_run_capture','zasp_authorization80_worker_no_truncate')
) AS capture_demand_0353
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:37:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_risk_findings'::regclass,'public.zasp_security_agent_definitions'::regclass) AND t.tgname='zasp_authorization80_worker_source_capture'
) AS capture_demand_0354
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:38:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN('public.zasp_red_team_definitions'::regclass,'public.zasp_inventory_entities'::regclass,'public.zasp_inventory_source_observations'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_attack_lab_credential_bindings'::regclass) AND t.tgname IN('zasp_authorization80_worker_target_capture','zasp_authorization80_worker_target_no_truncate')
) AS capture_demand_0355
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:39:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE (t.tgrelid IN('zasp_temporal72.runs'::regclass,'zasp_temporal72.schedules'::regclass,'public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_connection_subjects'::regclass,'public.zasp_connector_credentials'::regclass) AND t.tgname IN('zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate')) OR (t.tgrelid='public.zasp_workflow_idempotency'::regclass AND t.tgname='zasp_authorization80_worker_discovery_admission')
) AS capture_demand_0356
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:40:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE(t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_authorization80_worker_ordered_run') OR(t.tgrelid IN('public.zasp_red_team_definitions'::regclass,'public.zasp_inventory_entities'::regclass,'public.zasp_attack_lab_credential_bindings'::regclass,'public.zasp_risk_findings'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_source_observations'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_target','zasp_authorization80_worker_ordered_no_truncate'))
) AS capture_demand_0357
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:41:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE(t.tgrelid IN('public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_gateway','zasp_authorization80_worker_ordered_no_truncate')) OR(t.tgrelid IN('public.zasp_workflow_records'::regclass,'public.zasp_security_agent_temporary_policy_targets'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_policy','zasp_authorization80_worker_ordered_policy_no_truncate')) OR(t.tgrelid='zasp_temporal68.deliveries'::regclass AND t.tgname IN('ordered_policy_capture','ordered_policy_no_truncate'))
) AS capture_demand_0358
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspname='zasp_authorization80'
) AS capture_demand_0359
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid='zasp_authorization80.runtime_profile'::regclass AND NOT t.tgisinternal
) AS capture_demand_0360
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile-column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_authorization80.runtime_profile'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0361
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile-column:types:demand','identity',NULL,'handle','pg_type:'||type_row.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_type type_row WHERE type_row.oid IN(SELECT a.atttypid FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_authorization80.runtime_profile'::regclass AND a.attnum>0 AND NOT a.attisdropped)
) AS capture_demand_0362
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE pronamespace='zasp_authorization80'::regnamespace
) AS capture_demand_0363
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:home-source-function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE oid IN('public.zasp_inventory_home_summary(text,text,text)'::regprocedure,'public.zasp_inventory_home_summary_v29(text,text,text)'::regprocedure,'public.zasp_inventory_scope_state(text,text,text)'::regprocedure)
) AS capture_demand_0364
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE relnamespace='zasp_authorization80'::regnamespace
) AS capture_demand_0365
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80'::regnamespace
) AS capture_demand_0366
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80'::regnamespace
) AS capture_demand_0367
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:risk-relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid=ANY(ARRAY['public.zasp_risk_findings'::regclass,'public.zasp_risk_finding_evidence'::regclass,'public.zasp_risk_finding_factors'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_risk_attack_path_nodes'::regclass,'public.zasp_risk_attack_path_evidence'::regclass,'public.zasp_risk_break_options'::regclass])
) AS capture_demand_0368
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:risk-policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.oid=ANY(ARRAY['public.zasp_risk_findings'::regclass,'public.zasp_risk_finding_evidence'::regclass,'public.zasp_risk_finding_factors'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_risk_attack_path_nodes'::regclass,'public.zasp_risk_attack_path_evidence'::regclass,'public.zasp_risk_break_options'::regclass])
) AS capture_demand_0369
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='public.zasp_data_controls'::regclass
) AS capture_demand_0370
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p WHERE p.polrelid='public.zasp_data_controls'::regclass
) AS capture_demand_0371
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='public.zasp_data_controls'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0372
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-column:types:demand','identity',NULL,'handle','pg_type:'||type_row.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_type type_row WHERE type_row.oid IN(SELECT a.atttypid FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='public.zasp_data_controls'::regclass AND a.attnum>0 AND NOT a.attisdropped)
) AS capture_demand_0373
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-constraint:demand','identity',NULL,'handle','pg_constraint:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint c WHERE c.conrelid='public.zasp_data_controls'::regclass
) AS capture_demand_0374
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
) AS capture_demand_0375
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass) AND NOT t.tgisinternal
) AS capture_demand_0376
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0377
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-column:types:demand','identity',NULL,'handle','pg_type:'||type_row.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_type type_row WHERE type_row.oid IN(SELECT a.atttypid FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass) AND a.attnum>0 AND NOT a.attisdropped)
) AS capture_demand_0378
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-constraint:demand','identity',NULL,'handle','pg_constraint:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint c WHERE c.conrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
) AS capture_demand_0379
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p WHERE p.polrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
) AS capture_demand_0380
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization-temporal:triggers-ready:triggers:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace AND c.relname IN('zasp_integrations','zasp_integration_connections','zasp_discovery_syncs','zasp_inventory_entities') AND t.tgname='zasp_authorization79_capture'
) AS capture_demand_0381
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization-temporal:triggers-ready:routine:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.oid='zasp_authorization79.capture()'::regprocedure
) AS capture_demand_0382
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_risk_projection_current','zasp_discovery_risk_projection_items','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs','zasp_workflow_receipts'])
) AS capture_demand_0383
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND (p.proname LIKE 'zasp_execution_%' OR p.proname IN('zasp_workflow_mutate','zasp_risk_mutate','zasp_discovery_security_ready','zasp_reference_authorization_security_ready','zasp_discovery_request_sync','zasp_discovery_claim_jobs','zasp_discovery_claim_schedules','zasp_discovery_complete_schedule','zasp_discovery_finish_job','zasp_discovery_finish_projection','zasp_discovery_apply_snapshot','zasp_complete_reference_authorization')) AND p.proname NOT IN('zasp_execution_live_fingerprint','zasp_execution_readiness','zasp_execution_security_ready')
) AS capture_demand_0384
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:policy:demand','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy policy JOIN pg_class c ON c.oid=policy.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_risk_projection_current','zasp_discovery_risk_projection_items','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs'])
) AS capture_demand_0385
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:trigger:demand','identity',NULL,'handle','pg_trigger:'||trigger_value.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger trigger_value JOIN pg_class c ON c.oid=trigger_value.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND trigger_value.tgname LIKE 'zasp_execution_%' AND NOT trigger_value.tgisinternal
) AS capture_demand_0386
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:role:demand','identity',NULL,'handle','pg_authid:'||r.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles r WHERE r.rolname=ANY(ARRAY['zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker'])
) AS capture_demand_0387
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:table:demand','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_capability_evidence','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_evidence'])
) AS capture_demand_0388
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:policy:demand','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_capability_evidence'])
) AS capture_demand_0389
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:function:demand','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_inventory_%' OR procedure.proname IN('zasp_discovery_apply_snapshot','zasp_execution_job_input','zasp_execution_apply_risk_projection','zasp_typed_inventory_job_input_v13','zasp_workflow_mutate','zasp_risk_mutate','zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence')) AND procedure.proname<>'zasp_inventory_live_fingerprint'
) AS capture_demand_0390
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:function:core-owner:demand','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class WHERE oid='zasp_core_payloads'::regclass
) AS capture_demand_0391
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:role:demand','identity',NULL,'handle','pg_authid:'||role.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles role WHERE role.rolname='zasp_inventory_authority'
) AS capture_demand_0392
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:role:demand','identity',NULL,'handle','pg_authid:'||oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles WHERE rolname='zasp_security_agent_global_operator'
) AS capture_demand_0393
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.proowner='zasp_security_agent_global_operator'::regrole
) AS capture_demand_0394
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relowner='zasp_security_agent_global_operator'::regrole
) AS capture_demand_0395
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-schema:demand','identity',NULL,'handle','pg_namespace:'||oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace WHERE nspowner='zasp_security_agent_global_operator'::regrole
) AS capture_demand_0396
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-database:demand','identity',NULL,'handle','pg_database:'||oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_database WHERE datdba='zasp_security_agent_global_operator'::regrole
) AS capture_demand_0397
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:default-acl:demand','identity',NULL,'handle','pg_default_acl:'||oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_default_acl WHERE defaclrole='zasp_security_agent_global_operator'::regrole OR EXISTS(SELECT 1 FROM aclexplode(defaclacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole)
) AS capture_demand_0398
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid IN(SELECT oid FROM relations)
) AS capture_demand_0399
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN(SELECT oid FROM relations) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0400
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:constraint:demand','identity',NULL,'handle','pg_constraint:'||oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint WHERE conrelid IN(SELECT oid FROM relations)
) AS capture_demand_0401
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:index:demand','identity',NULL,'handle','pg_class:'||indexrelid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index WHERE indrelid IN(SELECT oid FROM relations)
) AS capture_demand_0402
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:policy:demand','identity',NULL,'handle','pg_policy:'||oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy WHERE polrelid IN(SELECT oid FROM relations)
) AS capture_demand_0403
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:trigger:demand','identity',NULL,'handle','pg_trigger:'||oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM relations) AND NOT tgisinternal
) AS capture_demand_0404
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings')
) AS capture_demand_0405
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0406
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings'
) AS capture_demand_0407
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings'
) AS capture_demand_0408
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings'
) AS capture_demand_0409
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND (starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings')
) AS capture_demand_0410
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:role:demand','identity',NULL,'handle','pg_authid:'||oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles WHERE rolname IN('zasp_compliance_worker','zasp_compliance_cleanup')
) AS capture_demand_0411
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:scope-authority:relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='public.zasp_authorized_scopes'::regclass
) AS capture_demand_0412
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:scope-authority:routines:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.oid IN('zasp_sa_multistep_prior.lock_scope(text,text,text,text)'::regprocedure,'zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text)'::regprocedure)
) AS capture_demand_0413
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:migration-helper:relations:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid IN(SELECT CASE WHEN EXISTS(SELECT 1 FROM zasp_temporal72.predecessor_functions s WHERE s.signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)')) THEN d.identity::regclass ELSE NULL END FROM (VALUES ('public.zasp_core_payloads'),('public.zasp_authorized_scopes')) AS d(identity))
) AS capture_demand_0414
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:migration-helper:routines:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE EXISTS(SELECT 1 FROM zasp_temporal72.predecessor_functions s WHERE s.signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)') AND p.oid=CASE WHEN s.signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)') THEN to_regprocedure('public.'||s.signature) ELSE NULL END)
) AS capture_demand_0415
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='public.zasp_admin_audit'::regclass
) AS capture_demand_0416
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:columns:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a WHERE a.attrelid='public.zasp_admin_audit'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0417
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:ready-relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='public.zasp_admin_audit'::regclass
) AS capture_demand_0418
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-workflow:relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='public.zasp_workflow_audit'::regclass
) AS capture_demand_0419
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-workflow:columns:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a WHERE a.attrelid='public.zasp_workflow_audit'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0420
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:predecessor68:routine:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_temporal68.predecessor_ready(text,text)'::regprocedure
) AS capture_demand_0421
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:ready68:routine:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_temporal68.ready(text,text)'::regprocedure
) AS capture_demand_0422
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:ready78:routine:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_temporal78.ready(text,text)'::regprocedure
) AS capture_demand_0423
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:base67:routine:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure
) AS capture_demand_0424
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:native-role-shape:roles:demand','identity',NULL,'handle','pg_authid:'||r.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles r WHERE r.rolname IN('zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting')
) AS capture_demand_0425
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:worker-catalog-ready:routine:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure
) AS capture_demand_0426
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:worker-catalog-ready:definition:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure
) AS capture_demand_0427
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:schema:demand','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace n WHERE n.nspname='zasp_compliance_predecessor'
) AS capture_demand_0428
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_compliance_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_compliance_')
) AS capture_demand_0429
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:schema:demand','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace n WHERE n.nspname='zasp_existing_tests_predecessor'
) AS capture_demand_0430
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_existing_tests_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_production_security_agent_existing_tests')
) AS capture_demand_0431
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:schema:demand','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace n WHERE n.nspname='zasp_run_context_predecessor'
) AS capture_demand_0432
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_run_context_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_production_security_agent_run_context')
) AS capture_demand_0433
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:schema:demand','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace n WHERE n.nspname='zasp_security_agent_budgets_predecessor'
) AS capture_demand_0434
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_security_agent_budgets_predecessor' OR n.nspname='public' AND (starts_with(p.proname,'zasp_security_agent_') OR starts_with(p.proname,'zasp_production_security_agent_budgets') OR p.proname='zasp_policy_deployment_store_temporary_source')
) AS capture_demand_0435
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:schema:demand','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace n WHERE n.nspname='zasp_audit_exports_predecessor'
) AS capture_demand_0436
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_audit_exports_predecessor' OR n.nspname='public' AND (starts_with(p.proname,'zasp_audit_export') OR starts_with(p.proname,'zasp_production_audit_exports'))
) AS capture_demand_0437
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
) AS capture_demand_0438
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations')) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0439
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k WHERE k.conrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
) AS capture_demand_0440
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i WHERE i.indrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
) AS capture_demand_0441
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p WHERE p.polrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
) AS capture_demand_0442
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations')) AND NOT t.tgisinternal
) AS capture_demand_0443
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
) AS capture_demand_0444
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0445
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE k.conrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
) AS capture_demand_0446
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE i.indrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
) AS capture_demand_0447
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE p.polrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
) AS capture_demand_0448
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE t.tgrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass) AND NOT t.tgisinternal
) AS capture_demand_0449
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_audit_export') AND c.relkind IN('r','p','v','S')
) AS capture_demand_0450
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND starts_with(c.relname,'zasp_audit_export') AND c.relkind IN('r','p','v','S') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0451
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit'))
) AS capture_demand_0452
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit'))
) AS capture_demand_0453
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit'))
) AS capture_demand_0454
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit')) AND NOT t.tgisinternal
) AS capture_demand_0455
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:activity-index:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_security_agent_activity_')
) AS capture_demand_0456
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:export-role:demand','identity',NULL,'handle','pg_authid:'||r.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_roles r WHERE r.rolname IN('zasp_audit_export_worker','zasp_audit_export_outbox')
) AS capture_demand_0457
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:view:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_audit_export') AND c.relkind='v'
) AS capture_demand_0458
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:normalization-relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='public.zasp_data_controls'::regclass
) AS capture_demand_0459
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:normalization-relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='public.zasp_environments'::regclass
) AS capture_demand_0460
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:source-shape:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid IN('public.zasp_admin_audit'::regclass,'public.zasp_workflow_audit'::regclass,'public.zasp_red_team_audit'::regclass)
) AS capture_demand_0461
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:red-team-relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='public.zasp_red_team_audit'::regclass
) AS capture_demand_0462
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:source-columns-shape:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.zasp_admin_audit'::regclass,'public.zasp_workflow_audit'::regclass,'public.zasp_red_team_audit'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0463
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:red-team-columns:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a WHERE a.attrelid='public.zasp_red_team_audit'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0464
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:legacy-approval-fence:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN('zasp_security_agent_decide_approval','zasp_security_agent_decide_approval_v22','zasp_security_agent_decide_approval_v23','zasp_security_agent_decide_approval_v24','zasp_security_agent_expire_approvals_v28')
) AS capture_demand_0465
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:legacy-action-fence:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN('zasp_security_agent_claim_temporary_policy_effects','zasp_security_agent_heartbeat_temporary_policy_effect','zasp_security_agent_dispatch_temporary_policy_run','zasp_security_agent_finish_temporary_policy_effect','zasp_security_agent_store_temporary_policy_target','zasp_security_agent_store_temporary_policy_target_v27','zasp_policy_deployment_store_temporary_source','zasp_security_agent_execute_run','zasp_security_agent_execute_run_v21','zasp_security_agent_execute_run_v22','zasp_security_agent_execute_run_v23','zasp_security_agent_execute_run_v24')
) AS capture_demand_0466
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:schema:demand','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_namespace n WHERE n.nspname='zasp_sa_multistep_prior'
) AS capture_demand_0467
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p WHERE p.pronamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_demand_0468
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:table:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace AND c.relkind IN('r','v','m','p','S')
) AS capture_demand_0469
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0470
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_demand_0471
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:index:demand','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_demand_0472
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_demand_0473
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:foreign-key-trigger:demand','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_demand_0474
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:policy:demand','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_demand_0475
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:ordered-writer-definition:routine:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.ordered_writer_definition(oid)'::regprocedure
) AS capture_demand_0476
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:ordered-writer-normalized-identity:routine:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.ordered_writer_normalized_identity(oid)'::regprocedure
) AS capture_demand_0477
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:function:demand','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='zasp_precision_predecessor' OR n.nspname='public' AND (p.proname LIKE '%precision%' OR p.proname LIKE '%precise%' OR p.proname IN('zasp_runtime_claim_archive_v2','zasp_runtime_claim_index_v2','zasp_runtime_claim_correlation_v4','zasp_runtime_claim_projection_v3','zasp_runtime_claim_completion_v3','zasp_runtime_claim_reconciliation_v2','zasp_runtime_claim_outbox_v2'))
) AS capture_demand_0478
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved-table:relation:demand','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_class c WHERE c.oid='zasp_sa_attack_lab_prior.functions'::regclass
) AS capture_demand_0479
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved-table:column:demand','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact','{}'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_sa_attack_lab_prior.functions'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_demand_0480
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved-table:constraint:demand','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact','{}'::jsonb) FROM pg_constraint k WHERE k.conrelid='zasp_sa_attack_lab_prior.functions'::regclass
) AS capture_demand_0481
