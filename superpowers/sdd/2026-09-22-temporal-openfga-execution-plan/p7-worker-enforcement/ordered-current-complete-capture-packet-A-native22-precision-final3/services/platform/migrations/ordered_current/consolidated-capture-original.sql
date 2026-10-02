SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM selected c
) AS capture_original_0001
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM selected c JOIN pg_constraint k ON k.conrelid=c.oid JOIN pg_trigger t ON t.tgconstraint=k.oid WHERE t.tgisinternal AND k.contype='f'
) AS capture_original_0002
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_original_0003
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_original_0004
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_original_0005
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_original_0006
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_original_0007
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_original_0008
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_original_0009
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_original_0010
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_original_0011
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:2','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'owner',((owner.rolname)::text),'row_security',(class.relrowsecurity),'forced_row_security',(class.relforcerowsecurity),'acl_text_or_empty',((COALESCE(class.relacl::text,''))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_temporary_policy_targets' AND class.relkind IN('r','i')
) AS capture_original_0012
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:3','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('name',((attribute.attname)::text),'type_identity',((attribute.atttypid::regtype::text)::text),'not_null',(attribute.attnotnull),'identity',((attribute.attidentity)::text),'generated',((attribute.attgenerated)::text),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE attribute.attrelid='public.zasp_security_agent_temporary_policy_targets'::regclass AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_original_0013
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:4','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((constraint_value.conname)::text),'constraint_type',((constraint_value.contype)::text),'validated',(constraint_value.convalidated),'deferrable',(constraint_value.condeferrable),'deferred',(constraint_value.condeferred),'definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_temporary_policy_targets'::regclass
) AS capture_original_0014
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:5','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((index_class.relname)::text),'valid',(index_value.indisvalid),'ready',(index_value.indisready),'unique',(index_value.indisunique),'primary',(index_value.indisprimary),'definition',((pg_get_indexdef(index_value.indexrelid))::text))) FROM pg_index index_value JOIN pg_class index_class ON index_class.oid=index_value.indexrelid WHERE (index_value.indrelid='public.zasp_runtime_gateway_events'::regclass AND index_class.relname='zasp_runtime_gateway_events_session_v24_idx') OR index_value.indrelid='public.zasp_security_agent_temporary_policy_targets'::regclass
) AS capture_original_0015
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:7','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((conname)::text),'validated',(convalidated),'definition_pretty',((pg_get_constraintdef(oid,true))::text))) FROM pg_constraint WHERE conrelid='public.zasp_security_agent_definitions'::regclass AND conname='zasp_security_agent_session_isolation_supervised_check'
) AS capture_original_0016
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:2','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((rolname)::text),'superuser',(rolsuper),'inherit',(rolinherit),'create_role',(rolcreaterole),'create_db',(rolcreatedb),'login',(rolcanlogin),'replication',(rolreplication),'bypass_rls',(rolbypassrls))) FROM pg_roles WHERE rolname IN('zasp_recovery_worker','zasp_recovery_outbox_worker')
) AS capture_original_0017
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:4','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'owner',((owner.rolname)::text),'row_security',(class.relrowsecurity),'forced_row_security',(class.relforcerowsecurity),'acl_text_or_empty',((COALESCE(class.relacl::text,''))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_recovery_%' AND class.relkind IN('r','i')
) AS capture_original_0018
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:5','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'definition',((pg_get_indexdef(class.oid))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_recovery_%' AND class.relkind='i'
) AS capture_original_0019
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:6','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((attribute.attname)::text),'type_identity',((attribute.atttypid::regtype::text)::text),'not_null',(attribute.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_recovery_%' AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_original_0020
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:7','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((constraint_value.conname)::text),'constraint_type',((constraint_value.contype)::text),'validated',(constraint_value.convalidated),'definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_recovery_%'
) AS capture_original_0021
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:8','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((attribute.attname)::text),'type_identity',((attribute.atttypid::regtype::text)::text),'not_null',(attribute.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname='zasp_runtime_gateway_events' AND attribute.attname='policy_ids' AND NOT attribute.attisdropped
) AS capture_original_0022
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:9','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((constraint_value.conname)::text),'constraint_type',((constraint_value.contype)::text),'validated',(constraint_value.convalidated),'definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname='zasp_runtime_gateway_events' AND constraint_value.conname='zasp_runtime_gateway_events_policy_ids_v27_ck'
) AS capture_original_0023
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:10','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((index_class.relname)::text),'owner',((owner.rolname)::text),'valid',(index_value.indisvalid),'ready',(index_value.indisready),'unique',(index_value.indisunique),'primary',(index_value.indisprimary),'definition',((pg_get_indexdef(index_value.indexrelid))::text))) FROM pg_index index_value JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_roles owner ON owner.oid=index_class.relowner WHERE index_value.indrelid='public.zasp_runtime_gateway_events'::regclass AND index_class.relname IN('zasp_runtime_gateway_events_policy_ids_v27_idx','zasp_runtime_gateway_events_policy_history_v27_idx')
) AS capture_original_0024
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:11','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((policy.polname)::text),'permissive',(policy.polpermissive),'using',((pg_get_expr(policy.polqual,policy.polrelid))::text),'check',((pg_get_expr(policy.polwithcheck,policy.polrelid))::text))) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_recovery_%'
) AS capture_original_0025
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:12','identity',NULL,'handle','pg_trigger:'||trigger.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((trigger.tgname)::text),'definition_pretty',((pg_get_triggerdef(trigger.oid,true))::text))) FROM pg_trigger trigger JOIN pg_class class ON class.oid=trigger.tgrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND trigger.tgname LIKE '%_recovery_hold' AND NOT trigger.tgisinternal
) AS capture_original_0026
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:2','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((rolname)::text),'superuser',(rolsuper),'inherit',(rolinherit),'create_role',(rolcreaterole),'create_db',(rolcreatedb),'login',(rolcanlogin),'replication',(rolreplication),'bypass_rls',(rolbypassrls))) FROM pg_roles WHERE rolname='zasp_policy_deployment_worker'
) AS capture_original_0027
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:4','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'owner',((owner.rolname)::text),'row_security',(class.relrowsecurity),'forced_row_security',(class.relforcerowsecurity),'acl_text_or_empty',((COALESCE(class.relacl::text,''))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_policy_deployment_%' AND class.relkind IN('r','i')
) AS capture_original_0028
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:5','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((attribute.attname)::text),'type_identity',((attribute.atttypid::regtype::text)::text),'not_null',(attribute.attnotnull),'identity',((attribute.attidentity)::text),'generated',((attribute.attgenerated)::text),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND (class.relname LIKE 'zasp_policy_deployment_%' OR class.relname IN('zasp_security_agent_temporary_policy_targets','zasp_security_agent_session_policy_targets')) AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_original_0029
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:6','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'definition',((pg_get_indexdef(class.oid))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_policy_deployment_%' AND class.relkind='i'
) AS capture_original_0030
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:7','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((constraint_value.conname)::text),'constraint_type',((constraint_value.contype)::text),'validated',(constraint_value.convalidated),'definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_policy_deployment_%'
) AS capture_original_0031
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:8','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((policy.polname)::text),'permissive',(policy.polpermissive),'using',((pg_get_expr(policy.polqual,policy.polrelid))::text),'check',((pg_get_expr(policy.polwithcheck,policy.polrelid))::text))) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_policy_deployment_%'
) AS capture_original_0032
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:9','identity',NULL,'handle','pg_trigger:'||trigger.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((trigger.tgname)::text),'definition_pretty',((pg_get_triggerdef(trigger.oid,true))::text))) FROM pg_trigger trigger JOIN pg_class class ON class.oid=trigger.tgrelid WHERE trigger.tgname LIKE '%policy_deployment%' OR trigger.tgname LIKE '%policy_sequence' OR trigger.tgname LIKE '%policy_verify'
) AS capture_original_0033
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:3','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((relname)::text),'owner',((relowner::regrole::text)::text),'row_security',(relrowsecurity),'forced_row_security',(relforcerowsecurity),'acl_text_or_empty',((COALESCE(relacl::text,''))::text))) FROM pg_class WHERE oid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass)
) AS capture_original_0034
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:4','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((conname)::text),'definition',((pg_get_constraintdef(oid))::text),'validated',(convalidated))) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass)
) AS capture_original_0035
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:5','identity',NULL,'handle','pg_attribute:'||attrelid::text||':'||attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation',((attrelid::regclass::text)::text),'name',((attname)::text),'type',((format_type(atttypid,atttypmod))::text),'not_null',(attnotnull))) FROM pg_attribute WHERE attrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass) AND attnum>0 AND NOT attisdropped
) AS capture_original_0036
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:6','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('namespace_name',((schemaname)::text),'table_name',((tablename)::text),'name',((policyname)::text),'roles_text',((roles::text)::text),'command',((cmd)::text),'using',((qual)::text),'check',((with_check)::text))) FROM pg_policies WHERE schemaname='public' AND tablename IN('zasp_runtime_session_events','zasp_runtime_session_projection_receipts')
) AS capture_original_0037
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:7','identity',NULL,'handle',(SELECT 'pg_class:'||capture_class.oid::text||':0' FROM pg_class capture_class JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_class.relname=indexname AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('name',((indexname)::text),'definition',((indexdef)::text))) FROM pg_indexes WHERE schemaname='public' AND tablename IN('zasp_runtime_session_events','zasp_runtime_session_projection_receipts')
) AS capture_original_0038
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:3','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((p.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(p.oid))::text),'owner',((r.rolname)::text),'security_definer',(p.prosecdef),'config_text_or_empty',((COALESCE(p.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(p.proacl::text,''))::text),'definition',((pg_get_functiondef(p.oid))::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_claim_session_stage_compatible','zasp_runtime_session_claim_version_guard','zasp_runtime_claim_projection_v2','zasp_runtime_claim_completion_v2')
) AS capture_original_0039
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:4','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition_pretty',((pg_get_triggerdef(t.oid,true))::text))) FROM pg_trigger t WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_runtime_session_claim_version'
) AS capture_original_0040
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:5','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((p.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(p.oid))::text),'owner',((r.rolname)::text),'security_definer',(p.prosecdef),'config_text_or_empty',((COALESCE(p.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(p.proacl::text,''))::text),'definition',((pg_get_functiondef(p.oid))::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid='public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure
) AS capture_original_0041
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:6','identity',NULL,'handle','pg_attribute:'||attrelid::text||':'||attnum::text,'multiplicity',1,'fact',jsonb_build_object('name',((attname)::text),'acl_text_or_empty',((COALESCE(attacl::text,''))::text))) FROM pg_attribute WHERE attrelid='public.zasp_runtime_session_events'::regclass AND attnum>0 AND NOT attisdropped
) AS capture_original_0042
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:7','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((p.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(p.oid))::text),'owner',((r.rolname)::text),'security_definer',(p.prosecdef),'config_text_or_empty',((COALESCE(p.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(p.proacl::text,''))::text),'definition',((pg_get_functiondef(p.oid))::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid IN('public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer)'::regprocedure,'public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text)'::regprocedure)
) AS capture_original_0043
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:8','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((p.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(p.oid))::text),'owner',((r.rolname)::text),'security_definer',(p.prosecdef),'config_text_or_empty',((COALESCE(p.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(p.proacl::text,''))::text),'definition',((pg_get_functiondef(p.oid))::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_claim_stage_sandbox_compatible','zasp_runtime_claim_correlation_v3','zasp_runtime_freeze_sandbox_candidates','zasp_production_runtime_sandbox_binding_security_ready','zasp_production_runtime_sandbox_binding_readiness','zasp_production_runtime_correlation_routing_readiness_v49','zasp_production_runtime_candidate_authority_live_fingerprint')
) AS capture_original_0044
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:4','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((relname)::text),'owner',((relowner::regrole::text)::text),'row_security',(relrowsecurity),'forced_row_security',(relforcerowsecurity),'acl_text_or_empty',((COALESCE(relacl::text,''))::text))) FROM pg_class WHERE oid='public.zasp_runtime_sandbox_search_outbox'::regclass
) AS capture_original_0045
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:5','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((conname)::text),'definition',((pg_get_constraintdef(oid))::text),'validated',(convalidated))) FROM pg_constraint WHERE conrelid='public.zasp_runtime_sandbox_search_outbox'::regclass
) AS capture_original_0046
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:6','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('name',((attname)::text),'type',((format_type(atttypid,atttypmod))::text),'not_null',(attnotnull),'acl_text_or_empty',((COALESCE(attacl::text,''))::text),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text))) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.zasp_runtime_sandbox_search_outbox'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0047
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:7','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('name',((policyname)::text),'roles_text',((roles::text)::text),'command',((cmd)::text),'using',((qual)::text),'check',((with_check)::text))) FROM pg_policies WHERE schemaname='public' AND tablename='zasp_runtime_sandbox_search_outbox'
) AS capture_original_0048
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:8','identity',NULL,'handle',(SELECT 'pg_class:'||capture_class.oid::text||':0' FROM pg_class capture_class JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_class.relname=indexname AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('name',((indexname)::text),'definition',((indexdef)::text))) FROM pg_indexes WHERE schemaname='public' AND tablename='zasp_runtime_sandbox_search_outbox'
) AS capture_original_0049
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:9','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((tgrelid::regclass::text)::text),'name',((tgname)::text),'enabled',((tgenabled)::text),'definition',((pg_get_triggerdef(oid))::text))) FROM pg_trigger WHERE tgrelid IN('public.zasp_runtime_session_projection_receipts'::regclass,'public.zasp_runtime_sandbox_search_outbox'::regclass,'public.zasp_runtime_session_search_outbox'::regclass) AND NOT tgisinternal
) AS capture_original_0050
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM selected c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0051
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM selected c JOIN pg_constraint k ON k.conrelid=c.oid
) AS capture_original_0052
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM selected c JOIN pg_index i ON i.indrelid=c.oid
) AS capture_original_0053
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM selected c JOIN pg_policy p ON p.polrelid=c.oid
) AS capture_original_0054
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',((nspowner::regrole::text)::text),'acl',((nspacl::text)::text))) FROM pg_namespace WHERE nspname='zasp_authorization80_temporal'
) AS capture_original_0055
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'owner',((c.relowner::regrole::text)::text),'acl',((c.relacl::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace
) AS capture_original_0056
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'acl',((a.attacl::text)::text),'default',((pg_get_expr(d.adbin,d.adrelid))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0057
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace
) AS capture_original_0058
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((p.polrelid::regclass::text)::text),'name',((p.polname)::text),'command',((p.polpermissive)::text),'permissive',(p.polcmd),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_temporal'::regnamespace
) AS capture_original_0059
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND(c.relnamespace='zasp_authorization80_temporal'::regnamespace OR t.tgname='zasp_authorization79_capture' AND t.tgrelid IN('public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_syncs'::regclass,'public.zasp_inventory_entities'::regclass))
) AS capture_original_0060
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_authorization80_temporal.predecessor_functions) captured GROUP BY fact
) AS capture_original_0061
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_ordered_public62'
) AS capture_original_0062
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_ordered_public62'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0063
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_original_0064
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_original_0065
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_original_0066
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_ordered_public62'::regnamespace
) AS capture_original_0067
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal68'
) AS capture_original_0068
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal68'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0069
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_original_0070
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_original_0071
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal68'::regnamespace
) AS capture_original_0072
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal68'::regnamespace AND NOT(t.tgrelid='zasp_temporal68.deliveries'::regclass AND t.tgname IN('ordered_policy_capture','ordered_policy_no_truncate'))
) AS capture_original_0073
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal68.predecessor_functions) captured GROUP BY fact
) AS capture_original_0074
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal69'
) AS capture_original_0075
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal69'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0076
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_original_0077
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_original_0078
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_original_0079
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal69'::regnamespace
) AS capture_original_0080
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal69.predecessor_functions) captured GROUP BY fact
) AS capture_original_0081
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal72'
) AS capture_original_0082
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal72'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0083
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_original_0084
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_original_0085
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_original_0086
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND NOT(t.tgname IN('zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate') AND t.tgrelid IN('zasp_temporal72.runs'::regclass,'zasp_temporal72.schedules'::regclass)) AND c.relnamespace='zasp_temporal72'::regnamespace
) AS capture_original_0087
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal78'
) AS capture_original_0088
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal78'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0089
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_original_0090
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_original_0091
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_original_0092
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal78'::regnamespace
) AS capture_original_0093
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:finding-ownership-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE t.tgname='zasp_temporal78_ownership' AND t.tgrelid IN('public.zasp_security_agent_runs'::regclass,'public.zasp_security_agent_effects'::regclass)
) AS capture_original_0094
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:finding-decision-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE t.tgname='zasp_temporal78_control_capture' AND t.tgrelid='public.zasp_security_agent_request_receipts'::regclass
) AS capture_original_0095
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal78.predecessor_functions) captured GROUP BY fact
) AS capture_original_0096
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',((nspowner::regrole::text)::text),'acl',((nspacl::text)::text))) FROM pg_namespace WHERE nspname='zasp_authorization79'
) AS capture_original_0097
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:relation','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'owner',((c.relowner::regrole::text)::text),'acl',((c.relacl::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE relnamespace='zasp_authorization79'::regnamespace
) AS capture_original_0098
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default',((pg_get_expr(d.adbin,d.adrelid))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization79'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0099
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization79'::regnamespace
) AS capture_original_0100
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization79'::regnamespace
) AS capture_original_0101
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE t.tgname='zasp_authorization79_capture'
) AS capture_original_0102
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal70'
) AS capture_original_0103
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_original_0104
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal70'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0105
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_original_0106
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_original_0107
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_original_0108
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_original_0109
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal70'::regnamespace
) AS capture_original_0110
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal70.predecessor_functions) captured GROUP BY fact
) AS capture_original_0111
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal71'
) AS capture_original_0112
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_original_0113
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal71'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0114
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_original_0115
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_original_0116
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_original_0117
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_original_0118
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal71'::regnamespace
) AS capture_original_0119
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal71.predecessor_functions) captured GROUP BY fact
) AS capture_original_0120
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_pretty_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid,true),''))::text))) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_risk_projection_current','zasp_discovery_risk_projection_items','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs','zasp_workflow_receipts']) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0121
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value JOIN pg_class c ON c.oid=constraint_value.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (c.relname LIKE 'zasp_discovery_execution_%' OR c.relname IN('zasp_discovery_connection_subjects','zasp_discovery_job_checkpoints','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_risk_projection_current','zasp_discovery_risk_projection_items','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_integration_connections')) AND (constraint_value.conname LIKE 'zasp_execution_%' OR c.relname<>'zasp_integration_connections')
) AS capture_original_0122
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:index','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('definition_pretty',((pg_get_indexdef(index_value.indexrelid,0,true))::text))) FROM pg_index index_value JOIN pg_class table_class ON table_class.oid=index_value.indrelid JOIN pg_class index_class ON index_class.oid=index_value.indexrelid JOIN pg_namespace n ON n.oid=table_class.relnamespace WHERE n.nspname='public' AND index_class.relname LIKE 'zasp_execution_%'
) AS capture_original_0123
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_precision_predecessor'
) AS capture_original_0124
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((conrelid::regclass::text)::text),'name',((conname)::text),'validated',(convalidated),'definition_pretty',((pg_get_constraintdef(oid,true))::text))) FROM pg_constraint WHERE conname='zasp_runtime_precision_source_check'
) AS capture_original_0125
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition_pretty',((pg_get_triggerdef(t.oid,true))::text),'function_name',((p.proname)::text),'function_identity_arguments',((pg_get_function_identity_arguments(p.oid))::text))) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN('public.zasp_runtime_batch_authorities'::regclass,'public.zasp_runtime_stage_work'::regclass,'public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass,'public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_projection_receipts'::regclass,'public.zasp_runtime_session_search_outbox'::regclass,'public.zasp_runtime_sandbox_search_outbox'::regclass,'public.zasp_runtime_ingest_reconciliation_work'::regclass,'public.zasp_runtime_ingest_reconciliation_state'::regclass,'public.zasp_discovery_outbox'::regclass,'public.zasp_discovery_outbox_topic_fairness'::regclass,'public.zasp_runtime_deliveries'::regclass) AND NOT t.tgisinternal AND NOT(t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_authorization80_runtime_stage_insert') AND NOT(t.tgrelid='public.zasp_discovery_outbox'::regclass AND t.tgname='zasp_temporal72_outbox_guard')
) AS capture_original_0126
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal65'
) AS capture_original_0127
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal65'::regnamespace
) AS capture_original_0128
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal65'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0129
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal65'::regnamespace
) AS capture_original_0130
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal65'::regnamespace
) AS capture_original_0131
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal65'::regnamespace
) AS capture_original_0132
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE t.tgname='zasp_temporal65_capture' AND t.tgrelid='public.zasp_security_agent_request_receipts'::regclass
) AS capture_original_0133
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal66'
) AS capture_original_0134
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal66'::regnamespace
) AS capture_original_0135
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal66'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0136
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal66'::regnamespace
) AS capture_original_0137
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal66'::regnamespace
) AS capture_original_0138
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',((c.relnamespace::regnamespace::text)::text),'relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal66'::regnamespace OR p.polname='zasp_temporal66_owner'
) AS capture_original_0139
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND (c.relnamespace='zasp_temporal66'::regnamespace OR t.tgname IN('zasp_temporal66_lease','zasp_temporal66_capture'))
) AS capture_original_0140
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal75'
) AS capture_original_0141
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_original_0142
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal75'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0143
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_original_0144
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_original_0145
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_original_0146
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_original_0147
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal75'::regnamespace
) AS capture_original_0148
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:owner-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_temporal75_owner'
) AS capture_original_0149
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:owner-policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((p.polrelid::regclass::text)::text),'name',((p.polname)::text),'permissive',(p.polpermissive),'command',((p.polcmd)::text),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p WHERE p.polname='zasp_temporal75_owner' AND p.polrelid='public.zasp_security_agent_runs'::regclass
) AS capture_original_0150
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal75.predecessor_functions) captured GROUP BY fact
) AS capture_original_0151
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal67'
) AS capture_original_0152
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_original_0153
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal67'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0154
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_original_0155
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_original_0156
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_original_0157
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal67'::regnamespace
) AS capture_original_0158
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal67.predecessor_functions) captured GROUP BY fact
) AS capture_original_0159
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal73'
) AS capture_original_0160
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_original_0161
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal73'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0162
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_original_0163
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_original_0164
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_original_0165
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_original_0166
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal73'::regnamespace
) AS capture_original_0167
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:capacity-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_temporal73_capacity'
) AS capture_original_0168
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal73.predecessor_functions) captured GROUP BY fact
) AS capture_original_0169
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal76'
) AS capture_original_0170
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_original_0171
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal76'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0172
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_original_0173
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_original_0174
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_original_0175
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_original_0176
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal76'::regnamespace
) AS capture_original_0177
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:human-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_request_receipts'::regclass AND t.tgname='zasp_temporal76_capture'
) AS capture_original_0178
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:owner-policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((p.polrelid::regclass::text)::text),'name',((p.polname)::text),'permissive',(p.polpermissive),'command',((p.polcmd)::text),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p WHERE p.polname='zasp_temporal76_owner' AND p.polrelid='public.zasp_security_agent_runs'::regclass
) AS capture_original_0179
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:executor-constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k WHERE k.conrelid='zasp_temporal74.run_owners'::regclass AND k.conname='run_owners_source_kind_check'
) AS capture_original_0180
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:saved-constraint','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text)) AS fact FROM zasp_temporal76.predecessor_constraints) captured GROUP BY fact
) AS capture_original_0181
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal76.predecessor_functions) captured GROUP BY fact
) AS capture_original_0182
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_temporal77'
) AS capture_original_0183
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_original_0184
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal77'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0185
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_original_0186
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_original_0187
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_original_0188
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_temporal77'::regnamespace AND NOT(t.tgrelid IN('zasp_temporal77.runtime_evaluations'::regclass,'zasp_temporal77.source_events'::regclass) AND t.tgname IN('zasp_authorization80_worker_runtime_capture','zasp_authorization80_worker_runtime_no_truncate'))
) AS capture_original_0189
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_temporal77'::regnamespace
) AS capture_original_0190
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:definition-guard','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_definitions'::regclass AND t.tgname='zasp_temporal77_definition_guard'
) AS capture_original_0191
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:source-capture','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((t.tgrelid::regclass::text)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE (t.tgrelid,t.tgname) IN(('public.zasp_risk_findings'::regclass,'zasp_temporal77_finding_source'),('public.zasp_risk_attack_paths'::regclass,'zasp_temporal77_path_source'),('public.zasp_runtime_gateway_events'::regclass,'zasp_temporal77_runtime_source'))
) AS capture_original_0192
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:occurrence-guard','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_temporal77_occurrence_guard'
) AS capture_original_0193
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl)::text)) AS fact FROM zasp_temporal77.predecessor_functions) captured GROUP BY fact
) AS capture_original_0194
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:role','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((rolname)::text),'superuser',(rolsuper),'inherit',(rolinherit),'create_role',(rolcreaterole),'create_db',(rolcreatedb),'login',(rolcanlogin),'replication',(rolreplication),'bypass_rls',(rolbypassrls))) FROM pg_roles WHERE rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy')
) AS capture_original_0195
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:table','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'owner',((owner.rolname)::text),'row_security',(class.relrowsecurity),'forced_row_security',(class.relforcerowsecurity),'acl_text_or_empty',((COALESCE(class.relacl::text,''))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_attack_lab_%' AND class.relkind IN('r','i')
) AS capture_original_0196
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:index','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'definition',((pg_get_indexdef(class.oid))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_attack_lab_%' AND class.relkind='i'
) AS capture_original_0197
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:column','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((attribute.attname)::text),'type_identity',((attribute.atttypid::regtype::text)::text),'not_null',(attribute.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_attack_lab_%' AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_original_0198
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:constraint','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((constraint_value.conname)::text),'constraint_type',((constraint_value.contype)::text),'validated',(constraint_value.convalidated),'definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_attack_lab_%'
) AS capture_original_0199
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:policy','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((policy.polname)::text),'permissive',(policy.polpermissive),'using',((pg_get_expr(policy.polqual,policy.polrelid))::text),'check',((pg_get_expr(policy.polwithcheck,policy.polrelid))::text))) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_attack_lab_%'
) AS capture_original_0200
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname LIKE 'zasp_attack_lab_%'
) AS capture_original_0201
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl::text)::text)) AS fact FROM zasp_schedule_replay_prior.functions) captured GROUP BY fact
) AS capture_original_0202
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_schedule_replay_prior'
) AS capture_original_0203
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',((n.nspname)::text),'name',((c.relname)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass) AND c.relkind='r'
) AS capture_original_0204
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE (n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0205
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass
) AS capture_original_0206
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass
) AS capture_original_0207
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:column','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('type',((format_type(attribute.atttypid,attribute.atttypmod))::text),'not_null',(attribute.attnotnull),'default_pretty_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid,true),''))::text))) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
    WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_capability_evidence','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_evidence']) AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_original_0208
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:constraint','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_capability_evidence','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_evidence'])
) AS capture_original_0209
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:index','identity',NULL,'handle','pg_class:'||index_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('definition',((pg_get_indexdef(index_value.oid))::text))) FROM pg_class index_value JOIN pg_namespace namespace ON namespace.oid=index_value.relnamespace WHERE namespace.nspname='public' AND index_value.relname IN('zasp_inventory_entities_kind_page_v14_idx','zasp_inventory_observations_identity_v14_idx','zasp_inventory_capability_evidence_edge_v14_idx')
) AS capture_original_0210
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:trigger','identity',NULL,'handle','pg_trigger:'||trigger_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('definition_pretty',((pg_get_triggerdef(trigger_value.oid,true))::text))) FROM pg_trigger trigger_value JOIN pg_class class ON class.oid=trigger_value.tgrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname='zasp_core_payloads' AND trigger_value.tgname='zasp_core_inventory_write_fence' AND NOT trigger_value.tgisinternal
) AS capture_original_0211
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:role','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((rolname)::text),'superuser',(rolsuper),'inherit',(rolinherit),'create_role',(rolcreaterole),'create_db',(rolcreatedb),'login',(rolcanlogin),'replication',(rolreplication),'bypass_rls',(rolbypassrls))) FROM pg_roles WHERE rolname IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter')
) AS capture_original_0212
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:table','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'owner',((owner.rolname)::text),'row_security',(class.relrowsecurity),'forced_row_security',(class.relforcerowsecurity),'acl_text_or_empty',((COALESCE(class.relacl::text,''))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_red_team_%' AND class.relkind IN('r','i')
) AS capture_original_0213
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:column','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((attribute.attname)::text),'type_identity',((attribute.atttypid::regtype::text)::text),'not_null',(attribute.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname LIKE 'zasp_red_team_%' AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_original_0214
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:constraint','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((constraint_value.conname)::text),'constraint_type',((constraint_value.contype)::text),'validated',(constraint_value.convalidated),'definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value JOIN pg_class class ON class.oid=constraint_value.conrelid WHERE class.relname LIKE 'zasp_red_team_%'
) AS capture_original_0215
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:policy','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'name',((policy.polname)::text),'permissive',(policy.polpermissive),'using',((pg_get_expr(policy.polqual,policy.polrelid))::text),'check',((pg_get_expr(policy.polwithcheck,policy.polrelid))::text))) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid WHERE class.relname LIKE 'zasp_red_team_%'
) AS capture_original_0216
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_red_team_%' OR procedure.proname='zasp_effective_scope_permissions')
) AS capture_original_0217
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl::text)::text)) AS fact FROM zasp_sa_attack_lab_prior.functions) captured GROUP BY fact
) AS capture_original_0218
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_sa_attack_lab_prior'
) AS capture_original_0219
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_sa_attack_lab_') AND c.relkind='r'
) AS capture_original_0220
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE n.nspname='public' AND starts_with(c.relname,'zasp_sa_attack_lab_') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0221
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE starts_with(c.relname,'zasp_sa_attack_lab_')
) AS capture_original_0222
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE starts_with(c.relname,'zasp_sa_attack_lab_')
) AS capture_original_0223
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_sa_export_prior'
) AS capture_original_0224
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',((n.nspname)::text),'name',((c.relname)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_')) AND c.relkind='r'
) AS capture_original_0225
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('namespace_name',((n.nspname)::text),'relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE (n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_')) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0226
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_')
) AS capture_original_0227
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE starts_with(c.relname,'zasp_sa_export_')
) AS capture_original_0228
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_')
) AS capture_original_0229
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',((n.nspname)::text),'relation_name',((c.relname)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE NOT t.tgisinternal AND (n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND starts_with(c.relname,'zasp_sa_export_'))
) AS capture_original_0230
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'kind',((c.relkind)::text),'persistence',((c.relpersistence)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_') AND c.relkind IN('r','v','m','p','S')
) AS capture_original_0231
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'identity',((a.attidentity)::text),'generated',((a.attgenerated)::text),'collation',((a.attcollation::regcollation::text)::text),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_') AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0232
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
) AS capture_original_0233
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'permissive',(p.polpermissive),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
) AS capture_original_0234
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready),'live',(i.indislive))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
) AS capture_original_0235
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
 -- FK trigger names contain installation-specific OIDs. Bind their constraint,
 -- both relations, function, event flags and enabled state, on both FK sides.
) AS capture_original_0236
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((k.conrelid::regclass::text)::text),'name',((k.conname)::text),'referenced_relation',((k.confrelid::regclass::text)::text),'trigger_relation',((t.tgrelid::regclass::text)::text),'constraint_relation',((t.tgconstrrelid::regclass::text)::text),'function',((t.tgfoid::regprocedure::text)::text),'event_bits',(t.tgtype),'enabled',((t.tgenabled)::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',((encode(t.tgargs,'hex'))::text),'columns_text',((t.tgattr::text)::text),'when_text_or_empty',((COALESCE(pg_get_expr(t.tgqual,t.tgrelid),''))::text))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
) AS capture_original_0237
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',((signature)::text),'definition',((definition)::text),'owner',((owner_name)::text),'acl',((acl::text)::text)) AS fact FROM zasp_sa_webhook_prior.functions) captured GROUP BY fact
) AS capture_original_0238
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((nspname)::text),'owner',((nspowner::regrole::text)::text),'acl_text_or_empty',((COALESCE(nspacl::text,''))::text))) FROM pg_namespace WHERE nspname='zasp_sa_webhook_prior'
) AS capture_original_0239
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',((n.nspname)::text),'name',((c.relname)::text),'owner',((c.relowner::regrole::text)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))) AND c.relkind='r'
) AS capture_original_0240
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'position',(a.attnum),'name',((a.attname)::text),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE (n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0241
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((k.conname)::text),'definition',((pg_get_constraintdef(k.oid))::text),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))
) AS capture_original_0242
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((p.polname)::text),'command',((p.polcmd)::text),'roles',((p.polroles::regrole[]::text)::text),'using',((pg_get_expr(p.polqual,p.polrelid))::text),'check',((pg_get_expr(p.polwithcheck,p.polrelid))::text))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_')
) AS capture_original_0243
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'definition',((pg_get_indexdef(i.indexrelid))::text),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))
) AS capture_original_0244
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',((c.relname)::text),'name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition',((pg_get_triggerdef(t.oid))::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND (c.relname='zasp_security_agent_webhook_deliveries' OR starts_with(c.relname,'zasp_sa_webhook_'))
) AS capture_original_0245
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:role','identity',NULL,'handle','pg_authid:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((rolname)::text),'superuser',(rolsuper),'inherit',(rolinherit),'create_role',(rolcreaterole),'create_db',(rolcreatedb),'login',(rolcanlogin),'replication',(rolreplication),'bypass_rls',(rolbypassrls))) FROM pg_roles WHERE rolname='zasp_security_agent_webhook_worker'
) AS capture_original_0246
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:table','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'owner',((owner.rolname)::text),'row_security',(class.relrowsecurity),'forced_row_security',(class.relforcerowsecurity),'acl_text_or_empty',((COALESCE(class.relacl::text,''))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_connector_revocations' AND class.relkind IN('r','i')
) AS capture_original_0247
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:column','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('name',((attribute.attname)::text),'type_identity',((attribute.atttypid::regtype::text)::text),'not_null',(attribute.attnotnull),'identity',((attribute.attidentity)::text),'generated',((attribute.attgenerated)::text),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE attribute.attrelid='public.zasp_security_agent_connector_revocations'::regclass AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_original_0248
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:table_constraint','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((constraint_value.conname)::text),'constraint_type',((constraint_value.contype)::text),'validated',(constraint_value.convalidated),'deferrable',(constraint_value.condeferrable),'deferred',(constraint_value.condeferred),'definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_connector_revocations'::regclass
) AS capture_original_0249
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:index','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((index_class.relname)::text),'valid',(index_value.indisvalid),'ready',(index_value.indisready),'unique',(index_value.indisunique),'primary',(index_value.indisprimary),'definition',((pg_get_indexdef(index_value.indexrelid))::text))) FROM pg_index index_value JOIN pg_class index_class ON index_class.oid=index_value.indexrelid WHERE index_value.indrelid='public.zasp_security_agent_connector_revocations'::regclass
) AS capture_original_0250
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:policy','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((policy.polname)::text),'command',((policy.polcmd)::text),'permissive',(policy.polpermissive),'roles_csv_public_sorted',((COALESCE((SELECT string_agg(CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE role_value.rolname END,',' ORDER BY CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE role_value.rolname END) FROM unnest(policy.polroles) role_oid LEFT JOIN pg_roles role_value ON role_value.oid=role_oid),''))::text),'using_text_or_empty',((COALESCE(pg_get_expr(policy.polqual,policy.polrelid),''))::text),'check_text_or_empty',((COALESCE(pg_get_expr(policy.polwithcheck,policy.polrelid),''))::text))) FROM pg_policy policy WHERE policy.polrelid='public.zasp_security_agent_connector_revocations'::regclass
) AS capture_original_0251
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_execution_control_detail','zasp_security_agent_execution_control_detail_v22_restore','zasp_security_agent_mutate_execution_control','zasp_security_agent_mutate_execution_control_v22_restore','zasp_security_agent_schedule_connector_revocation_triggers','zasp_security_agent_schedule_triggers_v23','zasp_security_agent_claim_runs_v23','zasp_security_agent_prepare_connector_revocation_run','zasp_security_agent_prepare_run_v23','zasp_security_agent_dispatch_connector_revocation_run','zasp_security_agent_execute_run_v23','zasp_security_agent_reconcile_connector_revocations','zasp_security_agent_approval_value_v23','zasp_security_agent_run_detail_v23','zasp_security_agent_approval_page_v23','zasp_security_agent_approval_detail_v23','zasp_security_agent_decide_approval_v23','zasp_connector_complete_revocation','zasp_connector_complete_revocation_v22','zasp_security_agent_connector_revocation_security_ready','zasp_workflow_mutate','zasp_risk_mutate'])
) AS capture_original_0252
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:constraint','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((conname)::text),'validated',(convalidated),'definition_pretty',((pg_get_constraintdef(oid,true))::text))) FROM pg_constraint WHERE conrelid='public.zasp_security_agent_definitions'::regclass AND conname='zasp_security_agent_connector_revocation_supervised_check'
) AS capture_original_0253
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:table','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((class.relname)::text),'owner',((owner.rolname)::text),'row_security',(class.relrowsecurity),'forced_row_security',(class.relforcerowsecurity),'acl_text_or_empty',((COALESCE(class.relacl::text,''))::text))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace JOIN pg_roles owner ON owner.oid=class.relowner WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_approval_notifications' AND class.relkind IN('r','i')
) AS capture_original_0254
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:column','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',((class.relname)::text),'position',(attribute.attnum),'name',((attribute.attname)::text),'type',((format_type(attribute.atttypid,attribute.atttypmod))::text),'not_null',(attribute.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute JOIN pg_class class ON class.oid=attribute.attrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef default_value ON default_value.adrelid=class.oid AND default_value.adnum=attribute.attnum WHERE namespace.nspname='public' AND class.relname='zasp_security_agent_approval_notifications' AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_original_0255
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:constraint','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((constraint_value.conname)::text),'constraint_type',((constraint_value.contype)::text),'validated',(constraint_value.convalidated),'definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_security_agent_approval_notifications'::regclass
) AS capture_original_0256
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:index','identity',NULL,'handle','pg_class:'||index_metadata.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((index_value.relname)::text),'definition',((pg_get_indexdef(index_value.oid))::text))) FROM pg_index index_metadata JOIN pg_class index_value ON index_value.oid=index_metadata.indexrelid WHERE index_metadata.indrelid='public.zasp_security_agent_approval_notifications'::regclass
) AS capture_original_0257
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:policy','identity',NULL,'handle','pg_policy:'||policy_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((policy_value.polname)::text),'permissive',(policy_value.polpermissive),'roles_csv_public_sorted',((COALESCE((SELECT string_agg(CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE role_value.rolname END,',' ORDER BY CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE role_value.rolname END) FROM unnest(policy_value.polroles) role_oid LEFT JOIN pg_roles role_value ON role_value.oid=role_oid),''))::text),'using_text_or_empty',((COALESCE(pg_get_expr(policy_value.polqual,policy_value.polrelid),''))::text),'check_text_or_empty',((COALESCE(pg_get_expr(policy_value.polwithcheck,policy_value.polrelid),''))::text))) FROM pg_policy policy_value WHERE policy_value.polrelid='public.zasp_security_agent_approval_notifications'::regclass
) AS capture_original_0258
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_security_agent_enqueue_approval_notification','zasp_security_agent_claim_approval_notification','zasp_security_agent_complete_approval_notification','zasp_security_agent_fail_approval_notification','zasp_production_approval_notification_security_ready','zasp_production_approval_notification_readiness','zasp_production_home_attention_readiness'])
) AS capture_original_0259
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:trigger','identity',NULL,'handle','pg_trigger:'||trigger_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((trigger_value.tgname)::text),'definition_pretty',((pg_get_triggerdef(trigger_value.oid,true))::text))) FROM pg_trigger trigger_value WHERE trigger_value.tgrelid='public.zasp_security_agent_approvals'::regclass AND trigger_value.tgname='zasp_security_agent_enqueue_approval_notification_v30' AND NOT trigger_value.tgisinternal
) AS capture_original_0260
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:home_attention:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_inventory_home_summary','zasp_inventory_home_summary_v29')
) AS capture_original_0261
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_setup:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_execution_integration_setup_status','zasp_production_integration_setup_security_ready')
) AS capture_original_0262
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_integration_webhook_test_public','zasp_integration_webhook_test_reserve','zasp_integration_webhook_test_complete','zasp_integration_webhook_test_status','zasp_production_integration_webhook_security_ready')
) AS capture_original_0263
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:table','identity',NULL,'handle','pg_class:'||table_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((table_value.relname)::text),'owner',((owner.rolname)::text),'row_security',(table_value.relrowsecurity),'forced_row_security',(table_value.relforcerowsecurity),'acl_text_or_empty',((COALESCE(table_value.relacl::text,''))::text))) FROM pg_class table_value JOIN pg_roles owner ON owner.oid=table_value.relowner WHERE table_value.oid='public.zasp_integration_webhook_tests'::regclass
) AS capture_original_0264
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:column','identity',NULL,'handle','pg_attribute:'||attribute.attrelid::text||':'||attribute.attnum::text,'multiplicity',1,'fact',jsonb_build_object('position',(attribute.attnum),'name',((attribute.attname)::text),'type',((format_type(attribute.atttypid,attribute.atttypmod))::text),'not_null',(attribute.attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute LEFT JOIN pg_attrdef default_value ON (default_value.adrelid,default_value.adnum)=(attribute.attrelid,attribute.attnum) WHERE attribute.attrelid='public.zasp_integration_webhook_tests'::regclass AND attribute.attnum>0 AND NOT attribute.attisdropped
) AS capture_original_0265
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:constraint','identity',NULL,'handle','pg_constraint:'||constraint_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((constraint_value.conname)::text),'definition_pretty',((pg_get_constraintdef(constraint_value.oid,true))::text))) FROM pg_constraint constraint_value WHERE constraint_value.conrelid='public.zasp_integration_webhook_tests'::regclass
) AS capture_original_0266
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:index','identity',NULL,'handle','pg_class:'||index_value.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('definition',((pg_get_indexdef(index_value.indexrelid))::text))) FROM pg_index index_value WHERE index_value.indrelid='public.zasp_integration_webhook_tests'::regclass
) AS capture_original_0267
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:policy','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((policy.polname)::text),'command',((policy.polcmd)::text),'permissive',(policy.polpermissive),'roles_named_array_text',((ARRAY(SELECT rolname FROM pg_roles WHERE oid=ANY(policy.polroles) ORDER BY rolname)::text)::text),'using',((pg_get_expr(policy.polqual,policy.polrelid))::text),'check',((pg_get_expr(policy.polwithcheck,policy.polrelid))::text))) FROM pg_policy policy WHERE policy.polrelid='public.zasp_integration_webhook_tests'::regclass
) AS capture_original_0268
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:reconciliation_lane_plan:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((p.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(p.oid))::text),'owner',((r.rolname)::text),'security_definer',(p.prosecdef),'config_text_or_empty',((COALESCE(p.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(p.proacl::text,''))::text),'definition',((pg_get_functiondef(p.oid))::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_connector_claim_reconciliation','zasp_production_reconciliation_lane_plan_readiness','zasp_production_reconciliation_lane_plan_security_ready')
) AS capture_original_0269
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_artifacts:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_red_team_artifacts_readiness','zasp_production_red_team_artifacts_security_ready','zasp_red_team_valid_input_artifact','zasp_red_team_finish_run','zasp_red_team_finish_run_v38','zasp_red_team_get_run')
) AS capture_original_0270
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_artifacts:constraint','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((conname)::text),'definition',((pg_get_constraintdef(oid))::text),'validated',(convalidated))) FROM pg_constraint WHERE conrelid='public.zasp_red_team_attempts'::regclass
) AS capture_original_0271
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_artifacts:column','identity',NULL,'handle','pg_attribute:'||attrelid::text||':'||attnum::text,'multiplicity',1,'fact',jsonb_build_object('name',((attname)::text),'type',((format_type(atttypid,atttypmod))::text),'not_null',(attnotnull))) FROM pg_attribute WHERE attrelid='public.zasp_red_team_attempts'::regclass AND attnum>0 AND NOT attisdropped
) AS capture_original_0272
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_invocation:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_red_team_invocation_security_ready')
) AS capture_original_0273
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_safety:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_red_team_safety_security_ready')
) AS capture_original_0274
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:workflow_compatibility:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_workflow_mutate','zasp_risk_mutate')
) AS capture_original_0275
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:acceptance:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((p.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(p.oid))::text),'owner',((r.rolname)::text),'security_definer',(p.prosecdef),'config_text_or_empty',((COALESCE(p.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(p.proacl::text,''))::text),'definition',((pg_get_functiondef(p.oid))::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_lookup_acceptance','zasp_production_runtime_acceptance_security_ready','zasp_production_runtime_acceptance_readiness','zasp_production_runtime_candidate_authority_readiness_v47')
) AS capture_original_0276
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((p.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(p.oid))::text),'owner',((r.rolname)::text),'security_definer',(p.prosecdef),'config_text_or_empty',((COALESCE(p.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(p.proacl::text,''))::text),'definition',((pg_get_functiondef(p.oid))::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_candidate_lineage_valid','zasp_runtime_candidate_execution_live','zasp_runtime_freeze_candidates','zasp_production_runtime_candidate_authority_security_ready','zasp_production_runtime_candidate_authority_readiness','zasp_production_reconciliation_lane_plan_readiness_v46')
) AS capture_original_0277
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'owner',((r.rolname)::text),'kind',((c.relkind)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text),'options_text_or_empty',((COALESCE(c.reloptions::text,''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN('zasp_runtime_candidate_observations','zasp_runtime_candidate_snapshots')
) AS capture_original_0278
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation',((a.attrelid::regclass::text)::text),'name',((a.attname)::text),'normalized_position',(CASE WHEN a.attrelid='public.zasp_runtime_candidate_observations'::regclass AND a.attname='sandbox_id' THEN (SELECT count(*) FROM pg_attribute live WHERE live.attrelid=a.attrelid AND live.attnum>0 AND live.attnum<=a.attnum AND NOT live.attisdropped) ELSE a.attnum END),'type',((format_type(a.atttypid,a.atttypmod))::text),'not_null',(a.attnotnull),'identity',((a.attidentity)::text),'generated',((a.attgenerated)::text),'acl_text_or_empty',((COALESCE(a.attacl::text,''))::text),'default_text_or_empty',((COALESCE(pg_get_expr(d.adbin,d.adrelid),''))::text))) FROM pg_attribute a LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0279
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:constraint','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((conrelid::regclass::text)::text),'name',((conname)::text),'validated',(convalidated),'definition_pretty',((pg_get_constraintdef(oid,true))::text))) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass)
) AS capture_original_0280
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:index','identity',NULL,'handle','pg_class:'||indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_identity',((indexrelid::regclass::text)::text),'valid',(indisvalid),'ready',(indisready),'live',(indislive),'definition',((pg_get_indexdef(indexrelid))::text))) FROM pg_index WHERE indrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass)
) AS capture_original_0281
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:policy','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('relation_name',((tablename)::text),'name',((policyname)::text),'roles_text',((roles::text)::text),'permissive',((permissive)::text),'command',((cmd)::text),'using',((qual)::text),'check',((with_check)::text))) FROM pg_policies WHERE schemaname='public' AND tablename IN('zasp_runtime_candidate_observations','zasp_runtime_candidate_snapshots')
) AS capture_original_0282
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:trigger','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((tgrelid::regclass::text)::text),'name',((tgname)::text),'enabled',((tgenabled)::text),'definition_pretty',((pg_get_triggerdef(oid,true))::text))) FROM pg_trigger WHERE tgrelid IN('public.zasp_runtime_candidate_observations'::regclass,'public.zasp_runtime_candidate_snapshots'::regclass) AND NOT tgisinternal
) AS capture_original_0283
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:correlation_routing:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((p.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(p.oid))::text),'owner',((r.rolname)::text),'security_definer',(p.prosecdef),'config_text_or_empty',((COALESCE(p.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(p.proacl::text,''))::text),'definition',((pg_get_functiondef(p.oid))::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_claim_stage_compatible','zasp_runtime_claim_correlation_v2','zasp_runtime_correlation_claim_version_guard','zasp_production_runtime_correlation_routing_security_ready','zasp_production_runtime_correlation_routing_readiness','zasp_production_runtime_acceptance_readiness_v48')
) AS capture_original_0284
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:correlation_routing:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((t.tgname)::text),'enabled',((t.tgenabled)::text),'definition_pretty',((pg_get_triggerdef(t.oid,true))::text))) FROM pg_trigger t WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_runtime_correlation_claim_version'
) AS capture_original_0285
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((p.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(p.oid))::text),'owner',((r.rolname)::text),'security_definer',(p.prosecdef),'config_text_or_empty',((COALESCE(p.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(p.proacl::text,''))::text),'definition',((pg_get_functiondef(p.oid))::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_pairing_immutable','zasp_runtime_bind_batch_domain','zasp_runtime_public_sensor_value','zasp_runtime_public_sensor_value_v44','zasp_runtime_public_create_sensor','zasp_runtime_public_create_sensor_v44','zasp_production_runtime_enrollment_pairing_readiness','zasp_production_runtime_enrollment_pairing_security_ready')
) AS capture_original_0286
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((c.relname)::text),'owner',((r.rolname)::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_text_or_empty',((COALESCE(c.relacl::text,''))::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains')
) AS capture_original_0287
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:column','identity',NULL,'handle',(SELECT 'pg_attribute:'||capture_attribute.attrelid::text||':'||capture_attribute.attnum::text FROM pg_attribute capture_attribute JOIN pg_class capture_class ON capture_class.oid=capture_attribute.attrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_attribute.attname=column_name AND capture_class.relname=table_name AND capture_ns.nspname=table_schema),'multiplicity',1,'fact',jsonb_build_object('relation_name',((table_name)::text),'name',((column_name)::text),'data_type',((data_type)::text),'is_nullable',((is_nullable)::text),'default_text_or_empty',((COALESCE(column_default,''))::text))) FROM information_schema.columns WHERE table_schema='public' AND table_name IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains')
) AS capture_original_0288
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:constraint','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation',((conrelid::regclass::text)::text),'name',((conname)::text),'definition_pretty',((pg_get_constraintdef(oid,true))::text))) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_sensor_pairings'::regclass,'public.zasp_runtime_batch_domains'::regclass) OR conname IN('zasp_sensor_kind_identity_v45','zasp_runtime_batch_source_identity_v45')
) AS capture_original_0289
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:policy','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('relation_name',((tablename)::text),'name',((policyname)::text),'roles_text',((roles::text)::text),'command',((cmd)::text),'using',((qual)::text),'check',((with_check)::text))) FROM pg_policies WHERE schemaname='public' AND tablename IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains')
) AS capture_original_0290
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:trigger','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((tgname)::text),'enabled',((tgenabled)::text),'definition_pretty',((pg_get_triggerdef(oid,true))::text))) FROM pg_trigger WHERE tgname IN('zasp_runtime_sensor_pairings_immutable','zasp_runtime_batch_domains_immutable','zasp_runtime_batch_domain_insert') AND NOT tgisinternal
) AS capture_original_0291
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:queue_replay:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_claim_delivery','zasp_runtime_commit_reserved_batch','zasp_production_runtime_queue_replay_security_ready')
) AS capture_original_0292
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_evidence:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_session_event_get','zasp_production_runtime_session_evidence_readiness','zasp_production_runtime_session_evidence_security_ready')
) AS capture_original_0293
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_query:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_runtime_session_query_status','zasp_runtime_session_query_hydrate','zasp_production_runtime_session_query_readiness','zasp_production_runtime_session_query_security_ready')
) AS capture_original_0294
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_runtime_session_reads_readiness','zasp_production_runtime_session_reads_security_ready','zasp_runtime_session_maintain_summary','zasp_runtime_session_summary_json','zasp_runtime_session_read_authorized','zasp_runtime_session_page','zasp_runtime_session_get','zasp_runtime_session_event_page')
) AS capture_original_0295
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:table','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((relname)::text),'owner',((relowner::regrole::text)::text),'row_security',(relrowsecurity),'forced_row_security',(relforcerowsecurity),'acl_text_or_empty',((COALESCE(relacl::text,''))::text))) FROM pg_class WHERE oid='public.zasp_runtime_session_summaries'::regclass
) AS capture_original_0296
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:constraint','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((conname)::text),'definition',((pg_get_constraintdef(oid))::text),'validated',(convalidated))) FROM pg_constraint WHERE conrelid='public.zasp_runtime_session_summaries'::regclass
) AS capture_original_0297
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:column','identity',NULL,'handle','pg_attribute:'||attrelid::text||':'||attnum::text,'multiplicity',1,'fact',jsonb_build_object('name',((attname)::text),'type',((format_type(atttypid,atttypmod))::text),'not_null',(attnotnull))) FROM pg_attribute WHERE attrelid='public.zasp_runtime_session_summaries'::regclass AND attnum>0 AND NOT attisdropped
) AS capture_original_0298
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:policy','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('name',((policyname)::text),'roles_text',((roles::text)::text),'command',((cmd)::text),'using',((qual)::text),'check',((with_check)::text))) FROM pg_policies WHERE schemaname='public' AND tablename='zasp_runtime_session_summaries'
) AS capture_original_0299
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:index','identity',NULL,'handle',(SELECT 'pg_class:'||capture_class.oid::text||':0' FROM pg_class capture_class JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_class.relname=indexname AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('name',((indexname)::text),'definition',((indexdef)::text))) FROM pg_indexes WHERE schemaname='public' AND tablename='zasp_runtime_session_summaries'
) AS capture_original_0300
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:trigger','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((tgname)::text),'enabled',((tgenabled)::text),'definition',((pg_get_triggerdef(oid))::text))) FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_events'::regclass AND NOT tgisinternal
) AS capture_original_0301
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((procedure.proname)::text),'identity_arguments',((pg_get_function_identity_arguments(procedure.oid))::text),'owner',((owner.rolname)::text),'security_definer',(procedure.prosecdef),'config_text_or_empty',((COALESCE(procedure.proconfig::text,''))::text),'acl_text_or_empty',((COALESCE(procedure.proacl::text,''))::text),'definition',((pg_get_functiondef(procedure.oid))::text),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_runtime_session_search_%' OR procedure.proname IN('zasp_production_runtime_session_search_readiness','zasp_production_runtime_session_search_security_ready'))
) AS capture_original_0302
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:table','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((relname)::text),'owner',((relowner::regrole::text)::text),'row_security',(relrowsecurity),'forced_row_security',(relforcerowsecurity),'acl_text_or_empty',((COALESCE(relacl::text,''))::text))) FROM pg_class WHERE oid='public.zasp_runtime_session_search_outbox'::regclass
) AS capture_original_0303
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:constraint','identity',NULL,'handle','pg_constraint:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((conname)::text),'definition',((pg_get_constraintdef(oid))::text),'validated',(convalidated))) FROM pg_constraint WHERE conrelid='public.zasp_runtime_session_search_outbox'::regclass
) AS capture_original_0304
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:column','identity',NULL,'handle','pg_attribute:'||attribute_value.attrelid::text||':'||attribute_value.attnum::text,'multiplicity',1,'fact',jsonb_build_object('name',((attname)::text),'type',((format_type(atttypid,atttypmod))::text),'not_null',(attnotnull),'default_text_or_empty',((COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),''))::text))) FROM pg_attribute attribute_value LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute_value.attrelid AND default_value.adnum=attribute_value.attnum WHERE attribute_value.attrelid='public.zasp_runtime_session_search_outbox'::regclass AND attribute_value.attnum>0 AND NOT attribute_value.attisdropped
) AS capture_original_0305
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:policy','identity',NULL,'handle',(SELECT 'pg_policy:'||capture_policy.oid::text||':0' FROM pg_policy capture_policy JOIN pg_class capture_class ON capture_class.oid=capture_policy.polrelid JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_policy.polname=policyname AND capture_class.relname=tablename AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('name',((policyname)::text),'roles_text',((roles::text)::text),'command',((cmd)::text),'using',((qual)::text),'check',((with_check)::text))) FROM pg_policies WHERE schemaname='public' AND tablename='zasp_runtime_session_search_outbox'
) AS capture_original_0306
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:index','identity',NULL,'handle',(SELECT 'pg_class:'||capture_class.oid::text||':0' FROM pg_class capture_class JOIN pg_namespace capture_ns ON capture_ns.oid=capture_class.relnamespace WHERE capture_class.relname=indexname AND capture_ns.nspname=schemaname),'multiplicity',1,'fact',jsonb_build_object('name',((indexname)::text),'definition',((indexdef)::text))) FROM pg_indexes WHERE schemaname='public' AND tablename='zasp_runtime_session_search_outbox'
) AS capture_original_0307
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:trigger','identity',NULL,'handle','pg_trigger:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',((tgname)::text),'enabled',((tgenabled)::text),'definition',((pg_get_triggerdef(oid))::text))) FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_projection_receipts'::regclass AND NOT tgisinternal
) AS capture_original_0308
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:3','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('granted_role',(granted.rolname),'member_role',(member.rolname),'admin_option',(membership.admin_option)) AS fact FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_recovery_worker','zasp_recovery_outbox_worker') AND member.rolname='zasp_discovery_authority') captured GROUP BY fact
) AS capture_original_0309
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:3','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('granted_role',(granted.rolname),'member_role',(member.rolname),'admin_option',(membership.admin_option)) AS fact FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname='zasp_policy_deployment_worker' AND member.rolname='zasp_discovery_authority') captured GROUP BY fact
) AS capture_original_0310
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:runtime-profile','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('singleton',(singleton::boolean),'name',(name::text),'audit_mode',(audit_mode::text)) AS fact FROM zasp_authorization80.runtime_profile) captured GROUP BY fact
) AS capture_original_0311
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('singleton',(singleton::boolean),'before_state',(before_state::jsonb),'after_state',(after_state::jsonb),'workflow_state',(workflow_state::jsonb)) AS fact FROM public.zasp_audit_export_source_acl) captured GROUP BY fact
) AS capture_original_0312
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:principals','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('principal_name',(principal_name::text),'authority_role',(authority_role::text)) AS fact FROM zasp_temporal72.principals) captured GROUP BY fact
) AS capture_original_0313
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:retired-authorities','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('schema_name',(schema_name::text),'original_fingerprint',(original_fingerprint::text),'retired_fingerprint',(retired_fingerprint::text)) AS fact FROM zasp_temporal66.retired_authorities WHERE schema_name IN ('zasp_ordered_worker63','zasp_ordered_scheduler64')) captured GROUP BY fact
) AS capture_original_0314
UNION ALL
SELECT * FROM (
WITH selected AS(SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY[
 'zasp_integrations','zasp_integration_connections','zasp_discovery_connection_subjects','zasp_connector_credentials','zasp_discovery_syncs','zasp_discovery_outbox','zasp_discovery_outbox_topic_fairness','zasp_discovery_generation_reservations','zasp_discovery_jobs','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_execution_quotas','zasp_discovery_snapshots','zasp_discovery_cursors','zasp_inventory_entities','zasp_inventory_evidence','zasp_inventory_source_observations','zasp_inventory_relationships','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_projection_work','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items'])) SELECT jsonb_build_object('ruleId','worker:projected_domain:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'name',(t.tgname),'enabled',(t.tgenabled),'trigger_definition',(pg_get_triggerdef(t.oid)),'definition',(CASE WHEN p.oid='public.zasp_runtime_precision_outbox_guard()'::regprocedure THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=p.oid) ELSE pg_get_functiondef(p.oid) END),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')))) FROM selected c JOIN pg_trigger t ON t.tgrelid=c.oid JOIN pg_proc p ON p.oid=t.tgfoid WHERE NOT t.tgisinternal AND NOT(
 (t.tgrelid IN('public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_gateway','zasp_authorization80_worker_ordered_no_truncate'))
 OR(t.tgrelid IN('public.zasp_workflow_records'::regclass,'public.zasp_security_agent_temporary_policy_targets'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_policy','zasp_authorization80_worker_ordered_policy_no_truncate')))
 AND NOT(t.tgrelid IN('public.zasp_inventory_entities'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_source_observations'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_target','zasp_authorization80_worker_ordered_no_truncate')) AND NOT(t.tgname IN('zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate') AND t.tgrelid IN('public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_connection_subjects'::regclass,'public.zasp_connector_credentials'::regclass) OR t.tgname='zasp_authorization80_worker_discovery_admission' AND t.tgrelid='public.zasp_workflow_idempotency'::regclass) AND NOT(t.tgname IN('zasp_authorization80_worker_target_capture','zasp_authorization80_worker_target_no_truncate') AND t.tgrelid IN('public.zasp_inventory_entities'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_source_observations'::regclass)) AND NOT(t.tgname='zasp_authorization79_capture' AND t.tgrelid IN('public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_syncs'::regclass,'public.zasp_inventory_entities'::regclass))
) AS capture_original_0315
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'acl',(p.proacl::text),'definition',(CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_temporal'::regnamespace OR p.oid IN('zasp_temporal72.fingerprint()'::regprocedure,'zasp_temporal72.domain_catalog()'::regprocedure,'zasp_temporal68.ready(text,text)'::regprocedure,'zasp_temporal68.fingerprint()'::regprocedure,'zasp_authorization79.capture()'::regprocedure)
) AS capture_original_0316
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('zasp_ordered_public62.api(text,text,jsonb)'::regprocedure,'zasp_ordered_public62.mutate(text,text,jsonb)'::regprocedure,'zasp_ordered_public62.fingerprint()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE p.pronamespace='zasp_ordered_public62'::regnamespace
) AS capture_original_0317
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('zasp_temporal68.ready(text,text)'::regprocedure,'zasp_temporal68.fingerprint()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_temporal.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal68'::regnamespace
) AS capture_original_0318
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(CASE WHEN p.oid IN('zasp_temporal69.inspect(jsonb)'::regprocedure,'zasp_temporal69.inspect_message(jsonb)'::regprocedure,'zasp_temporal69.stop(jsonb)'::regprocedure) THEN(SELECT s.acl FROM zasp_authorization80_worker.predecessor_functions s WHERE to_regprocedure(s.signature)=p.oid) ELSE COALESCE(p.proacl::text,'') END),'definition',(CASE WHEN p.oid='zasp_temporal69.fingerprint()'::regprocedure THEN(SELECT s.definition FROM zasp_authorization80_worker.predecessor_functions s WHERE to_regprocedure(s.signature)=p.oid) ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal69'::regnamespace
) AS capture_original_0319
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid='zasp_temporal72.fingerprint()'::regprocedure THEN(SELECT definition FROM zasp_authorization80_temporal.predecessor_functions WHERE signature='zasp_temporal72.fingerprint()') ELSE CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal72'::regnamespace
) AS capture_original_0320
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:precision-handoff','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid='zasp_temporal72.fingerprint()'::regprocedure THEN(SELECT definition FROM zasp_authorization80_temporal.predecessor_functions WHERE signature='zasp_temporal72.fingerprint()') ELSE CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END END))) FROM pg_proc p WHERE p.oid='public.zasp_production_runtime_precision_live_fingerprint()'::regprocedure
) AS capture_original_0321
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:bulk-handoff','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid='zasp_temporal72.fingerprint()'::regprocedure THEN(SELECT definition FROM zasp_authorization80_temporal.predecessor_functions WHERE signature='zasp_temporal72.fingerprint()') ELSE CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END END))) FROM pg_proc p WHERE p.oid IN('public.zasp_execution_claim_jobs(text,text,integer,integer)'::regprocedure,'public.zasp_execution_live_fingerprint()'::regprocedure,'public.zasp_discovery_schedule_replay_function_identity(oid)'::regprocedure)
) AS capture_original_0322
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal78'::regnamespace
) AS capture_original_0323
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:effective-predecessor','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%' OR signature LIKE 'zasp_temporal73.%' OR signature IN('zasp_temporal74.visible(text,text,text,text)','zasp_temporal76.executor74_fingerprint()','zasp_temporal76.fingerprint()'))
) AS capture_original_0324
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'owner',(p.proowner::regrole::text),'acl',(p.proacl::text),'definition',(CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE pronamespace='zasp_authorization79'::regnamespace
) AS capture_original_0325
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:view','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(c.relname),'definition',(CASE WHEN c.oid IN(SELECT signature::regclass FROM zasp_authorization80_worker.predecessor_views) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_views WHERE signature=c.oid::regclass::text) ELSE pg_get_viewdef(c.oid) END))) FROM pg_class c WHERE relnamespace='zasp_authorization79'::regnamespace AND relkind='v'
) AS capture_original_0326
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:6','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(procedure.proname),'identity_arguments',(pg_get_function_identity_arguments(procedure.oid)),'owner',(owner.rolname),'security_definer',(procedure.prosecdef),'config_text_or_empty',(COALESCE(procedure.proconfig::text,'')),'acl',(COALESCE(procedure.proacl::text,'')),'definition',(CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=procedure.oid::regprocedure::text) ELSE (CASE WHEN procedure.oid IN(
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'zasp_sa_multistep_prior.application(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'zasp_sa_multistep_prior.application_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'zasp_sa_multistep_prior.cleanup(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_security_agent_claim_session_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_security_agent_store_session_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_security_agent_temporary_policy_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'public.zasp_policy_deployment_execution_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid='public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamp with time zone)'::regprocedure THEN false ELSE true END THEN 'zasp_temporal77.base67_fingerprint()' ELSE NULL END)::regprocedure)
 THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=procedure.oid::regprocedure::text)
 ELSE pg_get_functiondef(procedure.oid) END) END),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname=ANY(ARRAY['zasp_runtime_gateway_record_event','zasp_runtime_gateway_record_event_v23_restore','zasp_security_agent_execution_control_detail','zasp_security_agent_execution_control_detail_v23_restore','zasp_security_agent_mutate_execution_control','zasp_security_agent_mutate_execution_control_v23_restore','zasp_security_agent_schedule_session_isolation_triggers','zasp_security_agent_schedule_triggers_v24','zasp_security_agent_run_v24','zasp_security_agent_prepare_session_isolation_run','zasp_security_agent_prepare_run_v24','zasp_security_agent_dispatch_session_isolation_run','zasp_security_agent_execute_run_v24','zasp_security_agent_claim_session_policy_effects','zasp_security_agent_heartbeat_session_policy_effect','zasp_security_agent_store_session_policy_target','zasp_security_agent_read_session_policy_target','zasp_security_agent_finish_session_policy_effect','zasp_security_agent_approval_value_v24','zasp_security_agent_run_detail_v24','zasp_security_agent_approval_page_v24','zasp_security_agent_approval_detail_v24','zasp_security_agent_decide_approval_v24','zasp_security_agent_session_isolation_security_ready','zasp_workflow_mutate','zasp_risk_mutate'])
) AS capture_original_0327
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:13','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(procedure.proname),'identity_arguments',(pg_get_function_identity_arguments(procedure.oid)),'owner',(owner.rolname),'security_definer',(procedure.prosecdef),'config_text_or_empty',(COALESCE(procedure.proconfig::text,'')),'acl',(COALESCE(procedure.proacl::text,'')),'definition',(CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=procedure.oid::regprocedure::text) ELSE (CASE WHEN procedure.oid IN(
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'zasp_sa_multistep_prior.application(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'zasp_sa_multistep_prior.application_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'zasp_sa_multistep_prior.cleanup(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_security_agent_claim_session_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_security_agent_store_session_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_security_agent_temporary_policy_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'public.zasp_policy_deployment_execution_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN('public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone)'::regprocedure,'public.zasp_recovery_execution_live_fingerprint()'::regprocedure) THEN false ELSE true END THEN 'zasp_temporal77.base67_fingerprint()' ELSE NULL END)::regprocedure)
 THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=procedure.oid::regprocedure::text)
 ELSE pg_get_functiondef(procedure.oid) END) END),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_recovery_%' OR procedure.proname IN('zasp_policy_id_array_valid','zasp_runtime_gateway_record_event_v27','zasp_policy_list_runtime_decisions'))
) AS capture_original_0328
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:10','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(procedure.proname),'identity_arguments',(pg_get_function_identity_arguments(procedure.oid)),'owner',(owner.rolname),'security_definer',(procedure.prosecdef),'config_text_or_empty',(COALESCE(procedure.proconfig::text,'')),'acl',(COALESCE(procedure.proacl::text,'')),'definition',(CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure)
 THEN (CASE WHEN procedure.oid IN(
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'zasp_sa_multistep_prior.application(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'zasp_sa_multistep_prior.application_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'zasp_sa_multistep_prior.cleanup(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_security_agent_claim_session_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_security_agent_store_session_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_security_agent_temporary_policy_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'public.zasp_policy_deployment_execution_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN procedure.oid IN(
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)'::regprocedure,
 'public.zasp_policy_deployment_execution_live_fingerprint()'::regprocedure) THEN true ELSE false END THEN 'zasp_temporal77.base67_fingerprint()' ELSE NULL END)::regprocedure)
 THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=procedure.oid::regprocedure::text)
 ELSE pg_get_functiondef(procedure.oid) END) ELSE pg_get_functiondef(procedure.oid) END),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_policy_deployment_%' OR procedure.proname IN('zasp_security_agent_store_temporary_policy_target','zasp_security_agent_store_session_policy_target','zasp_security_agent_expire_approvals_v28'))
) AS capture_original_0329
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:2','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(procedure.proname),'identity_arguments',(pg_get_function_identity_arguments(procedure.oid)),'owner',(owner.rolname),'security_definer',(procedure.prosecdef),'config_text_or_empty',(COALESCE(procedure.proconfig::text,'')),'acl',(COALESCE(procedure.proacl::text,'')),'definition',(CASE WHEN procedure.oid='public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=procedure.oid) ELSE pg_get_functiondef(procedure.oid) END),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,dimension),array_upper(procedure.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(procedure.proconfig)) dimension)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace JOIN pg_roles owner ON owner.oid=procedure.proowner WHERE namespace.nspname='public' AND procedure.proname IN('zasp_production_runtime_sessions_readiness','zasp_production_runtime_sessions_security_ready','zasp_runtime_finish_stage','zasp_runtime_finish_stage_v39','zasp_runtime_finish_session_projection')
) AS capture_original_0330
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:1','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(r.rolname),'security_definer',(p.prosecdef),'config_text_or_empty',(COALESCE(p.proconfig::text,'')),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('public.zasp_runtime_legacy_search_insert_guard()'::regprocedure,'public.zasp_runtime_sandbox_search_mutation_guard()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=p.oid) ELSE pg_get_functiondef(p.oid) END),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid IN('public.zasp_runtime_sandbox_search_enqueue()'::regprocedure,'public.zasp_runtime_legacy_search_insert_guard()'::regprocedure,'public.zasp_production_runtime_sandbox_search_security_ready()'::regprocedure,'public.zasp_production_runtime_sandbox_search_live_fingerprint()'::regprocedure)
) AS capture_original_0331
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:2','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(r.rolname),'security_definer',(p.prosecdef),'config_text_or_empty',(COALESCE(p.proconfig::text,'')),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('public.zasp_runtime_legacy_search_insert_guard()'::regprocedure,'public.zasp_runtime_sandbox_search_mutation_guard()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=p.oid) ELSE pg_get_functiondef(p.oid) END),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid IN('public.zasp_runtime_sandbox_query_status(text,text,text,text)'::regprocedure,'public.zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[])'::regprocedure)
) AS capture_original_0332
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:3','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(r.rolname),'security_definer',(p.prosecdef),'config_text_or_empty',(COALESCE(p.proconfig::text,'')),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('public.zasp_runtime_legacy_search_insert_guard()'::regprocedure,'public.zasp_runtime_sandbox_search_mutation_guard()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=p.oid) ELSE pg_get_functiondef(p.oid) END),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_sandbox_search_worker_ready','zasp_runtime_sandbox_search_mutation_guard','zasp_runtime_sandbox_search_claim','zasp_runtime_sandbox_search_heartbeat','zasp_runtime_sandbox_search_finish')
) AS capture_original_0333
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(pg_get_functiondef(p.oid)))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal70'::regnamespace
) AS capture_original_0334
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(pg_get_functiondef(p.oid)))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal71'::regnamespace
) AS capture_original_0335
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('zasp_temporal65.capture()'::regprocedure,'zasp_temporal65.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal74.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal65'::regnamespace
) AS capture_original_0336
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(CASE WHEN p.oid='zasp_temporal66.legacy_visible(text,text,text,text)'::regprocedure THEN (SELECT acl FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal66.legacy_visible(text,text,text,text)') ELSE COALESCE(p.proacl::text,'') END),'definition',(CASE WHEN p.oid='zasp_temporal66.fingerprint()'::regprocedure THEN (SELECT definition FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal66.fingerprint()') ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal66'::regnamespace
) AS capture_original_0337
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(pg_get_functiondef(p.oid)))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal75'::regnamespace
) AS capture_original_0338
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('zasp_temporal67.base_fingerprint()'::regprocedure,'zasp_temporal67.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal77.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal67'::regnamespace
) AS capture_original_0339
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('zasp_temporal73.unresolved(text,text,text,text)'::regprocedure,'zasp_temporal73.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal78.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal73'::regnamespace
) AS capture_original_0340
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('zasp_temporal76.executor74_fingerprint()'::regprocedure,'zasp_temporal76.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal78.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE CASE WHEN p.oid IN('zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.load_plan(jsonb)'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal76'::regnamespace
) AS capture_original_0341
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:executor-function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN('zasp_temporal76.executor74_fingerprint()'::regprocedure,'zasp_temporal76.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal78.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE CASE WHEN p.oid IN('zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.load_plan(jsonb)'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END END))) FROM pg_proc p WHERE p.oid IN('zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.fingerprint()'::regprocedure)
) AS capture_original_0342
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname),'name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'volatility',(p.provolatile),'parallel',(p.proparallel),'strict',(p.proisstrict),'leakproof',(p.proleakproof),'config_text_or_empty',(COALESCE(p.proconfig::text,'')),'acl',(COALESCE(p.proacl::text,'')),'definition',(pg_get_functiondef(p.oid)),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_sa_attack_lab_prior' OR n.nspname='public' AND starts_with(p.proname,'zasp_sa_attack_lab_')
) AS capture_original_0343
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname),'name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'volatility',(p.provolatile),'parallel',(p.proparallel),'strict',(p.proisstrict),'leakproof',(p.proleakproof),'config_text_or_empty',(COALESCE(p.proconfig::text,'')),'acl',(COALESCE(p.proacl::text,'')),'definition',(pg_get_functiondef(p.oid)),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_sa_export_prior' OR n.nspname='public' AND (starts_with(p.proname,'zasp_sa_export_') OR starts_with(p.proname,'zasp_sa_manual_'))
) AS capture_original_0344
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'volatility',(p.provolatile),'parallel',(p.proparallel),'strict',(p.proisstrict),'leakproof',(p.proleakproof),'config_text_or_empty',(COALESCE(p.proconfig::text,'')),'acl',(COALESCE(p.proacl::text,'')),'definition',(pg_get_functiondef(p.oid)),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND starts_with(p.proname,'zasp_sa_multistep_')
) AS capture_original_0345
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname),'name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'volatility',(p.provolatile),'parallel',(p.proparallel),'strict',(p.proisstrict),'leakproof',(p.proleakproof),'config_text_or_empty',(COALESCE(p.proconfig::text,'')),'acl',(COALESCE(p.proacl::text,'')),'definition',(pg_get_functiondef(p.oid)),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_sa_webhook_prior' OR n.nspname='public' AND (starts_with(p.proname,'zasp_sa_webhook_') OR p.proname LIKE '%security_agent_webhook%')
) AS capture_original_0346
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN (SELECT definition FROM zasp_temporal78.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN (CASE WHEN p.oid IN(
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'zasp_sa_multistep_prior.application(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'zasp_sa_multistep_prior.application_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'zasp_sa_multistep_prior.cleanup(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_claim_session_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_store_session_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_temporary_policy_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_policy_deployment_execution_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'zasp_temporal77.base67_fingerprint()' ELSE NULL END)::regprocedure)
 THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text)
 ELSE pg_get_functiondef(p.oid) END) ELSE pg_get_functiondef(p.oid) END END END))) FROM pg_proc p WHERE p.pronamespace='zasp_temporal77'::regnamespace
) AS capture_original_0347
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:effective-policy-boundary','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN (SELECT definition FROM zasp_temporal78.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN (CASE WHEN p.oid IN(
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'zasp_sa_multistep_prior.application(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'zasp_sa_multistep_prior.application_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'zasp_sa_multistep_prior.cleanup(text,text,jsonb)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_claim_session_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_finish_session_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_store_session_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_store_session_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_security_agent_temporary_policy_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'public.zasp_policy_deployment_execution_live_fingerprint()' ELSE NULL END)::regprocedure,
 (CASE WHEN CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN false ELSE CASE WHEN p.oid='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure THEN false ELSE CASE WHEN p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure THEN true ELSE false END END END THEN 'zasp_temporal77.base67_fingerprint()' ELSE NULL END)::regprocedure)
 THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text)
 ELSE pg_get_functiondef(p.oid) END) ELSE pg_get_functiondef(p.oid) END END END))) FROM pg_proc p WHERE p.oid IN('zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'::regprocedure,'zasp_temporal67.base_fingerprint()'::regprocedure,'zasp_temporal67.fingerprint()'::regprocedure)
) AS capture_original_0348
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname),'name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'volatility',(p.provolatile),'parallel',(p.proparallel),'strict',(p.proisstrict),'leakproof',(p.proleakproof),'config_text_or_empty',(COALESCE(p.proconfig::text,'')),'acl',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid IN((CASE WHEN p.oid IS NOT NULL THEN 'public.zasp_execution_live_fingerprint()' ELSE NULL END)::regprocedure,(CASE WHEN p.oid IS NOT NULL THEN 'public.zasp_discovery_schedule_replay_function_identity(oid)' ELSE NULL END)::regprocedure) THEN NULL ELSE pg_get_functiondef(p.oid) END),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_schedule_replay_prior' OR p.oid IN(SELECT signature::regprocedure FROM zasp_schedule_replay_prior.functions) OR n.nspname='public' AND starts_with(p.proname,'zasp_discovery_schedule_replay_')
) AS capture_original_0349
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_authorization80_runtime.predecessor_functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl::text)) AS fact FROM zasp_authorization80_runtime.predecessor_functions) captured GROUP BY fact
) AS capture_original_0350
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_authorization80_worker.predecessor_functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl::text)) AS fact FROM zasp_authorization80_worker.predecessor_functions) captured GROUP BY fact
) AS capture_original_0351
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_authorization80_temporal.predecessor_functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl::text)) AS fact FROM zasp_authorization80_temporal.predecessor_functions) captured GROUP BY fact
) AS capture_original_0352
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_temporal72.predecessor_functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl::text)) AS fact FROM zasp_temporal72.predecessor_functions) captured GROUP BY fact
) AS capture_original_0353
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_temporal78.predecessor_functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl::text)) AS fact FROM zasp_temporal78.predecessor_functions) captured GROUP BY fact
) AS capture_original_0354
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_authorization80_worker.predecessor_views','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text)) AS fact FROM zasp_authorization80_worker.predecessor_views) captured GROUP BY fact
) AS capture_original_0355
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_temporal74.predecessor_functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl::text)) AS fact FROM zasp_temporal74.predecessor_functions) captured GROUP BY fact
) AS capture_original_0356
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_temporal77.predecessor_functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl::text)) AS fact FROM zasp_temporal77.predecessor_functions) captured GROUP BY fact
) AS capture_original_0357
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_schedule_replay_prior.functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl::text)) AS fact FROM zasp_schedule_replay_prior.functions) captured GROUP BY fact
) AS capture_original_0358
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','ready78:saved-current:bindings','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(s.signature::text),'present',(p.oid IS NOT NULL),'resolvedIdentity',(p.oid::regprocedure::text),'definition',(CASE WHEN s.signature NOT IN('zasp_production_runtime_precision_live_fingerprint()','zasp_execution_claim_jobs(text,text,integer,integer)','zasp_execution_live_fingerprint()','zasp_discovery_schedule_replay_function_identity(oid)') THEN pg_get_functiondef(p.oid) ELSE NULL END),'owner',(p.proowner::regrole::text),'acl',(COALESCE(p.proacl::text,''))) AS fact FROM zasp_temporal72.predecessor_functions s LEFT JOIN pg_proc p ON p.oid=to_regprocedure(s.signature)) captured GROUP BY fact
) AS capture_original_0359
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','ready78:saved-current:routines','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(p.proowner::regrole::text),'acl_raw',(p.proacl::text))) FROM pg_proc p WHERE p.oid IN(SELECT to_regprocedure(signature) FROM zasp_temporal72.predecessor_functions)
) AS capture_original_0360
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:4','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(nspowner::regrole::text),'acl',(nspacl::text))) FROM pg_namespace WHERE nspname='zasp_authorization80_worker'
) AS capture_original_0361
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:5','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'acl',(p.proacl::text),'definition',(pg_get_functiondef(p.oid)))) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_worker'::regnamespace OR p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions)
) AS capture_original_0362
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:6','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(c.relname),'kind',(c.relkind),'owner',(c.relowner::regrole::text),'acl',(c.relacl::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace
) AS capture_original_0363
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:7','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'position',(a.attnum),'name',(a.attname),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'acl',(a.attacl::text),'default',(pg_get_expr(d.adbin,d.adrelid)))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0364
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:8','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'name',(k.conname),'definition',(pg_get_constraintdef(k.oid)),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace
) AS capture_original_0365
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:9','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(p.polrelid::regclass::text),'name',(p.polname),'permissive',(p.polpermissive),'command',(p.polcmd),'roles',(p.polroles::regrole[]::text),'using',(pg_get_expr(p.polqual,p.polrelid)),'check',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace
) AS capture_original_0366
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:10','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_authorization80_worker'::regnamespace
) AS capture_original_0367
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:11','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature),'definition',(definition),'owner_name',(owner_name),'acl',(acl)) AS fact FROM zasp_authorization80_worker.predecessor_functions) captured GROUP BY fact
) AS capture_original_0368
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:12','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature),'definition',(definition)) AS fact FROM zasp_authorization80_worker.predecessor_views) captured GROUP BY fact
) AS capture_original_0369
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:15','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(nspname),'owner',(nspowner::regrole::text),'acl',(nspacl::text))) FROM pg_namespace WHERE nspname='zasp_authorization80_runtime'
) AS capture_original_0370
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:16','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'acl',(p.proacl::text),'definition',(pg_get_functiondef(p.oid)))) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_runtime'::regnamespace OR p.oid IN(SELECT to_regprocedure(signature) FROM zasp_authorization80_runtime.predecessor_functions WHERE signature LIKE '%guard()') OR p.oid='public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure
) AS capture_original_0371
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:17','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(c.relname),'kind',(c.relkind),'owner',(c.relowner::regrole::text),'acl',(c.relacl::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
) AS capture_original_0372
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:18','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'position',(a.attnum),'name',(a.attname),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'acl',(a.attacl::text),'default',(pg_get_expr(d.adbin,d.adrelid)))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0373
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:19','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'name',(k.conname),'definition',(pg_get_constraintdef(k.oid)),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
) AS capture_original_0374
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:20','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'definition',(pg_get_indexdef(i.indexrelid)),'valid',(i.indisvalid),'ready',(i.indisready),'live',(i.indislive))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
) AS capture_original_0375
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:21','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(p.polrelid::regclass::text),'name',(p.polname),'permissive',(p.polpermissive),'command',(p.polcmd),'roles',(p.polroles::regrole[]::text),'using',(pg_get_expr(p.polqual,p.polrelid)),'check',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_runtime'::regnamespace
) AS capture_original_0376
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:22','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND(c.relnamespace='zasp_authorization80_runtime'::regnamespace OR t.tgfoid IN(SELECT to_regprocedure(signature) FROM zasp_authorization80_runtime.predecessor_functions WHERE signature LIKE '%guard()'))
) AS capture_original_0377
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:23','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)),'function_definition',(pg_get_functiondef(p.oid)),'function_owner',(p.proowner::regrole::text),'function_acl',(p.proacl::text))) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_authorization80_runtime_stage_insert'
) AS capture_original_0378
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:24','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_identity',(c.oid::regclass::text),'kind',(c.relkind),'owner',(c.relowner::regrole::text),'acl',(c.relacl::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE c.oid='public.zasp_runtime_stage_work'::regclass
) AS capture_original_0379
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:25','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('position',(a.attnum),'name',(a.attname),'acl',(a.attacl::text))) FROM pg_attribute a WHERE a.attrelid='public.zasp_runtime_stage_work'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0380
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:26','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.polname),'permissive',(p.polpermissive),'command',(p.polcmd),'roles',(p.polroles::regrole[]::text),'using',(pg_get_expr(p.polqual,p.polrelid)),'check',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p WHERE p.polrelid='public.zasp_runtime_stage_work'::regclass
) AS capture_original_0381
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:27','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature),'definition',(definition),'owner_name',(owner_name),'acl',(acl)) AS fact FROM zasp_authorization80_runtime.predecessor_functions) captured GROUP BY fact
) AS capture_original_0382
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:32','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)),'function_definition',(pg_get_functiondef(p.oid)),'function_owner',(p.proowner::regrole::text),'function_acl',(p.proacl::text))) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_authorization80_runtime_stage_insert'
) AS capture_original_0383
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:33','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)),'function_definition',(pg_get_functiondef(p.oid)),'function_owner',(p.proowner::regrole::text),'function_acl',(p.proacl::text))) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN('public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass,'public.zasp_runtime_session_summaries'::regclass,'public.zasp_runtime_gateway_events'::regclass,'zasp_temporal77.runtime_evaluations'::regclass,'zasp_temporal77.source_events'::regclass) AND t.tgname IN('zasp_authorization80_worker_runtime_capture','zasp_authorization80_worker_runtime_no_truncate')
) AS capture_original_0384
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:34','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'acl',(c.relacl::text),'definition',(pg_get_viewdef(c.oid)))) FROM pg_class c WHERE c.oid IN(SELECT signature::regclass FROM zasp_authorization80_worker.predecessor_views)
) AS capture_original_0385
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:35','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_identity',(c.oid::regclass::text),'definition',(pg_get_viewdef(c.oid)))) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace AND c.relkind='v'
) AS capture_original_0386
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:36','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)))) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname IN('zasp_authorization80_worker_run_capture','zasp_authorization80_worker_no_truncate')
) AS capture_original_0387
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:37','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)))) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_risk_findings'::regclass,'public.zasp_security_agent_definitions'::regclass) AND t.tgname='zasp_authorization80_worker_source_capture'
) AS capture_original_0388
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:38','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)),'function_definition',(pg_get_functiondef(p.oid)),'function_owner',(p.proowner::regrole::text),'function_acl',(p.proacl::text))) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN('public.zasp_red_team_definitions'::regclass,'public.zasp_inventory_entities'::regclass,'public.zasp_inventory_source_observations'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_attack_lab_credential_bindings'::regclass) AND t.tgname IN('zasp_authorization80_worker_target_capture','zasp_authorization80_worker_target_no_truncate')
) AS capture_original_0389
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:39','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)),'function_definition',(pg_get_functiondef(p.oid)),'function_owner',(p.proowner::regrole::text),'function_acl',(p.proacl::text))) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE (t.tgrelid IN('zasp_temporal72.runs'::regclass,'zasp_temporal72.schedules'::regclass,'public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_connection_subjects'::regclass,'public.zasp_connector_credentials'::regclass) AND t.tgname IN('zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate')) OR (t.tgrelid='public.zasp_workflow_idempotency'::regclass AND t.tgname='zasp_authorization80_worker_discovery_admission')
) AS capture_original_0390
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:40','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)),'function_definition',(pg_get_functiondef(p.oid)),'function_owner',(p.proowner::regrole::text),'function_acl',(p.proacl::text))) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE(t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_authorization80_worker_ordered_run') OR(t.tgrelid IN('public.zasp_red_team_definitions'::regclass,'public.zasp_inventory_entities'::regclass,'public.zasp_attack_lab_credential_bindings'::regclass,'public.zasp_risk_findings'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_source_observations'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_target','zasp_authorization80_worker_ordered_no_truncate'))
) AS capture_original_0391
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:41','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('projected_relation',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)),'function_definition',(pg_get_functiondef(p.oid)),'function_owner',(p.proowner::regrole::text),'function_acl',(p.proacl::text))) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE(t.tgrelid IN('public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_gateway','zasp_authorization80_worker_ordered_no_truncate')) OR(t.tgrelid IN('public.zasp_workflow_records'::regclass,'public.zasp_security_agent_temporary_policy_targets'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_policy','zasp_authorization80_worker_ordered_policy_no_truncate')) OR(t.tgrelid='zasp_temporal68.deliveries'::regclass AND t.tgname IN('ordered_policy_capture','ordered_policy_no_truncate'))
) AS capture_original_0392
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:schema','identity',NULL,'handle','pg_namespace:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(nspowner::regrole::text),'acl',(nspacl::text))) FROM pg_namespace WHERE nspname='zasp_authorization80'
) AS capture_original_0393
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('singleton',(singleton),'name',(name),'audit_mode',(audit_mode),'identity_mode',(identity_mode)) AS fact FROM zasp_authorization80.runtime_profile) captured GROUP BY fact
) AS capture_original_0394
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)))) FROM pg_trigger t WHERE t.tgrelid='zasp_authorization80.runtime_profile'::regclass AND NOT t.tgisinternal
) AS capture_original_0395
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile-column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('name',(a.attname),'type_identity',(a.atttypid::regtype::text),'typmod',(a.atttypmod),'not_null',(a.attnotnull),'acl',(a.attacl::text),'default',(pg_get_expr(d.adbin,d.adrelid)))) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_authorization80.runtime_profile'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0396
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile-column:types','identity',NULL,'handle','pg_type:'||type_row.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('identity',(type_row.oid::regtype::text))) FROM pg_type type_row WHERE type_row.oid IN(SELECT a.atttypid FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_authorization80.runtime_profile'::regclass AND a.attnum>0 AND NOT a.attisdropped)
) AS capture_original_0397
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'owner',(p.proowner::regrole::text),'acl',(p.proacl::text),'definition',(pg_get_functiondef(p.oid)))) FROM pg_proc p WHERE pronamespace='zasp_authorization80'::regnamespace
) AS capture_original_0398
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:home-source-function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname),'owner',(p.proowner::regrole::text),'acl',(p.proacl::text),'definition',(pg_get_functiondef(p.oid)))) FROM pg_proc p WHERE oid IN('public.zasp_inventory_home_summary(text,text,text)'::regprocedure,'public.zasp_inventory_home_summary_v29(text,text,text)'::regprocedure,'public.zasp_inventory_scope_state(text,text,text)'::regprocedure)
) AS capture_original_0399
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:relation','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(c.relname),'kind',(c.relkind),'owner',(c.relowner::regrole::text),'acl',(c.relacl::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE relnamespace='zasp_authorization80'::regnamespace
) AS capture_original_0400
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'name',(k.conname),'definition',(pg_get_constraintdef(k.oid)))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80'::regnamespace
) AS capture_original_0401
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'name',(p.polname),'roles',(p.polroles::regrole[]::text),'using',(pg_get_expr(p.polqual,p.polrelid)),'check',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80'::regnamespace
) AS capture_original_0402
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:risk-relation','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(c.relname),'owner',(c.relowner::regrole::text),'acl',(c.relacl::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE c.oid=ANY(ARRAY['public.zasp_risk_findings'::regclass,'public.zasp_risk_finding_evidence'::regclass,'public.zasp_risk_finding_factors'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_risk_attack_path_nodes'::regclass,'public.zasp_risk_attack_path_evidence'::regclass,'public.zasp_risk_break_options'::regclass])
) AS capture_original_0403
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:risk-policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'name',(p.polname),'permissive',(p.polpermissive),'command',(p.polcmd),'roles',(p.polroles::regrole[]::text),'using',(pg_get_expr(p.polqual,p.polrelid)),'check',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.oid=ANY(ARRAY['public.zasp_risk_findings'::regclass,'public.zasp_risk_finding_evidence'::regclass,'public.zasp_risk_finding_factors'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_risk_attack_path_nodes'::regclass,'public.zasp_risk_attack_path_evidence'::regclass,'public.zasp_risk_break_options'::regclass])
) AS capture_original_0404
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-relation','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(c.relname),'owner',(c.relowner::regrole::text),'acl',(c.relacl::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE c.oid='public.zasp_data_controls'::regclass
) AS capture_original_0405
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(p.polname),'permissive',(p.polpermissive),'command',(p.polcmd),'roles',(p.polroles::regrole[]::text),'using',(pg_get_expr(p.polqual,p.polrelid)),'check',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p WHERE p.polrelid='public.zasp_data_controls'::regclass
) AS capture_original_0406
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('name',(a.attname),'type_identity',(a.atttypid::regtype::text),'typmod',(a.atttypmod),'not_null',(a.attnotnull),'acl',(a.attacl::text),'identity',(a.attidentity),'generated',(a.attgenerated),'default',(pg_get_expr(d.adbin,d.adrelid)))) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='public.zasp_data_controls'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0407
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-column:types','identity',NULL,'handle','pg_type:'||type_row.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('identity',(type_row.oid::regtype::text))) FROM pg_type type_row WHERE type_row.oid IN(SELECT a.atttypid FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='public.zasp_data_controls'::regclass AND a.attnum>0 AND NOT a.attisdropped)
) AS capture_original_0408
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-constraint','identity',NULL,'handle','pg_constraint:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(c.conname),'definition',(pg_get_constraintdef(c.oid)))) FROM pg_constraint c WHERE c.conrelid='public.zasp_data_controls'::regclass
) AS capture_original_0409
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-relation','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(c.relname),'kind',(c.relkind),'owner',(c.relowner::regrole::text),'acl',(c.relacl::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE c.oid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
) AS capture_original_0410
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(t.tgrelid::regclass::text),'name',(t.tgname),'enabled',(t.tgenabled),'event_bits',(t.tgtype),'internal',(t.tgisinternal),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'constraint_present',(t.tgconstraint<>0),'constraint_identity',(CASE WHEN t.tgconstraint<>0 THEN (SELECT jsonb_build_array(k.connamespace::regnamespace::text,CASE WHEN k.conrelid<>0 THEN k.conrelid::regclass::text ELSE NULL END,CASE WHEN k.contypid<>0 THEN k.contypid::regtype::text ELSE NULL END,k.conname)::text FROM pg_constraint k WHERE k.oid=t.tgconstraint) ELSE NULL END),'constraint_relation_present',(t.tgconstrrelid<>0),'constraint_relation_identity',(CASE WHEN t.tgconstrrelid<>0 THEN (SELECT c.oid::regclass::text FROM pg_class c WHERE c.oid=t.tgconstrrelid) ELSE NULL END),'constraint_index_present',(t.tgconstrindid<>0),'constraint_index_identity',(CASE WHEN t.tgconstrindid<>0 THEN (SELECT c.oid::regclass::text FROM pg_class c WHERE c.oid=t.tgconstrindid) ELSE NULL END),'argument_count',(t.tgnargs),'columns',(t.tgattr),'qual',(CASE WHEN t.tgqual IS NULL THEN NULL::text ELSE (t.tgqual IS NULL)::text::integer::text END),'old_table',(t.tgoldtable),'new_table',(t.tgnewtable),'routine_identity',(t.tgfoid::regprocedure::text),'arguments',(encode(t.tgargs,'hex')),'definition',(pg_get_triggerdef(t.oid)))) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass) AND NOT t.tgisinternal
) AS capture_original_0411
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_identity',(a.attrelid::regclass::text),'name',(a.attname),'type_identity',(a.atttypid::regtype::text),'typmod',(a.atttypmod),'not_null',(a.attnotnull),'acl',(a.attacl::text),'identity',(a.attidentity),'generated',(a.attgenerated),'default',(pg_get_expr(d.adbin,d.adrelid)))) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0412
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-column:types','identity',NULL,'handle','pg_type:'||type_row.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('identity',(type_row.oid::regtype::text))) FROM pg_type type_row WHERE type_row.oid IN(SELECT a.atttypid FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass) AND a.attnum>0 AND NOT a.attisdropped)
) AS capture_original_0413
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-constraint','identity',NULL,'handle','pg_constraint:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(c.conrelid::regclass::text),'name',(c.conname),'definition',(pg_get_constraintdef(c.oid)))) FROM pg_constraint c WHERE c.conrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
) AS capture_original_0414
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(p.polrelid::regclass::text),'name',(p.polname),'permissive',(p.polpermissive),'command',(p.polcmd),'roles',(p.polroles::regrole[]::text),'using',(pg_get_expr(p.polqual,p.polrelid)),'check',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p WHERE p.polrelid IN('public.zasp_workspaces'::regclass,'public.zasp_environments'::regclass,'public.zasp_authorized_scopes'::regclass,'public.zasp_core_payloads'::regclass)
) AS capture_original_0415
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization-temporal:triggers-ready:triggers','identity',NULL,'handle','pg_trigger:'||t.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'name',(t.tgname::text),'enabled',(t.tgenabled::text),'event_bits',(t.tgtype),'internal',(t.tgisinternal),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'constraint_is_zero',(t.tgconstraint=0),'constraint_relation_is_zero',(t.tgconstrrelid=0),'constraint_index_is_zero',(t.tgconstrindid=0),'argument_count',(t.tgnargs),'columns',(t.tgattr::text),'qual_is_null',(t.tgqual IS NULL),'old_table',(t.tgoldtable::text),'new_table',(t.tgnewtable::text),'routine_identity',(t.tgfoid::regprocedure::text),'arguments',(encode(t.tgargs,'hex')))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace AND c.relname IN('zasp_integrations','zasp_integration_connections','zasp_discovery_syncs','zasp_inventory_entities') AND t.tgname='zasp_authorization79_capture'
) AS capture_original_0416
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization-temporal:triggers-ready:routine','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'config_raw',(p.proconfig::text),'acl_raw',(p.proacl::text),'config_json',(to_jsonb(p.proconfig)),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p WHERE p.oid='zasp_authorization79.capture()'::regprocedure
) AS capture_original_0417
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:membership','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('granted_role',(granted.rolname),'member_role',(member.rolname),'admin_option',(membership.admin_option)) AS fact FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_attack_lab_controller','zasp_attack_lab_outbox_worker','zasp_attack_lab_proxy') AND member.rolname='zasp_discovery_authority') captured GROUP BY fact
) AS capture_original_0418
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:membership','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('granted_role',(granted.rolname),'member_role',(member.rolname),'admin_option',(membership.admin_option)) AS fact FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE granted.rolname IN('zasp_red_team_worker','zasp_red_team_outbox_worker','zasp_red_team_adapter') AND member.rolname='zasp_discovery_authority') captured GROUP BY fact
) AS capture_original_0419
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','schedule:guard-registration','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('checksum',(checksum::text),'fingerprint',(fingerprint::text)) AS fact FROM zasp_temporal72.registration WHERE checksum='e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940' AND fingerprint='b5d7f17f5350c89b337c6c875975402ab67b10ffc6facc2ea34c042342e9f07e') captured GROUP BY fact
) AS capture_original_0420
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_sa_export_prior.functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl::text)) AS fact FROM zasp_sa_export_prior.functions) captured GROUP BY fact
) AS capture_original_0421
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:table','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(c.relowner::regrole::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'acl_raw',(c.relacl::text),'acl_grants',((SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor)))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_risk_projection_current','zasp_discovery_risk_projection_items','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs','zasp_workflow_receipts'])
) AS capture_original_0422
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'source_body',(CASE WHEN p.oid='public.zasp_execution_claim_jobs(text,text,integer,integer)'::regprocedure THEN (SELECT split_part(definition,chr(36)||'function'||chr(36),2) FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_execution_claim_jobs(text,text,integer,integer)') ELSE p.prosrc END),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'acl_raw',(p.proacl::text),'acl_grants',((SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND (p.proname LIKE 'zasp_execution_%' OR p.proname IN('zasp_workflow_mutate','zasp_risk_mutate','zasp_discovery_security_ready','zasp_reference_authorization_security_ready','zasp_discovery_request_sync','zasp_discovery_claim_jobs','zasp_discovery_claim_schedules','zasp_discovery_complete_schedule','zasp_discovery_finish_job','zasp_discovery_finish_projection','zasp_discovery_apply_snapshot','zasp_complete_reference_authorization')) AND p.proname NOT IN('zasp_execution_live_fingerprint','zasp_execution_readiness','zasp_execution_security_ready')
) AS capture_original_0423
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:policy','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('permissive',(policy.polpermissive),'command',(policy.polcmd::text),'roles',((SELECT jsonb_agg(role.rolname ORDER BY role.rolname) FROM unnest(policy.polroles) role_oid JOIN pg_roles role ON role.oid=role_oid)),'using',(pg_get_expr(policy.polqual,policy.polrelid)),'check',(pg_get_expr(policy.polwithcheck,policy.polrelid)))) FROM pg_policy policy JOIN pg_class c ON c.oid=policy.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['zasp_discovery_execution_principals','zasp_discovery_connection_subjects','zasp_discovery_execution_quotas','zasp_discovery_generation_reservations','zasp_discovery_job_authorities','zasp_discovery_job_checkpoints','zasp_discovery_upgrade_transitions','zasp_discovery_snapshot_inputs','zasp_discovery_snapshot_projection_items','zasp_discovery_projection_cursors','zasp_discovery_schedule_runs','zasp_discovery_projection_receipts','zasp_discovery_risk_projection_current','zasp_discovery_risk_projection_items','zasp_discovery_freshness_versions','zasp_discovery_outbox_topic_fairness','zasp_discovery_syncs'])
) AS capture_original_0424
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:trigger','identity',NULL,'handle','pg_trigger:'||trigger_value.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('definition',(pg_get_triggerdef(trigger_value.oid,true)),'enabled',(trigger_value.tgenabled::text),'function',(trigger_value.tgfoid::regprocedure::text))) FROM pg_trigger trigger_value JOIN pg_class c ON c.oid=trigger_value.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND trigger_value.tgname LIKE 'zasp_execution_%' AND NOT trigger_value.tgisinternal
) AS capture_original_0425
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:role','identity',NULL,'handle','pg_authid:'||r.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('login',(r.rolcanlogin),'inherit',(r.rolinherit),'superuser',(r.rolsuper),'create_db',(r.rolcreatedb),'create_role',(r.rolcreaterole),'replication',(r.rolreplication),'bypass_rls',(r.rolbypassrls))) FROM pg_roles r WHERE r.rolname=ANY(ARRAY['zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker'])
) AS capture_original_0426
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:table','identity',NULL,'handle','pg_class:'||class.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(class.relowner::regrole::text),'row_security',(class.relrowsecurity),'forced_row_security',(class.relforcerowsecurity),'acl_raw',(class.relacl::text),'acl_grants',((SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(class.relacl,acldefault('r',class.relowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor)))) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_capability_evidence','zasp_inventory_entities','zasp_inventory_source_observations','zasp_inventory_evidence'])
) AS capture_original_0427
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:policy','identity',NULL,'handle','pg_policy:'||policy.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('permissive',(policy.polpermissive),'command',(policy.polcmd::text),'roles',((SELECT jsonb_agg(role.rolname ORDER BY role.rolname) FROM unnest(policy.polroles) role_oid JOIN pg_roles role ON role.oid=role_oid)),'using',(pg_get_expr(policy.polqual,policy.polrelid)),'check',(pg_get_expr(policy.polwithcheck,policy.polrelid)))) FROM pg_policy policy JOIN pg_class class ON class.oid=policy.polrelid JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='public' AND class.relname=ANY(ARRAY['zasp_inventory_cutover_state','zasp_inventory_legacy_restore','zasp_inventory_identity_rules','zasp_inventory_identity_bindings','zasp_inventory_annotations','zasp_inventory_capability_evidence'])
) AS capture_original_0428
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:function','identity',NULL,'handle','pg_proc:'||procedure.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(procedure.proowner::regrole::text),'security_definer',(procedure.prosecdef),'source_body',(procedure.prosrc),'config_json',(to_jsonb(procedure.proconfig)),'config_raw',(procedure.proconfig::text),'config_dims',(array_dims(procedure.proconfig)),'config_ndims',(array_ndims(procedure.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(procedure.proconfig,d),array_upper(procedure.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(procedure.proconfig)) d)),'acl_raw',(procedure.proacl::text),'acl_grants',((SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor)))) FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace WHERE namespace.nspname='public' AND (procedure.proname LIKE 'zasp_inventory_%' OR procedure.proname IN('zasp_discovery_apply_snapshot','zasp_execution_job_input','zasp_execution_apply_risk_projection','zasp_typed_inventory_job_input_v13','zasp_workflow_mutate','zasp_risk_mutate','zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence')) AND procedure.proname<>'zasp_inventory_live_fingerprint'
) AS capture_original_0429
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:function:core-owner','identity',NULL,'handle','pg_class:'||oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(relowner::regrole::text))) FROM pg_class WHERE oid='zasp_core_payloads'::regclass
) AS capture_original_0430
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:role','identity',NULL,'handle','pg_authid:'||role.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('login',(role.rolcanlogin),'inherit',(role.rolinherit),'superuser',(role.rolsuper),'create_db',(role.rolcreatedb),'create_role',(role.rolcreaterole),'replication',(role.rolreplication),'bypass_rls',(role.rolbypassrls))) FROM pg_roles role WHERE role.rolname='zasp_inventory_authority'
) AS capture_original_0431
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:role','identity',NULL,'handle','pg_authid:'||oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(rolname),'superuser',(rolsuper),'inherit',(rolinherit),'create_role',(rolcreaterole),'create_db',(rolcreatedb),'login',(rolcanlogin),'replication',(rolreplication),'bypass_rls',(rolbypassrls),'connection_limit',(rolconnlimit),'valid_until_text_or_empty',(COALESCE(rolvaliduntil::text,'')),'config_raw_text_or_empty',(COALESCE(rolconfig::text,'')),'config_json',(to_jsonb(rolconfig)),'config_raw',(rolconfig::text),'config_dims',(array_dims(rolconfig)),'config_ndims',(array_ndims(rolconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(rolconfig,d),array_upper(rolconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(rolconfig)) d)))) FROM pg_roles WHERE rolname='zasp_security_agent_global_operator'
) AS capture_original_0432
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:membership','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('granted_role',(roleid::regrole::text),'member_role',(member::regrole::text),'grantor_role',(grantor::regrole::text),'admin_option',(admin_option)) AS fact FROM pg_auth_members WHERE roleid='zasp_security_agent_global_operator'::regrole OR member='zasp_security_agent_global_operator'::regrole) captured GROUP BY fact
) AS capture_original_0433
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-function','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('original_identity',(p.oid::regprocedure::text),'security_definer',(p.prosecdef),'acl_text_or_empty',(COALESCE(p.proacl::text,'')),'definition',(pg_get_functiondef(p.oid)))) FROM pg_proc p WHERE p.proowner='zasp_security_agent_global_operator'::regrole
) AS capture_original_0434
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-relation','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('original_identity',(c.oid::regclass::text),'relation_kind',(c.relkind))) FROM pg_class c WHERE c.relowner='zasp_security_agent_global_operator'::regrole
) AS capture_original_0435
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-schema','identity',NULL,'handle','pg_namespace:'||oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(nspname))) FROM pg_namespace WHERE nspowner='zasp_security_agent_global_operator'::regrole
) AS capture_original_0436
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-database','identity',NULL,'handle','pg_database:'||oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(datname))) FROM pg_database WHERE datdba='zasp_security_agent_global_operator'::regrole
) AS capture_original_0437
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:default-acl','identity',NULL,'handle','pg_default_acl:'||oid::text||':0','multiplicity',1,'fact',jsonb_build_object('role',(defaclrole::regrole::text),'namespace',(defaclnamespace::regnamespace::text),'object_type',(defaclobjtype),'acl_text',(defaclacl::text))) FROM pg_default_acl WHERE defaclrole='zasp_security_agent_global_operator'::regrole OR EXISTS(SELECT 1 FROM aclexplode(defaclacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole)
) AS capture_original_0438
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:table','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('original_identity',(c.oid::regclass::text),'relation_kind',(c.relkind),'persistence',(c.relpersistence),'row_security',(c.relrowsecurity),'force_row_security',(c.relforcerowsecurity),'owner',(c.relowner::regrole::text),'acl_text_or_empty',(COALESCE(c.relacl::text,'')),'options_text_or_empty',(COALESCE(c.reloptions::text,'')))) FROM pg_class c WHERE c.oid IN(SELECT oid FROM relations)
) AS capture_original_0439
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_identity',(a.attrelid::regclass::text),'physical_position',(a.attnum),'name',(a.attname),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'identity',(a.attidentity),'generated',(a.attgenerated),'collation',(a.attcollation::regcollation::text),'default_text_or_empty',(COALESCE(pg_get_expr(d.adbin,d.adrelid),'')),'acl_text_or_empty',(COALESCE(a.attacl::text,'')))) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN(SELECT oid FROM relations) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0440
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:constraint','identity',NULL,'handle','pg_constraint:'||oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(conrelid::regclass::text),'name',(conname),'validated',(convalidated),'definition_pretty',(pg_get_constraintdef(oid,true)))) FROM pg_constraint WHERE conrelid IN(SELECT oid FROM relations)
) AS capture_original_0441
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:index','identity',NULL,'handle','pg_class:'||indexrelid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(indrelid::regclass::text),'index_identity',(indexrelid::regclass::text),'valid',(indisvalid),'ready',(indisready),'live',(indislive),'definition',(pg_get_indexdef(indexrelid)))) FROM pg_index WHERE indrelid IN(SELECT oid FROM relations)
) AS capture_original_0442
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:policy','identity',NULL,'handle','pg_policy:'||oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(polrelid::regclass::text),'name',(polname),'permissive',(polpermissive),'command',(polcmd),'roles_csv',((SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(polroles) r)),'using_expression',(pg_get_expr(polqual,polrelid)),'check_expression',(pg_get_expr(polwithcheck,polrelid)))) FROM pg_policy WHERE polrelid IN(SELECT oid FROM relations)
) AS capture_original_0443
UNION ALL
SELECT * FROM (
WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ) SELECT jsonb_build_object('ruleId','special:global-control:trigger','identity',NULL,'handle','pg_trigger:'||oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(tgrelid::regclass::text),'name',(tgname),'enabled',(tgenabled),'definition_pretty',(pg_get_triggerdef(oid,true)),'routine_identity',(tgfoid::regprocedure::text))) FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM relations) AND NOT tgisinternal
) AS capture_original_0444
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:saved-trigger','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_name',(relation_name),'trigger_name',(trigger_name),'definition',(definition),'enabled',(enabled)) AS fact FROM zasp_existing_tests_predecessor.global_control_triggers) captured GROUP BY fact
) AS capture_original_0445
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:relation-grant','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_identity',(c.oid::regclass::text),'privilege',(a.privilege_type),'grantable',(a.is_grantable),'grantor_role',(a.grantor::regrole::text)) AS fact FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole) captured GROUP BY fact
) AS capture_original_0446
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:column-grant','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_identity',(c.attrelid::regclass::text),'column_name',(c.attname),'privilege',(a.privilege_type),'grantable',(a.is_grantable),'grantor_role',(a.grantor::regrole::text)) AS fact FROM pg_attribute c CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole) captured GROUP BY fact
) AS capture_original_0447
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:function-grant','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'privilege',(a.privilege_type),'grantable',(a.is_grantable),'grantor_role',(a.grantor::regrole::text)) AS fact FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole) captured GROUP BY fact
) AS capture_original_0448
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:schema-grant','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('namespace_name',(n.nspname),'privilege',(a.privilege_type),'grantable',(a.is_grantable),'grantor_role',(a.grantor::regrole::text)) AS fact FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole) captured GROUP BY fact
) AS capture_original_0449
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:relation','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(c.relname),'owner',(c.relowner::regrole::text),'relation_kind',(c.relkind),'row_security',(c.relrowsecurity),'force_row_security',(c.relforcerowsecurity),'acl_text_or_empty',(COALESCE(c.relacl::text,'')))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings')
) AS capture_original_0450
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'normalized_position',((SELECT count(*) FROM pg_attribute live WHERE live.attrelid=a.attrelid AND live.attnum>0 AND live.attnum<=a.attnum AND NOT live.attisdropped)),'name',(a.attname),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'default_text_or_empty',(COALESCE(pg_get_expr(d.adbin,d.adrelid),'')),'acl_text_or_empty',(COALESCE(a.attacl::text,'')),'identity',(a.attidentity),'generated',(a.attgenerated),'collation',(a.attcollation::regcollation::text))) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0451
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'name',(k.conname),'definition',(pg_get_constraintdef(k.oid)),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings'
) AS capture_original_0452
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'definition',(pg_get_indexdef(i.indexrelid)),'valid',(i.indisvalid),'ready',(i.indisready))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings'
) AS capture_original_0453
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'name',(p.polname),'command',(p.polcmd),'permissive',(p.polpermissive),'roles_csv',((SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(p.polroles) r)),'using_expression',(pg_get_expr(p.polqual,p.polrelid)),'check_expression',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings'
) AS capture_original_0454
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname),'name',(t.tgname),'enabled',(t.tgenabled),'definition',(pg_get_triggerdef(t.oid)))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND (starts_with(c.relname,'zasp_compliance_export_') OR c.relname='zasp_compliance_worker_bindings')
) AS capture_original_0455
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:role','identity',NULL,'handle','pg_authid:'||oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(rolname),'login',(rolcanlogin),'inherit',(rolinherit),'superuser',(rolsuper),'create_db',(rolcreatedb),'create_role',(rolcreaterole),'replication',(rolreplication),'bypass_rls',(rolbypassrls),'connection_limit',(rolconnlimit),'config_raw_text_or_empty',(COALESCE(rolconfig::text,'')),'valid_until_text_or_empty',(COALESCE(rolvaliduntil::text,'')),'config_json',(to_jsonb(rolconfig)),'config_raw',(rolconfig::text),'config_dims',(array_dims(rolconfig)),'config_ndims',(array_ndims(rolconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(rolconfig,d),array_upper(rolconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(rolconfig)) d)))) FROM pg_roles WHERE rolname IN('zasp_compliance_worker','zasp_compliance_cleanup')
) AS capture_original_0456
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:limits','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('revision',(p.revision),'controls',(p.controls),'records_per_control',(p.records_per_control),'format_bytes',(p.format_bytes),'package_bytes',(p.package_bytes),'snapshot_bytes',(p.snapshot_bytes),'scope_active',(p.scope_active),'deployment_active',(p.deployment_active),'attempts',(p.attempts),'lease_seconds',(p.lease_seconds),'retry_seconds',(p.retry_seconds),'retention_seconds',(p.retention_seconds),'scope_bytes',(p.scope_bytes),'deployment_bytes',(p.deployment_bytes),'scope_jobs',(p.scope_jobs),'deployment_jobs',(p.deployment_jobs),'job_grants',(p.job_grants),'principal_grants',(p.principal_grants)) AS fact FROM public.zasp_compliance_export_policy p) captured GROUP BY fact
) AS capture_original_0457
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:scope-authority:relation','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text))) FROM pg_class c WHERE c.oid='public.zasp_authorized_scopes'::regclass
) AS capture_original_0458
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:scope-authority:routines','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'raw_acl',(p.proacl::text))) FROM pg_proc p WHERE p.oid IN('zasp_sa_multistep_prior.lock_scope(text,text,text,text)'::regprocedure,'zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text)'::regprocedure)
) AS capture_original_0459
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:scope-authority:routine-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'grantor',(CASE WHEN a.grantor=0 THEN 'PUBLIC' ELSE a.grantor::regrole::text END),'grantee',(CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END),'privilege',(a.privilege_type::text),'grantable',(a.is_grantable)) AS fact FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid IN('zasp_sa_multistep_prior.lock_scope(text,text,text,text)'::regprocedure,'zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text)'::regprocedure)) captured GROUP BY fact
) AS capture_original_0460
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:migration-helper:relations','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text))) FROM pg_class c WHERE c.oid IN(SELECT CASE WHEN EXISTS(SELECT 1 FROM zasp_temporal72.predecessor_functions s WHERE s.signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)')) THEN d.identity::regclass ELSE NULL END FROM (VALUES ('public.zasp_core_payloads'),('public.zasp_authorized_scopes')) AS d(identity))
) AS capture_original_0461
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:migration-helper:routines','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'raw_acl',(p.proacl::text))) FROM pg_proc p WHERE EXISTS(SELECT 1 FROM zasp_temporal72.predecessor_functions s WHERE s.signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)') AND p.oid=CASE WHEN s.signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)') THEN to_regprocedure('public.'||s.signature) ELSE NULL END)
) AS capture_original_0462
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:migration-helper:routine-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'grantor',(CASE WHEN x.grantor=0 THEN 'PUBLIC' ELSE x.grantor::regrole::text END),'grantee',(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE x.grantee::regrole::text END),'privilege',(x.privilege_type::text),'grantable',(x.is_grantable)) AS fact FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) x WHERE EXISTS(SELECT 1 FROM zasp_temporal72.predecessor_functions s WHERE s.signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)') AND p.oid=CASE WHEN s.signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)') THEN to_regprocedure('public.'||s.signature) ELSE NULL END)) captured GROUP BY fact
) AS capture_original_0463
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:relation','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'raw_acl',(c.relacl::text))) FROM pg_class c WHERE c.oid='public.zasp_admin_audit'::regclass
) AS capture_original_0464
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:columns','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'raw_acl',(a.attacl::text))) FROM pg_attribute a WHERE a.attrelid='public.zasp_admin_audit'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0465
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:relation-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'acl_defaulted',(c.relacl IS NULL),'grantor',(CASE WHEN x.grantor=0 THEN 'PUBLIC' ELSE x.grantor::regrole::text END),'grantee',(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE x.grantee::regrole::text END),'privilege',(x.privilege_type::text),'grantable',(x.is_grantable)) AS fact FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x WHERE c.oid='public.zasp_admin_audit'::regclass) captured GROUP BY fact
) AS capture_original_0466
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:column-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'owner',(c.relowner::regrole::text),'grantor',(CASE WHEN x.grantor=0 THEN 'PUBLIC' ELSE x.grantor::regrole::text END),'grantee',(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE x.grantee::regrole::text END),'privilege',(x.privilege_type::text),'grantable',(x.is_grantable)) AS fact FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE c.oid='public.zasp_admin_audit'::regclass) captured GROUP BY fact
) AS capture_original_0467
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:ready-relation','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(c.oid::regclass::text),'kind',(c.relkind::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE c.oid='public.zasp_admin_audit'::regclass
) AS capture_original_0468
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-workflow:relation','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'raw_acl',(c.relacl::text))) FROM pg_class c WHERE c.oid='public.zasp_workflow_audit'::regclass
) AS capture_original_0469
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-workflow:columns','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'raw_acl',(a.attacl::text))) FROM pg_attribute a WHERE a.attrelid='public.zasp_workflow_audit'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0470
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-workflow:relation-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'acl_defaulted',(c.relacl IS NULL),'grantor',(CASE WHEN x.grantor=0 THEN 'PUBLIC' ELSE x.grantor::regrole::text END),'grantee',(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE x.grantee::regrole::text END),'privilege',(x.privilege_type::text),'grantable',(x.is_grantable)) AS fact FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x WHERE c.oid='public.zasp_workflow_audit'::regclass) captured GROUP BY fact
) AS capture_original_0471
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-workflow:column-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'owner',(c.relowner::regrole::text),'grantor',(CASE WHEN x.grantor=0 THEN 'PUBLIC' ELSE x.grantor::regrole::text END),'grantee',(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE x.grantee::regrole::text END),'privilege',(x.privilege_type::text),'grantable',(x.is_grantable)) AS fact FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE c.oid='public.zasp_workflow_audit'::regclass) captured GROUP BY fact
) AS capture_original_0472
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:predecessor68:routine','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(p.proowner::regrole::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_temporal68.predecessor_ready(text,text)'::regprocedure
) AS capture_original_0473
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:ready68:routine','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(p.proowner::regrole::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_temporal68.ready(text,text)'::regprocedure
) AS capture_original_0474
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:ready78:routine','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(p.proowner::regrole::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_temporal78.ready(text,text)'::regprocedure
) AS capture_original_0475
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:base67:routine','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(p.proowner::regrole::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_temporal77.base67_fingerprint()'::regprocedure
) AS capture_original_0476
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:native-role-shape:roles','identity',NULL,'handle','pg_authid:'||r.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(r.rolname::text),'login',(r.rolcanlogin),'superuser',(r.rolsuper),'create_db',(r.rolcreatedb),'create_role',(r.rolcreaterole),'replication',(r.rolreplication),'bypass_rls',(r.rolbypassrls))) FROM pg_roles r WHERE r.rolname IN('zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting')
) AS capture_original_0477
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:native-role-shape:membership','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('granted_role',(granted.rolname::text),'member_role',(member.rolname::text),'admin_option',(membership.admin_option)) AS fact FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE membership.roleid='zasp_temporal_accounting'::regrole OR membership.member IN('zasp_temporal_executor'::regrole,'zasp_temporal_compensation'::regrole,'zasp_temporal_accounting'::regrole)) captured GROUP BY fact
) AS capture_original_0478
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:worker-catalog-ready:routine','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'source_body',(p.prosrc::text),'owner',(p.proowner::regrole::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'security_definer',(p.prosecdef),'volatility',(p.provolatile::text),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)))) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure
) AS capture_original_0479
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:worker-catalog-ready:definition','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('definition',(pg_get_functiondef(p.oid)))) FROM pg_proc p WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure
) AS capture_original_0480
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:schema','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace',(n.nspname::text),'owner',(n.nspowner::regrole::text),'raw_acl',(n.nspacl::text))) FROM pg_namespace n WHERE n.nspname='zasp_compliance_predecessor'
) AS capture_original_0481
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname::text),'name',(p.proname::text),'routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(r.rolname::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_compliance_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_compliance_')
) AS capture_original_0482
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:schema','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace',(n.nspname::text),'owner',(n.nspowner::regrole::text),'raw_acl',(n.nspacl::text))) FROM pg_namespace n WHERE n.nspname='zasp_existing_tests_predecessor'
) AS capture_original_0483
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname::text),'name',(p.proname::text),'routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(r.rolname::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_existing_tests_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_production_security_agent_existing_tests')
) AS capture_original_0484
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:schema','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace',(n.nspname::text),'owner',(n.nspowner::regrole::text),'raw_acl',(n.nspacl::text))) FROM pg_namespace n WHERE n.nspname='zasp_run_context_predecessor'
) AS capture_original_0485
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname::text),'name',(p.proname::text),'routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(r.rolname::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_run_context_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_production_security_agent_run_context')
) AS capture_original_0486
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:schema','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace',(n.nspname::text),'owner',(n.nspowner::regrole::text),'raw_acl',(n.nspacl::text))) FROM pg_namespace n WHERE n.nspname='zasp_security_agent_budgets_predecessor'
) AS capture_original_0487
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname::text),'name',(p.proname::text),'routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(r.rolname::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_security_agent_budgets_predecessor' OR n.nspname='public' AND (starts_with(p.proname,'zasp_security_agent_') OR starts_with(p.proname,'zasp_production_security_agent_budgets') OR p.proname='zasp_policy_deployment_store_temporary_source')
) AS capture_original_0488
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:schema','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace',(n.nspname::text),'owner',(n.nspowner::regrole::text),'raw_acl',(n.nspacl::text))) FROM pg_namespace n WHERE n.nspname='zasp_audit_exports_predecessor'
) AS capture_original_0489
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname::text),'name',(p.proname::text),'routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(r.rolname::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='zasp_audit_exports_predecessor' OR n.nspname='public' AND (starts_with(p.proname,'zasp_audit_export') OR starts_with(p.proname,'zasp_production_audit_exports'))
) AS capture_original_0490
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:table','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(c.oid::regclass::text),'kind',(c.relkind::text),'persistence',(c.relpersistence::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'owner',(c.relowner::regrole::text),'raw_acl',(c.relacl::text))) FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
) AS capture_original_0491
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'identity',(a.attidentity::text),'generated',(a.attgenerated::text),'collation',(a.attcollation::regcollation::text),'default_expression',(pg_get_expr(d.adbin,d.adrelid)),'raw_acl',(a.attacl::text))) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations')) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0492
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(k.conrelid::regclass::text),'name',(k.conname::text),'validated',(k.convalidated),'definition',(pg_get_constraintdef(k.oid,true)))) FROM pg_constraint k WHERE k.conrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
) AS capture_original_0493
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(i.indrelid::regclass::text),'index_identity',(i.indexrelid::regclass::text),'valid',(i.indisvalid),'ready',(i.indisready),'live',(i.indislive),'definition',(pg_get_indexdef(i.indexrelid)))) FROM pg_index i WHERE i.indrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
) AS capture_original_0494
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(p.polrelid::regclass::text),'name',(p.polname::text),'permissive',(p.polpermissive),'command',(p.polcmd::text),'roles_csv',((SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(p.polroles) r)),'using_expression',(pg_get_expr(p.polqual,p.polrelid)),'check_expression',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p WHERE p.polrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations'))
) AS capture_original_0495
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(t.tgrelid::regclass::text),'name',(t.tgname::text),'enabled',(t.tgenabled::text),'definition',(pg_get_triggerdef(t.oid,true)),'routine_identity',(t.tgfoid::regprocedure::text))) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_security_agent_test_links'::regclass,to_regclass('public.zasp_security_agent_test_invocations')) AND NOT t.tgisinternal
) AS capture_original_0496
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:table','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(c.oid::regclass::text),'kind',(c.relkind::text),'persistence',(c.relpersistence::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'owner',(c.relowner::regrole::text),'raw_acl',(c.relacl::text))) FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
) AS capture_original_0497
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'identity',(a.attidentity::text),'generated',(a.attgenerated::text),'collation',(a.attcollation::regcollation::text),'default_expression',(pg_get_expr(d.adbin,d.adrelid)),'raw_acl',(a.attacl::text))) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0498
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(k.conrelid::regclass::text),'name',(k.conname::text),'validated',(k.convalidated),'definition',(pg_get_constraintdef(k.oid,true)))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE k.conrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
) AS capture_original_0499
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(i.indrelid::regclass::text),'index_identity',(i.indexrelid::regclass::text),'valid',(i.indisvalid),'ready',(i.indisready),'live',(i.indislive),'definition',(pg_get_indexdef(i.indexrelid)))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE i.indrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
) AS capture_original_0500
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(p.polrelid::regclass::text),'name',(p.polname::text),'permissive',(p.polpermissive),'command',(p.polcmd::text),'roles_csv',((SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(p.polroles) r)),'using_expression',(pg_get_expr(p.polqual,p.polrelid)),'check_expression',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE p.polrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass)
) AS capture_original_0501
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(t.tgrelid::regclass::text),'name',(t.tgname::text),'enabled',(t.tgenabled::text),'definition',(pg_get_triggerdef(t.oid,true)),'routine_identity',(t.tgfoid::regprocedure::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE t.tgrelid IN('public.zasp_security_agent_org_admissions'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'public.zasp_security_agent_step_reservations'::regclass,'public.zasp_security_agent_provider_reservations'::regclass) AND NOT t.tgisinternal
) AS capture_original_0502
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:table','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname::text),'relation_name',(c.relname::text),'relation_identity',(c.oid::regclass::text),'kind',(c.relkind::text),'persistence',(c.relpersistence::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'owner',(c.relowner::regrole::text),'raw_acl',(c.relacl::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_audit_export') AND c.relkind IN('r','p','v','S')
) AS capture_original_0503
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'identity',(a.attidentity::text),'generated',(a.attgenerated::text),'collation',(a.attcollation::regcollation::text),'default_expression',(pg_get_expr(d.adbin,d.adrelid)),'raw_acl',(a.attacl::text))) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND starts_with(c.relname,'zasp_audit_export') AND c.relkind IN('r','p','v','S') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0504
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(k.conrelid::regclass::text),'name',(k.conname::text),'validated',(k.convalidated),'definition',(pg_get_constraintdef(k.oid,true)))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit'))
) AS capture_original_0505
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(i.indrelid::regclass::text),'index_identity',(i.indexrelid::regclass::text),'valid',(i.indisvalid),'ready',(i.indisready),'live',(i.indislive),'definition',(pg_get_indexdef(i.indexrelid)))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit'))
) AS capture_original_0506
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(p.polrelid::regclass::text),'name',(p.polname::text),'permissive',(p.polpermissive),'command',(p.polcmd::text),'roles_csv',((SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(p.polroles) r)),'using_expression',(pg_get_expr(p.polqual,p.polrelid)),'check_expression',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit'))
) AS capture_original_0507
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(t.tgrelid::regclass::text),'name',(t.tgname::text),'enabled',(t.tgenabled::text),'definition',(pg_get_triggerdef(t.oid,true)),'routine_identity',(t.tgfoid::regprocedure::text))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (starts_with(c.relname,'zasp_audit_export') OR c.relname IN('zasp_admin_audit','zasp_workflow_audit','zasp_red_team_audit')) AND NOT t.tgisinternal
) AS capture_original_0508
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:activity-index','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'index_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'valid',(i.indisvalid),'ready',(i.indisready),'live',(i.indislive),'definition',(pg_get_indexdef(i.indexrelid)))) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_security_agent_activity_')
) AS capture_original_0509
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:export-role','identity',NULL,'handle','pg_authid:'||r.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(r.rolname::text),'login',(r.rolcanlogin),'inherit',(r.rolinherit),'superuser',(r.rolsuper),'create_db',(r.rolcreatedb),'create_role',(r.rolcreaterole),'replication',(r.rolreplication),'bypass_rls',(r.rolbypassrls),'connection_limit',(r.rolconnlimit),'valid_until',(r.rolvaliduntil::text),'config_raw',(r.rolconfig::text),'config_dims',(array_dims(r.rolconfig)),'config_ndims',(array_ndims(r.rolconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(r.rolconfig,d),array_upper(r.rolconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(r.rolconfig)) d)),'config_json',(to_jsonb(r.rolconfig)))) FROM pg_roles r WHERE r.rolname IN('zasp_audit_export_worker','zasp_audit_export_outbox')
) AS capture_original_0510
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:view','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(c.oid::regclass::text),'definition',(pg_get_viewdef(c.oid,true)),'options_raw',(c.reloptions::text))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'zasp_audit_export') AND c.relkind='v'
) AS capture_original_0511
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:normalization-relation','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'raw_acl',(c.relacl::text))) FROM pg_class c WHERE c.oid='public.zasp_data_controls'::regclass
) AS capture_original_0512
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:routine-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'grantor',(x.grantor::regrole::text),'grantee',(x.grantee::regrole::text),'privilege',(x.privilege_type::text),'grantable',(x.is_grantable)) AS fact FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) x WHERE p.oid='public.zasp_compliance_configuration(text,text,text)'::regprocedure) captured GROUP BY fact
) AS capture_original_0513
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:normalization-relation','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'raw_acl',(c.relacl::text))) FROM pg_class c WHERE c.oid='public.zasp_environments'::regclass
) AS capture_original_0514
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:routine-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'owner',(p.proowner::regrole::text),'grantor',(x.grantor::regrole::text),'grantee',(x.grantee::regrole::text),'privilege',(x.privilege_type::text),'grantable',(x.is_grantable)) AS fact FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) x WHERE p.oid='public.zasp_production_security_agent_run_context_lock_env(text,text,text)'::regprocedure) captured GROUP BY fact
) AS capture_original_0515
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:source-shape','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(c.oid::regclass::text),'kind',(c.relkind::text),'persistence',(c.relpersistence::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'options_raw',(c.reloptions::text))) FROM pg_class c WHERE c.oid IN('public.zasp_admin_audit'::regclass,'public.zasp_workflow_audit'::regclass,'public.zasp_red_team_audit'::regclass)
) AS capture_original_0516
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:red-team-relation','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'raw_acl',(c.relacl::text))) FROM pg_class c WHERE c.oid='public.zasp_red_team_audit'::regclass
) AS capture_original_0517
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:red-team-relation-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_identity',(c.oid::regclass::text),'owner',(c.relowner::regrole::text),'acl_defaulted',(c.relacl IS NULL),'grantor',(x.grantor::regrole::text),'grantee',(x.grantee::regrole::text),'privilege',(x.privilege_type::text),'grantable',(x.is_grantable)) AS fact FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x WHERE c.oid='public.zasp_red_team_audit'::regclass) captured GROUP BY fact
) AS capture_original_0518
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:source-columns-shape','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'identity',(a.attidentity::text),'generated',(a.attgenerated::text),'collation',(a.attcollation::regcollation::text),'default_expression',(pg_get_expr(d.adbin,d.adrelid)))) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.zasp_admin_audit'::regclass,'public.zasp_workflow_audit'::regclass,'public.zasp_red_team_audit'::regclass) AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0519
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:red-team-columns','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'raw_acl',(a.attacl::text))) FROM pg_attribute a WHERE a.attrelid='public.zasp_red_team_audit'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0520
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:red-team-column-acl','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('relation_identity',(a.attrelid::regclass::text),'number',(a.attnum),'name',(a.attname::text),'owner',(c.relowner::regrole::text),'grantor',(x.grantor::regrole::text),'grantee',(x.grantee::regrole::text),'privilege',(x.privilege_type::text),'grantable',(x.is_grantable)) AS fact FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE a.attrelid='public.zasp_red_team_audit'::regclass AND a.attnum>0 AND NOT a.attisdropped) captured GROUP BY fact
) AS capture_original_0521
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','saved-input:zasp_sa_multistep_prior.functions','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text),'owner_name',(owner_name::text),'acl',(acl)) AS fact FROM zasp_sa_multistep_prior.functions) captured GROUP BY fact
) AS capture_original_0522
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:legacy-approval-fence','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname::text),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'raw_owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'volatility',(p.provolatile::text),'parallel',(p.proparallel::text),'strict',(p.proisstrict),'leakproof',(p.proleakproof),'config_raw',(p.proconfig::text),'raw_acl',(p.proacl::text),'definition',(pg_get_functiondef(p.oid)),'config_json',(to_jsonb(p.proconfig)),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN('zasp_security_agent_decide_approval','zasp_security_agent_decide_approval_v22','zasp_security_agent_decide_approval_v23','zasp_security_agent_decide_approval_v24','zasp_security_agent_expire_approvals_v28')
) AS capture_original_0523
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:legacy-action-fence','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname::text),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'raw_owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'volatility',(p.provolatile::text),'parallel',(p.proparallel::text),'strict',(p.proisstrict),'leakproof',(p.proleakproof),'config_raw',(p.proconfig::text),'raw_acl',(p.proacl::text),'definition',(pg_get_functiondef(p.oid)),'config_json',(to_jsonb(p.proconfig)),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN('zasp_security_agent_claim_temporary_policy_effects','zasp_security_agent_heartbeat_temporary_policy_effect','zasp_security_agent_dispatch_temporary_policy_run','zasp_security_agent_finish_temporary_policy_effect','zasp_security_agent_store_temporary_policy_target','zasp_security_agent_store_temporary_policy_target_v27','zasp_policy_deployment_store_temporary_source','zasp_security_agent_execute_run','zasp_security_agent_execute_run_v21','zasp_security_agent_execute_run_v22','zasp_security_agent_execute_run_v23','zasp_security_agent_execute_run_v24')
) AS capture_original_0524
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:schema','identity',NULL,'handle','pg_namespace:'||n.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(n.nspname::text),'owner',(n.nspowner::regrole::text),'raw_acl',(n.nspacl::text))) FROM pg_namespace n WHERE n.nspname='zasp_sa_multistep_prior'
) AS capture_original_0525
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(p.proname::text),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'raw_owner',(p.proowner::regrole::text),'security_definer',(p.prosecdef),'volatility',(p.provolatile::text),'parallel',(p.proparallel::text),'strict',(p.proisstrict),'leakproof',(p.proleakproof),'config_raw',(p.proconfig::text),'raw_acl',(p.proacl::text),'definition',(pg_get_functiondef(p.oid)),'config_json',(to_jsonb(p.proconfig)),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p WHERE p.pronamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_original_0526
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:table','identity',NULL,'handle','pg_class:'||c.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('name',(c.relname::text),'kind',(c.relkind::text),'persistence',(c.relpersistence::text),'owner',(c.relowner::regrole::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity),'raw_acl',(c.relacl::text))) FROM pg_class c WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace AND c.relkind IN('r','v','m','p','S')
) AS capture_original_0527
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'position',(a.attnum),'name',(a.attname::text),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'identity',(a.attidentity::text),'generated',(a.attgenerated::text),'collation',(a.attcollation::regcollation::text),'default_expression',(pg_get_expr(d.adbin,d.adrelid)),'raw_acl',(a.attacl::text))) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0528
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'name',(k.conname::text),'definition',(pg_get_constraintdef(k.oid)),'validated',(k.convalidated))) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_original_0529
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:index','identity',NULL,'handle','pg_class:'||i.indexrelid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'definition',(pg_get_indexdef(i.indexrelid)),'valid',(i.indisvalid),'ready',(i.indisready),'live',(i.indislive))) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_original_0530
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'name',(t.tgname::text),'enabled',(t.tgenabled::text),'definition',(pg_get_triggerdef(t.oid)))) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_original_0531
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:foreign-key-trigger','identity',NULL,'handle','pg_trigger:'||t.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation',(k.conrelid::regclass::text),'name',(k.conname::text),'referenced_relation',(k.confrelid::regclass::text),'trigger_relation',(t.tgrelid::regclass::text),'constraint_relation',(t.tgconstrrelid::regclass::text),'function',(t.tgfoid::regprocedure::text),'event_bits',(t.tgtype),'enabled',(t.tgenabled::text),'deferrable',(t.tgdeferrable),'deferred',(t.tginitdeferred),'argument_count',(t.tgnargs),'arguments',(encode(t.tgargs,'hex')),'columns_text',(t.tgattr::text),'when_text_or_empty',(COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')))) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_original_0532
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:policy','identity',NULL,'handle','pg_policy:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('relation_name',(c.relname::text),'name',(p.polname::text),'command',(p.polcmd::text),'permissive',(p.polpermissive),'roles',(p.polroles::regrole[]::text),'using',(pg_get_expr(p.polqual,p.polrelid)),'check',(pg_get_expr(p.polwithcheck,p.polrelid)))) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace
) AS capture_original_0533
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:deployment-compile-saved','identity',fact::text,'handle',NULL,'multiplicity',count(*),'fact',fact) FROM (SELECT jsonb_build_object('signature',(signature::text),'definition',(definition::text)) AS fact FROM zasp_temporal77.predecessor_functions WHERE signature='zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)') captured GROUP BY fact
) AS capture_original_0534
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:ordered-writer-definition:routine','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(p.proowner::regrole::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.ordered_writer_definition(oid)'::regprocedure
) AS capture_original_0535
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:ordered-writer-normalized-identity:routine','identity',NULL,'handle','pg_proc:'||p.oid::text||':0','multiplicity',1,'fact',jsonb_build_object('routine_identity',(p.oid::regprocedure::text),'definition',(pg_get_functiondef(p.oid)),'source_body',(p.prosrc::text),'owner',(p.proowner::regrole::text),'raw_acl',(p.proacl::text),'language',(l.lanname::text),'volatility',(p.provolatile::text),'security_definer',(p.prosecdef),'strict',(p.proisstrict),'parallel',(p.proparallel::text),'leakproof',(p.proleakproof),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'result',(pg_get_function_result(p.oid)),'cost',(p.procost),'rows',(p.prorows))) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.ordered_writer_normalized_identity(oid)'::regprocedure
) AS capture_original_0536
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:function','identity',NULL,'handle','pg_proc:'||p.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('namespace_name',(n.nspname),'name',(p.proname),'identity_arguments',(pg_get_function_identity_arguments(p.oid)),'owner',(r.rolname),'security_definer',(p.prosecdef),'config_text_or_empty',(COALESCE(p.proconfig::text,'')),'acl_text_or_empty',(COALESCE(p.proacl::text,'')),'definition',(CASE WHEN p.oid='public.zasp_production_runtime_precision_live_fingerprint()'::regprocedure THEN (SELECT definition FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_production_runtime_precision_live_fingerprint()') ELSE CASE WHEN p.oid IN('public.zasp_runtime_precision_batch_insert_guard()'::regprocedure,'public.zasp_runtime_precision_batch_update_guard()'::regprocedure,'public.zasp_runtime_precision_stage_insert_guard()'::regprocedure,'public.zasp_runtime_precision_claim_version_guard()'::regprocedure,'public.zasp_runtime_precision_reconciliation_guard()'::regprocedure,'public.zasp_runtime_precision_outbox_guard()'::regprocedure,'public.zasp_runtime_precision_delivery_guard()'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE to_regprocedure(signature)=p.oid) ELSE pg_get_functiondef(p.oid) END END),'config_json',(to_jsonb(p.proconfig)),'config_raw',(p.proconfig::text),'config_dims',(array_dims(p.proconfig)),'config_ndims',(array_ndims(p.proconfig)),'config_bounds',((SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='zasp_precision_predecessor' OR n.nspname='public' AND (p.proname LIKE '%precision%' OR p.proname LIKE '%precise%' OR p.proname IN('zasp_runtime_claim_archive_v2','zasp_runtime_claim_index_v2','zasp_runtime_claim_correlation_v4','zasp_runtime_claim_projection_v3','zasp_runtime_claim_completion_v3','zasp_runtime_claim_reconciliation_v2','zasp_runtime_claim_outbox_v2'))
) AS capture_original_0537
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved-table:relation','identity',NULL,'handle','pg_class:'||c.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('owner',(c.relowner::regrole::text),'acl_raw',(c.relacl::text),'row_security',(c.relrowsecurity),'forced_row_security',(c.relforcerowsecurity))) FROM pg_class c WHERE c.oid='zasp_sa_attack_lab_prior.functions'::regclass
) AS capture_original_0538
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved-table:column','identity',NULL,'handle','pg_attribute:'||a.attrelid::text||':'||a.attnum::text,'multiplicity',1,'fact',jsonb_build_object('position',(a.attnum),'name',(a.attname::text),'type',(format_type(a.atttypid,a.atttypmod)),'not_null',(a.attnotnull),'default',(COALESCE(pg_get_expr(d.adbin,d.adrelid),'')))) FROM pg_attribute a LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_sa_attack_lab_prior.functions'::regclass AND a.attnum>0 AND NOT a.attisdropped
) AS capture_original_0539
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved-table:constraint','identity',NULL,'handle','pg_constraint:'||k.oid::text||':'||'0','multiplicity',1,'fact',jsonb_build_object('name',(k.conname::text),'definition',(pg_get_constraintdef(k.oid)))) FROM pg_constraint k WHERE k.conrelid='zasp_sa_attack_lab_prior.functions'::regclass
) AS capture_original_0540
