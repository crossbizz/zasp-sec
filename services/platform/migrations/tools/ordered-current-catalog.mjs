// Compiler-owned direct catalog projections. No caller supplies executable SQL.
import {canonicalOrderedJSON, normalizeOrderedFacts, admitCollectorSource} from './build-ordered-current-integrity.mjs';
import crypto from 'node:crypto';
import {staticDescriptor} from './ordered-current-static-catalog.mjs';
import {canonicalizeOrderedCurrentDirectReferenceIdentityV2,resolveOrderedCurrentForeignKeyEdge,canonicalizeOrderedCurrentSourceQualificationV2} from './ordered-current-direct-reference-v2.mjs';
import {admitOrderedDirectFrameSourceV1,bindOrderedDirectFrameV1,directFrameAdmissionSQL,directFrameExpressionV1,directFrameInstallSQL,directFrameRuleFieldMatrixV1,directFrameVersion} from './ordered-current-direct-frame-v1.mjs';
import {precisionResolverExpressionV1,precisionResolverAdmissionSQLV1,precisionResolverInstallSQLV1,admitOrderedPrecisionResolverSourceV1} from './ordered-current-precision-resolver-frame-v1.mjs';
import {lowerOrderedTemporal72Catalog} from './ordered-current-temporal72.mjs';
import fs from 'node:fs';
const staticKinds=new Set(['saved_view','saved_constraint','saved_trigger','registration','profile_registration','runtime_registration','worker_registration']);
const descriptorFor=(kind,namespaces)=>{
  if(!staticKinds.has(kind))return descriptors[kind];
  const descriptor=staticDescriptor(kind,namespaces);
  // This original signature field is selected only at temporal76's saved table.
  return kind==='saved_constraint'&&namespaces.every(n=>n==='zasp_temporal76')?
    {...descriptor,fields:{...descriptor.fields,signature:'s.row_key::text'}}:descriptor;
};

const quote = value => "'"+value.replaceAll("'","''")+"'";
const qualifiedRelation = 'c.oid::regclass::text';
const composite = (...parts) => "'['||"+parts.map(p=>'pg_catalog.to_json('+p+')::text').join("||','||")+"||']'";
const savedSchemas = ['zasp_sa_attack_lab_prior','zasp_sa_export_prior','zasp_sa_webhook_prior','zasp_schedule_replay_prior','zasp_sa_multistep_prior',...Array.from({length:12},(_,i)=>'zasp_temporal'+(i+67)),'zasp_authorization80_worker','zasp_authorization80_runtime','zasp_authorization80_temporal'];
export const orderedSavedFunctionTables = Object.freeze(savedSchemas.map(schema=>schema+'.'+(schema.endsWith('_prior')?'functions':'predecessor_functions')));
const nativeRoles=['zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting'];
// Fields below are available projections, not a release-wide hardening list.
// compileOrderedCollector emits only fields chosen by reviewed source selectors.
const descriptors = {
  namespace: {identity:'n.nspname::text', namespace:'n.nspname::text', from:'pg_catalog.pg_namespace n', fields:{owner:'n.nspowner::regrole::text',acl:'n.nspacl::text'}},
  routine: {identity:'p.oid::regprocedure::text', namespace:'n.nspname::text', from:'pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_language l ON l.oid=p.prolang', fields:{
    routine_oid:'p.oid::text',definition_oid:'p.oid::text',owner:'p.proowner::regrole::text',acl:'p.proacl::text',language:'l.lanname::text',definition:"CASE WHEN p.prokind<>'a' THEN pg_catalog.pg_get_functiondef(p.oid) ELSE NULL END",security_definer:'p.prosecdef',volatility:'p.provolatile::text',strict:'p.proisstrict',parallel:'p.proparallel::text',leakproof:'p.proleakproof',config:'p.proconfig',cost:'p.procost',rows:'p.prorows',result:'pg_catalog.pg_get_function_result(p.oid)',arguments:'pg_catalog.pg_get_function_arguments(p.oid)',binary:'p.probin',returns_set:'p.proretset'}},
  relation: {identity:qualifiedRelation,namespace:'n.nspname::text',from:'pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace',fields:{kind:'c.relkind::text',owner:'c.relowner::regrole::text',acl:'c.relacl::text',row_security:'c.relrowsecurity',forced_row_security:'c.relforcerowsecurity',persistence:'c.relpersistence::text',replica_identity:'c.relreplident::text',options:'c.reloptions',partition_bound:'pg_catalog.pg_get_expr(c.relpartbound,c.oid)'}},
  column: {identity:composite(qualifiedRelation,'a.attnum'),namespace:'n.nspname::text',from:'pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum)',where:'a.attnum>0 AND NOT a.attisdropped',fields:{name:'a.attname::text',position:'a.attnum',type:'pg_catalog.format_type(a.atttypid,a.atttypmod)',not_null:'a.attnotnull',default:'pg_catalog.pg_get_expr(d.adbin,d.adrelid)',acl:'a.attacl::text',collation:"NULLIF(a.attcollation::regcollation::text,'-')",identity:'a.attidentity::text',generated:'a.attgenerated::text',storage:'a.attstorage::text',compression:'a.attcompression::text',type_modifier:'a.atttypmod'}},
  constraint: {identity:composite(qualifiedRelation,'k.conname::text'),namespace:'n.nspname::text',from:'pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace',fields:{definition:'pg_catalog.pg_get_constraintdef(k.oid)',validated:'k.convalidated',deferrable:'k.condeferrable',deferred:'k.condeferred',constraint_type:'k.contype::text',no_inherit:'k.connoinherit'}},
  index: {identity:'i.indexrelid::regclass::text',namespace:'n.nspname::text',from:'pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace',fields:{definition:'pg_catalog.pg_get_indexdef(i.indexrelid)',valid:'i.indisvalid',ready:'i.indisready',live:'i.indislive',unique:'i.indisunique',primary:'i.indisprimary',exclusion:'i.indisexclusion',predicate:'pg_catalog.pg_get_expr(i.indpred,i.indrelid)',expressions:'pg_catalog.pg_get_expr(i.indexprs,i.indrelid)'}},
  policy: {identity:composite(qualifiedRelation,'p.polname::text'),namespace:'n.nspname::text',from:'pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace',fields:{command:'p.polcmd::text',permissive:'p.polpermissive',roles:'p.polroles::regrole[]::text',using:'pg_catalog.pg_get_expr(p.polqual,p.polrelid)',check:'pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)'}},
  trigger: {identity:composite(qualifiedRelation,'t.tgname::text'),namespace:'n.nspname::text',from:'pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace',fields:{enabled:'t.tgenabled::text',definition:'pg_catalog.pg_get_triggerdef(t.oid)',function:'t.tgfoid::regprocedure::text',internal:'t.tgisinternal',deferrable:'t.tgdeferrable',deferred:'t.tginitdeferred',arguments:"pg_catalog.encode(t.tgargs,'hex')",event_bits:'t.tgtype',when:'CASE WHEN t.tgqual IS NULL THEN NULL ELSE pg_catalog.pg_get_triggerdef(t.oid,true) END',old_table:'t.tgoldtable::text',new_table:'t.tgnewtable::text'}},
  view: {identity:qualifiedRelation,namespace:'n.nspname::text',from:'pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace',where:"c.relkind IN('v','m')",fields:{definition:'pg_catalog.pg_get_viewdef(c.oid)',owner:'c.relowner::regrole::text',acl:'c.relacl::text',options:'c.reloptions'}},
  rewrite: {identity:composite(qualifiedRelation,'r.rulename::text'),namespace:'n.nspname::text',from:'pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace',fields:{event:'r.ev_type::text',enabled:'r.ev_enabled::text',instead:'r.is_instead',definition:'pg_catalog.pg_get_ruledef(r.oid)'}},
  role: {identity:'r.rolname::text',namespace:"''::text",from:'pg_catalog.pg_roles r',fields:{login:'r.rolcanlogin',inherit:'r.rolinherit',superuser:'r.rolsuper',create_db:'r.rolcreatedb',create_role:'r.rolcreaterole',replication:'r.rolreplication',bypass_rls:'r.rolbypassrls'}},
  membership: {identity:composite('m.roleid::regrole::text','m.member::regrole::text','m.grantor::regrole::text'),namespace:'m.roleid::regrole::text',member:'m.member::regrole::text',from:'pg_catalog.pg_auth_members m',fields:{admin:'m.admin_option',inherit:'m.inherit_option',set:'m.set_option',grantor:'m.grantor::regrole::text'}},
  saved_function:{identity:composite('s.namespace::text','s.signature::text'),namespace:'s.namespace::text',fields:{definition:'s.definition::text',owner:'s.owner_name::text',acl:'s.acl::text'}},
  default_acl: {identity:composite('d.defaclrole::regrole::text',"COALESCE(n.nspname::text,'')",'d.defaclobjtype::text'),namespace:"COALESCE(n.nspname::text,'')",from:'pg_catalog.pg_default_acl d LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace',fields:{acl:'d.defaclacl::text'}},
  extension: {identity:'e.extname::text',namespace:'n.nspname::text',from:'pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace',fields:{schema:'n.nspname::text',version:'e.extversion',owner:'e.extowner::regrole::text',relocatable:'e.extrelocatable'}}
};
const strings = value => Array.isArray(value) && value.every(s=>typeof s==='string'&&s.length&&!s.includes('\0')) && new Set(value).size===value.length;
Object.assign(descriptors.trigger.fields,{function_definition:'pg_catalog.pg_get_functiondef(trigger_proc.oid)',function_owner:'trigger_proc.proowner::regrole::text',function_acl:'trigger_proc.proacl::text'});
Object.assign(descriptors.routine.fields,{name:'p.proname::text',identity_arguments:'pg_catalog.pg_get_function_identity_arguments(p.oid)',config_text_or_empty:"COALESCE(p.proconfig::text,'')",acl_text_or_empty:"COALESCE(p.proacl::text,'')"});
Object.assign(descriptors.routine.fields,{source:'p.prosrc::text',sql_body:'p.prosqlbody::text',kind:'p.prokind::text',input_types:'ARRAY(SELECT args.unnest::regtype::text FROM pg_catalog.unnest(p.proargtypes) WITH ORDINALITY AS args(unnest, ordinality) ORDER BY args.ordinality)',all_types:'p.proallargtypes::regtype[]::text[]',argument_names:'p.proargnames',argument_modes:'p.proargmodes::text[]',argument_defaults:'p.proargdefaults::text',default_count:'p.pronargdefaults',variadic_type:'CASE WHEN p.provariadic=0 THEN NULL ELSE p.provariadic::regtype::text END',result_type:'p.prorettype::regtype::text',support:'CASE WHEN p.prosupport=0 THEN NULL ELSE p.prosupport::regprocedure::text END',transforms:'p.protrftypes::regtype[]::text[]'});
Object.assign(descriptors.relation.fields,{name:'c.relname::text',acl_text_or_empty:"COALESCE(c.relacl::text,'')",options_text_or_empty:"COALESCE(c.reloptions::text,'')"});
Object.assign(descriptors.column.fields,{default_text_or_empty:"COALESCE(pg_catalog.pg_get_expr(d.adbin,d.adrelid),'')",acl_text_or_empty:"COALESCE(a.attacl::text,'')",normalized_position:"CASE WHEN a.attrelid='public.zasp_runtime_candidate_observations'::regclass AND a.attname='sandbox_id' THEN (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute live WHERE live.attrelid=a.attrelid AND live.attnum>0 AND live.attnum<=a.attnum AND NOT live.attisdropped) ELSE a.attnum END"});
Object.assign(descriptors.constraint.fields,{name:'k.conname::text',relation:'k.conrelid::regclass::text',definition_pretty:'pg_catalog.pg_get_constraintdef(k.oid,true)'});
Object.assign(descriptors.trigger.fields,{name:'t.tgname::text',definition_pretty:'pg_catalog.pg_get_triggerdef(t.oid,true)'});
descriptors.column_name={...descriptors.column,identity:composite(qualifiedRelation,'a.attname::text')};
descriptors.global_constraint={...descriptors.constraint,identity:composite('k.conrelid::regclass::text','k.conname::text'),from:'pg_catalog.pg_constraint k LEFT JOIN pg_catalog.pg_class c ON c.oid=k.conrelid LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace'};
descriptors.policy_view={identity:composite('v.schemaname::text','v.tablename::text','v.policyname::text'),namespace:'v.schemaname::text',from:'pg_catalog.pg_policies v',fields:{name:'v.policyname::text',table_name:'v.tablename::text',roles:'v.roles::text',command:'v.cmd::text',using:'v.qual::text',check:'v.with_check::text',permissive:'v.permissive::text'}};
descriptors.index_view={identity:composite('v.schemaname::text','v.tablename::text','v.indexname::text'),namespace:'v.schemaname::text',from:'pg_catalog.pg_indexes v',fields:{name:'v.indexname::text',table_name:'v.tablename::text',definition:'v.indexdef::text'}};
descriptors.information_column={identity:composite('v.table_schema::text','v.table_name::text','v.column_name::text'),namespace:'v.table_schema::text',from:'information_schema.columns v',fields:{name:'v.column_name::text',table_name:'v.table_name::text',data_type:'v.data_type::text',is_nullable:'v.is_nullable::text',default_text_or_empty:"COALESCE(v.column_default::text,'')"}};
descriptors.policy_view.fields.roles_text='v.roles::text';
descriptors.information_column.fields.relation_name='v.table_name::text';
descriptors.policy_view.fields.relation_name='v.tablename::text';
descriptors.column.fields.relation=qualifiedRelation;
descriptors.trigger.fields.relation=qualifiedRelation;
descriptors.fixed_runtime_profile={identity:composite("'zasp_authorization80.runtime_profile'::text",'s.singleton'),namespace:"'zasp_authorization80'::text",from:'zasp_authorization80.runtime_profile s',fields:{singleton:'s.singleton',name:'s.name::text'}};
descriptors.type={identity:'t.oid::regtype::text',namespace:'n.nspname::text',from:'pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace',fields:{kind:'t.typtype::text',category:'t.typcategory::text',owner:'t.typowner::regrole::text',acl:'t.typacl::text',relation:'CASE WHEN t.typrelid=0 THEN NULL ELSE t.typrelid::regclass::text END',element:'CASE WHEN t.typelem=0 THEN NULL ELSE t.typelem::regtype::text END',array:'CASE WHEN t.typarray=0 THEN NULL ELSE t.typarray::regtype::text END',base:'CASE WHEN t.typbasetype=0 THEN NULL ELSE t.typbasetype::regtype::text END',not_null:'t.typnotnull',default:'t.typdefault::text',collation:'CASE WHEN t.typcollation=0 THEN NULL ELSE t.typcollation::regcollation::text END',input:'t.typinput::regprocedure::text',output:'t.typoutput::regprocedure::text',receive:'CASE WHEN t.typreceive=0 THEN NULL ELSE t.typreceive::regprocedure::text END',send:'CASE WHEN t.typsend=0 THEN NULL ELSE t.typsend::regprocedure::text END',analyze:'CASE WHEN t.typanalyze=0 THEN NULL ELSE t.typanalyze::regprocedure::text END',subscript:'CASE WHEN t.typsubscript=0 THEN NULL ELSE t.typsubscript::regprocedure::text END',length:'t.typlen',by_value:'t.typbyval',alignment:'t.typalign::text',storage:'t.typstorage::text',delimiter:'t.typdelim::text',preferred:'t.typispreferred',defined:'t.typisdefined',type_modifier:'t.typtypmod',dimensions:'t.typndims'}};
descriptors.column.fields.relation_name='c.relname::text';
descriptors.index.fields.name='index_class.relname::text';
descriptors.index.from+=' JOIN pg_catalog.pg_class index_class ON index_class.oid=i.indexrelid';
Object.assign(descriptors.policy.fields,{name:'p.polname::text',roles_csv_public_sorted:"COALESCE((SELECT pg_catalog.string_agg(CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE role_row.rolname END,',' ORDER BY CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE role_row.rolname END) FROM pg_catalog.unnest(p.polroles) role_oid LEFT JOIN pg_catalog.pg_roles role_row ON role_row.oid=role_oid),'')",roles_named_array_text:'ARRAY(SELECT role_row.rolname FROM pg_catalog.pg_roles role_row WHERE role_row.oid=ANY(p.polroles) ORDER BY role_row.rolname)::text',using_text_or_empty:"COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')",check_text_or_empty:"COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),'')"});
Object.assign(descriptors.namespace.fields,{name:'n.nspname::text',acl_text_or_empty:"COALESCE(n.nspacl::text,'')"});
for(const kind of ['constraint','index','policy'])descriptors[kind].fields.relation_name='c.relname::text';
descriptors.foreign_key_trigger={identity:composite('k.conrelid::regclass::text','k.conname::text','t.tgrelid::regclass::text','t.tgfoid::regprocedure::text','t.tgtype'),namespace:'n.nspname::text',from:'pg_catalog.pg_trigger t JOIN pg_catalog.pg_constraint k ON k.oid=t.tgconstraint JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace',where:"t.tgisinternal AND k.contype='f'",fields:{relation:'k.conrelid::regclass::text',name:'k.conname::text',referenced_relation:'k.confrelid::regclass::text',trigger_relation:'t.tgrelid::regclass::text',constraint_relation:'t.tgconstrrelid::regclass::text',function:'t.tgfoid::regprocedure::text',event_bits:'t.tgtype',enabled:'t.tgenabled::text',deferrable:'t.tgdeferrable',deferred:'t.tginitdeferred',argument_count:'t.tgnargs',arguments:"pg_catalog.encode(t.tgargs,'hex')",columns_text:'t.tgattr::text',when_text_or_empty:"COALESCE(CASE WHEN t.tgqual IS NULL THEN NULL ELSE pg_catalog.pg_get_triggerdef(t.oid,true) END,'')"}};
descriptors.saved_function.fields.signature='s.signature::text';
Object.assign(descriptors.column.fields,{type_identity:'a.atttypid::regtype::text',default_pretty_text_or_empty:"COALESCE(pg_catalog.pg_get_expr(d.adbin,d.adrelid,true),'')"});
descriptors.index.fields.definition_pretty='pg_catalog.pg_get_indexdef(i.indexrelid,0,true)';
Object.assign(descriptors.trigger.fields,{function_name:'trigger_proc.proname::text',function_identity_arguments:'pg_catalog.pg_get_function_identity_arguments(t.tgfoid)',relation_name:'c.relname::text'});
Object.assign(descriptors.policy.fields,{namespace_name:'c.relnamespace::regnamespace::text',relation:'p.polrelid::regclass::text'});
for(const kind of ['relation','column','trigger'])descriptors[kind].fields.namespace_name='n.nspname::text';
descriptors.role.fields.name='r.rolname::text';
descriptors.routine.fields.namespace_name='n.nspname::text';
descriptors.column_all={...descriptors.column_name,where:'NOT a.attisdropped'};
descriptors.index.fields.owner='index_class.relowner::regrole::text';
descriptors.policy_view.fields.namespace_name='v.schemaname::text';
// Exact temporal72 source expressions. JSON arrays use PostgreSQL's lossless
// jsonb text encoding here; tuple ordering, NULLs and grantor names stay intact.
const executionACL=(acl,owner,kind)=>`COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM pg_catalog.aclexplode(COALESCE(${acl},pg_catalog.acldefault('${kind}',${owner}))) acl LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_catalog.pg_roles grantor ON grantor.oid=acl.grantor),'[]'::jsonb)::text`;
descriptors.relation.fields.execution_acl_text=executionACL('c.relacl','c.relowner','r');
descriptors.routine.fields.execution_acl_text=executionACL('p.proacl','p.proowner','f');
descriptors.routine.fields.execution_config_text="COALESCE(pg_catalog.to_jsonb(p.proconfig),'[]'::jsonb)::text";
descriptors.routine.fields.execution_body=String.raw`pg_catalog.regexp_replace(pg_catalog.btrim(CASE WHEN p.oid='public.zasp_execution_claim_jobs(text,text,integer,integer)'::regprocedure THEN (SELECT pg_catalog.split_part(definition,pg_catalog.chr(36)||'function'||pg_catalog.chr(36),2) FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_execution_claim_jobs(text,text,integer,integer)') ELSE p.prosrc END),E'\s+',' ','g')`;
descriptors.policy.fields.execution_roles_text='(SELECT pg_catalog.jsonb_agg(role.rolname ORDER BY role.rolname) FROM pg_catalog.unnest(p.polroles) role_oid JOIN pg_catalog.pg_roles role ON role.oid=role_oid)::text';
descriptors.trigger.fields.execution_definition=String.raw`pg_catalog.regexp_replace(pg_catalog.pg_get_triggerdef(t.oid,true),E'\s+',' ','g')`;
descriptors.role.fields.execution_v1_managed_here="pg_catalog.shobj_description(r.oid,'pg_authid')=ANY(ARRAY[pg_catalog.format('zasp-managed:production-discovery-execution-v1:database:%s:created',(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())),pg_catalog.format('zasp-managed:production-discovery-execution-v1:database:%s:bound',(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()))])";
descriptors.role.fields.inventory_v1_managed_here="pg_catalog.shobj_description(r.oid,'pg_authid')=ANY(ARRAY[pg_catalog.format('zasp-managed:typed-inventory-cutover-v1:database:%s:created',(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())),pg_catalog.format('zasp-managed:typed-inventory-cutover-v1:database:%s:bound',(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()))])";
const inventoryCore="p.proname IN('zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence')";
// Original literal resolves to this captured identity under pg_catalog,public.
// Keep its original resolution/error obligation outside this pg_catalog frame.
const inventoryOwner="(SELECT relowner FROM pg_catalog.pg_class WHERE oid='public.zasp_core_payloads'::regclass)";
descriptors.routine.fields.inventory_owner=`CASE WHEN ${inventoryCore} AND p.proowner=${inventoryOwner} THEN 'zasp-core-owner' ELSE p.proowner::regrole::text END`;
const inventoryGrantee=`CASE WHEN acl.grantee=0 THEN 'PUBLIC' WHEN ${inventoryCore} AND acl.grantee=${inventoryOwner} THEN 'zasp-core-owner' ELSE grantee.rolname END`;
const inventoryGrantor=`CASE WHEN ${inventoryCore} AND acl.grantor=${inventoryOwner} THEN 'zasp-core-owner' ELSE grantor.rolname END`;
descriptors.routine.fields.inventory_acl_text=`COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(${inventoryGrantee},acl.privilege_type,acl.is_grantable,${inventoryGrantor}) ORDER BY ${inventoryGrantee},acl.privilege_type,acl.is_grantable,${inventoryGrantor}) FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_catalog.pg_roles grantor ON grantor.oid=acl.grantor),'[]'::jsonb)::text`;
descriptors.routine.fields.inventory_body=String.raw`pg_catalog.regexp_replace(pg_catalog.btrim(p.prosrc),E'\s+',' ','g')`;
descriptors.routine.fields.precision_definition="CASE WHEN p.oid='public.zasp_production_runtime_precision_live_fingerprint()'::regprocedure THEN (SELECT definition FROM zasp_temporal72.predecessor_functions WHERE signature='zasp_production_runtime_precision_live_fingerprint()') ELSE CASE WHEN p.oid IN('public.zasp_runtime_precision_batch_insert_guard()'::regprocedure,'public.zasp_runtime_precision_batch_update_guard()'::regprocedure,'public.zasp_runtime_precision_stage_insert_guard()'::regprocedure,'public.zasp_runtime_precision_claim_version_guard()'::regprocedure,'public.zasp_runtime_precision_reconciliation_guard()'::regprocedure,'public.zasp_runtime_precision_outbox_guard()'::regprocedure,'public.zasp_runtime_precision_delivery_guard()'::regprocedure) THEN (SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE pg_catalog.to_regprocedure(signature)=p.oid) ELSE pg_catalog.pg_get_functiondef(p.oid) END END";
descriptors.class_index={identity:qualifiedRelation,namespace:'n.nspname::text',from:'pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace',fields:{name:'c.relname::text',definition:'pg_catalog.pg_get_indexdef(c.oid)'}};
const selectorFields = {
  namespace:{name:'n.nspname::text'},routine:{name:'p.proname::text'},
  relation:{name:'c.relname::text',relation_kind:'c.relkind::text'},
  column:{name:'a.attname::text',relation:qualifiedRelation,relation_name:'c.relname::text'},
  constraint:{name:'k.conname::text',relation:qualifiedRelation,relation_name:'c.relname::text'},
  index:{relation:qualifiedRelation,relation_name:'c.relname::text'},
  policy:{name:'p.polname::text',relation:qualifiedRelation,relation_name:'c.relname::text'},
  trigger:{name:'t.tgname::text',relation:qualifiedRelation,relation_name:'c.relname::text',function:'t.tgfoid::regprocedure::text'},
  view:{name:'c.relname::text',relation_kind:'c.relkind::text'},
  rewrite:{name:'r.rulename::text',relation:qualifiedRelation,relation_name:'c.relname::text'},
  role:{name:'r.rolname::text'},membership:{member:'m.member::regrole::text'},extension:{name:'e.extname::text'}
};
selectorFields.column_name=selectorFields.column;
selectorFields.column_all=selectorFields.column;
selectorFields.global_constraint={...selectorFields.constraint,relation:'k.conrelid::regclass::text'};
for(const kind of ['policy_view','index_view','information_column'])selectorFields[kind]={name:descriptors[kind].fields.name,relation:kind==='information_column'?"v.table_schema::text||'.'||v.table_name::text":"v.schemaname::text||'.'||v.tablename::text",relation_name:descriptors[kind].fields.table_name,table_name:descriptors[kind].fields.table_name};
selectorFields.foreign_key_trigger={name:'k.conname::text',relation:'k.conrelid::regclass::text',relation_name:'c.relname::text'};
selectorFields.class_index={name:'c.relname::text',relation_kind:'c.relkind::text'};
// Add new selector columns only when a new rule actually needs them. Existing
// frozen reference SELECT bytes remain unchanged for their original rule set.
const additionalSelectorFields={index:{name:'index_class.relname::text'},column:{relation_kind:'c.relkind::text'},column_name:{relation_kind:'c.relkind::text'}};
const selectedSelectorFields=(kind,rules)=>{
  const names=new Set();
  const visit=s=>{if(!s)return;if(s.field)names.add(s.field);for(const c of s.all??s.any??[])visit(c);if(s.not)visit(s.not);};
  rules.forEach(r=>visit(r.selector));
  return {...selectorFields[kind],...Object.fromEntries(Object.entries(additionalSelectorFields[kind]??{}).filter(([name])=>names.has(name)))};
};
function validateSelector(selector,fields,depth=0,kind) {
  if(!selector||typeof selector!=='object'||Array.isArray(selector)||depth>8)throw Error('invalid selector expression');
  const keys=Object.keys(selector).sort().join(',');
  if(keys==='not')validateSelector(selector.not,fields,depth+1,kind);
  else if(keys==='all'||keys==='any') {
    const children=selector[keys];if(!Array.isArray(children)||!children.length)throw Error('empty selector expression');
    for(const child of children)validateSelector(child,fields,depth+1,kind);
  } else if(keys==='field,regprocedureEquals') {
    if(kind!=='routine'||selector.field!=='identity'||typeof selector.regprocedureEquals!=='string'||!/^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*\([a-z0-9_, [\]]*\)$/.test(selector.regprocedureEquals))throw Error('invalid regprocedure selector');
  } else {
    if(!['equals,field','field,startsWith','field,like'].includes(keys)||!Object.hasOwn(fields,selector.field))throw Error('unknown selector field');
    const value=selector.equals??selector.startsWith??selector.like;if(typeof value!=='string'||!value||value.includes('\0'))throw Error('invalid selector literal');
    if(selector.like)likePattern(selector.like);
  }
}
function likePattern(pattern){let regex='^';const escape=c=>c.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');for(let i=0;i<pattern.length;i++){const c=pattern[i];if(c==='\\'){if(++i===pattern.length)throw Error('invalid LIKE escape');regex+=escape(pattern[i]);}else regex+=c==='%'?'[\\s\\S]*':c==='_'?'[\\s\\S]':escape(c);}return new RegExp(regex+'$','u');}
const selectorSQL=(selector,fields)=>selector.not?'(NOT '+selectorSQL(selector.not,fields)+')':selector.all?'('+selector.all.map(s=>selectorSQL(s,fields)).join(' AND ')+')':selector.any?'('+selector.any.map(s=>selectorSQL(s,fields)).join(' OR ')+')':Object.hasOwn(selector,'regprocedureEquals')?'('+fields[selector.field]+'::regprocedure='+quote(selector.regprocedureEquals)+'::regprocedure)':Object.hasOwn(selector,'equals')?'('+fields[selector.field]+'='+quote(selector.equals)+')':selector.like?'('+fields[selector.field]+' LIKE '+quote(selector.like)+')':'pg_catalog.starts_with('+fields[selector.field]+','+quote(selector.startsWith)+')';
const needsResolution=s=>Boolean(s&&(Object.hasOwn(s,'regprocedureEquals')||(s.all??s.any??[]).some(needsResolution)||needsResolution(s.not)));
function selectorMatches(selector,row){
  if(needsResolution(selector))throw Error('independent regprocedure resolution metadata required');
  if(selector.not){const value=selectorMatches(selector.not,row);return value===null?null:!value;}
  if(selector.all||selector.any){const values=(selector.all??selector.any).map(s=>selectorMatches(s,row));return selector.all?(values.includes(false)?false:values.includes(null)?null:true):(values.includes(true)?true:values.includes(null)?null:false);}
  if(row[selector.field]===null||row[selector.field]===undefined)return null;
  return Object.hasOwn(selector,'equals')?row[selector.field]===selector.equals:typeof row[selector.field]==='string'&&(selector.like?likePattern(selector.like).test(row[selector.field]):row[selector.field].startsWith(selector.startsWith));
}
export function validateOrderedSelectors(rules) {
  if (!Array.isArray(rules)||!rules.length) throw Error('empty selector program');
  const ids=new Set();
  for (const rule of rules) {
    const keys=rule&&Object.keys(rule).sort().join(',');
    const special=rule?.predicate==='fixed-native-negative-universe'&&rule.kind==='membership';
    const userTriggers=rule?.predicate==='user-triggers'&&rule.kind==='trigger';
    if (!rule || !['fields,id,identities,kind,namespaces','fields,id,identities,kind,namespaces,predicate','fields,id,identities,kind,namespaces,selector','fields,id,identities,kind,namespaces,predicate,selector'].includes(keys) || Object.hasOwn(rule,'predicate')&&!special&&!userTriggers || typeof rule.id!=='string'||!rule.id||ids.has(rule.id)||!Object.hasOwn(descriptors,rule.kind)&&!staticKinds.has(rule.kind)||!strings(rule.fields)||!rule.fields.length||!strings(rule.namespaces)||!strings(rule.identities)||!rule.namespaces.length&&!rule.identities.length&&!special&&!rule.selector) throw Error('unsupported selector');
    if(staticKinds.has(rule.kind)&&(rule.selector||rule.identities.length))throw Error('unsupported static selector');
    if(rule.kind==='fixed_runtime_profile'&&(rule.selector||rule.identities.length||rule.namespaces.length!==1||rule.namespaces[0]!=='zasp_authorization80'))throw Error('unsupported fixed profile selector');
    const descriptor=descriptorFor(rule.kind,rule.namespaces);
    if(rule.selector){if(rule.namespaces.length||rule.identities.length||special)throw Error('mixed selector representations');validateSelector(rule.selector,{identity:descriptors[rule.kind].identity,namespace:descriptors[rule.kind].namespace,...selectorFields[rule.kind],...additionalSelectorFields[rule.kind]},0,rule.kind);}
    if(special&&(rule.namespaces.length||rule.identities.length))throw Error('fixed native predicate cannot be widened');
    if(rule.kind==='saved_function'&&(!rule.namespaces.length||rule.namespaces.some(n=>!savedSchemas.includes(n))))throw Error('unsupported saved source');
    if(rule.fields.some(f=>!Object.hasOwn(descriptor.fields,f))) throw Error('unsupported field projection');
    ids.add(rule.id);
  }
}
export function projectOrderedFacts(rules, input) {
  validateOrderedSelectors(rules);
  if(rules.some(r=>needsResolution(r.selector)))throw Error('independent regprocedure resolution metadata required');
  if (!Array.isArray(input)) throw Error('invalid descriptor input');
  const seen=new Set();
  for(const row of input) {
    const key=canonicalOrderedJSON([row.kind,row.identity]);
    if(seen.has(key))throw Error('duplicate descriptor');seen.add(key);
    normalizeOrderedFacts([{kind:row.kind,identity:row.identity,fact:row.fact}]);
  }
  return normalizeOrderedFacts(rules.flatMap(rule=>input.filter(row=>row.kind===rule.kind&&(rule.predicate!=='user-triggers'||row.fact.internal===false)&&(rule.selector?selectorMatches(rule.selector,row):rule.predicate==='fixed-native-negative-universe'?(row.namespace==='zasp_temporal_accounting'||nativeRoles.includes(row.member)):(rule.namespaces.includes(row.namespace)||rule.identities.includes(row.identity)))).map(row=>({kind:row.kind,identity:canonicalOrderedJSON([rule.id,row.identity]),fact:Object.fromEntries(rule.fields.map(field=>{
    if(!Object.hasOwn(row.fact,field))throw Error('missing required descriptor field');
    return [field,row.fact[field]];
  }))}))));
}

const catalogBoundIdentityKinds = new Set(['column_name','column_all','constraint','foreign_key_trigger','index_view','policy','policy_view','relation','routine','trigger','fixed_runtime_profile']);
const foreignKeyRelationFields = ['relation','constraint_relation','trigger_relation','referenced_relation'];
const native16QualificationConstraintRules = new Set([
  'worker-edge:gateway_projected24:4',
  'worker-edge:gateway_projected27:7',
  'worker-edge:gateway_projected27:9',
  'worker-edge:ordered_projected28:7',
  'worker-edge:runtime_projected40:4',
  'worker-edge:runtime_projected50_search:5',
]);
function canonicalFKRelation(value, authority, ruleId, field) {
  if (typeof authority !== 'string' || !authority) throw Error(`${ruleId} semantic fact join ${field} authority unavailable`);
  if (typeof value !== 'string' || !value) throw Error(`${ruleId} semantic fact join ${field} value`);
  const separator = authority.indexOf('.');
  const unqualified = separator < 0 ? authority : authority.slice(separator + 1);
  if (value !== authority && value !== unqualified) throw Error(`${ruleId} semantic fact join ${field} qualification`);
  return authority;
}
export function canonicalizeOrderedCurrentDevelopmentFacts(facts, rules, catalog) {
  if (!Array.isArray(facts)||!Array.isArray(rules)||!catalog||typeof catalog!=='object') throw Error('invalid development identity boundary');
  const byId=new Map(rules.map(rule=>[rule.id,rule]));
  return facts.map(row=>{
    if (!row||typeof row.identity!=='string') throw Error('invalid development fact identity');
    let outer;try{outer=JSON.parse(row.identity);}catch{throw Error('invalid development fact identity');}
    if (!Array.isArray(outer)||outer.length!==2||typeof outer[0]!=='string'||typeof outer[1]!=='string') throw Error('invalid development fact identity');
    const rule=byId.get(outer[0]);
    if (!rule||!catalogBoundIdentityKinds.has(rule.kind)) return row;
    if ((rule.kind==='routine'&&!['inventory-fields:function','temporal72:function'].includes(rule.id))||
      (rule.kind==='relation'&&!['inventory-fields:table','temporal72:table'].includes(rule.id))||
      (rule.kind==='fixed_runtime_profile'&&rule.id!=='role-profile:current-profile')||
      (rule.kind==='trigger'&&!rule.id.startsWith('worker-edge:')) ) return row;
    const qualify = (rule.kind==='trigger'&&rule.id.startsWith('worker-edge:')) ||
      (rule.kind==='constraint'&&native16QualificationConstraintRules.has(rule.id));
    let sourceRow=row;
    if(qualify){
      try { sourceRow=canonicalizeOrderedCurrentSourceQualificationV2(rule,row,catalog); }
      catch(error){
        // A pinned candidate that differs beyond qualification is a refusal,
        // not an admission failure: retain the original fact so the native
        // mismatch remains visible. Missing/ambiguous authority still fails.
        if(!/semantic difference|not qualification-only|qualification target/.test(String(error?.message)))throw error;
      }
    }
    const descriptorIdentity=canonicalizeOrderedCurrentDirectReferenceIdentityV2(rule,{identity:outer[1],fact:sourceRow.fact},catalog);
    let fact=sourceRow.fact;
    if (['column_name','column_all'].includes(rule.kind)&&fact&&typeof fact==='object'&&Object.hasOwn(fact,'relation')) {
      let captureTuple;
      try { captureTuple=JSON.parse(outer[1]); } catch { throw Error(`${rule.id} semantic fact join identity`); }
      const candidates=catalog.columns.filter(candidate=>candidate.relation===captureTuple[0]&&candidate.position===captureTuple[1]&&candidate.name===captureTuple[2]);
      if (candidates.length!==1) throw Error(`${rule.id} semantic fact join catalog cardinality (${candidates.length})`);
      const qualified=candidates[0].relation;
      const separator=qualified.indexOf('.');
      const unqualified=separator<0?qualified:qualified.slice(separator+1);
      if (fact.relation!==qualified&&fact.relation!==unqualified) throw Error(`${rule.id} semantic fact join qualification`);
      fact={...fact,relation:qualified};
    }
    if (rule.kind==='foreign_key_trigger'&&fact&&typeof fact==='object') {
      const unknown=Object.keys(fact).filter(field=>!rule.fields.includes(field));
      if (unknown.length) throw Error(`${rule.id} semantic fact join unknown field`);
      const triggerTuple=JSON.parse(outer[1]);
      const canonicalTuple=JSON.parse(descriptorIdentity);
      const constraintCandidates=(catalog.constraints??[]).filter(candidate=>candidate?.relation===canonicalTuple[0]&&candidate?.name===canonicalTuple[1]);
      const triggerCandidates=(catalog.triggers??[]).filter(candidate=>candidate?.relation===triggerTuple[0]&&candidate?.name===triggerTuple[1]);
      if (constraintCandidates.length>1||triggerCandidates.length>1) throw Error(`${rule.id} semantic fact join relation cardinality`);
      const normalized={...fact};
      const edge=foreignKeyRelationFields.some(field=>Object.hasOwn(fact,field))?resolveOrderedCurrentForeignKeyEdge(rule,{identity:outer[1],fact},catalog):null;
      for (const field of foreignKeyRelationFields) {
        if (!Object.hasOwn(fact,field)) continue;
        let authority;
        if (field==='relation') authority=edge?.constraintRelation;
        else if (field==='constraint_relation') authority=edge?.constraintPeerRelation;
        else if (field==='trigger_relation') authority=edge?.triggerRelation;
        else if (field==='referenced_relation') authority=edge?.referencedRelation;
        normalized[field]=canonicalFKRelation(fact[field],authority,rule.id,field);
      }
      fact=normalized;
    }
    return {...sourceRow,identity:canonicalOrderedJSON([rule.id,descriptorIdentity]),fact};
  });
}
export function countOrderedReferenceCandidates(rules,input){
  validateOrderedSelectors(rules);
  if(rules.some(r=>needsResolution(r.selector)))throw Error('independent regprocedure resolution metadata required');
  return Object.fromEntries(rules.map(rule=>[rule.id,input.filter(row=>row.kind===rule.kind&&(rule.predicate!=='user-triggers'||row.fact?.internal===false)&&(rule.selector?selectorMatches(rule.selector,row):rule.predicate==='fixed-native-negative-universe'?(row.namespace==='zasp_temporal_accounting'||nativeRoles.includes(row.member)):(rule.namespaces.includes(row.namespace)||rule.identities.includes(row.identity)))).length]));
}
export function inspectOrderedReferenceRules(rules,input,capturedKinds){
  validateOrderedSelectors(rules);
  if(!(capturedKinds instanceof Set))throw Error('explicit captured descriptor universes required');
  const resolved=[],pending=[];
  for(const rule of rules){
    if(needsResolution(rule.selector)){pending.push({id:rule.id,kind:rule.kind,reason:'independent regprocedure resolution metadata required'});continue;}
    if(!capturedKinds.has(rule.kind)){pending.push({id:rule.id,kind:rule.kind,reason:'uncaptured descriptor universe'});continue;}
    const selected=input.filter(row=>row.kind===rule.kind&&(rule.predicate!=='user-triggers'||row.fact?.internal===false)&&(rule.selector?selectorMatches(rule.selector,row):(rule.namespaces.includes(row.namespace)||rule.identities.includes(row.identity))));
    const missingFields=[...new Set(selected.flatMap(row=>rule.fields.filter(field=>!Object.hasOwn(row.fact,field))))].sort();
    if(missingFields.length)pending.push({id:rule.id,kind:rule.kind,reason:'uncaptured selected projection',missingFields,candidates:selected.length});
    else resolved.push(rule);
  }
  return {resolved,pending};
}
// Offline reference adapter. Missing captured fields remain absent and selected
// projections then refuse; this never fills missing expectations from a target.
export function orderedReferenceInput(catalog) {
  const input=[],namespace=id=>id.slice(0,id.indexOf('.'));
  const relationKinds=new Map(catalog.relations.map(row=>[row.identity,row.kind]));
  const append=(kind,identity,ns,row,meta={})=>{
    const descriptor=descriptorFor(kind,[ns]);
    // Only source-exact trivial projections of captured atoms are derived here.
    // Never infer pretty deparse, persistence, type OIDs or joined FK metadata.
    const projected={...row};
    for(const [field,source] of [['acl_text_or_empty','acl'],['default_text_or_empty','default']])if(Object.hasOwn(row,source))projected[field]=row[source]??'';
    if(meta.relation_name!==undefined)projected.relation_name=meta.relation_name;
    if(meta.name!==undefined&&kind==='relation')projected.name=meta.name;
    if(['relation','column','column_name','trigger','policy'].includes(kind))projected.namespace_name=ns;
    const fact=Object.fromEntries(Object.keys(descriptor.fields).filter(k=>Object.hasOwn(projected,k)).map(k=>[k,projected[k]]));
    input.push({kind,identity,namespace:ns,...meta,fact});
  };
  for(const row of catalog.schemas)append('namespace',row.name,row.name,row,{name:row.name});
  for(const row of catalog.functions)append('routine',row.identity,namespace(row.identity),row,{name:row.identity.slice(row.identity.indexOf('.')+1,row.identity.indexOf('('))});
  for(const row of catalog.relations){
    const ns=namespace(row.identity),meta={name:row.identity.slice(row.identity.indexOf('.')+1),relation_kind:row.kind};
    append('relation',row.identity,ns,row,meta);
    if(['v','m'].includes(row.kind))append('view',row.identity,ns,{...row,definition:row.view},meta);
  }
  for(const [kind,source] of [['column','columns'],['constraint','constraints'],['index','indexes'],['policy','policies'],['trigger','triggers']])for(const row of catalog[source]){
    const ns=namespace(row.relation),meta={name:row.name,relation:row.relation,relation_name:row.relation.slice(row.relation.indexOf('.')+1)};
    if(kind==='column'){
      if(!relationKinds.has(row.relation))throw Error('captured column relation missing');
      meta.relation_kind=relationKinds.get(row.relation);
    }
    if(kind==='index'){
      if(!/^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/.test(row.identity))throw Error('captured index name requires exact quoted-name adapter');
      meta.name=row.identity.slice(row.identity.indexOf('.')+1);
    }
    let fact=row;
    if(kind==='trigger'){
      const functions=catalog.functions.filter(f=>f.identity===row.function);
      if(functions.length>1)throw Error('ambiguous trigger routine '+row.function);
      const f=functions[0];fact=f?{...row,function_definition:f.definition,function_owner:f.owner,function_acl:f.acl}:row;meta.function=row.function;
    }
    append(kind,kind==='index'?row.identity:canonicalOrderedJSON([row.relation,kind==='column'?row.position:row.name]),ns,fact,meta);
    if(kind==='column')append('column_name',canonicalOrderedJSON([row.relation,row.name]),ns,fact,meta);
    if(kind==='constraint')append('global_constraint',canonicalOrderedJSON([row.relation,row.name]),ns,fact,meta);
  }
  for(const row of catalog.saved_functions)append('saved_function',canonicalOrderedJSON([row.schema,row.signature]),row.schema,row);
  for(const row of catalog.saved_views)append('saved_view',canonicalOrderedJSON([row.schema+'.predecessor_views',row.signature]),row.schema,row);
  for(const row of catalog.saved_constraints??[])append('saved_constraint',canonicalOrderedJSON([row.schema+'.'+(row.schema==='zasp_temporal76'?'predecessor_constraints':'job_constraints'),row.signature??row.name]),row.schema,row);
  for(const row of catalog.registrations){
    const id=canonicalOrderedJSON([row.schema+'.registration',row.singleton]);
    append('registration',id,row.schema,row);
    if(row.schema==='zasp_authorization80_runtime')append('runtime_registration',id,row.schema,row);
    if(row.schema==='zasp_authorization80_worker')append('worker_registration',id,row.schema,row);
    if(row.schema==='zasp_authorization80_temporal')append('profile_registration',id,row.schema,row);
  }
  for(const row of catalog.memberships)append('membership',canonicalOrderedJSON([row.role,row.member,row.grantor]),row.role,row,{member:row.member});
  for(const row of catalog.roles)append('role',row.name,'',row,{name:row.name});
  return input;
}
export function compileOrderedCollector(rules) {
  validateOrderedSelectors(rules);
  const membership=(expression,values)=>values.length?expression+' IN('+values.map(quote).join(',')+')':'false';
  const nativePredicate=(role,member)=>role+"='zasp_temporal_accounting' OR "+membership(member,nativeRoles);
  const ruleFilter=(rule,attrs)=>rule.selector?selectorSQL(rule.selector,attrs):rule.predicate==='fixed-native-negative-universe'?'('+nativePredicate(attrs.namespace,attrs.member)+')':'('+membership(attrs.namespace,rule.namespaces)+' OR '+membership(attrs.identity,rule.identities)+')';
  const kinds=[...new Set(rules.map(r=>r.kind))].sort(), ctes=[];
  for(const kind of kinds) {
    const selected=rules.filter(r=>r.kind===kind);
    const fields=[...new Set(selected.flatMap(r=>r.fields))].sort();
    const namespace=[...new Set(selected.flatMap(r=>r.namespaces))].sort();
    const descriptor=descriptorFor(kind,namespace);
    const from=kind==='saved_function'?'('+namespace.map(n=>'SELECT '+quote(n)+'::text AS namespace,signature,definition,owner_name,acl::text AS acl FROM '+orderedSavedFunctionTables.find(t=>t.startsWith(n+'.'))).join(' UNION ALL ')+') s':descriptor.from+(kind==='trigger'&&fields.some(f=>f.startsWith('function_'))?' JOIN pg_catalog.pg_proc trigger_proc ON trigger_proc.oid=t.tgfoid':'');
    const extras=selectedSelectorFields(kind,selected);
    const extraSQL=Object.entries(extras).map(([name,expression])=>expression+' AS selector_'+name+', ').join('')+(kind==='trigger'?'t.tgisinternal AS internal, ':'');
    const attrs={identity:descriptor.identity,namespace:descriptor.namespace,...extras};
    ctes.push('direct_'+kind+' AS MATERIALIZED (SELECT '+descriptor.identity+' AS identity, '+descriptor.namespace+' AS namespace, '+extraSQL+'pg_catalog.jsonb_build_object('+fields.flatMap(f=>[quote(f),descriptor.fields[f]]).join(',')+') AS fact FROM '+from+' WHERE ('+selected.map(rule=>ruleFilter(rule,attrs)).join(' OR ')+')'+(descriptor.where?' AND ('+descriptor.where+')':'')+')');
  }
  const projections=rules.map(rule=>"SELECT "+quote(rule.kind)+"::text AS kind, "+composite(quote(rule.id)+'::text','identity')+" AS identity, pg_catalog.jsonb_build_object("+rule.fields.slice().sort().flatMap(f=>[quote(f),"fact->"+quote(f)]).join(',')+") AS fact FROM direct_"+rule.kind+" WHERE ("+ruleFilter(rule,{identity:'identity',namespace:'namespace',...Object.fromEntries(Object.keys(selectedSelectorFields(rule.kind,[rule])).map(name=>[name,'selector_'+name]))})+')'+(rule.predicate==='user-triggers'?' AND NOT internal':''));
  const sql='WITH '+ctes.join(',\n')+'\n'+projections.join('\nUNION ALL\n');
  admitCollectorSource(sql);
  return {sql,sourceSHA256:crypto.createHash('sha256').update(sql).digest('hex')};
}

// Separate successor API: never change the historical descriptor/compiler.
// The precision selected field is source-bound to the exact temporal72 rule;
// ordinary grouping, identity, other fields and projection bytes remain intact.
export function compileOrderedPrecisionResolverCollectorV1(rules){
  validateOrderedSelectors(rules);
  const selected=rules.filter(rule=>rule.fields.includes('precision_definition'));
  const contract=JSON.parse(fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url)));
  const sourceRule=lowerOrderedTemporal72Catalog(contract).rules.find(rule=>rule.id==='temporal72:precision-function');
  if(selected.length!==1||canonicalOrderedJSON(selected[0])!==canonicalOrderedJSON(sourceRule))throw Error('precision resolver source rule/site');
  const legacy=compileOrderedCollector(rules).sql;
  const original="'precision_definition',"+descriptors.routine.fields.precision_definition;
  if(legacy.split(original).length!==2)throw Error('precision resolver field site cardinality');
  const expression=precisionResolverExpressionV1(descriptors.routine.fields.precision_definition);
  const sql=legacy.replace(/^WITH /,()=> 'WITH precision_resolver_admission AS MATERIALIZED ('+precisionResolverAdmissionSQLV1+'),\n').replace(original,()=>"'precision_definition',"+expression);
  admitOrderedPrecisionResolverSourceV1(sql);
  return {sql,sourceSHA256:crypto.createHash('sha256').update(sql).digest('hex'),precisionResolverVersion:1,installable:false,admissionSQL:precisionResolverAdmissionSQLV1,installSQL:precisionResolverInstallSQLV1};
}

// Fixed versioned path; unlike compileOrderedCollector, this will bind the
// approved source-frame matrix one rule at a time while retaining canonical
// descriptor keys and selectors.
export function compileOrderedDirectFrameCollectorV1(rules){
  validateOrderedSelectors(rules);bindOrderedDirectFrameV1(rules);
  const membership=(expression,values)=>values.length?expression+' IN('+values.map(quote).join(',')+')':'false';
  const nativePredicate=(role,member)=>role+"='zasp_temporal_accounting' OR "+membership(member,nativeRoles);
  const ruleFilter=(rule,attrs)=>rule.selector?selectorSQL(rule.selector,attrs):rule.predicate==='fixed-native-negative-universe'?'('+nativePredicate(attrs.namespace,attrs.member)+')':'('+membership(attrs.namespace,rule.namespaces)+' OR '+membership(attrs.identity,rule.identities)+')';
  const ctes=['direct_frame_admission AS MATERIALIZED ('+directFrameAdmissionSQL+')'],projections=[];
  for(let index=0;index<rules.length;index++){
    const rule=rules[index],descriptor=descriptorFor(rule.kind,rule.namespaces),fields=rule.fields.slice().sort();
    const from=rule.kind==='saved_function'?'('+rule.namespaces.map(n=>'SELECT '+quote(n)+'::text AS namespace,signature,definition,owner_name,acl::text AS acl FROM '+orderedSavedFunctionTables.find(t=>t.startsWith(n+'.'))).join(' UNION ALL ')+') s':descriptor.from+(rule.kind==='trigger'&&fields.some(f=>f.startsWith('function_'))?' JOIN pg_catalog.pg_proc trigger_proc ON trigger_proc.oid=t.tgfoid':'');
    const extras=selectedSelectorFields(rule.kind,[rule]),extraSQL=Object.entries(extras).map(([name,expression])=>expression+' AS selector_'+name+', ').join('')+(rule.kind==='trigger'?'t.tgisinternal AS internal, ':'');
    const attrs={identity:descriptor.identity,namespace:descriptor.namespace,...extras},name='direct_frame_'+index;
    const fact=fields.flatMap(field=>[quote(field),'CASE WHEN admission.admitted IS TRUE THEN '+directFrameExpressionV1(rule.id,rule.kind,field,descriptor.fields[field])+' ELSE NULL END']);
    ctes.push(name+' AS MATERIALIZED (SELECT '+descriptor.identity+' AS identity, '+descriptor.namespace+' AS namespace, '+extraSQL+'pg_catalog.jsonb_build_object('+fact.join(',')+') AS fact FROM '+from+' CROSS JOIN direct_frame_admission admission WHERE admission.admitted IS TRUE AND ('+ruleFilter(rule,attrs)+')'+(descriptor.where?' AND ('+descriptor.where+')':'')+(rule.predicate==='user-triggers'?' AND NOT t.tgisinternal':'')+')');
    projections.push('SELECT '+quote(rule.kind)+'::text AS kind, '+composite(quote(rule.id)+'::text','identity')+' AS identity, fact FROM '+name);
  }
  const sql='WITH '+ctes.join(',\n')+'\n'+projections.join('\nUNION ALL\n');
  admitOrderedDirectFrameSourceV1(sql);
  return {sql,sourceSHA256:crypto.createHash('sha256').update(sql).digest('hex'),directFrameVersion,installable:false,admissionSQL:directFrameAdmissionSQL,installSQL:directFrameInstallSQL,ruleFieldMatrix:directFrameRuleFieldMatrixV1};
}
