package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Finite schemas found in the frozen release source, including optional retired
// predecessors. No namespace or table identifier is accepted from an artifact.
const workerUpgradeSchemasSQL = `ARRAY['public','zasp_audit_exports_predecessor','zasp_authorization79','zasp_authorization80','zasp_authorization80_audit','zasp_authorization80_identity','zasp_authorization80_runtime','zasp_authorization80_temporal','zasp_authorization80_worker','zasp_compliance_predecessor','zasp_existing_tests_predecessor','zasp_ordered_public62','zasp_ordered_worker63','zasp_ordered_scheduler64','zasp_precision_predecessor','zasp_run_context_predecessor','zasp_sa_attack_lab_prior','zasp_sa_export_prior','zasp_sa_multistep_prior','zasp_sa_webhook_prior','zasp_schedule_replay_prior','zasp_security_agent_budgets_predecessor','zasp_temporal65','zasp_temporal66','zasp_temporal67','zasp_temporal68','zasp_temporal69','zasp_temporal70','zasp_temporal71','zasp_temporal72','zasp_temporal73','zasp_temporal74','zasp_temporal75','zasp_temporal76','zasp_temporal77','zasp_temporal78']::text[]`

type workerUpgradeStaticSource struct{ table, category, fields, order string }

func workerUpgradeStaticSources() []workerUpgradeStaticSource {
	var sources []workerUpgradeStaticSource
	functions := func(schema, table string) {
		sources = append(sources, workerUpgradeStaticSource{schema + "." + table, "saved_functions", "'schema','" + schema + "','signature',signature,'definition',definition,'owner',owner_name,'acl',acl::text", "signature"})
	}
	for _, schema := range strings.Fields("zasp_sa_attack_lab_prior zasp_sa_export_prior zasp_sa_webhook_prior zasp_schedule_replay_prior zasp_sa_multistep_prior") {
		functions(schema, "functions")
	}
	for _, schema := range strings.Fields("zasp_temporal67 zasp_temporal68 zasp_temporal69 zasp_temporal70 zasp_temporal71 zasp_temporal72 zasp_temporal73 zasp_temporal74 zasp_temporal75 zasp_temporal76 zasp_temporal77 zasp_temporal78 zasp_authorization80_worker zasp_authorization80_runtime zasp_authorization80_temporal zasp_authorization80_audit") {
		functions(schema, "predecessor_functions")
	}
	sources = append(sources,
		workerUpgradeStaticSource{"zasp_authorization80_worker.predecessor_views", "saved_views", "'schema','zasp_authorization80_worker','signature',signature,'definition',definition", "signature"},
		workerUpgradeStaticSource{"zasp_temporal76.predecessor_constraints", "saved_constraints", "'schema','zasp_temporal76','signature',signature,'definition',definition", "signature"},
		workerUpgradeStaticSource{"zasp_sa_export_prior.job_constraints", "saved_constraints", "'schema','zasp_sa_export_prior','signature',name,'definition',definition", "name"},
		workerUpgradeStaticSource{"zasp_existing_tests_predecessor.global_control_triggers", "saved_triggers", "'schema','zasp_existing_tests_predecessor','relation',relation_name,'name',trigger_name,'definition',definition,'enabled',enabled", "relation_name"},
	)
	for _, schema := range strings.Fields("zasp_ordered_public62 zasp_ordered_worker63 zasp_ordered_scheduler64 zasp_temporal65 zasp_temporal66 zasp_temporal67 zasp_temporal68 zasp_temporal69 zasp_temporal70 zasp_temporal71 zasp_temporal72 zasp_temporal73 zasp_temporal74 zasp_temporal75 zasp_temporal76 zasp_temporal77 zasp_temporal78 zasp_authorization79 zasp_authorization80 zasp_authorization80_worker zasp_authorization80_runtime zasp_authorization80_temporal zasp_authorization80_audit") {
		predecessor, outbox, profile := "NULL::text", "NULL::text", "NULL::text"
		if schema == "zasp_temporal65" || schema == "zasp_temporal67" {
			predecessor = "predecessor"
		}
		if schema == "zasp_temporal67" {
			outbox = "outbox_predecessor"
		}
		if schema == "zasp_authorization80_temporal" {
			profile = "profile_name"
		}
		sources = append(sources, workerUpgradeStaticSource{schema + ".registration", "registrations", "'schema','" + schema + "','checksum',checksum,'fingerprint',fingerprint,'singleton',singleton,'predecessor'," + predecessor + ",'outbox_predecessor'," + outbox + ",'profile_name'," + profile, "checksum"})
	}
	return sources
}

func augmentWorkerUpgradeCatalog(ctx context.Context, tx pgx.Tx, raw json.RawMessage) (json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return nil, errors.New("invalid base catalog")
	}
	var structure json.RawMessage
	if err := tx.QueryRow(ctx, workerUpgradeStructureSQL).Scan(&structure); err != nil {
		return nil, err
	}
	var extra map[string]json.RawMessage
	if json.Unmarshal(structure, &extra) != nil {
		return nil, errors.New("invalid structural catalog")
	}
	for k, v := range extra {
		doc[k] = v
	}
	records := map[string][]json.RawMessage{}
	for _, category := range []string{"saved_functions", "saved_views", "saved_constraints", "saved_triggers", "registrations", "static_sources"} {
		records[category] = []json.RawMessage{}
	}
	for _, source := range workerUpgradeStaticSources() {
		var present bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, source.table).Scan(&present); err != nil {
			return nil, err
		}
		rows := []json.RawMessage{}
		if present {
			// Both identifiers and field expressions originate only in the fixed list.
			query := fmt.Sprintf("SELECT COALESCE(jsonb_agg(jsonb_build_object(%s) ORDER BY %s),'[]'::jsonb) FROM %s", source.fields, source.order, source.table)
			var encoded json.RawMessage
			if err := tx.QueryRow(ctx, query).Scan(&encoded); err != nil {
				return nil, err
			}
			if json.Unmarshal(encoded, &rows) != nil || len(rows) > 20000 {
				return nil, errors.New("invalid static source")
			}
		}
		records[source.category] = append(records[source.category], rows...)
		inventory, _ := json.Marshal(map[string]any{"identity": source.table, "category": source.category, "present": present, "rows": len(rows)})
		records["static_sources"] = append(records["static_sources"], inventory)
	}
	for category, rows := range records {
		value, err := json.Marshal(rows)
		if err != nil {
			return nil, err
		}
		doc[category] = value
	}
	return json.Marshal(doc)
}

// Only structural pg_catalog fields. Dependencies use stable object identities,
// never numeric OIDs as portable equality or any product-table content. Builtin
// dependencies remain edges, not a dump of global PostgreSQL/customer objects.
const workerUpgradeStructureSQL = `WITH
ns AS(SELECT oid,nspname,nspowner FROM pg_namespace WHERE nspname=ANY(` + workerUpgradeSchemasSQL + `)),
rels AS(SELECT c.* FROM pg_class c JOIN ns n ON n.oid=c.relnamespace WHERE n.nspname<>'public' OR left(c.relname,5)='zasp_'),
funcs AS(SELECT p.* FROM pg_proc p JOIN ns n ON n.oid=p.pronamespace WHERE n.nspname<>'public' OR left(p.proname,5)='zasp_' OR EXISTS(SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid=d.refobjid WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.refclassid='pg_extension'::regclass AND d.deptype='e' AND e.extname='pgcrypto')),
types AS(SELECT t.* FROM pg_type t JOIN ns n ON n.oid=t.typnamespace WHERE n.nspname<>'public' OR left(t.typname,5)='zasp_' OR t.typrelid IN(SELECT oid FROM rels) OR t.typelem IN(SELECT reltype FROM rels)),
constraints AS(SELECT k.* FROM pg_constraint k WHERE k.conrelid IN(SELECT oid FROM rels) OR k.contypid IN(SELECT oid FROM types)),
rules AS(SELECT r.* FROM pg_rewrite r WHERE r.ev_class IN(SELECT oid FROM rels)),
roles AS(SELECT oid FROM pg_roles WHERE left(rolname,5)='zasp_' UNION SELECT proowner FROM funcs UNION SELECT relowner FROM rels UNION SELECT nspowner FROM ns UNION SELECT member FROM pg_auth_members WHERE roleid IN(SELECT oid FROM pg_roles WHERE left(rolname,5)='zasp_')),
objects(classid,objid) AS(
 SELECT 'pg_namespace'::regclass::oid,oid FROM ns UNION SELECT 'pg_class'::regclass::oid,oid FROM rels
 UNION SELECT 'pg_proc'::regclass::oid,oid FROM funcs UNION SELECT 'pg_type'::regclass::oid,oid FROM types
 UNION SELECT 'pg_constraint'::regclass::oid,oid FROM constraints UNION SELECT 'pg_rewrite'::regclass::oid,oid FROM rules
 UNION SELECT 'pg_trigger'::regclass::oid,oid FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM rels)
 UNION SELECT 'pg_policy'::regclass::oid,oid FROM pg_policy WHERE polrelid IN(SELECT oid FROM rels)),
deps AS(SELECT d.* FROM pg_depend d WHERE EXISTS(SELECT 1 FROM objects o WHERE(o.classid,o.objid)=(d.classid,d.objid))),
exts AS(SELECT e.* FROM pg_extension e WHERE e.oid IN(SELECT refobjid FROM deps WHERE refclassid='pg_extension'::regclass) OR e.extname='pgcrypto')
SELECT jsonb_build_object(
'types',COALESCE((SELECT jsonb_agg(jsonb_build_object('identity',t.oid::regtype::text,'owner',t.typowner::regrole::text,'acl',t.typacl::text,'kind',t.typtype,'category',t.typcategory,'relation',NULLIF(t.typrelid,0)::regclass::text,'element',NULLIF(t.typelem,0)::regtype::text,'array',NULLIF(t.typarray,0)::regtype::text,'base',NULLIF(t.typbasetype,0)::regtype::text,'not_null',t.typnotnull,'default',t.typdefault,'collation',NULLIF(t.typcollation,0)::regcollation::text,'input',NULLIF(t.typinput,0)::regprocedure::text,'output',NULLIF(t.typoutput,0)::regprocedure::text,'receive',NULLIF(t.typreceive,0)::regprocedure::text,'send',NULLIF(t.typsend,0)::regprocedure::text,'analyze',NULLIF(t.typanalyze,0)::regprocedure::text,'subscript',NULLIF(t.typsubscript,0)::regprocedure::text,'length',t.typlen,'by_value',t.typbyval,'alignment',t.typalign,'storage',t.typstorage,'delimiter',t.typdelim,'preferred',t.typispreferred,'defined',t.typisdefined,'type_modifier',t.typtypmod,'dimensions',t.typndims) ORDER BY t.oid::regtype::text) FROM types t),'[]'::jsonb),
'enum_values',COALESCE((SELECT jsonb_agg(jsonb_build_object('type',e.enumtypid::regtype::text,'label',e.enumlabel,'order',e.enumsortorder) ORDER BY e.enumtypid::regtype::text,e.enumsortorder) FROM pg_enum e WHERE e.enumtypid IN(SELECT oid FROM types)),'[]'::jsonb),
'domain_constraints',COALESCE((SELECT jsonb_agg(jsonb_build_object('type',k.contypid::regtype::text,'name',k.conname,'definition',pg_get_constraintdef(k.oid),'validated',k.convalidated,'deferrable',k.condeferrable,'deferred',k.condeferred) ORDER BY k.contypid::regtype::text,k.conname) FROM constraints k WHERE k.contypid<>0),'[]'::jsonb),
'ranges',COALESCE((SELECT jsonb_agg(jsonb_build_object('type',r.rngtypid::regtype::text,'subtype',r.rngsubtype::regtype::text,'collation',NULLIF(r.rngcollation,0)::regcollation::text,'opclass',(pg_identify_object('pg_opclass'::regclass,r.rngsubopc,0)).identity,'canonical',NULLIF(r.rngcanonical,0)::regprocedure::text,'subdiff',NULLIF(r.rngsubdiff,0)::regprocedure::text,'multirange',r.rngmultitypid::regtype::text) ORDER BY r.rngtypid::regtype::text) FROM pg_range r WHERE r.rngtypid IN(SELECT oid FROM types) OR r.rngmultitypid IN(SELECT oid FROM types)),'[]'::jsonb),
'default_acls',COALESCE((SELECT jsonb_agg(jsonb_build_object('owner',d.defaclrole::regrole::text,'schema',n.nspname,'kind',d.defaclobjtype,'acl',d.defaclacl::text) ORDER BY d.defaclrole::regrole::text,n.nspname,d.defaclobjtype) FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE d.defaclnamespace IN(SELECT oid FROM ns) OR(d.defaclnamespace=0 AND d.defaclrole IN(SELECT oid FROM roles))),'[]'::jsonb),
'rewrite_rules',COALESCE((SELECT jsonb_agg(jsonb_build_object('relation',r.ev_class::regclass::text,'name',r.rulename,'enabled',r.ev_enabled,'instead',r.is_instead,'event',r.ev_type,'definition',pg_get_ruledef(r.oid)) ORDER BY r.ev_class::regclass::text,r.rulename) FROM rules r),'[]'::jsonb),
'dependencies',COALESCE((SELECT jsonb_agg(jsonb_build_object('object',(pg_identify_object(d.classid,d.objid,d.objsubid)).identity,'referenced',(pg_identify_object(d.refclassid,d.refobjid,d.refobjsubid)).identity,'kind',d.deptype) ORDER BY d.classid::regclass::text,(pg_identify_object(d.classid,d.objid,d.objsubid)).identity,d.refclassid::regclass::text,(pg_identify_object(d.refclassid,d.refobjid,d.refobjsubid)).identity,d.deptype) FROM deps d),'[]'::jsonb),
'shared_dependencies',COALESCE((SELECT jsonb_agg(jsonb_build_object('object',(pg_identify_object(d.classid,d.objid,d.objsubid)).identity,'referenced',(pg_identify_object(d.refclassid,d.refobjid,0)).identity,'kind',d.deptype) ORDER BY d.classid::regclass::text,(pg_identify_object(d.classid,d.objid,d.objsubid)).identity,d.refclassid::regclass::text,(pg_identify_object(d.refclassid,d.refobjid,0)).identity,d.deptype) FROM pg_shdepend d WHERE d.dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND EXISTS(SELECT 1 FROM objects o WHERE(o.classid,o.objid)=(d.classid,d.objid))),'[]'::jsonb),
'extensions',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',e.extname,'schema',e.extnamespace::regnamespace::text,'owner',e.extowner::regrole::text,'version',e.extversion,'relocatable',e.extrelocatable) ORDER BY e.extname) FROM exts e),'[]'::jsonb),
'role_settings',COALESCE((SELECT jsonb_agg(jsonb_build_object('role',CASE WHEN s.setrole=0 THEN '*' ELSE s.setrole::regrole::text END,'database',CASE WHEN s.setdatabase=0 THEN '*' ELSE current_database() END,'settings_sha256',encode(public.digest(convert_to(s.setconfig::text,'UTF8'),'sha256'),'hex')) ORDER BY s.setrole,s.setdatabase) FROM pg_db_role_setting s WHERE(s.setrole=0 OR s.setrole IN(SELECT oid FROM roles)) AND s.setdatabase IN(0,(SELECT oid FROM pg_database WHERE datname=current_database()))),'[]'::jsonb))`
