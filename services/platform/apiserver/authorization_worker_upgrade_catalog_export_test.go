package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const ordered69PredecessorCompiledChecksum = "ff7b2990b6bb507d3fe60780ef54306e35e02fa1789c089eb414087bb254668c"

var workerUpgradeCatalogFields = map[string]string{
	"functions":           "identity definition owner acl language volatility security_definer strict parallel config arguments result leakproof cost rows",
	"schemas":             "name owner acl",
	"relations":           "identity kind owner acl row_security forced_row_security options partition_bound view",
	"columns":             "relation position name type not_null acl default identity generated collation",
	"constraints":         "relation name definition validated deferrable deferred",
	"indexes":             "relation identity definition valid ready live",
	"triggers":            "relation name function enabled internal definition",
	"policies":            "relation name permissive command roles using check",
	"roles":               "name superuser inherit create_role create_db login replication bypass_rls connection_limit valid_until",
	"memberships":         "role member grantor admin inherit set",
	"saved_functions":     "schema signature definition owner acl",
	"saved_views":         "schema signature definition",
	"registrations":       "schema checksum fingerprint singleton predecessor outbox_predecessor profile_name",
	"saved_constraints":   "schema signature definition",
	"saved_triggers":      "schema relation name definition enabled",
	"static_sources":      "identity category present rows",
	"types":               "identity owner acl kind category relation element array base not_null default collation input output receive send analyze subscript length by_value alignment storage delimiter preferred defined type_modifier dimensions",
	"enum_values":         "type label order",
	"domain_constraints":  "type name definition validated deferrable deferred",
	"ranges":              "type subtype collation opclass canonical subdiff multirange",
	"default_acls":        "owner schema kind acl",
	"rewrite_rules":       "relation name enabled instead event definition",
	"dependencies":        "object referenced kind",
	"shared_dependencies": "object referenced kind",
	"extensions":          "name schema owner version relocatable",
	"role_settings":       "role database settings_sha256",
}

func workerUpgradeHash(s string) bool {
	return len(s) == 64 && strings.IndexFunc(s, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) < 0
}

// Only fixed internal codes/categories and numeric bounds reach Error(). The
// original filesystem cause remains available to errors.Is, never to the log.
type workerUpgradeCatalogRefusal struct {
	code, category string
	count, bytes   int
	cause          error
}

func (e *workerUpgradeCatalogRefusal) Error() string {
	return fmt.Sprintf("catalog refusal code=%s category=%s count=%d bytes=%d", e.code, e.category, e.count, e.bytes)
}
func (e *workerUpgradeCatalogRefusal) Unwrap() error { return e.cause }

func writeWorkerUpgradeCatalog(destination string, raw []byte) error {
	refuse := func(code, category string, count int, cause error) error {
		return &workerUpgradeCatalogRefusal{code: code, category: category, count: count, bytes: len(raw), cause: cause}
	}
	if !filepath.IsAbs(destination) {
		return refuse("output-path", "none", 0, nil)
	}
	if len(raw) == 0 || len(raw) > 64*1024*1024 {
		return refuse("document-size", "none", 0, nil)
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil || len(document) != len(workerUpgradeCatalogFields)+2 {
		return refuse("document-shape", "none", len(document), nil)
	}
	var format, checksum string
	if json.Unmarshal(document["format"], &format) != nil || format != "zasp-worker-effective-catalog-v2" || json.Unmarshal(document["compiled_checksum"], &checksum) != nil || checksum != ordered69PredecessorCompiledChecksum {
		return refuse("document-binding", "none", len(document), nil)
	}
	workerRegistrations := 0
	for category, columns := range workerUpgradeCatalogFields {
		var records []map[string]json.RawMessage
		if json.Unmarshal(document[category], &records) != nil || records == nil {
			return refuse("category-shape", category, len(records), nil)
		}
		limit := 20000
		// The bounded managed-object closure measured 20,943 dependencies.
		// Other categories and the whole-document byte ceiling are unchanged.
		if category == "dependencies" {
			limit = 32768
		}
		if len(records) > limit {
			return refuse("category-limit", category, len(records), nil)
		}
		if category == "functions" && len(records) == 0 {
			return refuse("functions-empty", category, 0, nil)
		}
		fields := strings.Fields(columns)
		for _, record := range records {
			if len(record) != len(fields) {
				return refuse("record-width", category, len(record), nil)
			}
			for _, field := range fields {
				value, ok := record[field]
				if !ok {
					return refuse("field-absent", category, len(record), nil)
				}
				var atom any
				if json.Unmarshal(value, &atom) != nil {
					return refuse("value-json", category, len(record), nil)
				}
				switch v := atom.(type) {
				case nil, string, bool, float64:
				case []any:
					for _, item := range v {
						if _, ok := item.(string); !ok {
							return refuse("array-value", category, len(record), nil)
						}
					}
				default:
					return refuse("value-type", category, len(record), nil)
				}
			}
			if category == "registrations" {
				var schema, c, f string
				if json.Unmarshal(record["schema"], &schema) != nil || json.Unmarshal(record["checksum"], &c) != nil || json.Unmarshal(record["fingerprint"], &f) != nil || !workerUpgradeHash(c) || !workerUpgradeHash(f) {
					return refuse("registration-hash", category, len(records), nil)
				}
				if schema == "zasp_authorization80_worker" {
					workerRegistrations++
					if c != checksum {
						return refuse("worker-checksum", category, len(records), nil)
					}
				}
			}
		}
	}
	if workerRegistrations != 1 {
		return refuse("worker-count", "registrations", workerRegistrations, nil)
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return refuse("output-open", "none", 0, err)
	}
	_, writeErr := f.Write(append(raw, '\n'))
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return refuse("output-finish", "none", 0, err)
	}
	return nil
}

// Dedicated callable exporter only: no default test entry, shared parent hook,
// environment-driven database connection, installer, or authority mutation.
// Future paired acceptance must pass its already-owned fixture connection.
func captureOrdered69PredecessorCatalog(t *testing.T, ctx context.Context, owner *pgx.Conn, destination string) {
	t.Helper()
	if owner == nil || destination == "" {
		t.Fatal("explicit owned capture required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := owner.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("static catalog transaction unavailable")
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		if err := tx.Rollback(cleanup); err != nil {
			t.Error("static catalog rollback failed")
		}
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'; SELECT pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0))`); err != nil {
		t.Fatal("static catalog frame unavailable")
	}
	var ready bool
	check := func() {
		t.Helper()
		if err := tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(checksum=$1) AND zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND to_regnamespace('zasp_authorization80_identity') IS NULL FROM zasp_authorization80_worker.registration`, ordered69PredecessorCompiledChecksum).Scan(&ready); err != nil || !ready {
			t.Fatal("static predecessor identity/catalog unavailable")
		}
	}
	check()
	var raw json.RawMessage
	if err := tx.QueryRow(ctx, workerUpgradeCatalogSQL, ordered69PredecessorCompiledChecksum).Scan(&raw); err != nil {
		t.Fatal("static catalog read unavailable")
	}
	raw, err = augmentWorkerUpgradeCatalog(ctx, tx, raw)
	if err != nil {
		t.Fatal("static catalog closure unavailable")
	}
	check()
	if err := writeWorkerUpgradeCatalog(destination, raw); err != nil {
		t.Fatal("static catalog export refused", err)
	}
	digest := sha256.Sum256(raw)
	fileDigest := sha256.Sum256(append(append([]byte(nil), raw...), '\n'))
	t.Log("static predecessor catalog bytes", len(raw), "payloadSHA256", hex.EncodeToString(digest[:]), "fileSHA256", hex.EncodeToString(fileDigest[:]))
}

// Explicit fields only. No SELECT/to_jsonb of product rows or verifier tables.
// All relation queries below read pg_catalog, never the selected relations.
const workerUpgradeCatalogSQL = `WITH
ns AS(SELECT oid,nspname,nspowner,nspacl FROM pg_namespace WHERE nspname=ANY(` + workerUpgradeSchemasSQL + `)),
rels AS(SELECT c.* FROM pg_class c JOIN ns n ON n.oid=c.relnamespace WHERE n.nspname<>'public' OR left(c.relname,5)='zasp_'),
funcs AS(SELECT p.* FROM pg_proc p JOIN ns n ON n.oid=p.pronamespace WHERE p.prokind='f' AND(n.nspname<>'public' OR left(p.proname,5)='zasp_' OR EXISTS(SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid=d.refobjid WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.refclassid='pg_extension'::regclass AND d.deptype='e' AND e.extname='pgcrypto')))
SELECT jsonb_build_object(
'format','zasp-worker-effective-catalog-v2','compiled_checksum',$1::text,
'functions',COALESCE((SELECT jsonb_agg(jsonb_build_object('identity',p.oid::regprocedure::text,'definition',pg_get_functiondef(p.oid),'owner',p.proowner::regrole::text,'acl',p.proacl::text,'language',l.lanname,'volatility',p.provolatile,'security_definer',p.prosecdef,'strict',p.proisstrict,'parallel',p.proparallel,'config',p.proconfig,'arguments',pg_get_function_identity_arguments(p.oid),'result',pg_get_function_result(p.oid),'leakproof',p.proleakproof,'cost',p.procost,'rows',p.prorows) ORDER BY p.oid::regprocedure::text) FROM funcs p JOIN pg_language l ON l.oid=p.prolang),'[]'::jsonb),
'schemas',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',nspname,'owner',nspowner::regrole::text,'acl',nspacl::text) ORDER BY nspname) FROM ns),'[]'::jsonb),
'relations',COALESCE((SELECT jsonb_agg(jsonb_build_object('identity',c.oid::regclass::text,'kind',c.relkind,'owner',c.relowner::regrole::text,'acl',c.relacl::text,'row_security',c.relrowsecurity,'forced_row_security',c.relforcerowsecurity,'options',c.reloptions,'partition_bound',pg_get_expr(c.relpartbound,c.oid),'view',CASE WHEN c.relkind IN('v','m') THEN pg_get_viewdef(c.oid) END) ORDER BY c.oid::regclass::text) FROM rels c),'[]'::jsonb),
'columns',COALESCE((SELECT jsonb_agg(jsonb_build_object('relation',c.oid::regclass::text,'position',a.attnum,'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'acl',a.attacl::text,'default',pg_get_expr(d.adbin,d.adrelid),'identity',a.attidentity,'generated',a.attgenerated,'collation',CASE WHEN a.attcollation<>0 THEN a.attcollation::regcollation::text END) ORDER BY c.oid::regclass::text,a.attnum) FROM rels c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb),
'constraints',COALESCE((SELECT jsonb_agg(jsonb_build_object('relation',c.oid::regclass::text,'name',k.conname,'definition',pg_get_constraintdef(k.oid),'validated',k.convalidated,'deferrable',k.condeferrable,'deferred',k.condeferred) ORDER BY c.oid::regclass::text,k.conname) FROM rels c JOIN pg_constraint k ON k.conrelid=c.oid),'[]'::jsonb),
'indexes',COALESCE((SELECT jsonb_agg(jsonb_build_object('relation',c.oid::regclass::text,'identity',i.indexrelid::regclass::text,'definition',pg_get_indexdef(i.indexrelid),'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive) ORDER BY i.indexrelid::regclass::text) FROM rels c JOIN pg_index i ON i.indrelid=c.oid),'[]'::jsonb),
'triggers',COALESCE((SELECT jsonb_agg(jsonb_build_object('relation',c.oid::regclass::text,'name',t.tgname,'function',t.tgfoid::regprocedure::text,'enabled',t.tgenabled,'internal',t.tgisinternal,'definition',pg_get_triggerdef(t.oid)) ORDER BY c.oid::regclass::text,t.tgname) FROM rels c JOIN pg_trigger t ON t.tgrelid=c.oid),'[]'::jsonb),
'policies',COALESCE((SELECT jsonb_agg(jsonb_build_object('relation',c.oid::regclass::text,'name',p.polname,'permissive',p.polpermissive,'command',p.polcmd,'roles',p.polroles::regrole[]::text,'using',pg_get_expr(p.polqual,p.polrelid),'check',pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY c.oid::regclass::text,p.polname) FROM rels c JOIN pg_policy p ON p.polrelid=c.oid),'[]'::jsonb),
'roles',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',rolname,'superuser',rolsuper,'inherit',rolinherit,'create_role',rolcreaterole,'create_db',rolcreatedb,'login',rolcanlogin,'replication',rolreplication,'bypass_rls',rolbypassrls,'connection_limit',rolconnlimit,'valid_until',rolvaliduntil::text) ORDER BY rolname) FROM pg_roles WHERE oid IN(SELECT proowner FROM funcs UNION SELECT relowner FROM rels UNION SELECT nspowner FROM ns UNION SELECT oid FROM pg_roles WHERE left(rolname,5)='zasp_' UNION SELECT member FROM pg_auth_members WHERE roleid IN(SELECT oid FROM pg_roles WHERE left(rolname,5)='zasp_'))),'[]'::jsonb),
'memberships',COALESCE((SELECT jsonb_agg(jsonb_build_object('role',roleid::regrole::text,'member',member::regrole::text,'grantor',grantor::regrole::text,'admin',admin_option,'inherit',to_jsonb(m)->'inherit_option','set',to_jsonb(m)->'set_option') ORDER BY roleid::regrole::text,member::regrole::text,grantor::regrole::text) FROM pg_auth_members m WHERE left(roleid::regrole::text,5)='zasp_' OR left(member::regrole::text,5)='zasp_'),'[]'::jsonb),
'saved_functions','[]'::jsonb,
'saved_views','[]'::jsonb,
'registrations','[]'::jsonb)`

func TestWorkerUpgradeCatalogExportPrivacy(t *testing.T) {
	valid := string(workerUpgradeCompleteFixture(t))
	file := filepath.Join(t.TempDir(), "catalog.json")
	if err := writeWorkerUpgradeCatalog(file, []byte(valid)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil || strings.TrimSpace(string(got)) != valid {
		t.Fatal("exact static manifest missing or changed")
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("catalog artifact permissions")
	}
	if err := writeWorkerUpgradeCatalog(file, []byte(valid)); !errors.Is(err, os.ErrExist) {
		t.Fatal("catalog overwrite allowed")
	}
	for _, tc := range []struct{ name, raw string }{
		{"product_rows", strings.Replace(valid, `"roles":[]`, `"roles":[],"product_rows":["private"]`, 1)},
		{"key_field", strings.Replace(valid, `"owner":"authority"`, `"owner":"authority","key":"private"`, 1)},
		{"nested_value", strings.Replace(valid, `"owner":"authority"`, `"owner":{"secret":"private"}`, 1)},
		{"wrong_release", strings.ReplaceAll(valid, ordered69PredecessorCompiledChecksum, strings.Repeat("b", 64))},
		{"null_category", strings.Replace(valid, `"roles":[]`, `"roles":null`, 1)},
		{"unknown_format", strings.Replace(valid, `effective-catalog-v2`, `effective-catalog-v3`, 1)},
		{"no_functions", strings.Replace(valid, `"functions":[`, `"functions":[],"discard":[`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "invalid.json")
			if writeWorkerUpgradeCatalog(p, []byte(tc.raw)) == nil {
				t.Fatal("unsafe catalog accepted")
			}
			if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused catalog wrote data")
			}
		})
	}
	var parsed map[string]json.RawMessage
	if json.Unmarshal(got, &parsed) != nil || len(parsed) != 28 {
		t.Fatal("unexpected manifest fields")
	}
}
