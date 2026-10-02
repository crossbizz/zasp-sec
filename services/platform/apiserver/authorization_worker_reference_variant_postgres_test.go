package apiserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Only the frozen Variant B overlay substitutes this starter. No environment
// setting chooses a migration owner, and the existing fixture owns PostgreSQL.
func startOrderedCurrentReferenceVariantB(t *testing.T) string {
	t.Helper()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("reference preparation connection")
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if conn.Close(cleanup) != nil {
			t.Error("reference preparation connection cleanup")
		}
	}()
	err = prepareOrderedReferenceVariant(ctx, orderedReferenceIO{
		snapshot: func(call context.Context) (orderedReferenceState, error) {
			var state orderedReferenceState
			err := conn.QueryRow(call, orderedReferencePristineSQL).Scan(&state.Session, &state.Current, &state.Inventory, &state.Scratch, &state.Migrated)
			return state, err
		},
		exec: func(call context.Context, sql string) error { _, err := conn.Exec(call, sql); return err },
	})
	if err != nil {
		t.Fatal(err)
	}
	return dsn
}

// Identity sets are compared before/after in this same pristine database, not
// across references. No rows/definitions/credentials are logged. Ordinary
// scratch DDL is intentional: SQL TEMP would retain pg_temp namespaces.
const orderedReferencePristineSQL = `SELECT session_user::text,current_user::text,
 jsonb_build_object(
 'schemas',(SELECT jsonb_agg(jsonb_build_array(oid,nspname,nspowner) ORDER BY oid) FROM pg_namespace),
 'relations',(SELECT jsonb_agg(jsonb_build_array(oid,relnamespace,relname,relowner) ORDER BY oid) FROM pg_class),
 'functions',(SELECT jsonb_agg(jsonb_build_array(oid,pronamespace,proname,proowner) ORDER BY oid) FROM pg_proc),
 'types',(SELECT jsonb_agg(jsonb_build_array(oid,typnamespace,typname,typowner) ORDER BY oid) FROM pg_type),
 'roles',(SELECT jsonb_agg(jsonb_build_array(oid,rolname) ORDER BY oid) FROM pg_roles)
 )::text,
 to_regnamespace('p7_reference_oid_shift') IS NOT NULL,
 (to_regclass('public.zasp_schema_versions') IS NOT NULL
 OR to_regclass('public.zasp_schema_metadata') IS NOT NULL
 OR to_regnamespace('zasp_authorization80_worker') IS NOT NULL)`

type orderedReferenceOIDWitness struct {
	Login                                                string
	CatalogReady, Linked, Registration, RegistrationType uint32
}

// Prepared for the later reviewed collector caller; deliberately not wired to
// today's exporter. These OIDs are provenance only, never semantic constants.
func readOrderedCurrentReferenceVariantBWitness(parent context.Context, conn *pgx.Conn) (orderedReferenceOIDWitness, error) {
	var w orderedReferenceOIDWitness
	if parent == nil || conn == nil || parent.Err() != nil {
		return w, errors.New("reference witness dependencies")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	err := conn.QueryRow(ctx, `SELECT session_user::text,
 to_regprocedure('zasp_authorization80_worker.catalog_ready()')::oid,
 to_regprocedure('zasp_temporal68.linked(jsonb)')::oid,
 c.oid,c.reltype FROM pg_class c
 WHERE c.oid=to_regclass('zasp_authorization80_worker.registration')`).Scan(&w.Login, &w.CatalogReady, &w.Linked, &w.Registration, &w.RegistrationType)
	if err != nil || ctx.Err() != nil || w.Login != "zasp_e2e" || w.CatalogReady == 0 || w.Linked == 0 || w.Registration == 0 || w.RegistrationType == 0 {
		return orderedReferenceOIDWitness{}, errors.New("reference witness incomplete")
	}
	return w, nil
}
