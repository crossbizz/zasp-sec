package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func assertOrdered68SigningInnerBoundaries(t *testing.T, ctx context.Context, owner, executor *pgx.Conn) {
	t.Helper()
	for _, spec := range []struct{ name, args string }{
		{"ordered68_signing_boundary", "text"},
		{"ordered68_signing_facts_inner", "boolean,jsonb"},
		{"ordered68_signing_effect_metadata_inner", "text,jsonb"},
		{"ordered68_signing_effect_source_inner", "text,jsonb"},
		{"ordered68_signing_metadata_inner", "text,jsonb"},
		{"ordered68_signing_source_inner", "text,jsonb"},
		{"ordered68_signing_proof_inner", "text,jsonb"},
		{"ordered68_signing_read_inner", "jsonb"},
	} {
		signature := "zasp_authorization80_worker." + spec.name + "(" + spec.args + ")"
		t.Run(spec.name+"-private", func(t *testing.T) {
			var definition, ownerName, acl string
			if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef(oid),proowner::regrole::text,proacl::text FROM pg_proc WHERE oid=$1::regprocedure`, signature).Scan(&definition, &ownerName, &acl); err != nil || ownerName != "zasp_discovery_authority" || acl != "{zasp_discovery_authority=X/zasp_discovery_authority}" {
				t.Fatal("private signing helper identity", err)
			}
			var args []string
			for _, kind := range strings.Split(spec.args, ",") {
				args = append(args, "NULL::"+kind)
			}
			var result any
			err := executor.QueryRow(ctx, "SELECT zasp_authorization80_worker."+spec.name+"("+strings.Join(args, ",")+")").Scan(&result)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Fatal("registered executor invoked private signing helper", err)
			}
		})
		for _, mutation := range []string{"body", "acl", "owner"} {
			t.Run(spec.name+"-"+mutation, func(t *testing.T) {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					if err := tx.Rollback(bounded); err != nil {
						t.Error("rollback signing helper mutation", err)
					}
				}()
				statement := "GRANT EXECUTE ON FUNCTION " + signature + " TO " + pgx.Identifier{executor.Config().User}.Sanitize()
				if mutation == "owner" {
					statement = "ALTER FUNCTION " + signature + " OWNER TO " + pgx.Identifier{owner.Config().User}.Sanitize()
				}
				if mutation == "body" {
					var definition string
					if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, signature).Scan(&definition); err != nil || strings.Count(definition, "AS $function$") != 1 {
						t.Fatal("signing helper definition anchor", err)
					}
					statement = strings.Replace(definition, "AS $function$", "AS $function$\n-- unchanged-result signing control\n", 1)
				}
				if _, err := tx.Exec(ctx, statement); err != nil {
					t.Fatal(err)
				}
				var ready bool
				if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() OR zasp_temporal68.current_ready()`).Scan(&ready); err != nil || ready {
					t.Fatal("private signing drift accepted by catalog", err)
				}
			})
		}
	}
}
