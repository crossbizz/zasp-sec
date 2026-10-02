package apiserver

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func assertOrdered62InnerBoundaries(t *testing.T, ctx context.Context, owner, api *pgx.Conn) {
	t.Helper()
	checksum, fingerprint := migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint()
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.ordered62_inner_ready($1,$2)`, checksum, fingerprint).Scan(&ready); err != nil || !ready {
		t.Fatal("effective compiled62 registration or local projected identity differs", err)
	}
	for _, name := range []string{"ordered62_inner_ready", "ordered62_decide_inner", "ordered62_mutate_inner"} {
		t.Run(name+"-private", func(t *testing.T) {
			args := []any{checksum, fingerprint}
			query := "SELECT zasp_authorization80_worker." + name + "($1::text,$2::text)"
			if name != "ordered62_inner_ready" {
				query = "SELECT zasp_authorization80_worker." + name + "($1::text,$2::text,$3::jsonb)"
				args = append(args, `{"operation":"cancel"}`)
			}
			var result any
			err := api.QueryRow(ctx, query, args...).Scan(&result)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Fatal("private approval helper became callable", err)
			}
			if name != "ordered62_inner_ready" {
				err = owner.QueryRow(ctx, query, args...).Scan(&result)
				if !errors.As(err, &native) || native.Code != "22023" {
					t.Fatal("private approval admitted non-decide operation", err)
				}
			}
		})
		for _, mutation := range []string{"body", "acl", "pin"} {
			if mutation == "pin" && name != "ordered62_inner_ready" {
				continue
			}
			t.Run(name+"-"+mutation, func(t *testing.T) {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := tx.Rollback(cleanup); err != nil {
						t.Error(err)
					}
				}()
				signature := "zasp_authorization80_worker." + name + "(text,text)"
				if name != "ordered62_inner_ready" {
					signature = "zasp_authorization80_worker." + name + "(text,text,jsonb)"
				}
				statement := "GRANT EXECUTE ON FUNCTION " + signature + " TO " + pgx.Identifier{api.Config().User}.Sanitize()
				if mutation != "acl" {
					var definition string
					if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef(to_regprocedure($1::text))`, signature).Scan(&definition); err != nil {
						t.Fatal(err)
					}
					if mutation == "body" {
						if strings.Count(definition, "AS $function$") != 1 {
							t.Fatal("inner helper body anchor changed")
						}
						statement = strings.Replace(definition, "AS $function$", "AS $function$\n-- unchanged-result control\n", 1)
					} else {
						pin := regexp.MustCompile(`zasp_authorization80_worker\.projected62\(\)='[a-f0-9]{64}'`)
						if len(pin.FindAllString(definition, -1)) != 1 {
							t.Fatal("inner helper projected pin anchor changed")
						}
						statement = pin.ReplaceAllString(definition, "zasp_authorization80_worker.projected62()='"+strings.Repeat("0", 64)+"'")
					}
				}
				if _, err := tx.Exec(ctx, statement); err != nil {
					t.Fatal(err)
				}
				if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() OR zasp_temporal78.current_ready()`).Scan(&ready); err != nil || ready {
					t.Fatal("private approval catalog mutation accepted", err)
				}
			})
		}
	}
}
