package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Removing the native provider full-row comparison must fail these controls.
// Owner-only corruption is rollback-only; the consuming call runs with the
// actual registered session identity, not merely SET ROLE under a superuser.
func assertOrdered68ProviderEvidence(t *testing.T, ctx context.Context, owner *pgx.Conn, principal, o, w, e, run string, request json.RawMessage) {
	t.Helper()
	evidence := func() []byte {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var raw []byte
		err := owner.QueryRow(bounded, `SELECT jsonb_build_array(
 (SELECT to_jsonb(p) FROM public.zasp_security_agent_plans p WHERE(p.organization_id,p.workspace_id,p.environment_id,p.run_id)=($1,$2,$3,$4)),
 (SELECT to_jsonb(a) FROM zasp_temporal68.admissions a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id)=($1,$2,$3,$4)),
 (SELECT jsonb_agg(to_jsonb(p) ORDER BY attempt) FROM zasp_temporal68.provider_reservations p WHERE(p.organization_id,p.workspace_id,p.environment_id,p.run_id)=($1,$2,$3,$4)),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM public.zasp_security_agent_audit a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id)=($1,$2,$3,$4)),
 (SELECT jsonb_agg(to_jsonb(f) ORDER BY step_id,generation) FROM zasp_temporal68.effects f WHERE(f.organization_id,f.workspace_id,f.environment_id,f.run_id)=($1,$2,$3,$4)),
 (SELECT jsonb_agg(to_jsonb(c) ORDER BY step_id) FROM zasp_authorization80_worker.ordered_effect_scope c WHERE(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=($1,$2,$3,$4)))`, o, w, e, run).Scan(&raw)
		if err != nil {
			t.Fatal("provider evidence snapshot", ordered62TraceClass(err))
		}
		return raw
	}
	before := evidence()
	for _, control := range []string{"unchanged", "ordinary-field", "timestamp-instant"} {
		if !t.Run("provider-evidence-"+control, func(t *testing.T) {
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			tx, err := owner.Begin(bounded)
			if err != nil {
				t.Fatal("provider control begin", ordered62TraceClass(err))
			}
			defer orderedProviderRollback(t, tx)
			if control != "unchanged" {
				assignment := "maximum_cost_nano_credits=maximum_cost_nano_credits+1"
				if control == "timestamp-instant" {
					assignment = "reserved_at=reserved_at-interval '1 microsecond'"
				}
				tag, err := tx.Exec(bounded, `UPDATE zasp_temporal68.provider_reservations p SET `+assignment+` FROM zasp_temporal68.admissions a WHERE(p.organization_id,p.workspace_id,p.environment_id,p.run_id,p.attempt)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt) AND(a.organization_id,a.workspace_id,a.environment_id,a.run_id)=($1,$2,$3,$4)`, o, w, e, run)
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("provider control mutation", tag.RowsAffected(), ordered62TraceClass(err))
				}
			}
			if _, err := tx.Exec(bounded, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{principal}.Sanitize()); err != nil {
				t.Fatal("provider control identity", ordered62TraceClass(err))
			}
			var exact bool
			if err := tx.QueryRow(bounded, `SELECT session_user=$1 AND current_user=$1 AND NOT rolsuper FROM pg_roles WHERE rolname=session_user`, principal).Scan(&exact); err != nil || !exact {
				t.Fatal("provider control not registered nonsuperuser session", exact, ordered62TraceClass(err))
			}
			_, err = tx.Exec(bounded, `SELECT zasp_authorization80_worker.prepare_ordered68_effect($1::jsonb)`, request)
			if control == "unchanged" {
				if err != nil {
					t.Fatal("unchanged provider rejected", ordered62TraceClass(err))
				}
			} else {
				var native *pgconn.PgError
				if !errors.As(err, &native) || native.Code != "40001" || native.Message != "ordered provider authority changed" {
					t.Fatal("provider mutation did not reach exact native digest refusal", ordered62TraceClass(err))
				}
			}
		}) {
			t.Fatal("provider evidence control failed")
		}
		if !bytes.Equal(before, evidence()) {
			t.Fatal("provider control changed accepted plan, accounting, audit or effects")
		}
	}
	if !t.Run("provider-canonical-row-leaf", func(t *testing.T) {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		tx, err := owner.BeginTx(bounded, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal("row serialization begin", ordered62TraceClass(err))
		}
		defer orderedProviderRollback(t, tx)
		var prior []byte
		for _, zone := range []string{"America/Los_Angeles", "UTC"} {
			if _, err := tx.Exec(bounded, `SELECT set_config('TimeZone',$1,true)`, zone); err != nil {
				t.Fatal("row serialization zone", ordered62TraceClass(err))
			}
			var raw []byte
			if err := tx.QueryRow(bounded, `SELECT zasp_authorization80_worker.ordered68_row_json(p) FROM zasp_temporal68.provider_reservations p JOIN zasp_temporal68.admissions a USING(organization_id,workspace_id,environment_id,run_id,attempt) WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id)=($1,$2,$3,$4)`, o, w, e, run).Scan(&raw); err != nil {
				t.Fatal("row serialization query", ordered62TraceClass(err))
			}
			if prior != nil && !bytes.Equal(prior, raw) {
				t.Fatal("typed-row proof serialization changed across timezones")
			}
			prior = raw
		}
		var exact bool
		if err := tx.QueryRow(bounded, `SELECT zasp_authorization80_worker.ordered68_row_json($1::jsonb)=$1::jsonb`, json.RawMessage(`{"ordinary_string":"2026-09-26T00:00:00-07:00","nested":{"time":"unchanged"}}`)).Scan(&exact); err != nil || !exact {
			t.Fatal("typed leaf reinterpreted captured JSON", exact, ordered62TraceClass(err))
		}
	}) {
		t.Fatal("canonical provider leaf failed")
	}
	if !bytes.Equal(before, evidence()) {
		t.Fatal("serialization control changed native evidence")
	}
}

func orderedProviderRollback(t *testing.T, tx pgx.Tx) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tx.Rollback(cleanup); err != nil {
		t.Error("provider control rollback", ordered62TraceClass(err))
	}
}
