package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Installed current authority must refuse an already prepared effect after
// connector/schedule revocation, binding drift or original-budget expiry.
func TestTemporalDiscoveryCurrentEffectGuardPostgres(t *testing.T) {
	f, worker, start, deadline := temporalDiscoveryPageFixture(t)
	var raw []byte
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,0,'')`, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, replayIntegration, start.InputDigest, deadline).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var prepared struct {
		EffectID string `json:"effect_id"`
	}
	if json.Unmarshal(raw, &prepared) != nil || prepared.EffectID == "" {
		t.Fatal("prepared effect", string(raw))
	}
	query := `SELECT zasp_temporal72.guard_page_effect($1,$2,$3,$4,$5,$6)`
	args := []any{replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, prepared.EffectID, deadline}
	var allowed bool
	if err := worker.QueryRow(f.ctx, query, args...).Scan(&allowed); err != nil || !allowed {
		t.Fatal("current prepared effect refused", err)
	}
	for _, c := range []struct{ name, mutation string }{
		{"disabled_connector", `UPDATE public.zasp_integrations SET state='disabled' WHERE id=$1`},
		{"changed_configuration", `UPDATE public.zasp_integrations SET configuration=configuration||'{"region":"us-west-2"}'::jsonb WHERE id=$1`},
		{"revoked_connection", `UPDATE public.zasp_integration_connections SET state='revoked',revoked_at=clock_timestamp() WHERE integration_id=$1`},
		{"changed_credential_reference", `UPDATE public.zasp_integration_connections SET connection_reference='ref:aws/external-id/foreign-0001' WHERE integration_id=$1`},
		{"changed_subject", `UPDATE public.zasp_discovery_connection_subjects SET subject_id='999999999999' WHERE integration_id=$1`},
		{"disabled_schedule", `UPDATE zasp_temporal72.schedules SET state='disabled' WHERE integration_id=$1`},
		{"expired_original_budget", `UPDATE zasp_temporal72.runs SET admitted_at=clock_timestamp()-interval '25 hours',deadline=clock_timestamp()-interval '1 hour' WHERE integration_id=$1`},
	} {
		t.Run(c.name, func(t *testing.T) {
			tx, err := f.owner.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			mutation := c.mutation
			// A single clock value keeps the immutable24h relation exact.
			if c.name == "expired_original_budget" {
				mutation = `WITH n AS(SELECT clock_timestamp() v) UPDATE zasp_temporal72.runs SET admitted_at=n.v-interval '25 hours',deadline=n.v-interval '1 hour' FROM n WHERE integration_id=$1`
			}
			if _, err := tx.Exec(f.ctx, mutation, replayIntegration); err != nil {
				t.Fatal("fixture mutation", err)
			}
			localArgs := append([]any(nil), args...)
			if c.name == "expired_original_budget" {
				var original time.Time
				if err := tx.QueryRow(f.ctx, `SELECT deadline FROM zasp_temporal72.runs WHERE job_id=$1`, start.Ref.RunID).Scan(&original); err != nil {
					t.Fatal(err)
				}
				localArgs[5] = original
			}
			// The transaction owns only disposable fixture mutations. Invoke the
			// real definer guard as the exact registered session principal.
			if _, err := tx.Exec(f.ctx, "SET LOCAL SESSION AUTHORIZATION "+pgx.Identifier{f.registration.discovery}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			if err := tx.QueryRow(f.ctx, query, localArgs...).Scan(&allowed); err == nil {
				t.Fatal("prepared effect retained stale authority")
			}
		})
		if err := worker.QueryRow(f.ctx, query, args...).Scan(&allowed); err != nil || !allowed {
			t.Fatal("rollback did not preserve original effect", c.name, err)
		}
	}
	var legacyCount int
	if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM public.zasp_discovery_jobs`).Scan(&legacyCount); err != nil || legacyCount != 0 {
		t.Fatal("legacy authority inserted", err)
	}
}
