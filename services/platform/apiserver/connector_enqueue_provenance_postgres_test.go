package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const connectorCapturedEnqueueSQL = `SELECT zasp_connector_provenance.capture_pkce_cleanup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

// Actual original native80 admission, registered API session and official FGA
// fixture. No task, grant, effect or origin is seeded for these assertions.
// This tests captured-INACTIVE provenance only, not any of the eight worker
// lifecycle operations or runtime readiness/activation.
func TestConnectorCapturedEnqueueOriginalAuthorizationPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t, true)
	f.freshReferenceSession(t)
	runner, err := migrations.NewRunner(&orderedAdmissionMigrationDatabase{connection: f.owner, t: t})
	if err != nil {
		t.Fatal("runner unavailable")
	}
	beforeNative := connectorProvenanceNativeState(t, f)
	if err := runner.UpProductionConnectorEnqueueProvenance(f.ctx); err != nil {
		t.Fatal("capture profile installation refused")
	}
	if connectorProvenanceNativeState(t, f) != beforeNative {
		t.Fatal("capture installation changed predecessor state")
	}
	pin, err := migrations.ConnectorEnqueueProvenanceProfileChecksum()
	if err != nil {
		t.Fatal("compiled capture pin unavailable")
	}
	var admitted bool
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_connector_provenance.catalog_matches($1) AND NOT EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace='zasp_connector_provenance'::regnamespace AND proname IN('claim','ready','activate','begin_attempt','settle'))`, pin).Scan(&admitted); err != nil || !admitted {
		t.Fatal("captured-only catalog refused")
	}

	args := func(n int) []any {
		digest := sha256.Sum256([]byte(fmt.Sprintf("original connector PKCE cleanup intent %d", n)))
		i := f.browser
		return []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), fmt.Sprintf("pid_782101%02d-0000-4000-8000-000000000001", n), integrationClientExisting, "", "github", fmt.Sprintf("ref:oauth/pkce/provenance-%02d", n), digest[:], time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond), "oauth_start_rejected"}
	}
	proof := func(t *testing.T, operation string) string {
		t.Helper()
		g, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": integrationClientExisting}})
		if err != nil {
			t.Fatal("original authorization refused")
		}
		raw, err := authorizationProofJSON(g)
		if err != nil {
			t.Fatal("original signed proof unavailable")
		}
		return string(raw)
	}
	invoke := func(t *testing.T, p string, a []any, rollback bool) ([]byte, error) {
		t.Helper()
		tx, err := f.api.Begin(f.ctx)
		if err != nil {
			t.Fatal("registered API transaction unavailable")
		}
		defer tx.Rollback(f.ctx)
		var raw []byte
		err = tx.QueryRow(f.ctx, connectorCapturedEnqueueSQL, append([]any{p}, a...)...).Scan(&raw)
		if err != nil {
			return nil, err
		}
		if rollback {
			_, err = tx.Exec(f.ctx, `SELECT 1/0`)
			return raw, err
		}
		return raw, tx.Commit(f.ctx)
	}
	reject := func(t *testing.T, p string, a []any, code string) {
		t.Helper()
		before := connectorProvenanceBusinessState(t, f)
		_, err := invoke(t, p, a, false)
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != code {
			t.Fatal("expected native refusal missing")
		}
		if connectorProvenanceBusinessState(t, f) != before {
			t.Fatal("refusal left enqueue, origin, lane or audit mutation")
		}
	}

	t.Run("authentic capture and exact replay", func(t *testing.T) {
		a := args(1)
		p := proof(t, "authorizeIntegration")
		raw, err := invoke(t, p, a, false)
		if err != nil {
			t.Fatal("authenticated capture refused")
		}
		var result struct {
			ID        string `json:"id"`
			Operation string `json:"operation"`
			Status    string `json:"status"`
			Attempt   int    `json:"attempt"`
		}
		if err := json.Unmarshal(raw, &result); err != nil || result.ID != a[3] || result.Operation != "pkce_cleanup" || result.Status != "unknown" || result.Attempt != 0 {
			t.Fatal("original enqueue result changed")
		}
		source := sha256.Sum256([]byte(p))
		var exact bool
		if err := f.owner.QueryRow(f.ctx, `SELECT x.status='captured_inactive' AND x.operation_id='authorizeIntegration' AND x.principal_id=$2 AND x.source_proof_digest=$3 AND x.committed_request_digest=n.request_digest AND octet_length(x.committed_effect_digest)=32 AND x.committed_effect_digest<>x.source_proof_digest AND x.source_proof_digest<>x.committed_request_digest AND n.attempt=0 AND n.lease_owner IS NULL FROM zasp_connector_provenance.origins x JOIN public.zasp_connector_effects n ON(x.organization_id,x.workspace_id,x.environment_id,x.effect_id)=(n.organization_id,n.workspace_id,n.environment_id,n.id) WHERE x.effect_id=$1`, a[3], f.browser.PrincipalID.String(), source[:]).Scan(&exact); err != nil || !exact {
			t.Fatal("committed source and effect provenance missing or conflated")
		}
		before := connectorProvenanceBusinessState(t, f)
		replay, err := invoke(t, proof(t, "authorizeIntegration"), a, false)
		if err != nil || string(replay) != string(raw) || connectorProvenanceBusinessState(t, f) != before {
			t.Fatal("exact replay changed original output or first provenance")
		}
		changed := append([]any(nil), a...)
		digest := sha256.Sum256([]byte("conflicting authenticated intent"))
		changed[8] = digest[:]
		reject(t, proof(t, "authorizeIntegration"), changed, "23505")
	})
	t.Run("wrong signed purpose", func(t *testing.T) { reject(t, proof(t, "getIntegration"), args(2), "42501") })
	t.Run("wrong selected scope", func(t *testing.T) {
		a := args(3)
		a[2] = "pid_78210999-0000-4000-8000-000000000001"
		reject(t, proof(t, "authorizeIntegration"), a, "42501")
	})
	t.Run("modified signed envelope", func(t *testing.T) {
		p := proof(t, "authorizeIntegration")
		var object map[string]any
		if err := json.Unmarshal([]byte(p), &object); err != nil {
			t.Fatal("signed fixture envelope malformed")
		}
		// A malformed envelope is a negative only; no synthetic proof is admitted.
		object["unexpected_connector_field"] = true
		changed, err := json.Marshal(object)
		if err != nil {
			t.Fatal("negative envelope unavailable")
		}
		reject(t, string(changed), args(4), "42501")
	})
	t.Run("existing originless effect refused", func(t *testing.T) {
		a := args(5)
		p := proof(t, "authorizeIntegration")
		tx, err := f.api.Begin(f.ctx)
		if err != nil {
			t.Fatal("native transaction unavailable")
		}
		// Original signed native fence is still required. This retained original
		// enqueue intentionally lacks the supplementary receipt, never a fake origin.
		_, err = tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, p)
		if err == nil {
			var raw []byte
			err = tx.QueryRow(f.ctx, `SELECT public.zasp_connector_stage_pkce_cleanup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, a...).Scan(&raw)
		}
		if err != nil {
			_ = tx.Rollback(f.ctx)
			t.Fatal("original authenticated enqueue refused")
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal("original enqueue commit refused")
		}
		reject(t, proof(t, "authorizeIntegration"), a, "42501")
	})
	t.Run("later transaction failure rolls back enqueue and origin", func(t *testing.T) {
		before := connectorProvenanceBusinessState(t, f)
		_, err := invoke(t, proof(t, "authorizeIntegration"), args(6), true)
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != "22012" {
			t.Fatal("post-enqueue transaction failure missing")
		}
		if connectorProvenanceBusinessState(t, f) != before {
			t.Fatal("rollback retained enqueue, origin, lane or audit")
		}
	})
	t.Run("own catalog drift refused", func(t *testing.T) {
		if _, err := f.owner.Exec(f.ctx, `ALTER TABLE zasp_connector_provenance.origins ADD COLUMN unexpected text`); err != nil {
			t.Fatal("own catalog negative unavailable")
		}
		reject(t, proof(t, "authorizeIntegration"), args(7), "42501")
		if _, err := f.owner.Exec(f.ctx, `ALTER TABLE zasp_connector_provenance.origins DROP COLUMN unexpected`); err != nil {
			t.Fatal("own catalog restoration refused")
		}
		if err := runner.UpProductionConnectorEnqueueProvenance(f.ctx); err != nil {
			t.Fatal("restored own catalog refused")
		}
	})
	t.Run("outbox consumer cannot capture", func(t *testing.T) {
		conn := connectRuntimeDataPlanePrincipal(t, f.ctx, f.dsn, "auth80_outbox")
		defer conn.Close(f.ctx)
		before := connectorProvenanceBusinessState(t, f)
		_, err := conn.Exec(f.ctx, connectorCapturedEnqueueSQL, append([]any{proof(t, "authorizeIntegration")}, args(8)...)...)
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != "42501" {
			t.Fatal("outbox capture permission was broadened")
		}
		if connectorProvenanceBusinessState(t, f) != before {
			t.Fatal("denied outbox capture mutated state")
		}
	})
	if connectorProvenanceNativeState(t, f) != beforeNative {
		t.Fatal("capture controls changed original native catalogs or principals")
	}
}

// Full selected mutable tables, not counts, detect partial writes including
// the original lane triggers and audit side effects of the unchanged stage.
func connectorProvenanceBusinessState(t *testing.T, f *integrationClientFixture) string {
	t.Helper()
	var raw string
	if err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_array(
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY organization_id,workspace_id,environment_id,id),'[]') FROM public.zasp_connector_effects x),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY organization_id,workspace_id,environment_id,effect_id),'[]') FROM zasp_connector_provenance.origins x),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY organization_id,workspace_id,environment_id,id),'[]') FROM public.zasp_connector_audit x),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY provider,operation,organization_id,workspace_id,environment_id),'[]') FROM public.zasp_connector_effect_lane_scopes x))::text`).Scan(&raw); err != nil {
		t.Fatal("complete connector state unavailable")
	}
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func connectorProvenanceNativeState(t *testing.T, f *integrationClientFixture) string {
	t.Helper()
	var raw string
	if err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_array(
 (SELECT count(*) FROM public.zasp_schema_versions),
 zasp_temporal72.current_ready(),zasp_authorization79.ready($1),zasp_authorization80.ready($2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY principal_name) FROM public.zasp_discovery_principal_bindings x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY principal_name) FROM zasp_temporal72.principals x),
 zasp_authorization79.fingerprint())::text`, migrations.ProductionAuthorizationProjection().Checksum(), migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&raw); err != nil {
		t.Fatal("original native state unavailable")
	}
	var fields []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil || len(fields) != 7 || string(fields[0]) != "61" || string(fields[1]) != "true" || string(fields[2]) != "true" || string(fields[3]) != "true" {
		t.Fatal("original native readiness prerequisite refused")
	}
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
