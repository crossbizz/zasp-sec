package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func exerciseAuthorizationAttestation(t *testing.T, ctx context.Context, owner, api *pgx.Conn, grant RequestAuthorization, visible, hidden string) {
	t.Helper()
	proof, err := authorizationProofJSON(grant)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Body    []byte `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}
	if json.Unmarshal(proof, &envelope) != nil {
		t.Fatal("test envelope invalid")
	}
	key := authorizationFixtureAttestor(t)
	tables := map[string]string{"zasp_risk_attack_paths": "id", "zasp_risk_attack_path_nodes": "path_id", "zasp_risk_attack_path_evidence": "path_id", "zasp_risk_break_options": "path_id", "zasp_risk_findings": "id", "zasp_risk_finding_evidence": "finding_id", "zasp_risk_finding_factors": "finding_id"}
	assertRows := func(t *testing.T, tx pgx.Tx, want int) {
		t.Helper()
		for table, id := range tables {
			var count int
			var wrong bool
			if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT count(*),COALESCE(bool_or(%s<>$1 OR environment_id<>$2),false) FROM %s`, id, table), visible, grant.Identity.Scope.EnvironmentID().String()).Scan(&count, &wrong); err != nil || count != want || wrong {
				t.Fatalf("native %s count=%d foreign=%v error=%v", table, count, wrong, err)
			}
		}
	}
	var copiedProof, copiedSeal string
	t.Run("current Check reads exact native rows", func(t *testing.T) {
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
			t.Fatal(err)
		}
		assertRows(t, tx, 1)
		if err = tx.QueryRow(ctx, `SELECT current_setting('zasp.authorization80'),current_setting('zasp.authorization80_seal')`).Scan(&copiedProof, &copiedSeal); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='potential' WHERE id=$1`, visible); err != nil {
			t.Fatal(err)
		}
		var state string
		if err = tx.QueryRow(ctx, `SELECT state FROM zasp_risk_attack_paths WHERE id=$1`, visible).Scan(&state); err != nil || state != "verified" {
			t.Fatalf("raw API write escaped read policy: %v", err)
		}
	})
	t.Run("copied context fails in another transaction", func(t *testing.T) {
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SELECT txid_current(),set_config('zasp.authorization80',$1,true),set_config('zasp.authorization80_seal',$2,true)`, copiedProof, copiedSeal); err != nil {
			t.Fatal(err)
		}
		assertRows(t, tx, 0)
	})
	t.Run("same narrow attestation rechecks new transaction", func(t *testing.T) {
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
			t.Fatal(err)
		}
		assertRows(t, tx, 1)
	})
	for _, name := range []string{"permission tamper", "wrong version", "wrong MAC", "unsigned allowed", "duplicate envelope", "duplicate signed claims", "expired", "future", "wrong model", "wrong scope"} {
		t.Run(name, func(t *testing.T) {
			candidate := envelope
			var claims map[string]json.RawMessage
			_ = json.Unmarshal(envelope.Body, &claims)
			resign := false
			switch name {
			case "permission tamper":
				claims["permission"] = json.RawMessage(`"manage_identity"`)
			case "wrong version":
				candidate.Version = strings.Repeat("0", 64)
			case "wrong MAC":
				candidate.MAC = strings.Repeat("0", 64)
			case "expired":
				claims["issued_at"], _ = json.Marshal(time.Now().Add(-2 * time.Minute).UnixMilli())
				claims["expires_at"], _ = json.Marshal(time.Now().Add(-time.Minute).UnixMilli())
				resign = true
			case "future":
				claims["issued_at"], _ = json.Marshal(time.Now().Add(time.Minute).UnixMilli())
				claims["expires_at"], _ = json.Marshal(time.Now().Add(2 * time.Minute).UnixMilli())
				resign = true
			case "wrong model":
				var revision map[string]json.RawMessage
				_ = json.Unmarshal(claims["revision"], &revision)
				revision["model_id"] = json.RawMessage(`"01K00000000000000000000009"`)
				claims["revision"], _ = json.Marshal(revision)
				resign = true
			case "wrong scope":
				claims["environment_id"], _ = json.Marshal(hidden)
				resign = true
			}
			candidate.Body, _ = json.Marshal(claims)
			if name == "duplicate signed claims" {
				candidate.Body = append([]byte(`{"operation_id":"getHomeSummary",`), candidate.Body[1:]...)
				resign = true
			}
			encoded, _ := json.Marshal(candidate)
			if resign {
				encoded, err = key.Sign(candidate.Body)
				if err != nil {
					t.Fatal(err)
				}
			}
			if name == "unsigned allowed" {
				encoded = append([]byte(`{"allowed":[],`), encoded[1:]...)
			}
			if name == "duplicate envelope" {
				encoded = append([]byte(`{"mac":"forged",`), encoded[1:]...)
			}
			tx, err := api.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(encoded)); err == nil {
				t.Fatal("invalid attestation reached current context")
			}
		})
	}
	t.Run("API cannot read or replace verifier", func(t *testing.T) {
		if _, err := api.Exec(ctx, `SELECT key FROM zasp_authorization80.verifier`); err == nil {
			t.Fatal("API read private verifier")
		}
		if _, err := api.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, key.Version(), key.Verifier()); err == nil {
			t.Fatal("API registered its own issuer")
		}
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err == nil {
			t.Fatal("API assumed source authority")
		}
	})
	t.Run("context stops disclosure at signed expiry", func(t *testing.T) {
		var claims map[string]json.RawMessage
		_ = json.Unmarshal(envelope.Body, &claims)
		claims["issued_at"], _ = json.Marshal(time.Now().UnixMilli())
		claims["expires_at"], _ = json.Marshal(time.Now().Add(2 * time.Second).UnixMilli())
		body, _ := json.Marshal(claims)
		shortProof, err := key.Sign(body)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(shortProof)); err != nil {
			t.Fatal(err)
		}
		assertRows(t, tx, 1)
		if _, err = tx.Exec(ctx, `SELECT pg_sleep(2.1)`); err != nil {
			t.Fatal(err)
		}
		assertRows(t, tx, 0)
	})
}
