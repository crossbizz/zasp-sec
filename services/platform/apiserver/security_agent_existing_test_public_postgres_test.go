package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSecurityAgentExistingTestPublicProofPostgres(t *testing.T) {
	t.Setenv("ZASP_EXISTING_TEST_PUBLIC_PROOF", "true")
	t.Setenv("ZASP_EXISTING_TEST_REGISTERED_DISPATCH", "true")
	TestSecurityAgentExistingTestSettlementPostgres(t)
}

func TestSecurityAgentExistingTestPublicStoppedProofPostgres(t *testing.T) {
	t.Setenv("ZASP_TEST_EXISTING_SETTLEMENT_STOPPED", "true")
	TestSecurityAgentExistingTestPublicProofPostgres(t)
}

func TestSecurityAgentExistingTestPublicRecoveryProofPostgres(t *testing.T) {
	t.Setenv("ZASP_TEST_EXISTING_SETTLEMENT_RECOVERY", "true")
	TestSecurityAgentExistingTestPublicProofPostgres(t)
}

func TestSecurityAgentExistingTestPublicComposedProofPostgres(t *testing.T) {
	if os.Getenv("ZASP_RECONCILE_CLIENT_BINARY") == "" {
		t.Fatal("requires owned registered reconciliation worker binary")
	}
	t.Setenv("ZASP_EXISTING_TEST_PUBLIC_PROOF", "true")
	t.Setenv("ZASP_EXISTING_TEST_REGISTERED_DISPATCH", "true")
	t.Setenv("ZASP_RECONCILE_COMPOSE_ARTIFACTS", "true")
	t.Setenv("ZASP_RECONCILE_INCLUDE_BASELINE", "true")
	TestSecurityAgentExistingTestWorkerFinishPostgres(t)
}

func TestSecurityAgentExistingTestPublicCancellationProofPostgres(t *testing.T) {
	t.Setenv("ZASP_EXISTING_TEST_PUBLIC_PROOF", "true")
	t.Setenv("ZASP_EXISTING_TEST_REGISTERED_DISPATCH", "true")
	TestSecurityAgentExistingTestComposedStoppedPostgres(t)
}

// Read through the existing registered API after real dispatch/settlement, not
// through an owner-only helper. No client supplies proof or target parameters.
func assertExistingTestPublicProof(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, r, s string, settled bool) {
	t.Helper()
	config := owner.Config().Copy()
	config.User = "security_agent_v33_api_login"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	args := existingTestReadPins([]any{o, w, e, r})
	var raw json.RawMessage
	before := existingTestDispatchSnapshot(t, ctx, owner, o, w, e, r)
	if err := api.QueryRow(ctx, postgresExistingTestRunContextSQL, args...).Scan(&raw); err != nil {
		t.Fatalf("registered public proof read: %v", err)
	}
	if _, err := decodeSecurityAgentRunContextEnvelope(raw, r); err != nil {
		t.Fatalf("actual Go consumer rejected registered proof: %v", err)
	}
	var envelope struct {
		Actions struct {
			Steps []struct {
				Existing json.RawMessage `json:"existing_test"`
			} `json:"steps"`
		} `json:"action_details"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Actions.Steps) != 1 || len(envelope.Actions.Steps[0].Existing) == 0 {
		t.Fatalf("linked public proof missing: %s", raw)
	}
	proof := envelope.Actions.Steps[0].Existing
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT $6::jsonb->>'definition_id'=l.test_definition_id
 AND ($6::jsonb->>'definition_version')::bigint=l.test_definition_version
 AND $6::jsonb->>'test_run_id'=l.test_run_id
 AND $6::jsonb->>'state'=CASE WHEN l.reconcile_state='settled' THEN 'settled' ELSE 'pending' END
 AND $6::jsonb->'cancellation_outcome' IS NOT DISTINCT FROM COALESCE(to_jsonb(l.cancellation_outcome),'null'::jsonb)
 AND CASE WHEN $7 THEN $6::jsonb->'verification'->>'outcome'=l.reconcile_settlement->'receipt'->>'outcome'
  AND $6::jsonb->'verification'->>'reason'=l.reconcile_settlement->'receipt'->>'reason'
  AND $6::jsonb->'verification'->>'proof_digest'='sha256:'||encode(f.result_digest,'hex')
  AND $6::jsonb->'verification'->'checks'=COALESCE(l.reconcile_settlement->'proof'->'checks','[]'::jsonb)
 ELSE $6::jsonb->'verification'='null'::jsonb END
 FROM zasp_security_agent_test_links l JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id)
 WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5)`, o, w, e, r, s, proof, settled).Scan(&exact); err != nil || !exact {
		t.Fatalf("public proof differs from stored authority: %s %v", proof, err)
	}
	for _, secret := range []string{"s3://", "proof_hex", "token_digest", "credential_reference", "target_resolution", "lease_token", "reconcile_worker", "\"key\""} {
		if strings.Contains(string(proof), secret) {
			t.Fatalf("private field escaped: %s", secret)
		}
	}
	if before != existingTestDispatchSnapshot(t, ctx, owner, o, w, e, r) {
		t.Fatal("public read mutated authority")
	}
	if err := owner.QueryRow(ctx, postgresExistingTestRunContextSQL, args...).Scan(&raw); err == nil {
		t.Fatal("owner accepted as registered API")
	}
	config.User = "security_agent_v33_worker_login"
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	var denied *pgconn.PgError
	if err := worker.QueryRow(ctx, postgresExistingTestRunContextSQL, args...).Scan(&raw); !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatalf("worker accepted as registered API: %v", err)
	}
	for i := 0; i < 3; i++ {
		bad := append([]any(nil), args...)
		bad[i] = "pid_89ffffff-0000-4000-8000-000000000001"
		if err := api.QueryRow(ctx, postgresExistingTestRunContextSQL, bad...).Scan(&raw); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("foreign scope %d returned proof: %s %v", i, raw, err)
		}
	}
	if !settled {
		return
	}
	var original json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT reconcile_settlement FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, r, s).Scan(&original); err != nil {
		t.Fatal(err)
	}
	assertExistingTestPublicArtifactIdentities(t, proof, original)
	// A revoked credential affects new execution, not the immutable historical
	// comparison. Read through the API while that current authority is revoked.
	var target, credentialState string
	if err := owner.QueryRow(ctx, `SELECT b.target_id,b.state FROM zasp_attack_lab_credential_bindings b JOIN zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,target_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5)`, o, w, e, r, s).Scan(&target, &credentialState); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`, o, w, e, target); err != nil {
		t.Fatal(err)
	}
	readErr := api.QueryRow(ctx, postgresExistingTestRunContextSQL, args...).Scan(&raw)
	_, restoreErr := owner.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET state=$5 WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`, o, w, e, target, credentialState)
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if readErr != nil || json.Unmarshal(raw, &envelope) != nil || len(envelope.Actions.Steps) != 1 || string(envelope.Actions.Steps[0].Existing) != string(proof) {
		t.Fatalf("current credential revocation changed historical proof: %v", readErr)
	}
	for _, path := range []string{"{receipt,proof_sha256}", "{receipt,run_id}", "{proof_hex}", "{snapshot,organization_id}", "{snapshot,definition_id}"} {
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_settlement=jsonb_set(reconcile_settlement,$6::text[],to_jsonb('tampered'::text)) WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, r, s, path); err != nil {
			t.Fatal(err)
		}
		readErr := api.QueryRow(ctx, postgresExistingTestRunContextSQL, args...).Scan(&raw)
		_, restoreErr := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_settlement=$6 WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, r, s, original)
		if restoreErr != nil {
			t.Fatal(restoreErr)
		}
		var pg *pgconn.PgError
		if !errors.As(readErr, &pg) || pg.Code != "55000" {
			t.Fatalf("tampered %s returned proof: %v", path, readErr)
		}
	}
}

func assertExistingTestPublicArtifactIdentities(t *testing.T, publicProof, settlement json.RawMessage) {
	t.Helper()
	type savedArtifact struct {
		Reference string `json:"reference"`
		VersionID string `json:"version_id"`
		SHA256    string `json:"sha256"`
		SizeBytes int64  `json:"size_bytes"`
	}
	type savedAttempt struct {
		RunID       string        `json:"run_id"`
		Attempt     int           `json:"attempt"`
		InputDigest string        `json:"input_digest"`
		Input       savedArtifact `json:"input_artifact"`
		Output      savedArtifact `json:"output_artifact"`
	}
	var saved struct {
		Proof struct{ Before, After *savedAttempt }
	}
	var displayed SecurityAgentExistingTestDetail
	if json.Unmarshal(settlement, &saved) != nil || json.Unmarshal(publicProof, &displayed) != nil || displayed.Verification == nil {
		t.Fatal("invalid stored/public artifact fixture")
	}
	artifact := func(value savedArtifact) SecurityAgentExistingTestArtifactIdentity {
		digest := sha256.Sum256([]byte(value.Reference))
		return SecurityAgentExistingTestArtifactIdentity{ReferenceDigest: hex.EncodeToString(digest[:]), VersionID: value.VersionID, SHA256: value.SHA256, SizeBytes: value.SizeBytes}
	}
	for _, pair := range []struct {
		name      string
		saved     *savedAttempt
		displayed *SecurityAgentExistingTestAttemptProof
	}{
		{"before", saved.Proof.Before, displayed.Verification.Before}, {"after", saved.Proof.After, displayed.Verification.After},
	} {
		var want *SecurityAgentExistingTestAttemptProof
		if pair.saved != nil {
			want = &SecurityAgentExistingTestAttemptProof{RunID: pair.saved.RunID, Attempt: pair.saved.Attempt, InputDigest: pair.saved.InputDigest, InputArtifact: artifact(pair.saved.Input), OutputArtifact: artifact(pair.saved.Output)}
		}
		if !reflect.DeepEqual(pair.displayed, want) {
			t.Fatalf("%s public attempt lost exact stored artifact identity", pair.name)
		}
	}
}
