package redteamadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type ownedJournalDatabase struct{ connection *pgx.Conn }

// Lose only the acknowledgement, after the real completion transaction commits.
type ownedLostAckJournal struct{ InvocationJournal }

func (j ownedLostAckJournal) Complete(ctx context.Context, request JournalRequest, attempt int, observation InvocationObservation) error {
	if err := j.InvocationJournal.Complete(ctx, request, attempt, observation); err != nil {
		return err
	}
	return ErrAdapter
}

func (d ownedJournalDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	var body json.RawMessage
	err := d.connection.QueryRow(ctx, query, args...).Scan(&body)
	return body, err
}

// Run only as a child of the owned apiserver fixture. The client uses the real
// registered adapter role; the separate owner connection only observes commits.
// TLS routing and credentials are controlled, not live discovery/provider proof.
func TestPostgresJournalOwnedHTTPS(t *testing.T) {
	dsn := os.Getenv("ZASP_JOURNAL_OWNER_DSN")
	if dsn == "" {
		t.Skip("requires owned PostgreSQL fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	config := owner.Config().Copy()
	config.User = "existing_test_red_adapter"
	adapter, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close(context.Background())
	ids := make([]domain.ProductID, 3)
	for i, key := range []string{"ZASP_JOURNAL_ORG", "ZASP_JOURNAL_WORKSPACE", "ZASP_JOURNAL_ENVIRONMENT"} {
		ids[i], err = domain.ParseProductID(os.Getenv(key))
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	run := os.Getenv("ZASP_JOURNAL_RUN")
	client, err := NewPostgresInvocationJournal(ownedJournalDatabase{adapter}, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	lease := strings.Repeat("a", 32)
	binding, err := client.ResolveTarget(ctx, TargetResolution{Scope: scope, RunID: run, LeaseToken: lease, TargetID: "pid_89000011-0000-4000-8000-000000000001", TargetKind: "agent_endpoint", Category: "prompt_injection"})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	response := `{"output":"ZASP_RED_TEAM_PROMPT_INJECTION"}`
	unknown := os.Getenv("ZASP_JOURNAL_INVALID_RESPONSE") == "1"
	if unknown {
		response = `{"output":null}`
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		payload, readErr := io.ReadAll(r.Body)
		digest := sha256.Sum256(payload)
		var committed bool
		err := owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_security_agent_test_invocations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND test_run_id=$4 AND category='prompt_injection' AND state='started' AND request_digest=$5`, ids[0].String(), ids[1].String(), ids[2].String(), run, digest[:]).Scan(&committed)
		if readErr != nil || err != nil || !committed || r.Header.Get("X-Zasp-Payload-Digest") != "sha256:"+hex.EncodeToString(digest[:]) {
			t.Errorf("target reached without matching committed start: committed=%v read=%v query=%v", committed, readErr, err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()
	invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var journal InvocationJournal = client
	lostAck := os.Getenv("ZASP_JOURNAL_LOST_ACK") == "1"
	if lostAck {
		journal = ownedLostAckJournal{client}
	}
	handler, err := NewJournaledHandler(Config{WorkerToken: []byte(testWorkerToken), MaximumRequestBytes: 4096}, client, invoker, journal)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(requestBody{TargetID: binding.TargetID, TargetKind: binding.TargetKind, Category: "prompt_injection", Input: curatedInputs["prompt_injection"]})
	if err != nil {
		t.Fatal(err)
	}
	call := func(handler *Handler, changedHeader, value string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/linked/evaluate", strings.NewReader(string(body))).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+testWorkerToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Zasp-Organization-ID", ids[0].String())
		r.Header.Set("X-Zasp-Workspace-ID", ids[1].String())
		r.Header.Set("X-Zasp-Environment-ID", ids[2].String())
		r.Header.Set("X-Zasp-Run-ID", run)
		r.Header.Set("X-Zasp-Run-Lease", lease)
		if changedHeader != "" {
			r.Header.Set(changedHeader, value)
		}
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, r)
		return result
	}
	for _, header := range []string{"Authorization", "X-Zasp-Organization-ID", "X-Zasp-Workspace-ID", "X-Zasp-Environment-ID", "X-Zasp-Run-ID", "X-Zasp-Run-Lease"} {
		value := "pid_89ffffff-0000-4000-8000-000000000001"
		want := http.StatusServiceUnavailable
		if header == "Authorization" {
			value, want = "Bearer wrong", http.StatusForbidden
		} else if header == "X-Zasp-Run-Lease" {
			value = strings.Repeat("b", 32)
		}
		denied := call(handler, header, value)
		if denied.Code != want || calls.Load() != 0 {
			t.Fatalf("wrong %s admitted: status=%d calls=%d", header, denied.Code, calls.Load())
		}
	}
	first := call(handler, "", "")
	wantDigest := sha256.Sum256([]byte(response))
	checkObservation := func(result *httptest.ResponseRecorder) {
		fields, shapeErr := exactJournalObject(result.Body.Bytes(), "schema_version run_id category observation credential_version_digest target_comparison")
		observation, observationErr := exactJournalObject(fields["observation"], "http_status response_digest protected")
		if shapeErr != nil || observationErr != nil || len(fields) != 6 || len(observation) != 3 {
			t.Fatalf("unexpected linked response fields: %s", result.Body.String())
		}
		var linked LinkedObservationResponse
		err := json.Unmarshal(result.Body.Bytes(), &linked)
		comparisonBytes, marshalErr := json.Marshal(linked.TargetComparison)
		var exactComparison bool
		comparisonErr := owner.QueryRow(ctx, `SELECT $1::jsonb=target_resolution->'comparison' FROM zasp_security_agent_test_invocations WHERE test_run_id=$2 AND category='prompt_injection'`, string(comparisonBytes), run).Scan(&exactComparison)
		if marshalErr != nil || comparisonErr != nil || !exactComparison {
			t.Fatalf("HTTP comparison differs from durable invocation: %v %v", marshalErr, comparisonErr)
		}
		if result.Code != 200 || err != nil || linked.SchemaVersion != "red-team-linked-observation-v1" || linked.RunID != run || linked.Category != "prompt_injection" || linked.Observation.Protected == nil || *linked.Observation.Protected || linked.Observation.ResponseDigest != hex.EncodeToString(wantDigest[:]) || linked.Observation.HTTPStatus != 200 || linked.CredentialVersionDigest != strings.Repeat("d", 64) || calls.Load() != 1 {
			t.Fatalf("HTTP observation lost or resent: status=%d body=%s err=%v calls=%d", result.Code, result.Body.String(), err, calls.Load())
		}
		if result.Header().Get("Cache-Control") != "no-store" || strings.Contains(result.Body.String(), "ZASP_RED_TEAM") || strings.Contains(result.Body.String(), "credential_reference") || strings.Contains(result.Body.String(), `"output"`) {
			t.Fatalf("raw target data leaked: %s", result.Body.String())
		}
	}
	if lostAck || unknown {
		if first.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
			t.Fatalf("uncertain execution reported success: status=%d calls=%d", first.Code, calls.Load())
		}
	} else {
		checkObservation(first)
	}
	// A fresh registered connection models adapter restart, not an in-memory cache.
	if err := adapter.Close(ctx); err != nil {
		t.Fatal(err)
	}
	restarted, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close(context.Background())
	client, err = NewPostgresInvocationJournal(ownedJournalDatabase{restarted}, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewJournaledHandler(Config{WorkerToken: []byte(testWorkerToken), MaximumRequestBytes: 4096}, client, invoker, client)
	if err != nil {
		t.Fatal(err)
	}
	replay := call(handler, "", "")
	if unknown {
		var retained bool
		err := owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_security_agent_test_invocations WHERE test_run_id=$1 AND state='started' AND completed_at IS NULL`, run).Scan(&retained)
		if replay.Code != http.StatusServiceUnavailable || calls.Load() != 1 || err != nil || !retained {
			t.Fatalf("unknown outcome retried or lost: status=%d calls=%d retained=%v err=%v", replay.Code, calls.Load(), retained, err)
		}
	} else {
		checkObservation(replay)
		// A durable result must not be presented as comparable after rotation or
		// effective target configuration changes under the same target identity.
		var originalVersion int64
		var originalDigest []byte
		var originalAttributes json.RawMessage
		var originalSafety, originalCategories json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT d.safety,d.categories FROM zasp_red_team_definitions d JOIN zasp_red_team_runs r ON (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=(r.organization_id,r.workspace_id,r.environment_id,r.definition_id) WHERE r.run_id=$1`, run).Scan(&originalSafety, &originalCategories); err != nil {
			t.Fatal(err)
		}
		var journalBefore string
		var comparison struct {
			OrganizationID           string   `json:"organization_id"`
			WorkspaceID              string   `json:"workspace_id"`
			EnvironmentID            string   `json:"environment_id"`
			TestDefinitionID         string   `json:"test_definition_id"`
			TestDefinitionVersion    int64    `json:"test_definition_version"`
			TargetID                 string   `json:"target_id"`
			TargetKind               string   `json:"target_kind"`
			Categories               []string `json:"categories"`
			SafetyDigest             string   `json:"safety_digest"`
			SchemaVersion            string   `json:"schema_version"`
			EndpointDigest           string   `json:"endpoint_digest"`
			ConfigurationDigest      string   `json:"configuration_digest"`
			CredentialBindingID      string   `json:"credential_binding_id"`
			CredentialBindingVersion int64    `json:"credential_binding_version"`
			CredentialBindingDigest  string   `json:"credential_binding_digest"`
		}
		var comparisonBytes json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(i)::text,target_resolution->'comparison' FROM zasp_security_agent_test_invocations i WHERE test_run_id=$1`, run).Scan(&journalBefore, &comparisonBytes); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT b.version,b.reference_digest,e.winning_attributes FROM zasp_attack_lab_credential_bindings b JOIN zasp_inventory_entities e ON (e.organization_id,e.workspace_id,e.environment_id,e.id)=(b.organization_id,b.workspace_id,b.environment_id,b.target_id) WHERE (b.organization_id,b.workspace_id,b.environment_id,b.target_id,b.credential_reference)=($1,$2,$3,$4,$5)`, ids[0].String(), ids[1].String(), ids[2].String(), binding.TargetID, binding.CredentialReference).Scan(&originalVersion, &originalDigest, &originalAttributes); err != nil {
			t.Fatal(err)
		}
		for _, change := range []string{"credential_version", "credential_digest", "configuration", "safety", "categories"} {
			query := `UPDATE zasp_attack_lab_credential_bindings SET version=version+1 WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`
			if change == "credential_digest" {
				query = `UPDATE zasp_attack_lab_credential_bindings SET reference_digest=decode(repeat('ef',32),'hex') WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`
			} else if change == "configuration" {
				query = `UPDATE zasp_inventory_entities SET winning_attributes=winning_attributes||'{"model":"changed-model"}'::jsonb WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`
			} else if change == "safety" {
				query = `UPDATE zasp_red_team_definitions SET safety=jsonb_set(safety,'{expected_side_effects}','["changed bounded evaluation"]'::jsonb) WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`
			} else if change == "categories" {
				query = `UPDATE zasp_red_team_definitions SET categories='["prompt_injection","tool_abuse"]'::jsonb WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`
			}
			if _, err := owner.Exec(ctx, query, ids[0].String(), ids[1].String(), ids[2].String(), binding.TargetID); err != nil {
				t.Fatal(err)
			}
			changed := call(handler, "", "")
			_, credentialErr := owner.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET version=$5,reference_digest=$6 WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`, ids[0].String(), ids[1].String(), ids[2].String(), binding.TargetID, originalVersion, originalDigest)
			_, attributesErr := owner.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=$5 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, ids[0].String(), ids[1].String(), ids[2].String(), binding.TargetID, originalAttributes)
			_, definitionErr := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET safety=$5,categories=$6 WHERE (organization_id,workspace_id,environment_id,target_id)=($1,$2,$3,$4)`, ids[0].String(), ids[1].String(), ids[2].String(), binding.TargetID, originalSafety, originalCategories)
			if credentialErr != nil || attributesErr != nil || definitionErr != nil {
				t.Fatalf("restore owned comparison fixture: %v %v %v", credentialErr, attributesErr, definitionErr)
			}
			if changed.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
				t.Errorf("changed %s reused prior execution: status=%d calls=%d", change, changed.Code, calls.Load())
			}
			var journalAfter string
			if err := owner.QueryRow(ctx, `SELECT to_jsonb(i)::text FROM zasp_security_agent_test_invocations i WHERE test_run_id=$1`, run).Scan(&journalAfter); err != nil || journalAfter != journalBefore {
				t.Fatalf("%s refusal changed durable journal: %v", change, err)
			}
		}
		endpointDigest := sha256.Sum256([]byte("https://adapter.customer.example/v1/evaluate"))
		if json.Unmarshal(comparisonBytes, &comparison) != nil || comparison.SchemaVersion != "red-team-target-comparison-v1" || comparison.EndpointDigest != hex.EncodeToString(endpointDigest[:]) || comparison.CredentialBindingVersion != originalVersion || comparison.CredentialBindingDigest != hex.EncodeToString(originalDigest) || !releaseDigestPattern.MatchString(comparison.ConfigurationDigest) {
			t.Fatalf("stored comparison identity missing: %s", comparisonBytes)
		}
		if _, err := domain.ParseProductID(comparison.CredentialBindingID); err != nil {
			t.Fatalf("stored credential identity missing: %s", comparisonBytes)
		}
		safetyDigest := sha256.Sum256(originalSafety)
		if comparison.OrganizationID != ids[0].String() || comparison.WorkspaceID != ids[1].String() || comparison.EnvironmentID != ids[2].String() || comparison.TestDefinitionID != "pid_89000012-0000-4000-8000-000000000002" || comparison.TestDefinitionVersion != 1 || comparison.TargetID != binding.TargetID || comparison.TargetKind != binding.TargetKind || len(comparison.Categories) != 1 || comparison.Categories[0] != "prompt_injection" || comparison.SafetyDigest != hex.EncodeToString(safetyDigest[:]) {
			t.Fatalf("stored scoped test/safety comparison missing: %s", comparisonBytes)
		}
		checkObservation(call(handler, "", ""))
	}
}
