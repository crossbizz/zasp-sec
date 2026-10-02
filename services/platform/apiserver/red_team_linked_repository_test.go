package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestLinkedRedTeamClaimRepository(t *testing.T) {
	scope := fixtureRequestIdentity(t).Scope
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := "pid_99000001-0000-4000-8000-000000000001"
	definitionID := "pid_99000002-0000-4000-8000-000000000002"
	run := RedTeamRun{ID: runID, Version: 2, DefinitionID: definitionID, DefinitionVersion: 1, Status: "leased", Attempt: 1, QueuedAt: now, StartedAt: &now}
	definition := RedTeamDefinition{ID: definitionID, Version: 1, Name: "Bounded prompt injection", TargetID: "pid_99000004-0000-4000-8000-000000000004", TargetKind: "agent_endpoint", Categories: []string{"prompt_injection"}, Safety: RedTeamSafety{Environment: "test", CredentialClass: "read_only", ExpectedSideEffects: []string{"read-only evaluation"}}, Enabled: true, CreatedAt: now, UpdatedAt: now}
	fixture := func() map[string]any {
		return map[string]any{"disposition": "claimed", "evidence_version": "red-team-v2", "run": run, "definition": definition, "input_digest": strings.Repeat("ab", 32), "lease_expires_at": now.Add(20 * time.Second)}
	}
	for _, mode := range []string{"claimed", "retry_later", "ack_terminal", "reconcile_required", "unknown_disposition", "legacy_evidence", "no_version", "zero_digest", "uppercase_digest", "wrong_run", "wrong_definition", "disabled_definition", "cancelled", "expired", "too_long", "extra", "null", "duplicate", "case_alias", "nested_duplicate", "nested_alias", "safety_alias", "empty_categories", "trailing", "nonclaim_authority", "provider_error"} {
		t.Run(mode, func(t *testing.T) {
			body := fixture()
			valid := false
			switch mode {
			case "claimed":
				valid = true
			case "retry_later", "ack_terminal", "reconcile_required":
				body = map[string]any{"disposition": mode}
				valid = true
			case "unknown_disposition":
				body["disposition"] = "resume_anyway"
			case "legacy_evidence":
				body["evidence_version"] = "red-team-v1"
			case "no_version":
				delete(body, "evidence_version")
			case "zero_digest":
				body["input_digest"] = strings.Repeat("0", 64)
			case "uppercase_digest":
				body["input_digest"] = strings.Repeat("AB", 32)
			case "wrong_run":
				v := run
				v.ID = definitionID
				body["run"] = v
			case "wrong_definition":
				v := definition
				v.Version = 2
				body["definition"] = v
			case "disabled_definition":
				v := definition
				v.Enabled = false
				body["definition"] = v
			case "cancelled":
				v := run
				v.CancelRequested = true
				body["run"] = v
			case "expired":
				body["lease_expires_at"] = now.Add(-time.Second)
			case "too_long":
				body["lease_expires_at"] = now.Add(time.Hour)
			case "extra":
				body["credential"] = "must-not-leak"
			case "null":
				body["run"] = nil
			case "empty_categories":
				v := definition
				v.Categories = nil
				body["definition"] = v
			case "nonclaim_authority":
				body["disposition"] = "reconcile_required"
			}
			raw := mustRedTeamJSON(t, body)
			switch mode {
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `"disposition":"claimed"`, `"disposition":"ack_terminal","disposition":"claimed"`, 1))
			case "case_alias":
				raw = []byte(strings.Replace(string(raw), `"evidence_version"`, `"Evidence_Version"`, 1))
			case "nested_duplicate":
				raw = []byte(strings.Replace(string(raw), `"attempt":1`, `"attempt":0,"attempt":1`, 1))
			case "nested_alias":
				raw = []byte(strings.Replace(string(raw), `"definition_version":1`, `"Definition_Version":1`, 1))
			case "safety_alias":
				raw = []byte(strings.Replace(string(raw), `"credential_class"`, `"Credential_Class"`, 1))
			case "trailing":
				raw = append(raw, []byte(` {}`)...)
			}
			db := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresLinkedRedTeamReadySQL: json.RawMessage(`true`), postgresRedTeamPrincipalReadySQL: json.RawMessage(`true`), postgresLinkedRedTeamClaimSQL: raw}}
			repo, err := NewLinkedRedTeamExecutionRepository(db)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "provider_error" {
				db.errors = map[string]error{postgresLinkedRedTeamClaimSQL: errors.New("must-not-leak")}
			}
			result, err := repo.ClaimRedTeamRun(context.Background(), scope, runID, "linked-worker", strings.Repeat("a", 32), 60)
			if !valid {
				if err == nil || !reflect.DeepEqual(result, RedTeamRunClaim{}) || strings.Contains(err.Error(), "must-not-leak") {
					t.Fatalf("hostile claim accepted or leaked: %#v %v", result, err)
				}
				return
			}
			if err != nil || result.Disposition != mode {
				t.Fatalf("claim=%#v %v", result, err)
			}
			if mode == "claimed" && (result.EvidenceVersion != "red-team-v2" || result.Run.ID != runID || result.Definition.ID != definitionID || result.InputDigest[0] != 0xab || !result.LeaseExpiresAt.Equal(now.Add(20*time.Second))) {
				t.Fatalf("lost bounded claim: %#v", result)
			}
			if mode != "claimed" && !reflect.DeepEqual(result, RedTeamRunClaim{Disposition: mode}) {
				t.Fatalf("nonclaim carried authority: %#v", result)
			}
			expected := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID, "linked-worker", []byte(strings.Repeat("a", 32)), 60, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
			if db.query != postgresLinkedRedTeamClaimSQL || !reflect.DeepEqual(db.args, expected) {
				t.Fatalf("claim not pinned/scoped: %s %#v", db.query, db.args)
			}
		})
	}
	for _, mode := range []string{"nil", "release", "role", "malformed_ready", "provider"} {
		db := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresLinkedRedTeamReadySQL: json.RawMessage(`true`), postgresRedTeamPrincipalReadySQL: json.RawMessage(`true`)}}
		if mode == "release" {
			db.responses[postgresLinkedRedTeamReadySQL] = json.RawMessage(`false`)
		}
		if mode == "role" {
			db.responses[postgresRedTeamPrincipalReadySQL] = json.RawMessage(`false`)
		}
		if mode == "malformed_ready" {
			db.responses[postgresLinkedRedTeamReadySQL] = json.RawMessage(`null`)
		}
		if mode == "provider" {
			db.errors = map[string]error{postgresLinkedRedTeamReadySQL: errors.New("must-not-leak")}
		}
		if mode == "nil" {
			db = nil
		}
		if repo, err := NewLinkedRedTeamExecutionRepository(db); repo != nil || !errors.Is(err, ErrRepositoryConfiguration) {
			t.Fatalf("bad constructor %s: %v %v", mode, repo, err)
		}
	}
	db := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresLinkedRedTeamReadySQL: json.RawMessage(`true`), postgresRedTeamPrincipalReadySQL: json.RawMessage(`true`)}}
	repo, err := NewLinkedRedTeamExecutionRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"scope", "run", "worker", "token", "lease", "context"} {
		s, id, worker, token, seconds := scope, runID, "linked-worker", strings.Repeat("a", 32), 60
		ctx := context.Background()
		switch mode {
		case "scope":
			s = domain.Scope{}
		case "run":
			id = "bad"
		case "worker":
			worker = "BAD"
		case "token":
			token = "short"
		case "lease":
			seconds = 29
		case "context":
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		before := len(db.queries)
		if _, err := repo.ClaimRedTeamRun(ctx, s, id, worker, token, seconds); err == nil || len(db.queries) != before {
			t.Fatalf("invalid %s reached database: %v", mode, err)
		}
	}
}

func TestLinkedRedTeamHeartbeatRepository(t *testing.T) {
	scope := fixtureRequestIdentity(t).Scope
	expires := time.Now().UTC().Add(20 * time.Second)
	for _, test := range []struct {
		name, body             string
		valid, renewed, cancel bool
	}{
		{"renewed", `{"renewed":true,"cancel_requested":false,"lease_expires_at":"` + expires.Format(time.RFC3339Nano) + `"}`, true, true, false},
		{"lost", `{"renewed":false,"cancel_requested":false}`, true, false, false},
		{"cancel", `{"renewed":false,"cancel_requested":true}`, true, false, true},
		{"cancel_renewed", `{"renewed":true,"cancel_requested":true,"lease_expires_at":"` + expires.Format(time.RFC3339Nano) + `"}`, false, false, false},
		{"missing_expiry", `{"renewed":true,"cancel_requested":false}`, false, false, false},
		{"expired", `{"renewed":true,"cancel_requested":false,"lease_expires_at":"2000-01-01T00:00:00Z"}`, false, false, false},
		{"long_expiry", `{"renewed":true,"cancel_requested":false,"lease_expires_at":"` + expires.Add(time.Hour).Format(time.RFC3339Nano) + `"}`, false, false, false},
		{"lost_authority", `{"renewed":false,"cancel_requested":false,"lease_expires_at":"` + expires.Format(time.RFC3339Nano) + `"}`, false, false, false},
		{"duplicate", `{"renewed":false,"renewed":true,"cancel_requested":false}`, false, false, false},
		{"alias", `{"Renewed":false,"cancel_requested":false}`, false, false, false},
		{"null", `{"renewed":null,"cancel_requested":false}`, false, false, false},
		{"extra", `{"renewed":false,"cancel_requested":false,"secret":"must-not-leak"}`, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresLinkedRedTeamReadySQL: json.RawMessage(`true`), postgresRedTeamPrincipalReadySQL: json.RawMessage(`true`), postgresLinkedRedTeamHeartbeatSQL: json.RawMessage(test.body)}}
			repo, err := NewLinkedRedTeamExecutionRepository(db)
			if err != nil {
				t.Fatal(err)
			}
			result, err := repo.HeartbeatRedTeamRun(context.Background(), scope, "pid_99000001-0000-4000-8000-000000000001", "linked-worker", strings.Repeat("b", 32), 60)
			if !test.valid {
				if err == nil || result != (RedTeamRunHeartbeat{}) {
					t.Fatalf("invalid heartbeat carried authority: %#v %v", result, err)
				}
				return
			}
			if err != nil || result.Renewed != test.renewed || result.CancelRequested != test.cancel || test.renewed && (result.LeaseExpiresAt == nil || !result.LeaseExpiresAt.Equal(expires)) || !test.renewed && result.LeaseExpiresAt != nil {
				t.Fatalf("heartbeat=%#v %v", result, err)
			}
			expected := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "pid_99000001-0000-4000-8000-000000000001", "linked-worker", []byte(strings.Repeat("b", 32)), 60, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
			if db.query != postgresLinkedRedTeamHeartbeatSQL || !reflect.DeepEqual(db.args, expected) {
				t.Fatal("heartbeat lost scope/pins")
			}
		})
	}
}
