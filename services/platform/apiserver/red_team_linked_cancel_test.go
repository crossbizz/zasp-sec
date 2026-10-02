package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestLinkedRedTeamCancellationRepository(t *testing.T) {
	scope := fixtureRequestIdentity(t).Scope
	runID := "pid_99000001-0000-4000-8000-000000000001"
	now := time.Now().UTC()
	run := RedTeamRun{ID: runID, Version: 3, DefinitionID: "pid_99000003-0000-4000-8000-000000000003", DefinitionVersion: 1, Status: "cancelled", Attempt: 1, CancelRequested: true, QueuedAt: now, StartedAt: &now, CompletedAt: &now, ErrorCode: "cancelled"}
	digest := sha256.Sum256([]byte("linked-input"))
	for _, mode := range []string{"unstarted", "partial", "unknown", "wrong_outcome", "contradictory", "wrong_run", "not_requested", "zero_attempt", "duplicate", "nested_duplicate", "alias", "null", "extra", "oversized", "zero_digest", "bad_lease", "cancelled_context"} {
		t.Run(mode, func(t *testing.T) {
			value, outcome := run, "cancelled_before_execution"
			switch mode {
			case "partial":
				outcome = "cancelled_after_partial_execution"
			case "unknown":
				value.Status, value.ErrorCode, outcome = "failed", "outcome_unknown", "outcome_unknown"
			case "wrong_outcome":
				outcome = "cancelled"
			case "contradictory":
				outcome = "outcome_unknown"
			case "wrong_run":
				value.ID = value.DefinitionID
			case "not_requested":
				value.CancelRequested = false
			case "zero_attempt":
				value.Attempt = 0
				value.StartedAt = nil
			}
			raw, _ := json.Marshal(map[string]any{"run": value, "cancellation_outcome": outcome})
			switch mode {
			case "duplicate":
				raw = append(raw[:len(raw)-1], []byte(`,"cancellation_outcome":"outcome_unknown"}`)...)
			case "nested_duplicate":
				raw = []byte(strings.Replace(string(raw), `"status":"cancelled"`, `"status":"failed","status":"cancelled"`, 1))
			case "alias":
				raw = []byte(strings.Replace(string(raw), `"status"`, `"Status"`, 1))
			case "null":
				raw = []byte(strings.Replace(string(raw), `"cancel_requested":true`, `"cancel_requested":null`, 1))
			case "extra":
				raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
			case "oversized":
				raw = append(raw, bytes.Repeat([]byte(" "), 16384)...)
			}
			db := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresLinkedRedTeamReadySQL: json.RawMessage(`true`), postgresRedTeamPrincipalReadySQL: json.RawMessage(`true`), postgresLinkedRedTeamCancelSQL: raw}}
			repo, err := NewLinkedRedTeamExecutionRepository(db)
			if err != nil {
				t.Fatal(err)
			}
			inputDigest, lease := digest, strings.Repeat("a", 32)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "zero_digest" {
				inputDigest = [sha256.Size]byte{}
			}
			if mode == "bad_lease" {
				lease = "bad"
			}
			if mode == "cancelled_context" {
				cancel()
			}
			got, err := repo.CancelLinkedRedTeamRun(ctx, scope, runID, "linked-worker", lease, inputDigest)
			if mode != "unstarted" && mode != "partial" && mode != "unknown" {
				if err == nil {
					t.Fatalf("invalid %s accepted: %#v", mode, got)
				}
				if (mode == "zero_digest" || mode == "bad_lease" || mode == "cancelled_context") && len(db.callsFor(postgresLinkedRedTeamCancelSQL)) != 0 {
					t.Fatal("invalid request reached database")
				}
				return
			}
			if err != nil || got.ID != runID || got.Status != value.Status || got.ErrorCode != value.ErrorCode {
				t.Fatalf("cancel result %#v %v", got, err)
			}
			calls := db.callsFor(postgresLinkedRedTeamCancelSQL)
			if len(calls) != 1 || len(calls[0]) != 9 || calls[0][0] != scope.OrganizationID().String() || calls[0][1] != scope.WorkspaceID().String() || calls[0][2] != scope.EnvironmentID().String() || calls[0][3] != runID || calls[0][4] != "linked-worker" || !bytes.Equal(calls[0][5].([]byte), []byte(lease)) || !bytes.Equal(calls[0][6].([]byte), digest[:]) || calls[0][7] != migrations.ProductionSecurityAgentExistingTests().Checksum() || calls[0][8] != migrations.SecurityAgentExistingTestsFingerprint() {
				t.Fatalf("cancel lost scope/lease/input/pins: %#v", calls)
			}
		})
	}
}
