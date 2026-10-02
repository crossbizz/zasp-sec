package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

// Real repository clients and router, controlled database responses. SQL-side
// protocol classification is verified separately against registered PostgreSQL.
func TestRedTeamRoutedAuthorityNeverFallsBack(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	run := "pid_99200001-0000-4000-8000-000000000001"
	digest := sha256.Sum256([]byte("routing-input"))
	key := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + run
	completion := apiserver.RedTeamRunCompletion{RunID: run, Worker: "routing-worker", LeaseToken: strings.Repeat("a", 32), InputDigest: digest, Verdict: "pass", Objective: "Evaluate curated categories: prompt_injection", Behavior: "1 of 1 curated security checks passed; 0 exposed unsafe behavior.", Evidence: []string{"prompt_injection: protected"}, EvidenceReference: "s3://zasp-evidence/" + key, EvidenceKey: key, EvidenceVersionID: "immutable-output", EvidenceChecksum: bytes.Repeat([]byte{0xab}, 32), EvidenceSizeBytes: 1024, InputArtifact: &apiserver.RedTeamArtifactReference{Reference: "s3://zasp-evidence/" + strings.TrimSuffix(key, run) + "pid_99200004-0000-4000-8000-000000000004", VersionID: "immutable-input", SHA256: strings.Repeat("cd", 32), SizeBytes: 512}}
	for _, protocol := range []string{"legacy", "linked", "unknown", "unavailable"} {
		completion.EvidenceArtifact = []byte(`{"schema_version":"red-team-evidence-bundle-v2"}`)
		artifactDigest := sha256.Sum256(completion.EvidenceArtifact)
		completion.EvidenceChecksum = artifactDigest[:]
		completion.EvidenceSizeBytes = int64(len(completion.EvidenceArtifact))
		for _, operation := range []string{"claim", "heartbeat", "finish", "retry", "legacy_cancel", "linked_cancel"} {
			t.Run(protocol+"/"+operation, func(t *testing.T) {
				db := &protocolRoutingDatabase{protocol: protocol}
				router, err := newRoutedRedTeamAuthority(db)
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				switch operation {
				case "claim":
					_, err = router.ClaimRedTeamRun(ctx, scope, run, "routing-worker", strings.Repeat("a", 32), 60)
				case "heartbeat":
					_, err = router.HeartbeatRedTeamRun(ctx, scope, run, "routing-worker", strings.Repeat("a", 32), 60)
				case "finish":
					_, err = router.FinishRedTeamRun(ctx, scope, completion)
				case "retry":
					_, err = router.RetryRedTeamRun(ctx, scope, run, "routing-worker", strings.Repeat("a", 32), digest, "retryable", time.Now().UTC().Add(time.Second))
				case "legacy_cancel":
					_, err = router.CancelClaimedRedTeamRun(ctx, scope, run, "routing-worker", strings.Repeat("a", 32), digest)
				case "linked_cancel":
					_, err = router.CancelLinkedRedTeamRun(ctx, scope, run, "routing-worker", strings.Repeat("a", 32), digest)
				}
				if err == nil {
					t.Fatal("unacknowledged database mutation succeeded")
				}
				if db.selections != 1 {
					t.Fatalf("protocol reads=%d", db.selections)
				}
				want := ""
				if protocol == "legacy" && operation != "linked_cancel" {
					want = map[string]string{"claim": "zasp_red_team_claim_run", "heartbeat": "zasp_red_team_heartbeat_run", "finish": "zasp_red_team_finish_run", "retry": "zasp_red_team_retry_run", "legacy_cancel": "zasp_red_team_cancel_claimed_run"}[operation]
				}
				if protocol == "linked" && (operation == "claim" || operation == "heartbeat" || operation == "finish" || operation == "linked_cancel") {
					name := operation
					if operation == "linked_cancel" {
						name = "cancel"
					}
					want = "zasp_production_security_agent_existing_tests_worker_" + name
				}
				if want == "" {
					if len(db.mutations) != 0 {
						t.Fatalf("forbidden fallback: %v", db.mutations)
					}
				} else if len(db.mutations) != 1 || !strings.Contains(db.mutations[0], want+"(") {
					t.Fatalf("selected writes=%v want=%s", db.mutations, want)
				}
			})
		}
	}
}

func TestComposeRedTeamWorkerRequiresLinkedRelease(t *testing.T) {
	db := &protocolRoutingDatabase{missingLinked: true}
	_, err := composeRedTeamWorkerRuntime(validRedTeamRuntimeConfig(), db, &productionRedTeamDependencies{Queue: &recordingDiscoveryQueue{}, Runner: &recordingRedTeamRunner{}, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
	if err == nil {
		t.Fatal("production worker ignored missing linked protocol release")
	}
}

func TestRedTeamInstalledAuthorityRejectsLegacyClassification(t *testing.T) {
	db := &protocolRoutingDatabase{protocol: "legacy"}
	linked, err := apiserver.NewLinkedRedTeamExecutionRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	router := &routedRedTeamAuthority{linked: linked, installedLinked: true}
	if _, err := router.protocol(context.Background(), fixtureRedTeamScope(t), "pid_99200001-0000-4000-8000-000000000001"); err == nil {
		t.Fatal("installed linked boundary selected absent standalone authority")
	}
	if len(db.mutations) != 0 {
		t.Fatal("classification refusal mutated")
	}
}

func TestComposeRedTeamWorkerRoutesTerminalDeliveries(t *testing.T) {
	for _, protocol := range []string{"legacy", "linked"} {
		t.Run(protocol, func(t *testing.T) {
			scope := fixtureRedTeamScope(t)
			run := mustProductID(t, "pid_99200001-0000-4000-8000-000000000001")
			digest := sha256.Sum256([]byte("routing-input"))
			db := &protocolRoutingDatabase{protocol: protocol, terminal: true}
			queue := &linkedRuntimeQueue{delivery: jobqueue.Delivery{Job: jobqueue.Job{Scope: scope, JobID: run, Kind: "red-team", AuthorityDigest: digest, Payload: redTeamQueuePayload(t, scope, run.String(), "pid_99200002-0000-4000-8000-000000000002", 1, digest)}}}
			runner := linkedRuntimeRunner(func(context.Context, redTeamExecutionRequest) (redTeamExecutionResult, error) {
				t.Error("terminal delivery executed")
				return redTeamExecutionResult{}, errors.New("unexpected execution")
			})
			deps, err := composeRedTeamWorkerRuntime(validRedTeamRuntimeConfig(), db, &productionRedTeamDependencies{Queue: queue, Runner: runner, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer deps.Close()
			if err := deps.Processor.RunOnce(context.Background()); err != nil || queue.acks.Load() != 1 || db.selections != 1 || len(db.mutations) != 1 {
				t.Fatalf("composed routing: err=%v ack=%d reads=%d writes=%v", err, queue.acks.Load(), db.selections, db.mutations)
			}
			want := "zasp_red_team_claim_run("
			if protocol == "linked" {
				want = "zasp_production_security_agent_existing_tests_worker_claim("
			}
			if !strings.Contains(db.mutations[0], want) {
				t.Fatalf("wrong production route: %v", db.mutations)
			}
		})
	}
}

type protocolRoutingDatabase struct {
	readyWorkerDatabase
	protocol      string
	missingLinked bool
	terminal      bool
	selections    int
	mutations     []string
}

func (d *protocolRoutingDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if strings.Contains(statement, "zasp_production_security_agent_existing_tests_client_ready(") && d.missingLinked {
		return json.RawMessage(`false`), nil
	}
	if strings.Contains(statement, "zasp_production_security_agent_existing_tests_worker_protocol(") {
		d.selections++
		if d.protocol == "unavailable" {
			return nil, errors.New("protocol unavailable")
		}
		return json.Marshal(map[string]string{"protocol": d.protocol})
	}
	for _, operation := range []string{"claim_run(", "heartbeat_run(", "finish_run(", "retry_run(", "cancel_claimed_run(", "worker_claim(", "worker_heartbeat(", "worker_finish(", "worker_cancel("} {
		if strings.Contains(statement, operation) {
			d.mutations = append(d.mutations, statement)
			if d.terminal && (operation == "claim_run(" || operation == "worker_claim(") {
				return json.RawMessage(`{"disposition":"ack_terminal"}`), nil
			}
			return nil, errors.New("commit acknowledgement unavailable")
		}
	}
	return d.readyWorkerDatabase.QueryJSON(ctx, statement, args...)
}
