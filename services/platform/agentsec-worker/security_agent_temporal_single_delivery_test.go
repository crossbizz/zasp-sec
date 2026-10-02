package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"strings"
	"testing"
	"time"
)

// Removing owned routing must invoke the retained claim and fail these cases.
// Transport doubles represent only DB/RPC boundaries; the real processor owns
// validation, routing, lease exclusion, retry errors and ACK ordering.
func TestSingleTestDeliveryUsesDurableWakeWithoutRetainedClaim(t *testing.T) {
	for _, tc := range []struct {
		name                                      string
		terminal, signalFail, commitFail, unowned bool
		want                                      string
		wantErr                                   bool
	}{
		{name: "wake then accept then ack", want: "[consume read wake accept ack]"},
		{name: "verified terminal duplicate", terminal: true, want: "[consume read accept ack]"},
		{name: "signal failure unacknowledged", signalFail: true, want: "[consume read wake]", wantErr: true},
		{name: "receipt commit failure unacknowledged", commitFail: true, want: "[consume read wake accept]", wantErr: true},
		{name: "unowned retains original claim", unowned: true, want: "[consume read lease claim ack]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope := fixtureRedTeamScope(t)
			run := mustProductID(t, "pid_99200001-0000-4000-8000-000000000001")
			digest := sha256.Sum256([]byte("test74-delivery"))
			steps := []string{}
			payload := redTeamQueuePayload(t, scope, run.String(), "pid_99200002-0000-4000-8000-000000000002", 1, digest)
			queue := &recordingDiscoveryQueue{deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: run, Kind: "red-team", Payload: payload, AuthorityDigest: digest}}}, steps: &steps}
			authority := &recordingRedTeamExecutionAuthority{steps: &steps, claim: apiserver.RedTeamRunClaim{Disposition: "ack_terminal"}}
			processor, err := newRedTeamProcessor(redTeamProcessorConfig{Authority: authority, Queue: queue, Runner: &recordingRedTeamRunner{steps: &steps}, WorkerID: "red-team-worker-01", LeaseSeconds: 60, BatchSize: 1, Now: time.Now, NewLeaseToken: func() (string, error) { steps = append(steps, "lease"); return strings.Repeat("a", 32), nil }})
			if err != nil {
				t.Fatal(err)
			}
			binder, ok := any(processor).(interface {
				bindSingleTestDelivery(apiserver.JSONDatabase, func(context.Context, orchestration.StartRequest) error) error
			})
			if !ok {
				t.Fatal("owned delivery composition missing")
			}
			start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RunID: "pid_99200004-0000-4000-8000-000000000004"}, DefinitionVersion: 1, InputDigest: strings.Repeat("a", 64)}
			db := singleDeliveryDatabaseFunc(func(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
				if statement != `SELECT zasp_temporal74.delivery($1::jsonb)` || len(args) != 1 {
					t.Fatal("wrong authority", statement)
				}
				var q struct {
					Operation string          `json:"operation"`
					Message   json.RawMessage `json:"message"`
				}
				raw, _ := json.Marshal(args[0])
				if decodeStrictWorkerJSON(raw, &q) != nil || !jsonEqualWorker(q.Message, payload) {
					t.Fatal("delivery message changed", string(raw))
				}
				steps = append(steps, q.Operation)
				if tc.unowned {
					return json.RawMessage(`{"owned":false}`), nil
				}
				if q.Operation == "accept" && tc.commitFail {
					return nil, errors.New("receipt commit unavailable")
				}
				result := map[string]any{"owned": true, "start": start, "terminal": tc.terminal, "effect_key": strings.Repeat("b", 64), "delivery_digest": strings.Repeat("c", 64), "accepted_at": nil}
				if q.Operation == "accept" {
					result["accepted_at"] = "2026-09-23T10:00:00Z"
				}
				return json.Marshal(result)
			})
			if err := binder.bindSingleTestDelivery(db, func(ctx context.Context, q orchestration.StartRequest) error {
				if q != start {
					t.Fatal("wrong workflow identity", q)
				}
				steps = append(steps, "wake")
				if tc.signalFail {
					return errors.New("signal unavailable")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			err = processor.RunOnce(context.Background())
			if (err != nil) != tc.wantErr || fmt.Sprint(steps) != tc.want {
				t.Fatal("delivery result", err, steps, "want", tc.want)
			}
		})
	}
}

type singleDeliveryDatabaseFunc func(context.Context, string, ...any) (json.RawMessage, error)

func (f singleDeliveryDatabaseFunc) SchemaVersion(context.Context) (string, error) {
	return "", errors.New("unexpected schema read")
}
func (f singleDeliveryDatabaseFunc) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected direct execution")
}

func (f singleDeliveryDatabaseFunc) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	return f(ctx, q, args...)
}
func jsonEqualWorker(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xx, _ := json.Marshal(x)
	yy, _ := json.Marshal(y)
	return string(xx) == string(yy)
}
