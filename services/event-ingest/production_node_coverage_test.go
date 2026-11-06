package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

// The actual production factory/router is exercised here. The controlled fixed
// commit capability proves application mounting, not PostgreSQL or provider E2E.
func TestProductionNodeCoverageComposedCommitBoundary(t *testing.T) {
	for _, mode := range []string{"accepted", "expired_not_committed", "commit_unknown", "pin_drift", "foreign_enrollment", "disabled_legacy", "missing_commit_capability"} {
		t.Run(mode, func(t *testing.T) {
			values := validProductionIngestEnvironment()
			values["ZASP_RUNTIME_DATABASE_PROFILE"] = migrations.AuthorizationRuntimeProfileName
			config, e := loadProductionIngestConfig(func(k string) string { return values[k] })
			if e != nil {
				t.Fatal(e)
			}
			config.NodeCoverageRetention = mode != "disabled_legacy"
			if config.NodeCoverageRetention {
				config.NodeCoverageProfileChecksum = migrations.SensorNodeCoverageProfileChecksum()
			}
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			db := &nodeCoverageCompositionDatabase{mode: mode, now: now}
			var actual interface {
				QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
			} = db
			if mode == "missing_commit_capability" {
				actual = &nodeCoverageQueryOnly{db}
			}
			deps, e := composeProductionIngestDependencies(context.Background(), config, actual, &compositionArtifacts{}, func(context.Context) error { return nil }, func() time.Time { return now }, func() error { return nil })
			if mode == "missing_commit_capability" {
				if e == nil {
					t.Fatal("enabled retention accepted database without actual commit capability")
				}
				return
			}
			if e != nil {
				t.Fatal("actual connected factory refused", e)
			}
			raw := nodeCoverageCompositionWire(t, now, mode == "expired_not_committed", mode == "foreign_enrollment")
			credential, e := sensor.NewTokenCredential(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x41}, 32))
			if e != nil {
				t.Fatal(e)
			}
			defer credential.Destroy()
			token, e := credential.Wire()
			if e != nil {
				t.Fatal(e)
			}
			req := httptest.NewRequest(http.MethodPost, sensor.PrivateHeartbeatPath, bytes.NewReader(raw))
			req.Header.Set("Content-Type", sensor.PrivateHeartbeatMediaType)
			req.Header.Set("X-Zasp-Schema-Version", nodecoveragewire.HeartbeatSchema)
			req.Header.Set("Authorization", "Bearer "+token)
			if mode == "pin_drift" {
				db.unready = true
			}
			response := httptest.NewRecorder()
			deps.Handler.ServeHTTP(response, req)
			positive := mode == "accepted" || mode == "expired_not_committed"
			if positive {
				if response.Code != http.StatusOK {
					t.Fatalf("mounted retained heartbeat status=%d", response.Code)
				}
				receipt, e := nodecoveragewire.ParseReceipt(response.Body.Bytes())
				if e != nil || receipt.Disposition != mode || db.commits != 1 {
					t.Fatal("confirmed typed receipt lost", e, db.commits)
				}
			} else {
				if response.Code == http.StatusOK || response.Code == http.StatusNoContent {
					t.Fatal("unknown/refused/disabled path published success")
				}
				expected := 0
				if mode == "commit_unknown" {
					expected = 1
				}
				if db.commits != expected {
					t.Fatal("rejected authority reached commit", db.commits)
				}
			}
			if mode == "disabled_legacy" && db.retentionChecks != 0 {
				t.Fatal("legacy composition consulted addon")
			}
			if positive && db.retentionChecks < 2 {
				t.Fatal("cached readiness hid current request gate")
			}
		})
	}
}

type nodeCoverageQueryOnly struct {
	db *nodeCoverageCompositionDatabase
}

func (q *nodeCoverageQueryOnly) QueryJSON(c context.Context, s string, a ...any) (json.RawMessage, error) {
	return q.db.QueryJSON(c, s, a...)
}

type nodeCoverageCompositionDatabase struct {
	compositionDatabase
	mode                     string
	now                      time.Time
	commits, retentionChecks int
}

func (d *nodeCoverageCompositionDatabase) QueryJSON(c context.Context, q string, a ...any) (json.RawMessage, error) {
	if strings.Contains(q, "zasp_sensor_coverage_v1.caller_ready") {
		d.retentionChecks++
		if d.unready {
			return json.RawMessage(`{"ready":false}`), nil
		}
		return json.RawMessage(`{"ready":true}`), nil
	}
	if strings.Contains(q, "ingest_profile_identity") {
		return json.RawMessage(`{"matched":true}`), nil
	}
	if strings.Contains(q, "zasp_authorization80_runtime.ready") {
		return json.RawMessage(`{"ready":true}`), nil
	}
	if strings.Contains(q, "runtime_authenticate_sensor") {
		return json.RawMessage(`{"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","sensor_id":"pid_10000004-0000-4000-8000-000000000004","sensor_kind":"tetragon","sensor_mode":"full","sensor_version":1,"token_id":"pid_10000005-0000-4000-8000-000000000005","token_generation":1,"audience":"event-ingest"}`), nil
	}
	return d.compositionDatabase.QueryJSON(c, q, a...)
}
func (d *nodeCoverageCompositionDatabase) CommitNodeCoverage(ctx context.Context, locator, secret, raw []byte) (nodecoveragewire.Receipt, error) {
	d.commits++
	if len(locator) != 16 || len(secret) != 32 || ctx.Err() != nil {
		return nodecoveragewire.Receipt{}, errors.New("invalid controlled authority")
	}
	if d.mode == "commit_unknown" {
		return nodecoveragewire.Receipt{}, errors.New("commit outcome unknown")
	}
	v, e := nodecoveragewire.ParseEnvelope(raw)
	if e != nil {
		return nodecoveragewire.Receipt{}, e
	}
	sum := sha256.Sum256(raw)
	return nodecoveragewire.Receipt{SensorID: "pid_10000004-0000-4000-8000-000000000004", Sequence: v.Sequence, RequestDigest: hex.EncodeToString(sum[:]), Disposition: d.mode, ResolvedAt: d.now, SourceObservedAt: v.SourceObservedAt, ExpiresAt: v.SourceObservedAt.Add(time.Duration(v.TTLSeconds) * time.Second)}, nil
}
func nodeCoverageCompositionWire(t *testing.T, now time.Time, expired, foreign bool) []byte {
	t.Helper()
	o, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
	w, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
	e, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
	id, _ := domain.ParseProductID("pid_10000004-0000-4000-8000-000000000004")
	scope, _ := domain.NewScope(o, w, e)
	binding, _ := sensor.EnrollmentBinding(scope, id)
	if foreign {
		binding = strings.Repeat("f", 64)
	}
	stamp := now.Add(-time.Second)
	if expired {
		stamp = now.Add(-time.Minute)
	}
	target := nodecoveragewire.CoverageTarget{Namespace: "edge", Name: "sensor", Release: "zasp", ReleaseNamespace: "edge", Image: "example/sensor@sha256:" + strings.Repeat("a", 64), ServiceAccount: "sensor", Container: "sensor"}
	other := target
	other.Name = "tetragon"
	v := nodecoveragewire.Envelope{Heartbeat: nodecoveragewire.Heartbeat{Sequence: 7, Status: "degraded", Capabilities: []string{"process"}, Kernel: "unknown"}, CoverageSchema: nodecoveragewire.CoverageSchema, StateUID: "11111111-1111-4111-8111-111111111111", StorageEpoch: 1, Selection: nodecoveragewire.NodeCoverageSelection{SourceProfile: "tetragon-local-stream-v2", ClusterUID: "22222222-2222-4222-8222-222222222222", EnrollmentBinding: binding, MatchLabels: map[string]string{"group": "selected"}, Sensor: target, Tetragon: other}, TargetDigest: strings.Repeat("b", 64), InventoryObservedAt: stamp, SourceObservedAt: stamp, TTLSeconds: 30, SensorDaemonSetUID: "33333333-3333-4333-8333-333333333333", TetragonDaemonSetUID: "44444444-4444-4444-8444-444444444444", SelectedNodes: []nodecoveragewire.SelectedNode{{NodeName: "node-a", NodeUID: "55555555-5555-4555-8555-555555555555", BootID: "66666666-6666-4666-8666-666666666666"}}, Reports: []nodecoveragewire.NodeCoverageV2{}}
	raw, err := nodecoveragewire.MarshalEnvelope(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
