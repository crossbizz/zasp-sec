package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

type agentExportPipelineDatabase struct {
	snapshot, prepared                  json.RawMessage
	captures, prepares, loads, finishes int
	finishLost                          bool
	retry                               string
}

func (d *agentExportPipelineDatabase) QueryJSON(_ context.Context, q string, args ...any) (json.RawMessage, error) {
	switch q {
	case complianceCaptureSQL:
		d.captures++
		return d.snapshot, nil
	case compliancePrepareSQL:
		payload := args[7].(json.RawMessage)
		if string(payload) == "{}" {
			d.loads++
			return bytes.Clone(d.prepared), nil
		}
		d.prepares++
		d.prepared = bytes.Clone(payload)
		return bytes.Clone(d.prepared), nil
	case complianceFinishSQL:
		d.finishes++
		if d.finishLost {
			return nil, errors.New("lost committed finish response")
		}
		return json.RawMessage(`{}`), nil
	case complianceRetrySQL:
		var p struct {
			Outcome string `json:"outcome"`
		}
		if json.Unmarshal(args[7].(json.RawMessage), &p) != nil {
			return nil, errors.New("invalid retry payload")
		}
		d.retry = p.Outcome
		return json.RawMessage(`{}`), nil
	}
	return nil, errors.New("unexpected pipeline query")
}

// Exercises the real processor and render/prepare/store bridge. Wrong routing
// must prevent an agent package, and failures after Put must retain uncertainty.
func TestSecurityAgentExportWorkerProcessorPipeline(t *testing.T) {
	for _, mode := range []string{"agent", "browser", "wrong_binding", "put_error", "finish_lost"} {
		t.Run(mode, func(t *testing.T) {
			l := complianceRuntimeLease(t)
			snapshot, binding := securityAgentExportSnapshotFixture(t, l)
			l.JobOrigin = "agent_run"
			l.AgentBinding = &binding
			revision := "security-agent-run-evidence-v1"
			if mode == "browser" {
				l.JobOrigin = ""
				l.AgentBinding = nil
				snapshot = complianceSnapshotFixture(t, l)
				revision = "product-evidence-v1"
			}
			if mode == "wrong_binding" {
				binding.Selection[0].Version++
			}
			hash := sha256.Sum256(snapshot)
			db := &agentExportPipelineDatabase{snapshot: json.RawMessage(fmt.Sprintf(`{"snapshot":%s,"sha256":%q,"mapping_revision":%q}`, snapshot, hex.EncodeToString(hash[:]), revision)), finishLost: mode == "finish_lost"}
			puts := 0
			var firstBody []byte
			store, err := artifactstore.NewExport(complianceReplayDriver{put: func(_ context.Context, obj artifactstore.DriverObject) (artifactstore.DriverObject, error) {
				puts++
				if db.prepares != 1 || len(db.prepared) == 0 {
					t.Error("Put preceded durable preparation")
				}
				var envelope struct {
					Version int             `json:"version"`
					ID      string          `json:"id"`
					JSON    json.RawMessage `json:"json"`
					CSV     string          `json:"csv"`
					Human   string          `json:"human"`
				}
				if json.Unmarshal(obj.Body, &envelope) != nil || envelope.Version != 1 || envelope.ID != l.ExportID || envelope.CSV == "" || envelope.Human == "" {
					t.Error("missing actual rendered formats")
				}
				if mode != "browser" && (!strings.Contains(string(envelope.JSON), `"run_id":"pid_20000001-0000-4000-8000-000000000001"`) || !strings.Contains(string(envelope.JSON), `"source_version":7`)) {
					t.Error("wrong agent content")
				}
				if firstBody == nil {
					firstBody = bytes.Clone(obj.Body)
				} else if !bytes.Equal(firstBody, obj.Body) {
					t.Error("prepared replay changed bytes")
				}
				if mode == "put_error" {
					return artifactstore.DriverObject{}, errors.New("unknown write")
				}
				obj.VersionID = "immutable-agent-export-v1"
				return obj, nil
			}}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 8 << 20})
			if err != nil {
				t.Fatal(err)
			}
			processor := &complianceExportProcessor{authority: newPostgresComplianceExportAuthority(db), store: store, timeout: time.Second, heartbeat: time.Hour}
			err = processor.process(context.Background(), &l)
			switch mode {
			case "wrong_binding":
				if err == nil || puts != 0 || db.prepares != 0 || db.retry != "source_failed" {
					t.Fatalf("binding bypass: err=%v puts=%d prepares=%d retry=%s", err, puts, db.prepares, db.retry)
				}
			case "put_error", "finish_lost":
				if err == nil || puts != 1 || db.retry != "unknown" {
					t.Fatalf("lost uncertain intent: err=%v puts=%d retry=%s", err, puts, db.retry)
				}
			default:
				if err != nil || puts != 1 || db.finishes != 1 || db.retry != "" {
					t.Fatalf("processor failed: err=%v puts=%d finishes=%d retry=%s", err, puts, db.finishes, db.retry)
				}
				l.Prepared = true
				// A new processor with unusable current source must load the old bytes.
				db.snapshot = json.RawMessage(`null`)
				restarted := &complianceExportProcessor{authority: newPostgresComplianceExportAuthority(db), store: store, timeout: time.Second, heartbeat: time.Hour}
				if err = restarted.process(context.Background(), &l); err != nil || puts != 2 || db.captures != 1 || db.prepares != 1 || db.loads != 1 {
					t.Fatalf("prepared replay recomputed: err=%v captures=%d prepares=%d loads=%d puts=%d", err, db.captures, db.prepares, db.loads, puts)
				}
			}
		})
	}
}

// Returning a shallow lease permits a consumer to mutate heartbeat authority.
func TestSecurityAgentExportWorkerLeaseBindingOwnership(t *testing.T) {
	l := complianceRuntimeLease(t)
	_, binding := securityAgentExportSnapshotFixture(t, l)
	l.JobOrigin = "agent_run"
	l.AgentBinding = &binding
	h := &complianceLeaseHandle{lease: l}
	snapshot := h.current()
	snapshot.AgentBinding.RunID = l.ExportID
	snapshot.AgentBinding.Selection[0].Version = 99
	next := h.current()
	if next.AgentBinding.RunID != "pid_20000001-0000-4000-8000-000000000001" || next.AgentBinding.Selection[0].Version != 7 {
		t.Fatal("lease copy mutated owned authority")
	}
}

// Capture must preserve exact bytes but reject content from another link,
// even when the database response carries a valid hash for that other content.
func TestSecurityAgentExportWorkerCaptureBinding(t *testing.T) {
	for _, mode := range []string{"valid", "browser", "run", "step", "selection", "scope", "digest", "mapping", "missing_binding", "unknown_origin", "extra_field"} {
		t.Run(mode, func(t *testing.T) {
			l := complianceRuntimeLease(t)
			snapshot, binding := securityAgentExportSnapshotFixture(t, l)
			l.JobOrigin = "agent_run"
			l.AgentBinding = &binding
			switch mode {
			case "browser":
				l.JobOrigin = ""
				l.AgentBinding = nil
				snapshot = complianceSnapshotFixture(t, l)
			case "run":
				binding.RunID = l.ExportID
			case "step":
				binding.StepID = l.ExportID
			case "selection":
				binding.Selection[0].Version++
			case "scope":
				snapshot = bytes.Replace(snapshot, []byte(l.Scope.OrganizationID().String()), []byte(l.ExportID), 1)
			case "missing_binding":
				l.AgentBinding = nil
			case "unknown_origin":
				l.JobOrigin = "unknown"
			case "extra_field":
				snapshot = append([]byte(`{"unknown":true,`), snapshot[1:]...)
			}
			hash := sha256.Sum256(snapshot)
			revision := "security-agent-run-evidence-v1"
			if mode == "browser" {
				revision = "product-evidence-v1"
			}
			if mode == "mapping" {
				revision = "product-evidence-v1"
			}
			digest := hex.EncodeToString(hash[:])
			if mode == "digest" {
				digest = strings.Repeat("0", 64)
			}
			// Keep PostgreSQL-style RawMessage bytes intact across this wire boundary.
			raw := []byte(fmt.Sprintf(`{"snapshot":%s,"sha256":%q,"mapping_revision":%q}`, snapshot, digest, revision))
			db := &complianceDatabaseFixture{body: raw}
			got, err := newPostgresComplianceExportAuthority(db).Capture(context.Background(), l)
			if mode == "valid" || mode == "browser" {
				if err != nil || !bytes.Equal(got, snapshot) {
					t.Fatalf("capture changed/refused exact %s bytes: %v", mode, err)
				}
			} else if err == nil || len(got) != 0 {
				t.Fatalf("capture accepted %s", mode)
			}
		})
	}
}

// Prepared agent bytes must survive restart and never cross the browser union.
func TestSecurityAgentExportWorkerPreparedOrigin(t *testing.T) {
	for _, mode := range []string{"valid", "browser", "wrong_revision", "missing_binding", "unknown_origin", "bad_digest"} {
		t.Run(mode, func(t *testing.T) {
			l := complianceRuntimeLease(t)
			snapshot, binding := securityAgentExportSnapshotFixture(t, l)
			l.JobOrigin = "agent_run"
			l.AgentBinding = &binding
			p, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, binding, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "browser":
				l.JobOrigin = ""
				l.AgentBinding = nil
				p, err = renderComplianceExportPackage(context.Background(), l, complianceSnapshotFixture(t, l))
				if err != nil {
					t.Fatal(err)
				}
			case "wrong_revision":
				p.RendererRevision = "compliance-envelope-v1"
			case "missing_binding":
				l.AgentBinding = nil
			case "unknown_origin":
				l.JobOrigin = "unknown"
			case "bad_digest":
				p.SHA256 = strings.Repeat("0", 64)
			}
			raw, err := json.Marshal(map[string]any{"bytes_hex": hex.EncodeToString(p.Bytes), "renderer_revision": p.RendererRevision, "reference": p.Reference, "size": p.Size, "sha256": p.SHA256, "format_sizes": p.FormatSizes})
			if err != nil {
				t.Fatal(err)
			}
			for _, load := range []bool{false, true} {
				db := &complianceDatabaseFixture{body: raw}
				a := newPostgresComplianceExportAuthority(db)
				var got compliancePreparedArtifact
				if load {
					got, err = a.LoadPrepared(context.Background(), l)
				} else {
					got, err = a.Prepare(context.Background(), l, p)
				}
				if mode == "valid" || mode == "browser" {
					if err != nil || !bytes.Equal(got.Bytes, p.Bytes) || got.RendererRevision != p.RendererRevision {
						t.Fatalf("prepared origin %s load=%v: %v", mode, load, err)
					}
				} else if err == nil || len(got.Bytes) != 0 {
					t.Fatalf("accepted %s load=%v", mode, load)
				}
			}
		})
	}
}

func agentExportClaimWire(t *testing.T) (complianceExportLease, map[string]any) {
	t.Helper()
	l := complianceRuntimeLease(t)
	l.ExpiresAt = time.Now().Add(time.Minute)
	return l, map[string]any{
		"organization_id": l.Scope.OrganizationID().String(), "workspace_id": l.Scope.WorkspaceID().String(), "environment_id": l.Scope.EnvironmentID().String(),
		"export_id": l.ExportID, "generation": 1, "attempt": 1, "lease_expires_at": l.ExpiresAt, "lane": "execute", "captured": false, "prepared": false, "reference": "", "version": "", "size": 0, "sha256": "",
		"job_origin": "agent_run", "binding": map[string]any{"run_id": "pid_20000001-0000-4000-8000-000000000001", "step_id": "pid_20000002-0000-4000-8000-000000000002", "selection": []any{map[string]any{"source_kind": "finding", "source_id": "pid_20000003-0000-4000-8000-000000000003", "source_version": 7, "association_digest": "sha256:" + strings.Repeat("a", 64)}}},
	}
}

// Rejecting all extended claims strands valid agent jobs before capture.
// Accepting an invalid union lets unrelated source bindings reach the worker.
func TestSecurityAgentExportWorkerClaimUnion(t *testing.T) {
	for _, mode := range []string{"valid", "browser", "unknown_origin", "missing_binding", "missing_origin", "unknown_binding_field", "empty", "duplicate", "overflow", "foreign_kind", "bad_id", "bad_version", "bad_digest", "bad_run"} {
		t.Run(mode, func(t *testing.T) {
			l, v := agentExportClaimWire(t)
			b := v["binding"].(map[string]any)
			selection := b["selection"].([]any)
			record := selection[0].(map[string]any)
			switch mode {
			case "browser":
				delete(v, "job_origin")
				delete(v, "binding")
			case "unknown_origin":
				v["job_origin"] = "unknown"
			case "missing_binding":
				delete(v, "binding")
			case "missing_origin":
				delete(v, "job_origin")
			case "unknown_binding_field":
				b["scope"] = "forged"
			case "empty":
				b["selection"] = []any{}
			case "duplicate":
				b["selection"] = append(selection, record)
			case "overflow":
				items := make([]any, 101)
				for i := range items {
					items[i] = record
				}
				b["selection"] = items
			case "foreign_kind":
				record["source_kind"] = "credential"
			case "bad_id":
				record["source_id"] = "run-prefixed-evidence"
			case "bad_version":
				record["source_version"] = 0
			case "bad_digest":
				record["association_digest"] = "sha256:bad"
			case "bad_run":
				b["run_id"] = "foreign"
			}
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			db := &complianceDatabaseFixture{body: raw}
			got, err := newPostgresComplianceExportAuthority(db).Claim(context.Background(), l.Scope, l.ExportID, "worker-1", strings.Repeat("a", 64), "execute")
			if mode == "valid" || mode == "browser" {
				if err != nil || got == nil || got.ExportID != l.ExportID {
					t.Fatalf("valid %s claim rejected: %v", mode, err)
				}
				if mode == "browser" {
					if got.JobOrigin != "" || got.AgentBinding != nil {
						t.Fatal("browser acquired agent authority")
					}
				} else if got.JobOrigin != "agent_run" || got.AgentBinding == nil || got.AgentBinding.RunID != "pid_20000001-0000-4000-8000-000000000001" || got.AgentBinding.StepID != "pid_20000002-0000-4000-8000-000000000002" || len(got.AgentBinding.Selection) != 1 || got.AgentBinding.Selection[0] != (securityAgentExportSelection{Kind: "finding", ID: "pid_20000003-0000-4000-8000-000000000003", Version: 7, AssociationDigest: "sha256:" + strings.Repeat("a", 64)}) {
					t.Fatalf("claim lost immutable binding: %#v", got.AgentBinding)
				}
			} else if err == nil || got != nil {
				t.Fatalf("invalid %s claim accepted: %#v %v", mode, got, err)
			}
		})
	}
}

// A 16KiB claim cap silently excludes valid selections near the100-record limit.
func TestSecurityAgentExportWorkerClaimSelectionBoundary(t *testing.T) {
	for _, count := range []int{100, 101} {
		l, v := agentExportClaimWire(t)
		items := make([]any, count)
		for i := range items {
			items[i] = map[string]any{"source_kind": "finding", "source_id": fmt.Sprintf("pid_20000003-0000-4000-8000-%012d", i+1), "source_version": 7, "association_digest": "sha256:" + strings.Repeat("a", 64)}
		}
		v["binding"].(map[string]any)["selection"] = items
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) <= 16384 {
			t.Fatal("fixture does not cross previous wire bound")
		}
		db := &complianceDatabaseFixture{body: raw}
		got, err := newPostgresComplianceExportAuthority(db).Claim(context.Background(), l.Scope, l.ExportID, "worker-1", strings.Repeat("a", 64), "execute")
		if count == 100 {
			if err != nil || got == nil || got.AgentBinding == nil || len(got.AgentBinding.Selection) != 100 || got.AgentBinding.Selection[99].ID != "pid_20000003-0000-4000-8000-000000000100" {
				t.Fatalf("bounded selection lost: %v", err)
			}
		} else if err == nil || got != nil {
			t.Fatal("101 unique records accepted")
		}
	}
}
