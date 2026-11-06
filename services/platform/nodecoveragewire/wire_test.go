package nodecoveragewire_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func wireFixture() wire.Envelope {
	stamp := time.Date(2026, 10, 17, 12, 0, 0, 123456000, time.UTC)
	target := wire.CoverageTarget{Namespace: "edge", Name: "sensor", Release: "zasp", ReleaseNamespace: "edge", Image: "example/sensor@sha256:" + strings.Repeat("a", 64), ServiceAccount: "sensor", Container: "sensor"}
	other := target
	other.Name = "tetragon"
	other.Container = "tetragon"
	s := wire.NodeCoverageSelection{SourceProfile: "tetragon-local-stream-v2", ClusterUID: uid(1), EnrollmentBinding: strings.Repeat("b", 64), MatchLabels: map[string]string{"nodegroup": "selected"}, Sensor: target, Tetragon: other}
	report := wire.NodeCoverageV2{Schema: "zasp-node-coverage-v2", EnrollmentBinding: s.EnrollmentBinding, ClusterUID: s.ClusterUID, NodeName: "node-a", NodeUID: uid(2), BootID: uid(3), ReporterPodName: "sensor-a", ReporterPodUID: uid(4), TetragonPodName: "tetragon-a", TetragonPodUID: uid(5), GenerationID: uid(6), SourceProfile: s.SourceProfile, IdentityObservedAt: stamp, MeasuredAt: stamp, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8", BTF: true, EventRate: 12, Drops: 0}
	return wire.Envelope{Heartbeat: wire.Heartbeat{Sequence: 1, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8", BTF: true, EventRate: 12}, CoverageSchema: wire.CoverageSchema, StateUID: uid(7), StorageEpoch: 1, Selection: s, TargetDigest: strings.Repeat("c", 64), InventoryObservedAt: stamp, SourceObservedAt: stamp, TTLSeconds: 30, SensorDaemonSetUID: uid(8), TetragonDaemonSetUID: uid(9), SelectedNodes: []wire.SelectedNode{{NodeName: report.NodeName, NodeUID: report.NodeUID, BootID: report.BootID}}, Reports: []wire.NodeCoverageV2{report}}
}
func uid(n int) string { return fmt.Sprintf("%08x-1111-4111-8111-111111111111", n) }
func originalBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func cloneEnvelope(t *testing.T, v wire.Envelope) wire.Envelope {
	t.Helper()
	var result wire.Envelope
	if e := json.Unmarshal(originalBytes(t, v), &result); e != nil {
		t.Fatal(e)
	}
	return result
}

func TestRetainedCoverageWireFullInventoryAndOriginalTimes(t *testing.T) {
	v := wireFixture()
	template := v.Reports[0]
	v.SelectedNodes = nil
	v.Reports = nil
	for i := 0; i < 1000; i++ {
		r := template
		r.NodeName = fmt.Sprintf("node-%04d", i) + strings.Repeat("a", 240)
		r.NodeUID = uid(100 + i)
		r.BootID = uid(2100 + i)
		r.ReporterPodName = "sensor-" + strings.Repeat("b", 240)
		r.TetragonPodName = "tetragon-" + strings.Repeat("c", 240)
		r.Kernel = strings.Repeat("<", 128)
		v.SelectedNodes = append(v.SelectedNodes, wire.SelectedNode{NodeName: r.NodeName, NodeUID: r.NodeUID, BootID: r.BootID})
		v.Reports = append(v.Reports, r)
	}
	v.Kernel = strings.Repeat("<", 128)
	v.EventRate = 12000
	b, e := wire.MarshalEnvelope(v)
	if e != nil {
		t.Fatalf("legal1000-node envelope rejected: %v", e)
	}
	if len(b) > wire.MaxEnvelopeBytes || len(b) == 0 {
		t.Fatalf("bounded complete payload bytes=%d", len(b))
	}
	got, e := wire.ParseEnvelope(b)
	if e != nil || !reflect.DeepEqual(got, v) {
		t.Fatalf("whole inventory/original timestamp roundtrip: %v", e)
	}
	again, e := wire.MarshalEnvelope(got)
	if e != nil || !bytes.Equal(b, again) {
		t.Fatal("canonical original bytes changed")
	}
	if wire.ValidateFreshEnvelope(got, v.SourceObservedAt.Add(29*time.Second)) != nil {
		t.Fatal("fresh original observation refused")
	}
}
func TestRetainedCoverageWireStructuralExpiryAndIncompleteInventory(t *testing.T) {
	v := wireFixture()
	v.Status = "degraded"
	v.BTF = false
	v.Reports = []wire.NodeCoverageV2{}
	v.Capabilities = []string{"process"}
	v.Kernel = "unknown"
	v.EventRate = 0
	b := originalBytes(t, v)
	got, e := wire.ParseEnvelope(b)
	if e != nil || len(got.SelectedNodes) != 1 || len(got.Reports) != 0 {
		t.Fatalf("missing report must retain selected node: %v", e)
	}
	if wire.ValidateEnvelope(got) != nil {
		t.Fatal("expired structural observation cannot be resolved")
	}
	if !errors.Is(wire.ValidateFreshEnvelope(got, v.SourceObservedAt.Add(31*time.Second)), wire.ErrInvalid) {
		t.Fatal("expired observation accepted for forward send")
	}
	if !errors.Is(wire.ValidateFreshEnvelope(got, v.SourceObservedAt.Add(-6*time.Second)), wire.ErrInvalid) {
		t.Fatal("future observation accepted")
	}
}
func TestRetainedCoverageWireClosedNestedContract(t *testing.T) {
	v := wireFixture()
	raw := string(originalBytes(t, v))
	cases := map[string]string{
		"case alias":         strings.Replace(raw, `"sequence":1`, `"Sequence":1`, 1),
		"nested null":        strings.Replace(raw, `"node_uid":"00000002-1111-4111-8111-111111111111"`, `"node_uid":null`, 1),
		"unpaired surrogate": strings.Replace(raw, `"kernel":"6.8"`, `"kernel":"\ud800"`, 1),
		"duplicate root":     strings.Replace(raw, `"sequence":1`, `"sequence":1,"sequence":1`, 1),
		"duplicate nested":   strings.Replace(raw, `"source_profile":"tetragon-local-stream-v2"`, `"source_profile":"tetragon-local-stream-v2","source_profile":"tetragon-local-stream-v2"`, 1),
		"null false":         strings.Replace(raw, `"btf":true`, `"btf":null`, 1),
		"null reports":       strings.Replace(raw, `"reports":[`, `"reports":null,"unexpected":[`, 1),
		"unknown nested":     strings.Replace(raw, `"node_name":"node-a"`, `"node_name":"node-a","covered":true`, 1),
		"missing zero field": strings.Replace(raw, `"drops":0,`, "", 1),
		"trailing":           raw + `{}`, "oversize": strings.Repeat(" ", wire.MaxEnvelopeBytes+1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := wire.ParseEnvelope([]byte(body)); !errors.Is(e, wire.ErrInvalid) {
				t.Fatal("hostile envelope admitted")
			}
		})
	}
	for _, change := range []func(*wire.Envelope){func(x *wire.Envelope) { x.Reports[0].EnrollmentBinding = strings.Repeat("d", 64) }, func(x *wire.Envelope) { x.SelectedNodes = append(x.SelectedNodes, x.SelectedNodes[0]) }, func(x *wire.Envelope) { x.Reports[0].NodeUID = uid(99) }, func(x *wire.Envelope) { x.SourceObservedAt = x.SourceObservedAt.Add(time.Second) }, func(x *wire.Envelope) { x.Reports = append(x.Reports, x.Reports[0]) }, func(x *wire.Envelope) { x.StorageEpoch = 0 }} {
		x := cloneEnvelope(t, v)
		change(&x)
		if _, e := wire.ParseEnvelope(originalBytes(t, x)); !errors.Is(e, wire.ErrInvalid) {
			t.Fatal("invalid inventory/binding admitted")
		}
	}
}
func TestRetainedCoverageWireReceiptDispositionsAreExact(t *testing.T) {
	v := wireFixture()
	for _, kind := range []string{"accepted", "expired_not_committed"} {
		r := wire.Receipt{SensorID: "pid_10000001-0000-4000-8000-000000000001", Sequence: 1, RequestDigest: strings.Repeat("a", 64), Disposition: kind, ResolvedAt: v.SourceObservedAt.Add(31 * time.Second), SourceObservedAt: v.SourceObservedAt, ExpiresAt: v.SourceObservedAt.Add(30 * time.Second)}
		b, e := wire.MarshalReceipt(r)
		if e != nil {
			t.Fatalf("typed %s receipt rejected", kind)
		}
		got, e := wire.ParseReceipt(b)
		if e != nil || !reflect.DeepEqual(got, r) {
			t.Fatal("receipt facts changed")
		}
		for _, bad := range []string{strings.Replace(string(b), `"replayed":false`, `"replayed":null`, 1), strings.Replace(string(b), `"sequence":1`, `"sequence":1,"sequence":1`, 1), strings.Replace(string(b), kind, "timeout", 1), string(b) + `{}`} {
			if _, e := wire.ParseReceipt([]byte(bad)); !errors.Is(e, wire.ErrInvalid) {
				t.Fatal("ambiguous receipt admitted")
			}
		}
	}
}
func TestRetainedCoverageWireExistingReportCompatibility(t *testing.T) {
	r := wireFixture().Reports[0]
	var old sensoradapter.NodeCoverageV2
	if e := json.Unmarshal(originalBytes(t, r), &old); e != nil {
		t.Fatal(e)
	}
	oldEncoded, e := sensoradapter.EncodeNodeCoverage(old)
	if e != nil {
		t.Fatal(e)
	}
	newEncoded, e := wire.EncodeNodeCoverage(r)
	if e != nil || newEncoded != oldEncoded {
		t.Fatal("original report codec changed")
	}
	decoded, e := wire.DecodeNodeCoverage(oldEncoded)
	if e != nil || !reflect.DeepEqual(decoded, r) {
		t.Fatal("existing annotation report rejected")
	}
	if sensoradapter.ErrNodeCoverage != wire.ErrInvalid {
		t.Fatal("shared error identity not delegated")
	}
	if reflect.TypeOf(old) != reflect.TypeOf(r) {
		t.Fatal("existing exported report type not alias-preserved")
	}
}
