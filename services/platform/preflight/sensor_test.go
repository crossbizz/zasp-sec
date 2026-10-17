package preflight

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSensorAuthorityObservesKubernetesIndependentlyOfAWS(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer explicit-kubernetes-observer-token" {
			t.Error("non-read or wrong credential request")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"name": "kube-system", "uid": "11111111-1111-4111-8111-111111111111"}, "status": map[string]string{"phase": "Active"}})
		case "/api/v1/nodes":
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"resourceVersion": "1"}, "items": []any{}})
		default:
			w.WriteHeader(403)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	token := filepath.Join(dir, "token")
	if os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600) != nil || os.WriteFile(token, []byte("explicit-kubernetes-observer-token"), 0600) != nil {
		t.Fatal("owned authority fixture write failed")
	}
	c := sdkContractConfig(t)
	c.Credentials.Kind = "operator_file"
	c.Credentials.File = filepath.Join(dir, "missing-aws-credentials")
	c.Kubernetes = &KubernetesAuthority{Endpoint: server.URL, CAFile: ca, ClusterUID: "11111111-1111-4111-8111-111111111111", Credentials: KubernetesCredentials{Kind: "explicit_bearer_file", TokenFile: token}}
	target := sensoradapter.CoverageTarget{Namespace: "edge", Name: "sensor-agent", Release: "zasp", ReleaseNamespace: "edge", Image: "example/sensor@sha256:" + strings.Repeat("a", 64), ServiceAccount: "sensor-agent", Container: "sensor-agent"}
	tetra := target
	tetra.Name, tetra.Release, tetra.Container = "zasp-tetragon", "zasp-tetragon", "tetragon"
	tetra.ServiceAccount = "zasp-tetragon"
	c.Sensor = &sensoradapter.NodeCoverageSelection{SourceProfile: "tetragon-local-stream-v2", ClusterUID: c.Kubernetes.ClusterUID, EnrollmentBinding: strings.Repeat("b", 64), MatchLabels: map[string]string{"eks.amazonaws.com/nodegroup": "selected-sensors"}, Sensor: target, Tetragon: tetra}
	for _, mode := range []string{"required", "optional", "disabled"} {
		c.Features.SensorMode = mode
		before := calls
		r, e := NewRunner(c)
		if e != nil {
			t.Fatal("explicit read-only config refused")
		}
		report, e := r.Run(context.Background(), "installed")
		r.Close()
		if e == nil || report.Ready || report.ProductionEndToEndVerified {
			t.Fatal("sensor observations promoted missing core/deployed proof")
		}
		var sensor Check
		for _, v := range report.Checks {
			if v.Name == "sensor" {
				sensor = v
			}
		}
		if mode == "disabled" {
			if calls != before {
				t.Fatal("disabled mode read sensor authority")
			}
		} else {
			if calls-before != 2 {
				t.Fatal("AWS failure suppressed independent Kubernetes observation")
			}
			if mode == "optional" && sensor.Status != "warn" || mode == "required" && sensor.Status != "fail" {
				t.Fatal("sensor mode severity changed")
			}
		}
		body, _ := json.Marshal(report)
		if strings.Contains(string(body), "explicit-kubernetes-observer-token") || strings.Contains(string(body), server.URL) {
			t.Fatal("authority secret or endpoint leaked")
		}
	}
}
