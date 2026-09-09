package sensoradapter

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
)

func TestTetragonProducesContentFreeSearchSelectorsFromObservedFields(t *testing.T) {
	for _, test := range []struct{ name, line, field, value string }{
		{"process", tetragonExecFixture(), "process", "/usr/bin/agent"},
		{"file", tetragonFileFixture(), "file", "/etc/shadow"},
		{"network", tetragonNetworkFixture(), "resource", "tcp://10.0.0.9:443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			event, err := NormalizeTetragonLine([]byte(test.line))
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Search runtimemetadata.Fields `json:"search_metadata"`
			}
			if json.Unmarshal(body, &wire) != nil {
				t.Fatal("invalid adapter wire")
			}
			want, err := runtimemetadata.DigestSelector(test.field, test.value)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{"process": wire.Search.ProcessDigest, "file": wire.Search.FileDigest, "resource": wire.Search.ResourceDigest}[test.field]
			if got != want {
				t.Fatalf("actual %s selector=%s want=%s", test.field, got, want)
			}
			if !wire.Search.Valid("tetragon") || wire.Search.PrincipalID != "" || wire.Search.CredentialID != "" || wire.Search.Decision != "" || wire.Search.DomainDigest != "" {
				t.Fatal("kernel event invented semantic authority")
			}
		})
	}
}

func TestContentFreeProcessExitCanReachRuntimeTransport(t *testing.T) {
	line := `{"process_exit":{"process":` + tetragonProcess() + `,"time":"2026-08-20T12:00:01.000Z"},"node_name":"node-a","time":"2026-08-20T12:00:01.000Z","cluster_name":"cluster-a","node_labels":{}}`
	event, err := NormalizeTetragonLine([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	if !validRuntimeEvent(event, now) {
		t.Fatal("normalized process exit was rejected by its transport")
	}
}
