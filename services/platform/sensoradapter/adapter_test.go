package sensoradapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTetragonLineProducesClosedRedactedRuntimeEvents(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, line, class, action, contentKey string
	}{
		{name: "process", line: tetragonExecFixture(), class: "process", action: "exec", contentKey: "binary_digest"},
		{name: "file", line: tetragonFileFixture(), class: "file", action: "write", contentKey: "path_digest"},
		{name: "network", line: tetragonNetworkFixture(), class: "network", action: "connect", contentKey: "destination_digest"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			event, err := NormalizeTetragonLine([]byte(test.line))
			if err != nil {
				t.Fatalf("NormalizeTetragonLine: %v", err)
			}
			if event.Class != test.class || event.Action != test.action || event.WorkloadID == "" || event.EventID == "" || event.EvidenceID == "" || event.EventTime != "2026-08-20T12:00:00.000Z" {
				t.Fatalf("event = %#v", event)
			}
			if !strings.HasPrefix(event.Content[test.contentKey], "sha256:") {
				t.Fatalf("content = %#v", event.Content)
			}
			encoded, _ := json.Marshal(event)
			for _, secret := range []string{"--password", "super-secret", "/etc/shadow", "10.0.0.9"} {
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatalf("normalized event leaked %q: %s", secret, encoded)
				}
			}
		})
	}
}

func TestNormalizeTetragonLineCanonicalizesProtobufNanosecondTimestamps(t *testing.T) {
	t.Parallel()
	line := strings.ReplaceAll(tetragonExecFixture(), ".000Z", ".580666032Z")
	event, err := NormalizeTetragonLine([]byte(line))
	if err != nil || event.EventTime != "2026-08-20T12:00:00.580Z" {
		t.Fatalf("NormalizeTetragonLine = %#v, %v", event, err)
	}
	normalizer, _ := NewNormalizer(8)
	if normalized, err := normalizer.Normalize([]byte(line)); err != nil || normalized.EventTime != event.EventTime {
		t.Fatalf("Normalizer.Normalize = %#v, %v", normalized, err)
	}
}

func TestNormalizeTetragonLineAcceptsProductionProcessExitShape(t *testing.T) {
	t.Parallel()
	line := `{"process_exit":{"process":` + tetragonProcess() + `,"parent":` + tetragonProcess() + `,"time":"2026-08-20T12:00:01.123456789Z"},"node_name":"node-a","time":"2026-08-20T12:00:01.123456789Z","cluster_name":"cluster-a","node_labels":{}}`
	event, err := NormalizeTetragonLine([]byte(line))
	if err != nil || event.Class != "process" || event.Action != "exit" || event.EventTime != "2026-08-20T12:00:01.123Z" || len(event.Content) != 0 {
		t.Fatalf("NormalizeTetragonLine = %#v, %v", event, err)
	}
}

func TestNormalizerCorrelatesBoundedPartialProbeIdentityFromExactExec(t *testing.T) {
	t.Parallel()
	normalizer, err := NewNormalizer(128)
	if err != nil {
		t.Fatalf("NewNormalizer: %v", err)
	}
	if _, err := normalizer.Normalize([]byte(tetragonExecFixture())); err != nil {
		t.Fatalf("exec: %v", err)
	}
	partial := strings.Replace(tetragonFileFixture(), tetragonProcess(), `{"pid":42,"flags":"unknown","start_time":"2026-08-20T12:00:00.000Z"}`, 1)
	event, err := normalizer.Normalize([]byte(partial))
	if err != nil || event.Class != "file" || event.Action != "write" || event.WorkloadID == "" {
		t.Fatalf("partial probe = %#v, %v", event, err)
	}
	missing, _ := NewNormalizer(128)
	if value, err := missing.Normalize([]byte(partial)); err == nil || !reflect.DeepEqual(value, RuntimeEvent{}) {
		t.Fatalf("missing correlation = %#v, %v", value, err)
	}
	drifted := strings.Replace(partial, "2026-08-20T12:00:00.000Z", "2026-08-20T12:00:01.000Z", 1)
	if value, err := normalizer.Normalize([]byte(drifted)); err == nil || !reflect.DeepEqual(value, RuntimeEvent{}) {
		t.Fatalf("drifted correlation = %#v, %v", value, err)
	}
}

func TestNormalizerBoundsProcessCorrelationCache(t *testing.T) {
	t.Parallel()
	normalizer, _ := NewNormalizer(1)
	if _, err := normalizer.Normalize([]byte(tetragonExecFixture())); err != nil {
		t.Fatalf("first exec: %v", err)
	}
	second := strings.ReplaceAll(tetragonExecFixture(), "exec-1", "exec-2")
	second = strings.ReplaceAll(second, `"pid":42`, `"pid":43`)
	if _, err := normalizer.Normalize([]byte(second)); err != nil {
		t.Fatalf("second exec: %v", err)
	}
	firstPartial := strings.Replace(tetragonFileFixture(), tetragonProcess(), `{"pid":42,"flags":"unknown","start_time":"2026-08-20T12:00:00.000Z"}`, 1)
	if _, err := normalizer.Normalize([]byte(firstPartial)); err == nil {
		t.Fatal("evicted process identity accepted")
	}
}

func TestNormalizeTetragonLineRejectsHostileOrUnsupportedProviderOutput(t *testing.T) {
	t.Parallel()
	valid := tetragonExecFixture()
	for name, line := range map[string]string{
		"empty":            "",
		"oversized":        `{"process_exec":{"process":{"exec_id":"` + strings.Repeat("a", maximumTetragonLineBytes) + `"}}}`,
		"duplicate":        strings.Replace(valid, `"node_name":"node-a"`, `"node_name":"node-a","node_name":"node-b"`, 1),
		"unknown root":     strings.Replace(valid, `"time":`, `"token":"secret","time":`, 1),
		"missing pod":      strings.Replace(valid, `"pod":`, `"not_pod":`, 1),
		"unsupported":      `{"process_tracepoint":{},"node_name":"node-a","time":"2026-08-20T12:00:00.000Z","cluster_name":"cluster-a","node_labels":{}}`,
		"bad time":         strings.ReplaceAll(valid, "2026-08-20T12:00:00.000Z", "2026-08-20T12:00:00.1Z"),
		"missing identity": strings.Replace(valid, `"uid":"11111111-2222-4333-8444-555555555555"`, `"uid":""`, 1),
		"secret protocol":  strings.Replace(tetragonNetworkFixture(), `"protocol":"IPPROTO_TCP"`, `"protocol":"super-secret"`, 1),
	} {
		name, line := name, line
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if value, err := NormalizeTetragonLine([]byte(line)); err == nil || !reflect.DeepEqual(value, RuntimeEvent{}) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "super") {
				t.Fatalf("NormalizeTetragonLine = %#v, %v", value, err)
			}
		})
	}
}

func TestProductionClientContainsPanicsAndHonorsCancellationBeforeCredentialRead(t *testing.T) {
	t.Parallel()
	event, _ := NormalizeTetragonLine([]byte(tetragonExecFixture()))
	for _, test := range []struct {
		name  string
		token func() ([]byte, error)
		do    func(*http.Request) (*http.Response, error)
		now   func() time.Time
	}{
		{name: "token panic", token: func() ([]byte, error) { panic("token-secret") }, do: func(*http.Request) (*http.Response, error) { t.Fatal("provider called"); return nil, nil }, now: time.Now},
		{name: "clock panic", token: func() ([]byte, error) { t.Fatal("token read"); return nil, nil }, do: func(*http.Request) (*http.Response, error) { t.Fatal("provider called"); return nil, nil }, now: func() time.Time { panic("clock-secret") }},
		{name: "provider panic", token: func() ([]byte, error) { return []byte(fixtureSensorToken()), nil }, do: func(*http.Request) (*http.Response, error) { panic("provider-secret") }, now: func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", Token: test.token, Do: test.do, Now: test.now})
			if err != nil {
				t.Fatalf("NewProductionClient: %v", err)
			}
			if err := client.Ingest(context.Background(), []RuntimeEvent{event}); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("Ingest error = %v", err)
			}
		})
	}

	reads := 0
	client, _ := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", Token: func() ([]byte, error) { reads++; return []byte(fixtureSensorToken()), nil }, Do: func(*http.Request) (*http.Response, error) { t.Fatal("provider called"); return nil, nil }, Now: func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Ingest(ctx, []RuntimeEvent{event}); err == nil || reads != 0 {
		t.Fatalf("canceled Ingest = %v, reads=%d", err, reads)
	}
}

func TestProductionClientSendsExactPrivateHeartbeatAndIngest(t *testing.T) {
	t.Parallel()
	token := fixtureSensorToken()
	requests := make([]*http.Request, 0, 2)
	bodies := make([][]byte, 0, 2)
	client, err := NewProductionClient(ProductionClientConfig{
		BaseURL: "https://runtime.example.test",
		Token:   func() ([]byte, error) { return []byte(token), nil },
		Do: func(request *http.Request) (*http.Response, error) {
			clone := request.Clone(request.Context())
			body, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Fatalf("read body: %v", readErr)
			}
			requests = append(requests, clone)
			bodies = append(bodies, body)
			status := http.StatusNoContent
			responseBody := ""
			if request.URL.Path == runtimeEventsPath {
				status, responseBody = http.StatusAccepted, `{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`
			}
			return &http.Response{StatusCode: status, Header: http.Header{"Cache-Control": []string{"no-store"}}, Body: io.NopCloser(strings.NewReader(responseBody))}, nil
		},
		Now: func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewProductionClient: %v", err)
	}
	report := Heartbeat{Sequence: 9, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8.1", BTF: true, EventRate: 12, Drops: 0}
	if err := client.Heartbeat(context.Background(), report); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	event, _ := NormalizeTetragonLine([]byte(tetragonExecFixture()))
	if err := client.Ingest(context.Background(), []RuntimeEvent{event}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %d", len(requests))
	}
	if requests[0].Method != http.MethodPost || requests[0].URL.String() != "https://runtime.example.test/internal/v1/sensor/heartbeat" || requests[0].Header.Get("Content-Type") != heartbeatMediaType || requests[0].Header.Get("X-Zasp-Schema-Version") != heartbeatSchema || requests[0].Header.Get("Authorization") != "Bearer "+token {
		t.Fatalf("heartbeat request = %#v", requests[0])
	}
	if requests[1].Method != http.MethodPost || requests[1].URL.String() != "https://runtime.example.test/internal/v1/runtime/events" || requests[1].Header.Get("Content-Type") != "application/json" || requests[1].Header.Get("X-Zasp-Runtime-Schema") != runtimeEventSchema || requests[1].Header.Get("Authorization") != "Bearer "+token || requests[1].Header.Get("Idempotency-Key") == "" {
		t.Fatalf("ingest request = %#v", requests[1])
	}
	if !bytes.Equal(bodies[0], []byte(`{"sequence":9,"status":"healthy","capabilities":["file","network","process"],"kernel":"6.8.1","btf":true,"event_rate":12,"drops":0}`)) {
		t.Fatalf("heartbeat body = %s", bodies[0])
	}
	var payload struct {
		Source string         `json:"source"`
		Events []RuntimeEvent `json:"events"`
	}
	if json.Unmarshal(bodies[1], &payload) != nil || payload.Source != "tetragon" || len(payload.Events) != 1 || !reflect.DeepEqual(payload.Events[0], event) {
		t.Fatalf("ingest body = %s", bodies[1])
	}
}

func TestProductionClientFailsClosedWithoutLeakingCredentialOrProviderBody(t *testing.T) {
	t.Parallel()
	token := fixtureSensorToken()
	for _, test := range []struct {
		name     string
		status   int
		response string
	}{
		{name: "redirect", status: http.StatusTemporaryRedirect, response: "https://evil.invalid/"},
		{name: "denied", status: http.StatusForbidden, response: token},
		{name: "retry", status: http.StatusServiceUnavailable, response: "provider-secret"},
		{name: "oversized", status: http.StatusAccepted, response: strings.Repeat("x", maximumResponseBytes+1)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", Token: func() ([]byte, error) { return []byte(token), nil }, Do: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(test.response))}, nil
			}, Now: time.Now})
			if err != nil {
				t.Fatalf("NewProductionClient: %v", err)
			}
			event, _ := NormalizeTetragonLine([]byte(tetragonExecFixture()))
			err = client.Ingest(context.Background(), []RuntimeEvent{event})
			if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "provider-secret") || strings.Contains(err.Error(), "evil") {
				t.Fatalf("Ingest error = %v", err)
			}
		})
	}
}

func fixtureSensorToken() string {
	return "zasp_sensor_v1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
}

func tetragonProcess() string {
	return `{"exec_id":"exec-1","pid":42,"uid":1000,"cwd":"/tmp","binary":"/usr/bin/agent","arguments":"--password super-secret","flags":"execve","start_time":"2026-08-20T12:00:00.000Z","auid":4294967295,"pod":{"namespace":"agentsec","name":"agent-a","uid":"11111111-2222-4333-8444-555555555555","container":{"id":"containerd://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"agent","image":{"id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":"agent:prod"},"start_time":"2026-08-20T11:59:00.000Z","pid":12,"security_context":{}},"pod_labels":{"app":"agent"},"workload":"agent-a","workload_kind":"Pod"},"docker":"aaaaaaaaaaaaaaaaaaaaaaaa","parent_exec_id":"parent-1","cap":{},"ns":{},"tid":42,"process_credentials":{},"in_init_tree":false}`
}

func tetragonExecFixture() string {
	return `{"process_exec":{"process":` + tetragonProcess() + `,"parent":` + tetragonProcess() + `},"node_name":"node-a","time":"2026-08-20T12:00:00.000Z","cluster_name":"cluster-a","node_labels":{}}`
}

func tetragonFileFixture() string {
	return `{"process_kprobe":{"process":` + tetragonProcess() + `,"function_name":"security_file_permission","args":[{"file_arg":{"path":"/etc/shadow","permission":"-rw-r-----"}},{"int_arg":2}],"action":"KPROBE_ACTION_POST","policy_name":"zasp-sensitive-file","return_action":"KPROBE_ACTION_POST"},"node_name":"node-a","time":"2026-08-20T12:00:00.000Z","cluster_name":"cluster-a","node_labels":{}}`
}

func tetragonNetworkFixture() string {
	return `{"process_kprobe":{"process":` + tetragonProcess() + `,"function_name":"tcp_connect","args":[{"sock_arg":{"family":"AF_INET","type":"SOCK_STREAM","protocol":"IPPROTO_TCP","saddr":"10.0.0.8","daddr":"10.0.0.9","sport":40000,"dport":443,"cookie":"0","state":"TCP_SYN_SENT"}}],"action":"KPROBE_ACTION_POST","policy_name":"zasp-network-connect","return_action":"KPROBE_ACTION_POST"},"node_name":"node-a","time":"2026-08-20T12:00:00.000Z","cluster_name":"cluster-a","node_labels":{}}`
}
