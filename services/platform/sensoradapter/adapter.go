// Package sensoradapter translates the deliberately small supported Tetragon
// event surface into the private v15 runtime-event wire contract.
package sensoradapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

const (
	maximumTetragonLineBytes = 256 << 10
	maximumResponseBytes     = 16 << 10
	maximumBatchEvents       = 1000
	heartbeatPath            = "/internal/v1/sensor/heartbeat"
	runtimeEventsPath        = "/internal/v1/runtime/events"
	heartbeatMediaType       = "application/vnd.zasp.sensor-heartbeat+json"
	heartbeatSchema          = "sensor-heartbeat-v1"
	runtimeEventSchema       = "runtime-event-v1"
	timestampLayout          = "2006-01-02T15:04:05.000Z"
)

var (
	ErrAdapter             = errors.New("sensor adapter input rejected")
	ErrClient              = errors.New("sensor transport rejected")
	ErrClientDenied        = errors.New("sensor transport authentication rejected")
	ErrClientRetryable     = errors.New("sensor transport temporarily unavailable")
	providerTokenPattern   = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,256}$`)
	capabilityTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,95}$`)
)

type RuntimeEvent struct {
	EventID    string            `json:"event_id"`
	Class      string            `json:"class"`
	Action     string            `json:"action"`
	WorkloadID string            `json:"workload_id"`
	EventTime  string            `json:"event_time"`
	EvidenceID string            `json:"evidence_id"`
	Content    map[string]string `json:"content,omitempty"`
}

type Heartbeat struct {
	Sequence     int64    `json:"sequence"`
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
	Kernel       string   `json:"kernel"`
	BTF          bool     `json:"btf"`
	EventRate    uint64   `json:"event_rate"`
	Drops        uint64   `json:"drops"`
}

type providerRoot struct {
	ProcessExec   *providerExec              `json:"process_exec,omitempty"`
	ProcessExit   *providerExit              `json:"process_exit,omitempty"`
	ProcessKprobe *providerKprobe            `json:"process_kprobe,omitempty"`
	NodeName      string                     `json:"node_name"`
	Time          string                     `json:"time"`
	ClusterName   string                     `json:"cluster_name"`
	NodeLabels    map[string]json.RawMessage `json:"node_labels"`
}

type providerExec struct {
	Process providerProcess `json:"process"`
}
type providerExit struct {
	Process providerProcess `json:"process"`
	Parent  json.RawMessage `json:"parent,omitempty"`
	Signal  string          `json:"signal,omitempty"`
	Status  uint32          `json:"status"`
}
type providerKprobe struct {
	Process      providerProcess `json:"process"`
	Parent       json.RawMessage `json:"parent,omitempty"`
	FunctionName string          `json:"function_name"`
	Args         []providerArg   `json:"args"`
	Action       string          `json:"action"`
	PolicyName   string          `json:"policy_name"`
	ReturnAction string          `json:"return_action"`
}
type providerArg struct {
	File *providerFile `json:"file_arg,omitempty"`
	Int  *int64        `json:"int_arg,omitempty"`
	Sock *providerSock `json:"sock_arg,omitempty"`
}
type providerFile struct {
	Path       string `json:"path"`
	Permission string `json:"permission"`
}
type providerSock struct {
	Family, Type, Protocol, Saddr, Daddr, Cookie, State string
	Sport, Dport                                        uint16
}

func (value *providerSock) UnmarshalJSON(payload []byte) error {
	type wire struct {
		Family   string `json:"family"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
		Saddr    string `json:"saddr"`
		Daddr    string `json:"daddr"`
		Sport    uint16 `json:"sport"`
		Dport    uint16 `json:"dport"`
		Cookie   string `json:"cookie"`
		State    string `json:"state"`
	}
	var decoded wire
	if decodeClosed(payload, &decoded) != nil {
		return ErrAdapter
	}
	*value = providerSock{Family: decoded.Family, Type: decoded.Type, Protocol: decoded.Protocol, Saddr: decoded.Saddr, Daddr: decoded.Daddr, Sport: decoded.Sport, Dport: decoded.Dport, Cookie: decoded.Cookie, State: decoded.State}
	return nil
}

type providerProcess struct {
	ExecID             string                     `json:"exec_id"`
	PID                uint32                     `json:"pid"`
	UID                uint32                     `json:"uid"`
	Cwd                string                     `json:"cwd"`
	Binary             string                     `json:"binary"`
	Arguments          string                     `json:"arguments"`
	Flags              string                     `json:"flags"`
	StartTime          string                     `json:"start_time"`
	AUID               uint32                     `json:"auid"`
	Pod                providerPod                `json:"pod"`
	Docker             string                     `json:"docker"`
	ParentExecID       string                     `json:"parent_exec_id"`
	Cap                map[string]json.RawMessage `json:"cap"`
	NS                 map[string]json.RawMessage `json:"ns"`
	TID                uint32                     `json:"tid"`
	ProcessCredentials map[string]json.RawMessage `json:"process_credentials"`
	InInitTree         bool                       `json:"in_init_tree"`
	Refcnt             *uint32                    `json:"refcnt,omitempty"`
}
type providerPod struct {
	Namespace    string            `json:"namespace"`
	Name         string            `json:"name"`
	UID          string            `json:"uid"`
	Container    providerContainer `json:"container"`
	PodLabels    map[string]string `json:"pod_labels"`
	Workload     string            `json:"workload"`
	WorkloadKind string            `json:"workload_kind"`
}
type providerContainer struct {
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	Image           providerImage              `json:"image"`
	StartTime       string                     `json:"start_time"`
	PID             uint32                     `json:"pid"`
	SecurityContext map[string]json.RawMessage `json:"security_context"`
}
type providerImage struct{ ID, Name string }

func (value *providerImage) UnmarshalJSON(payload []byte) error {
	type wire struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var decoded wire
	if decodeClosed(payload, &decoded) != nil {
		return ErrAdapter
	}
	*value = providerImage(decoded)
	return nil
}

func NormalizeTetragonLine(line []byte) (RuntimeEvent, error) {
	root, err := decodeProviderRoot(line)
	if err != nil {
		return RuntimeEvent{}, err
	}
	return normalizeProviderRoot(line, root)
}

func decodeProviderRoot(line []byte) (providerRoot, error) {
	if len(line) == 0 || len(line) > maximumTetragonLineBytes || !utf8.Valid(line) || !uniqueJSON(line) {
		return providerRoot{}, ErrAdapter
	}
	var root providerRoot
	if decodeClosed(line, &root) != nil || !boundedText(root.NodeName, 253) || !boundedText(root.ClusterName, 253) || root.NodeLabels == nil {
		return providerRoot{}, ErrAdapter
	}
	when, err := time.Parse(timestampLayout, root.Time)
	if err != nil || when.Location() != time.UTC || when.Format(timestampLayout) != root.Time {
		return providerRoot{}, ErrAdapter
	}
	kinds := 0
	if root.ProcessExec != nil {
		kinds++
	}
	if root.ProcessExit != nil {
		kinds++
	}
	if root.ProcessKprobe != nil {
		kinds++
	}
	if kinds != 1 {
		return providerRoot{}, ErrAdapter
	}
	return root, nil
}

func normalizeProviderRoot(line []byte, root providerRoot) (RuntimeEvent, error) {
	var process providerProcess
	class, action := "", ""
	content := map[string]string{}
	var err error
	switch {
	case root.ProcessExec != nil:
		process = root.ProcessExec.Process
		class, action = "process", "exec"
		content["binary_digest"] = digestText(process.Binary)
	case root.ProcessExit != nil:
		process = root.ProcessExit.Process
		class, action = "process", "exit"
		content["exit_status"] = strconv.FormatUint(uint64(root.ProcessExit.Status), 10)
	case root.ProcessKprobe != nil:
		process = root.ProcessKprobe.Process
		class, action, content, err = normalizeKprobe(root.ProcessKprobe)
		if err != nil {
			return RuntimeEvent{}, ErrAdapter
		}
	}
	if !validProcessIdentity(process) {
		return RuntimeEvent{}, ErrAdapter
	}
	workloadDigest := sha256.Sum256([]byte(strings.Join([]string{"zasp-tetragon-workload-v1", root.ClusterName, root.NodeName, process.Pod.Namespace, process.Pod.UID, process.Pod.Container.ID}, "\x00")))
	lineDigest := sha256.Sum256(append([]byte("zasp-tetragon-event-v1\x00"), line...))
	evidence, err := productIDFromDigest(lineDigest)
	if err != nil {
		return RuntimeEvent{}, ErrAdapter
	}
	return RuntimeEvent{
		EventID: "tetragon:" + hex.EncodeToString(lineDigest[:]), Class: class, Action: action,
		WorkloadID: "k8s:" + hex.EncodeToString(workloadDigest[:]), EventTime: root.Time,
		EvidenceID: evidence.String(), Content: content,
	}, nil
}

type processCorrelationKey struct {
	node      string
	pid       uint32
	startedAt string
}

// Normalizer correlates bounded Tetragon probe/exit references to the exact
// preceding exec identity. It retains no raw arguments, file paths, addresses,
// credentials, or other provider content.
type Normalizer struct {
	mu      sync.Mutex
	maximum int
	order   []processCorrelationKey
	values  map[processCorrelationKey]providerProcess
}

func NewNormalizer(maximumProcesses int) (*Normalizer, error) {
	if maximumProcesses < 1 || maximumProcesses > 100_000 {
		return nil, ErrAdapter
	}
	return &Normalizer{maximum: maximumProcesses, values: make(map[processCorrelationKey]providerProcess, maximumProcesses)}, nil
}

func (normalizer *Normalizer) Normalize(line []byte) (RuntimeEvent, error) {
	if normalizer == nil {
		return RuntimeEvent{}, ErrAdapter
	}
	root, err := decodeProviderRoot(line)
	if err != nil {
		return RuntimeEvent{}, err
	}
	normalizer.mu.Lock()
	defer normalizer.mu.Unlock()
	var process *providerProcess
	switch {
	case root.ProcessExec != nil:
		process = &root.ProcessExec.Process
	case root.ProcessExit != nil:
		process = &root.ProcessExit.Process
	case root.ProcessKprobe != nil:
		process = &root.ProcessKprobe.Process
	}
	if process == nil {
		return RuntimeEvent{}, ErrAdapter
	}
	key, keyOK := correlationKey(root.NodeName, *process)
	if !validProcessIdentity(*process) {
		correlated, found := normalizer.values[key]
		if !keyOK || !found {
			return RuntimeEvent{}, ErrAdapter
		}
		*process = correlated
	}
	event, err := normalizeProviderRoot(line, root)
	if err != nil {
		return RuntimeEvent{}, err
	}
	if root.ProcessExec != nil {
		if !keyOK {
			return RuntimeEvent{}, ErrAdapter
		}
		identity := retainedProcessIdentity(*process)
		if prior, found := normalizer.values[key]; found {
			if !sameProcessIdentity(prior, identity) {
				return RuntimeEvent{}, ErrAdapter
			}
			return event, nil
		}
		if len(normalizer.order) == normalizer.maximum {
			delete(normalizer.values, normalizer.order[0])
			copy(normalizer.order, normalizer.order[1:])
			normalizer.order = normalizer.order[:len(normalizer.order)-1]
		}
		normalizer.order = append(normalizer.order, key)
		normalizer.values[key] = identity
	}
	if root.ProcessExit != nil && keyOK {
		delete(normalizer.values, key)
		for index, candidate := range normalizer.order {
			if candidate == key {
				normalizer.order = append(normalizer.order[:index], normalizer.order[index+1:]...)
				break
			}
		}
	}
	return event, nil
}

func correlationKey(node string, process providerProcess) (processCorrelationKey, bool) {
	if !boundedText(node, 253) || process.PID == 0 {
		return processCorrelationKey{}, false
	}
	startedAt, err := time.Parse(timestampLayout, process.StartTime)
	if err != nil || startedAt.Format(timestampLayout) != process.StartTime {
		return processCorrelationKey{}, false
	}
	return processCorrelationKey{node: node, pid: process.PID, startedAt: process.StartTime}, true
}

func retainedProcessIdentity(value providerProcess) providerProcess {
	return providerProcess{
		ExecID: value.ExecID, PID: value.PID, Binary: "correlated", StartTime: value.StartTime,
		Pod: providerPod{Namespace: value.Pod.Namespace, Name: value.Pod.Name, UID: value.Pod.UID,
			Container: providerContainer{ID: value.Pod.Container.ID, Name: value.Pod.Container.Name}},
	}
}

func sameProcessIdentity(left, right providerProcess) bool {
	return left.ExecID == right.ExecID && left.PID == right.PID && left.StartTime == right.StartTime && left.Pod.Namespace == right.Pod.Namespace && left.Pod.Name == right.Pod.Name && left.Pod.UID == right.Pod.UID && left.Pod.Container.ID == right.Pod.Container.ID && left.Pod.Container.Name == right.Pod.Container.Name
}

func normalizeKprobe(value *providerKprobe) (string, string, map[string]string, error) {
	if value == nil || !providerTokenPattern.MatchString(value.PolicyName) || value.Action == "" || value.ReturnAction == "" {
		return "", "", nil, ErrAdapter
	}
	switch value.FunctionName {
	case "security_file_permission":
		if len(value.Args) != 2 || value.Args[0].File == nil || value.Args[0].Int != nil || value.Args[0].Sock != nil || value.Args[1].Int == nil || value.Args[1].File != nil || value.Args[1].Sock != nil || !boundedText(value.Args[0].File.Path, 4096) {
			return "", "", nil, ErrAdapter
		}
		action := "read"
		if *value.Args[1].Int&2 != 0 {
			action = "write"
		}
		return "file", action, map[string]string{"path_digest": digestText(value.Args[0].File.Path)}, nil
	case "tcp_connect", "inet_csk_accept":
		if len(value.Args) != 1 || value.Args[0].Sock == nil || value.Args[0].Int != nil || value.Args[0].File != nil || !boundedText(value.Args[0].Sock.Daddr, 256) || value.Args[0].Sock.Dport == 0 || value.Args[0].Sock.Protocol != "IPPROTO_TCP" && value.Args[0].Sock.Protocol != "TCP" {
			return "", "", nil, ErrAdapter
		}
		action := "connect"
		if value.FunctionName == "inet_csk_accept" {
			action = "accept"
		}
		return "network", action, map[string]string{"destination_digest": digestText(value.Args[0].Sock.Daddr), "destination_port": strconv.FormatUint(uint64(value.Args[0].Sock.Dport), 10), "protocol": value.Args[0].Sock.Protocol}, nil
	default:
		return "", "", nil, ErrAdapter
	}
}

func validProcessIdentity(value providerProcess) bool {
	pod, container := value.Pod, value.Pod.Container
	if !boundedText(pod.Namespace, 253) || !boundedText(pod.Name, 253) || !boundedText(pod.UID, 128) || !boundedText(container.ID, 256) || !boundedText(container.Name, 253) || !boundedText(value.Binary, 4096) || !boundedText(value.ExecID, 256) {
		return false
	}
	return strings.TrimSpace(pod.Namespace) == pod.Namespace && strings.TrimSpace(pod.UID) == pod.UID && strings.TrimSpace(container.ID) == container.ID
}

func productIDFromDigest(digest [sha256.Size]byte) (domain.ProductID, error) {
	value := [16]byte{}
	copy(value[:], digest[:16])
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	text := fmt.Sprintf("pid_%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
	return domain.ParseProductID(text)
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func boundedText(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func decodeClosed(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrAdapter
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return ErrAdapter
	}
	return nil
}

type ProductionClientConfig struct {
	BaseURL string
	Token   func() ([]byte, error)
	Do      func(*http.Request) (*http.Response, error)
	Now     func() time.Time
}

type ProductionClient struct {
	base  *url.URL
	token func() ([]byte, error)
	do    func(*http.Request) (*http.Response, error)
	now   func() time.Time
}

func NewProductionClient(config ProductionClientConfig) (*ProductionClient, error) {
	base, err := url.Parse(config.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" || config.Token == nil || config.Do == nil || config.Now == nil {
		return nil, ErrClient
	}
	return &ProductionClient{base: base, token: config.Token, do: config.Do, now: config.Now}, nil
}

func (client *ProductionClient) Heartbeat(ctx context.Context, report Heartbeat) error {
	if client == nil || !validHeartbeat(report) {
		return ErrClient
	}
	body, err := json.Marshal(report)
	if err != nil {
		return ErrClient
	}
	defer clear(body)
	return client.send(ctx, heartbeatPath, heartbeatMediaType, heartbeatSchema, "", body, http.StatusNoContent, false)
}

func (client *ProductionClient) Ingest(ctx context.Context, events []RuntimeEvent) error {
	if client == nil || len(events) == 0 || len(events) > maximumBatchEvents {
		return ErrClient
	}
	now, err := safeNow(client.now)
	if err != nil {
		return err
	}
	for _, event := range events {
		if !validRuntimeEvent(event, now) {
			return ErrClient
		}
	}
	body, err := json.Marshal(struct {
		Source string         `json:"source"`
		Events []RuntimeEvent `json:"events"`
	}{Source: "tetragon", Events: events})
	if err != nil {
		return ErrClient
	}
	defer clear(body)
	digest := sha256.Sum256(body)
	idempotency := "runtime-v1:" + hex.EncodeToString(digest[:])
	return client.send(ctx, runtimeEventsPath, "application/json", runtimeEventSchema, idempotency, body, http.StatusAccepted, true)
}

func (client *ProductionClient) send(ctx context.Context, path, media, schema, idempotency string, body []byte, expected int, requireJSON bool) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrClientRetryable
	}
	tokenBytes, err := safeToken(client.token)
	if err != nil || len(tokenBytes) == 0 {
		clear(tokenBytes)
		return ErrClientDenied
	}
	defer clear(tokenBytes)
	credential, err := sensor.ParseTokenCredential(string(tokenBytes))
	if err != nil {
		return ErrClientDenied
	}
	wire, err := credential.Wire()
	credential.Destroy()
	if err != nil {
		return ErrClientDenied
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return ErrClient
	}
	request.Header.Set("Authorization", "Bearer "+wire)
	request.Header.Set("Content-Type", media)
	if path == heartbeatPath {
		request.Header.Set("X-Zasp-Schema-Version", schema)
	} else {
		request.Header.Set("X-Zasp-Runtime-Schema", schema)
	}
	if idempotency != "" {
		request.Header.Set("Idempotency-Key", idempotency)
	}
	response, err := safeDo(client.do, request)
	if err != nil || response == nil || response.Body == nil {
		return ErrClientRetryable
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	defer clear(responseBody)
	if readErr != nil || len(responseBody) > maximumResponseBytes {
		return ErrClientRetryable
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return ErrClientDenied
	}
	if response.StatusCode != expected || response.Header.Get("Cache-Control") != "no-store" {
		return ErrClientRetryable
	}
	if !requireJSON {
		if len(responseBody) != 0 {
			return ErrClient
		}
		return nil
	}
	var result struct {
		BatchID string `json:"batch_id"`
	}
	if !uniqueJSON(responseBody) || decodeClosed(responseBody, &result) != nil {
		return ErrClientRetryable
	}
	if _, err := domain.ParseProductID(result.BatchID); err != nil {
		return ErrClientRetryable
	}
	return nil
}

func validHeartbeat(value Heartbeat) bool {
	if value.Sequence < 0 || value.Status != "healthy" && value.Status != "degraded" || !boundedText(value.Kernel, 128) || value.EventRate > 1_000_000_000 || value.Drops > 1_000_000_000 || len(value.Capabilities) == 0 || len(value.Capabilities) > 32 {
		return false
	}
	copyValue := append([]string(nil), value.Capabilities...)
	sort.Strings(copyValue)
	for index, capability := range value.Capabilities {
		if !capabilityTokenPattern.MatchString(capability) || copyValue[index] != capability || index > 0 && capability == value.Capabilities[index-1] {
			return false
		}
	}
	return true
}

func validRuntimeEvent(value RuntimeEvent, now time.Time) bool {
	when, err := time.Parse(timestampLayout, value.EventTime)
	if err != nil || when.Format(timestampLayout) != value.EventTime || when.Before(now.Add(-24*time.Hour)) || when.After(now.Add(5*time.Minute)) || !strings.HasPrefix(value.EventID, "tetragon:") || len(value.EventID) != 73 || len(value.WorkloadID) != 68 || !strings.HasPrefix(value.WorkloadID, "k8s:") {
		return false
	}
	if _, err := domain.ParseProductID(value.EvidenceID); err != nil {
		return false
	}
	allowed := map[string]map[string]bool{"process": {"exec": true, "exit": true}, "file": {"read": true, "write": true}, "network": {"connect": true, "accept": true}}
	if !allowed[value.Class][value.Action] || len(value.Content) == 0 || len(value.Content) > 8 {
		return false
	}
	for key, item := range value.Content {
		if !capabilityTokenPattern.MatchString(key) || !boundedText(item, 256) {
			return false
		}
	}
	return true
}

func safeDo(do func(*http.Request) (*http.Response, error), request *http.Request) (response *http.Response, err error) {
	defer func() {
		if recover() != nil {
			response = nil
			err = ErrClientRetryable
		}
	}()
	return do(request)
}

func safeToken(token func() ([]byte, error)) (value []byte, err error) {
	defer func() {
		if recover() != nil {
			clear(value)
			value = nil
			err = ErrClientDenied
		}
	}()
	return token()
}

func safeNow(now func() time.Time) (value time.Time, err error) {
	defer func() {
		if recover() != nil {
			value = time.Time{}
			err = ErrClientRetryable
		}
	}()
	value = now()
	if value.IsZero() {
		return time.Time{}, ErrClientRetryable
	}
	return value.UTC(), nil
}

func uniqueJSON(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if !consumeUniqueJSON(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func consumeUniqueJSON(decoder *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			token, err := decoder.Token()
			key, keyOK := token.(string)
			if err != nil || !keyOK || len(key) > 128 {
				return false
			}
			if _, exists := seen[key]; exists {
				return false
			}
			seen[key] = struct{}{}
			if !consumeUniqueJSON(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		count := 0
		for decoder.More() {
			count++
			if count > 2048 || !consumeUniqueJSON(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}
