package sandboxcutover

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

type ObservationConfig struct {
	Binding                                             ReleaseBinding
	ExpectedJSON, CAPEM, BearerToken                    string
	ReleaseDirectory, NodeExecutable, KubectlExecutable string
}

// Configuration consistency and resolved paths are not artifact provenance.
type ObservationClient struct {
	config   ObservationConfig
	entry    string
	expected []observationExpected
	lifetime context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	active   sync.WaitGroup
	previous map[Observation]string
}

type observationExpected struct {
	Name           string            `json:"name"`
	TemplateDigest string            `json:"templateDigest"`
	ImageIDs       map[string]string `json:"imageIDs"`
}
type observationPod struct {
	UID      string            `json:"uid"`
	Name     string            `json:"name"`
	ImageIDs map[string]string `json:"imageIDs"`
}
type observationDeployment struct {
	Name               string           `json:"name"`
	UID                string           `json:"uid"`
	Generation         int64            `json:"generation"`
	ObservedGeneration int64            `json:"observedGeneration"`
	TemplateDigest     string           `json:"templateDigest"`
	ReplicaSetUID      string           `json:"replicaSetUID"`
	Pods               []observationPod `json:"pods"`
}
type observationSnapshot struct {
	Context      string                  `json:"context"`
	Namespace    string                  `json:"namespace"`
	NamespaceUID string                  `json:"namespaceUID"`
	ObservedAt   int64                   `json:"observedAt"`
	Deployments  []observationDeployment `json:"deployments"`
}
type observationEnvelope struct {
	Schema             string              `json:"schema"`
	Observation        observationSnapshot `json:"observation"`
	APIResourceVersion string              `json:"apiResourceVersion"`
}

var observationNames = []string{"agentsec-api", "agentsec-event-ingest", "agentsec-gateway-control", "agentsec-runtime-archive", "agentsec-runtime-complete", "agentsec-runtime-coordinator", "agentsec-runtime-correlation", "agentsec-runtime-index", "agentsec-runtime-outbox", "agentsec-runtime-projection", "agentsec-runtime-session-index-v2"}

const observationSchema = "sandbox-query-observation-v1"
const observationContext = "sandbox-cutover"
const observationMaximumBytes = 4 << 20
const observationCacheLimit = 8

func NewObservation(config ObservationConfig) (*ObservationClient, error) {
	if !validRelease(config.Binding) || !kubeName(config.Binding.Namespace) || !observationIdentity(config.Binding.NamespaceUID) || !text(config.BearerToken) || strings.IndexFunc(config.BearerToken, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return nil, errRejected
	}
	u, err := url.Parse(config.Binding.KubernetesServer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != config.Binding.KubernetesServer {
		return nil, errRejected
	}
	block, rest := pem.Decode([]byte(config.CAPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || hashKubeBytes(block.Bytes) != config.Binding.KubernetesCADigest {
		return nil, errRejected
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, errRejected
	}
	if len(config.ExpectedJSON) == 0 || len(config.ExpectedJSON) > 1<<20 {
		return nil, errRejected
	}
	var wrapped struct {
		Expected []observationExpected `json:"expected"`
	}
	if strictObservationJSON([]byte(`{"expected":`+config.ExpectedJSON+`}`), &wrapped) != nil || len(wrapped.Expected) != len(observationNames) {
		return nil, errRejected
	}
	sort.Slice(wrapped.Expected, func(i, j int) bool { return wrapped.Expected[i].Name < wrapped.Expected[j].Name })
	for i, want := range wrapped.Expected {
		if want.Name != observationNames[i] || !digest(want.TemplateDigest) || len(want.ImageIDs) == 0 || len(want.ImageIDs) > 64 {
			return nil, errRejected
		}
		if want.Name == "agentsec-api" && want.TemplateDigest != config.Binding.From.APITemplateDigest {
			return nil, errRejected
		}
		for name, image := range want.ImageIDs {
			at := strings.LastIndex(image, "@sha256:")
			if !kubeName(name) || at < 1 || !digest(image[at+8:]) || strings.IndexFunc(image, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 {
				return nil, errRejected
			}
		}
	}
	config.NodeExecutable, err = observationFile(config.NodeExecutable, true)
	if err != nil {
		return nil, errRejected
	}
	config.KubectlExecutable, err = observationFile(config.KubectlExecutable, true)
	if err != nil {
		return nil, errRejected
	}
	if !filepath.IsAbs(config.ReleaseDirectory) {
		return nil, errRejected
	}
	config.ReleaseDirectory, err = filepath.EvalSymlinks(config.ReleaseDirectory)
	if err != nil {
		return nil, errRejected
	}
	entry, err := observationFile(filepath.Join(config.ReleaseDirectory, "deploy", "production", "sandbox-query-observation.mjs"), false)
	if err != nil {
		return nil, errRejected
	}
	relative, err := filepath.Rel(config.ReleaseDirectory, entry)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errRejected
	}
	encoded, _ := json.Marshal(wrapped.Expected)
	config.ExpectedJSON = string(encoded)
	lifetime, cancel := context.WithCancel(context.Background())
	return &ObservationClient{config: config, entry: entry, expected: wrapped.Expected, lifetime: lifetime, cancel: cancel, previous: map[Observation]string{}}, nil
}

func (c *ObservationClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	c.previous = map[Observation]string{}
	c.mu.Unlock()
	c.active.Wait()
	return nil
}
func (c *ObservationClient) begin(ctx context.Context, binding ReleaseBinding) (context.Context, func(), error) {
	if c == nil || c.lifetime == nil || c.cancel == nil || ctx == nil || ctx.Err() != nil || binding != c.config.Binding {
		return nil, nil, errRejected
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, nil, errRejected
	}
	c.active.Add(1)
	c.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, evidenceLifetime)
	stop := context.AfterFunc(c.lifetime, cancel)
	return bounded, func() { stop(); cancel(); c.active.Done() }, nil
}

func (c *ObservationClient) ObserveBackfill(ctx context.Context, binding ReleaseBinding) (Observation, error) {
	return c.observe(ctx, binding, nil, false)
}
func (c *ObservationClient) ObserveQuery(ctx context.Context, binding ReleaseBinding) (Observation, error) {
	return c.observe(ctx, binding, nil, true)
}
func (c *ObservationClient) RevalidateBackfill(ctx context.Context, binding ReleaseBinding, previous Observation) (Observation, error) {
	return c.observe(ctx, binding, &previous, false)
}

func (c *ObservationClient) observe(ctx context.Context, binding ReleaseBinding, previous *Observation, query bool) (result Observation, err error) {
	ctx, done, err := c.begin(ctx, binding)
	if err != nil {
		return Observation{}, errRejected
	}
	defer done()
	started := time.Now()
	expected, operation := c.expected, "observe"
	prior := ""
	if query {
		// Constructor-owned entries and image maps are immutable. Copy the
		// entry slice before changing exactly the API template digest.
		expected = append([]observationExpected(nil), c.expected...)
		for i := range expected {
			if expected[i].Name == "agentsec-api" {
				expected[i].TemplateDigest = c.config.Binding.To.APITemplateDigest
			}
		}
		operation = "observe-query"
	} else {
		c.mu.Lock()
		for key := range c.previous {
			if !fresh(key.ObservedAt, started) {
				delete(c.previous, key)
			}
		}
		if previous != nil {
			prior = c.previous[*previous]
		}
		full := len(c.previous) >= observationCacheLimit
		c.mu.Unlock()
		if full || (previous != nil && prior == "") {
			return Observation{}, errRejected
		}
	}
	directory, err := os.MkdirTemp("", "zasp-cutover-observation-")
	if err != nil {
		return Observation{}, errRejected
	}
	var requestFile *os.File
	cleanup := func() error {
		var closeErr, removeErr error
		if requestFile != nil {
			closeErr = requestFile.Close()
			requestFile = nil
		}
		if directory != "" {
			removeErr = os.RemoveAll(directory)
			directory = ""
		}
		return errors.Join(closeErr, removeErr)
	}
	defer func() {
		if cleanup() != nil {
			result = Observation{}
			err = errRejected
		}
	}()
	bin := filepath.Join(directory, "bin")
	if os.Mkdir(bin, 0700) != nil || os.Symlink(c.config.KubectlExecutable, filepath.Join(bin, "kubectl")) != nil {
		return Observation{}, errRejected
	}
	kubeconfig := filepath.Join(directory, "kubeconfig.json")
	configuration := map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": observationContext, "clusters": []any{map[string]any{"name": "pinned", "cluster": map[string]any{"server": binding.KubernetesServer, "certificate-authority-data": []byte(c.config.CAPEM)}}}, "users": []any{map[string]any{"name": "pinned", "user": map[string]any{"token": c.config.BearerToken}}}, "contexts": []any{map[string]any{"name": observationContext, "context": map[string]any{"cluster": "pinned", "user": "pinned", "namespace": binding.Namespace}}}}
	configBody, _ := json.Marshal(configuration)
	if os.WriteFile(kubeconfig, configBody, 0600) != nil {
		return Observation{}, errRejected
	}
	deadline, _ := ctx.Deadline()
	request := map[string]any{"schema": observationSchema, "operation": operation, "options": map[string]any{"kubeconfig": kubeconfig, "context": observationContext, "namespace": binding.Namespace, "namespaceUID": binding.NamespaceUID, "expected": expected, "deadlineUnixMs": deadline.UnixMilli()}}
	if previous != nil {
		request["operation"] = "revalidate"
		request["previous"] = json.RawMessage(prior)
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > observationMaximumBytes || ctx.Err() != nil {
		return Observation{}, errRejected
	}
	command := exec.Command(c.config.NodeExecutable, c.entry)
	command.Dir = c.config.ReleaseDirectory
	command.Env = []string{"PATH=" + bin, "HOME=" + directory, "XDG_CACHE_HOME=" + filepath.Join(directory, "cache"), "LANG=C", "LC_ALL=C", "TZ=UTC"}
	requestPath := filepath.Join(directory, "request.json")
	if os.WriteFile(requestPath, body, 0600) != nil {
		return Observation{}, errRejected
	}
	requestFile, err = os.Open(requestPath)
	if err != nil {
		return Observation{}, errRejected
	}
	command.Stdin = requestFile
	output, err := runObservationProcess(ctx, command)
	if err != nil {
		return Observation{}, errRejected
	}
	if query {
		result, err = c.decodeExpected(output, started, expected)
	} else {
		result, err = c.decode(output, started)
	}
	if err != nil || ctx.Err() != nil {
		return Observation{}, errRejected
	}
	if previous != nil && (result.API != previous.API || result.IdentityDigest != previous.IdentityDigest || !fresh(previous.ObservedAt, time.Now())) {
		return Observation{}, errRejected
	}
	if query {
		return c.publishResult(ctx, result, output, previous, cleanup, false)
	}
	return c.publish(ctx, result, output, previous, cleanup)
}

// The callback is the fixed owned file/directory cleanup above, never caller
// configuration. Keeping publication at this boundary makes cleanup failures
// independent of transport success and permits deterministic lifecycle tests.
func (c *ObservationClient) publish(ctx context.Context, result Observation, output []byte, previous *Observation, cleanup func() error) (Observation, error) {
	return c.publishResult(ctx, result, output, previous, cleanup, true)
}

func (c *ObservationClient) publishResult(ctx context.Context, result Observation, output []byte, previous *Observation, cleanup func() error, cache bool) (Observation, error) {
	if cleanup() != nil {
		return Observation{}, errRejected
	}
	// Cleanup may consume the remaining request budget. It must finish before
	// the final clock/context check and before retaining evidence.
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.closed || ctx.Err() != nil || !fresh(result.ObservedAt, now) || previous != nil && !fresh(previous.ObservedAt, now) || cache && len(c.previous) >= observationCacheLimit {
		return Observation{}, errRejected
	}
	if cache {
		c.previous[result] = string(output)
	}
	return result, nil
}

func (c *ObservationClient) decode(body []byte, started time.Time) (Observation, error) {
	return c.decodeExpected(body, started, c.expected)
}

func (c *ObservationClient) decodeExpected(body []byte, started time.Time, expected []observationExpected) (Observation, error) {
	var envelope observationEnvelope
	if strictObservationJSON(body, &envelope) != nil || envelope.Schema != observationSchema || !observationVersion(envelope.APIResourceVersion) {
		return Observation{}, errRejected
	}
	snapshot := envelope.Observation
	if snapshot.Context != observationContext || snapshot.Namespace != c.config.Binding.Namespace || snapshot.NamespaceUID != c.config.Binding.NamespaceUID || snapshot.ObservedAt < started.UnixMilli() || len(snapshot.Deployments) != len(expected) {
		return Observation{}, errRejected
	}
	observed := time.UnixMilli(snapshot.ObservedAt).UTC()
	if !fresh(observed, time.Now()) {
		return Observation{}, errRejected
	}
	var api APIIdentity
	seen := map[string]bool{}
	for i, row := range snapshot.Deployments {
		want := expected[i]
		if row.Name != want.Name || !observationIdentity(row.UID) || seen[row.UID] || row.Generation < 1 || row.Generation > 9007199254740991 || row.ObservedGeneration != row.Generation || row.TemplateDigest != want.TemplateDigest || !observationIdentity(row.ReplicaSetUID) || len(row.Pods) == 0 {
			return Observation{}, errRejected
		}
		seen[row.UID] = true
		pods := map[string]bool{}
		for _, pod := range row.Pods {
			if !observationIdentity(pod.UID) || !observationIdentity(pod.Name) || pods[pod.UID] || !reflect.DeepEqual(pod.ImageIDs, want.ImageIDs) {
				return Observation{}, errRejected
			}
			pods[pod.UID] = true
		}
		if row.Name == "agentsec-api" {
			api = APIIdentity{UID: row.UID, ResourceVersion: envelope.APIResourceVersion, TemplateDigest: row.TemplateDigest}
		}
	}
	snapshot.ObservedAt = 0
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		return Observation{}, errRejected
	}
	return Observation{ObservedAt: observed, IdentityDigest: hashKubeBytes(canonical), API: api}, nil
}

func strictObservationJSON(body []byte, target any) error {
	original, err := kubeObject(body)
	if err != nil {
		return errRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errRejected
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errRejected
	}
	// DisallowUnknownFields still accepts case-insensitive struct aliases.
	// These complete wire shapes have no optional fields: a structural round
	// trip must preserve every exact key and value. Map keys remain opaque,
	// while aliases, alias overwrites and omitted struct fields cannot survive.
	encoded, err := json.Marshal(target)
	if err != nil {
		return errRejected
	}
	canonical, err := kubeObject(encoded)
	if err != nil || !reflect.DeepEqual(original, canonical) {
		return errRejected
	}
	return nil
}
func observationFile(path string, executable bool) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errRejected
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", errRejected
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || executable && info.Mode().Perm()&0111 == 0 {
		return "", errRejected
	}
	return resolved, nil
}
func observationIdentity(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for i, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if i > 0 && strings.ContainsRune("_.:/-", r) {
			continue
		}
		return false
	}
	return true
}
func observationVersion(value string) bool {
	return len(value) > 0 && len(value) <= 256 && strings.IndexFunc(value, func(r rune) bool { return r <= 32 || r == 127 }) < 0
}
