package sandboxcutover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// KubernetesConfig contains already verified, immutable configuration. This
// constructor checks consistency and transport pins; it does NOT authenticate
// release provenance. A trusted loader/verifier is still required for live use.
// Templates use sorted-key compact JSON, matching the release template digest.
type KubernetesConfig struct {
	Binding                                              ReleaseBinding
	FromTemplateJSON, ToTemplateJSON, CAPEM, BearerToken string
}

type KubernetesClient struct {
	config    KubernetesConfig
	from, to  map[string]any
	client    *http.Client
	transport *http.Transport
	lifetime  context.Context
	cancel    context.CancelFunc
}

const kubeMaximumBody = 4 << 20
const auditPrefix = "zasp.io/cutover-"

func NewKubernetes(c KubernetesConfig) (*KubernetesClient, error) {
	if !validRelease(c.Binding) || !kubeName(c.Binding.Namespace) || !text(c.BearerToken) || strings.IndexFunc(c.BearerToken, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return nil, errRejected
	}
	u, err := url.Parse(c.Binding.KubernetesServer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != c.Binding.KubernetesServer {
		return nil, errRejected
	}
	block, rest := pem.Decode([]byte(c.CAPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errRejected
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || hashKubeBytes(block.Bytes) != c.Binding.KubernetesCADigest {
		return nil, errRejected
	}
	from, err := kubeObject([]byte(c.FromTemplateJSON))
	if err != nil {
		return nil, errRejected
	}
	to, err := kubeObject([]byte(c.ToTemplateJSON))
	if err != nil {
		return nil, errRejected
	}
	for _, entry := range []struct {
		body   string
		value  map[string]any
		digest string
	}{{c.FromTemplateJSON, from, c.Binding.From.APITemplateDigest}, {c.ToTemplateJSON, to, c.Binding.To.APITemplateDigest}} {
		encoded, e := marshalKube(entry.value)
		if e != nil || string(encoded) != entry.body || hashKubeBytes(encoded) != entry.digest {
			return nil, errRejected
		}
	}
	// Independently restrict the reviewed template delta to the one API selector.
	copyFrom, _ := kubeObject([]byte(c.FromTemplateJSON))
	spec, ok := copyFrom["spec"].(map[string]any)
	if !ok {
		return nil, errRejected
	}
	containers, ok := spec["containers"].([]any)
	if !ok || len(containers) != 1 {
		return nil, errRejected
	}
	container, ok := containers[0].(map[string]any)
	if !ok {
		return nil, errRejected
	}
	envs, ok := container["env"].([]any)
	if !ok {
		return nil, errRejected
	}
	selections := 0
	for _, raw := range envs {
		env, ok := raw.(map[string]any)
		if !ok {
			return nil, errRejected
		}
		if env["name"] == "ZASP_RUNTIME_SESSION_INDEX" {
			if len(env) != 2 || env["value"] != "zasp-runtime-sessions-v1" {
				return nil, errRejected
			}
			env["value"] = "zasp-runtime-sessions-v2"
			selections++
		}
	}
	if selections != 1 || !reflect.DeepEqual(copyFrom, to) {
		return nil, errRejected
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableCompression: true, DisableKeepAlives: true}
	lifetime, cancel := context.WithCancel(context.Background())
	return &KubernetesClient{config: c, from: from, to: to, transport: transport, client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, lifetime: lifetime, cancel: cancel}, nil
}

// Close cancels active requests and closes the client's own transport. It is
// safe to repeat, and never changes global/default HTTP transports.
func (c *KubernetesClient) Close() {
	if c != nil {
		c.cancel()
		c.transport.CloseIdleConnections()
	}
}

func (c *KubernetesClient) DispatchQuery(ctx context.Context, b ReleaseBinding, old APIIdentity, a Audit) (AppliedState, error) {
	if !c.validCall(ctx, b, a) || old.UID != a.APIUID || old.ResourceVersion != a.SourceResourceVersion || old.TemplateDigest != b.From.APITemplateDigest {
		return AppliedState{}, ErrCASRefused
	}
	if c.namespace(ctx) != nil {
		return AppliedState{}, ErrCASRefused
	}
	deployment, err := c.deployment(ctx)
	if err != nil {
		return AppliedState{}, ErrCASRefused
	}
	meta := deployment["metadata"].(map[string]any)
	spec := deployment["spec"].(map[string]any)
	if meta["uid"] != old.UID || meta["resourceVersion"] != old.ResourceVersion || !reflect.DeepEqual(spec["template"], c.from) {
		return AppliedState{}, ErrCASRefused
	}
	// Namespace replacement is checked again immediately before the sole PATCH.
	// This is not a cross-object transaction or server-side namespace UID fence.
	if c.namespace(ctx) != nil {
		return AppliedState{}, ErrCASRefused
	}
	type operation struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}
	ops := []operation{{"test", "/metadata/uid", old.UID}, {"test", "/metadata/resourceVersion", old.ResourceVersion}, {"test", "/spec/template", c.from}, {"replace", "/spec/template", c.to}}
	annotations := auditAnnotations(a)
	if meta["annotations"] == nil {
		ops = append(ops, operation{"add", "/metadata/annotations", annotations})
	} else {
		keys := make([]string, 0, len(annotations))
		for key := range annotations {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			ops = append(ops, operation{"add", "/metadata/annotations/" + kubePointer(key), annotations[key]})
		}
	}
	body, err := marshalKube(ops)
	if err != nil || len(body) > kubeMaximumBody || ctx.Err() != nil {
		return AppliedState{}, ErrCASRefused
	}
	status, response, err := c.request(ctx, http.MethodPatch, c.deploymentPath(), body)
	if err != nil {
		return AppliedState{}, errRejected
	}
	if status == 409 || status == 422 {
		failure, e := kubeObject(response)
		if e == nil && failure["apiVersion"] == "v1" && failure["kind"] == "Status" && failure["status"] == "Failure" && failure["code"] == json.Number(strconv.Itoa(status)) && (failure["reason"] == "Conflict" || failure["reason"] == "Invalid") {
			return AppliedState{}, ErrCASRefused
		}
	}
	if status != 200 {
		return AppliedState{}, errRejected
	}
	return c.applied(response, a)
}

func (c *KubernetesClient) Reconcile(ctx context.Context, b ReleaseBinding, a Audit) (AppliedState, error) {
	if !c.validCall(ctx, b, a) || c.namespace(ctx) != nil {
		return AppliedState{}, errRejected
	}
	status, body, err := c.request(ctx, http.MethodGet, c.deploymentPath(), nil)
	if err != nil || status != 200 {
		return AppliedState{}, errRejected
	}
	return c.applied(body, a)
}

func (c *KubernetesClient) validCall(ctx context.Context, b ReleaseBinding, a Audit) bool {
	return c != nil && ctx != nil && ctx.Err() == nil && c.lifetime.Err() == nil && b == c.config.Binding && text(a.TransitionID) && a.ReleaseDigest == b.ArtifactDigest && digest(a.ReceiptSetDigest) && a.ReceiptCount >= 0 && a.ReceiptCount <= 10000 && !a.AuthorizedAt.IsZero() && a.DatabaseIdentity == b.DatabaseIdentity && a.ProviderIdentity == b.ProviderIdentity && text(a.APIUID) && text(a.SourceResourceVersion) && a.TargetTemplateDigest == b.To.APITemplateDigest
}
func (c *KubernetesClient) deploymentPath() string {
	return "/apis/apps/v1/namespaces/" + c.config.Binding.Namespace + "/deployments/agentsec-api"
}
func (c *KubernetesClient) namespace(ctx context.Context) error {
	status, body, err := c.request(ctx, http.MethodGet, "/api/v1/namespaces/"+c.config.Binding.Namespace, nil)
	if err != nil || status != 200 {
		return errRejected
	}
	object, err := kubeObject(body)
	if err != nil {
		return errRejected
	}
	meta, _ := object["metadata"].(map[string]any)
	if object["apiVersion"] != "v1" || object["kind"] != "Namespace" || meta["name"] != c.config.Binding.Namespace || meta["uid"] != c.config.Binding.NamespaceUID || meta["deletionTimestamp"] != nil {
		return errRejected
	}
	return nil
}
func (c *KubernetesClient) deployment(ctx context.Context) (map[string]any, error) {
	status, body, err := c.request(ctx, http.MethodGet, c.deploymentPath(), nil)
	if err != nil || status != 200 {
		return nil, errRejected
	}
	return c.validDeployment(body)
}
func (c *KubernetesClient) validDeployment(body []byte) (map[string]any, error) {
	object, err := kubeObject(body)
	if err != nil {
		return nil, errRejected
	}
	meta, _ := object["metadata"].(map[string]any)
	spec, _ := object["spec"].(map[string]any)
	uid, _ := meta["uid"].(string)
	rv, _ := meta["resourceVersion"].(string)
	template, _ := spec["template"].(map[string]any)
	if object["apiVersion"] != "apps/v1" || object["kind"] != "Deployment" || meta["name"] != "agentsec-api" || meta["namespace"] != c.config.Binding.Namespace || !text(uid) || !text(rv) || meta["deletionTimestamp"] != nil || template == nil {
		return nil, errRejected
	}
	if meta["annotations"] != nil {
		annotations, ok := meta["annotations"].(map[string]any)
		if !ok {
			return nil, errRejected
		}
		for _, v := range annotations {
			if _, ok := v.(string); !ok {
				return nil, errRejected
			}
		}
	}
	return object, nil
}
func (c *KubernetesClient) applied(body []byte, a Audit) (AppliedState, error) {
	d, err := c.validDeployment(body)
	if err != nil {
		return AppliedState{}, errRejected
	}
	meta := d["metadata"].(map[string]any)
	spec := d["spec"].(map[string]any)
	annotations, _ := meta["annotations"].(map[string]any)
	if meta["uid"] != a.APIUID || meta["resourceVersion"] == a.SourceResourceVersion || !reflect.DeepEqual(spec["template"], c.to) {
		return AppliedState{}, errRejected
	}
	for key, value := range auditAnnotations(a) {
		if annotations[key] != value {
			return AppliedState{}, errRejected
		}
	}
	return AppliedState{APIIdentity{a.APIUID, meta["resourceVersion"].(string), a.TargetTemplateDigest}, a}, nil
}
func auditAnnotations(a Audit) map[string]string {
	return map[string]string{auditPrefix + "transition-id": a.TransitionID, auditPrefix + "release-digest": a.ReleaseDigest, auditPrefix + "receipt-set-digest": a.ReceiptSetDigest, auditPrefix + "receipt-count": strconv.Itoa(a.ReceiptCount), auditPrefix + "authorized-at": a.AuthorizedAt.UTC().Format(time.RFC3339Nano), auditPrefix + "database-identity": a.DatabaseIdentity, auditPrefix + "provider-identity": a.ProviderIdentity, auditPrefix + "api-uid": a.APIUID, auditPrefix + "source-resource-version": a.SourceResourceVersion, auditPrefix + "target-template-digest": a.TargetTemplateDigest}
}
func (c *KubernetesClient) request(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if ctx == nil || ctx.Err() != nil || c.lifetime.Err() != nil {
		return 0, nil, errRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.lifetime, cancel)
	defer stop()
	request, err := http.NewRequestWithContext(ctx, method, c.config.Binding.KubernetesServer+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errRejected
	}
	request.GetBody = nil // no replayable PATCH body; never retry a mutation.
	request.Header.Set("Authorization", "Bearer "+c.config.BearerToken)
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPatch {
		request.Header.Set("Content-Type", "application/json-patch+json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return 0, nil, errRejected
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, kubeMaximumBody+1))
	if err != nil || len(data) > kubeMaximumBody || ctx.Err() != nil || c.lifetime.Err() != nil {
		return 0, nil, errRejected
	}
	if strings.Split(response.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return 0, nil, errRejected
	}
	return response.StatusCode, data, nil
}
func kubeName(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func hashKubeBytes(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func kubePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
func marshalKube(value any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	encoded := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	// JSON.stringify (the reviewed templateDigest producer) emits these two
	// valid JSON characters literally. encoding/json always escapes them. Walk
	// escapes rather than replacing substrings: a literal "\\u2028" must stay
	// literal and must never turn into a different annotation value.
	out := make([]byte, 0, len(encoded))
	for i := 0; i < len(encoded); {
		if encoded[i] == '\\' && i+1 < len(encoded) {
			if i+6 <= len(encoded) && (string(encoded[i:i+6]) == `\u2028` || string(encoded[i:i+6]) == `\u2029`) {
				if encoded[i+5] == '8' {
					out = append(out, []byte("\u2028")...)
				} else {
					out = append(out, []byte("\u2029")...)
				}
				i += 6
				continue
			}
			out = append(out, encoded[i], encoded[i+1])
			i += 2
			continue
		}
		out = append(out, encoded[i])
		i++
	}
	return out, nil
}

// Kubernetes objects may contain unknown metadata/status fields. Reject duplicate
// keys and malformed/oversized JSON without imposing a stale closed K8s schema.
func kubeObject(body []byte) (map[string]any, error) {
	if len(body) == 0 || len(body) > kubeMaximumBody || !utf8.Valid(body) {
		return nil, errRejected
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 64 {
			return nil, errRejected
		}
		token, err := d.Token()
		if err != nil {
			return nil, errRejected
		}
		switch v := token.(type) {
		case json.Delim:
			switch v {
			case '{':
				m := map[string]any{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return nil, errRejected
					}
					name, ok := key.(string)
					if !ok {
						return nil, errRejected
					}
					if _, exists := m[name]; exists {
						return nil, errRejected
					}
					value, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					m[name] = value
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, errRejected
				}
				return m, nil
			case '[':
				a := []any{}
				for d.More() {
					value, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, value)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, errRejected
				}
				return a, nil
			}
			return nil, errRejected
		default:
			return token, nil
		}
	}
	value, err := read(0)
	if err != nil {
		return nil, errRejected
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errRejected
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errRejected
	}
	return object, nil
}
