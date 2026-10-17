package preflight

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Closed outcomes contain no provider body, credential or dependency error.
type awsKubernetesOutcomeError struct{ outcome string }

func (*awsKubernetesOutcomeError) Error() string { return "Kubernetes observation unavailable" }
func (*awsKubernetesOutcomeError) Unwrap() error { return ErrRejected }

type awsKubernetesIdentityReader struct {
	client    *http.Client
	transport *http.Transport
	endpoint  string
	token     func(context.Context) ([]byte, error)
	paths     map[string]bool
}

func newAWSKubernetesIdentityReader(endpoint string, ca []byte, token func(context.Context) ([]byte, error), c *AWSAuthorityConfig, inventory []awsRoleRequirement) (*awsKubernetesIdentityReader, error) {
	if c == nil || token == nil || endpoint != c.Cluster.Endpoint || len(ca) < 1 || len(ca) > 1<<20 {
		return nil, ErrRejected
	}
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrRejected
	}
	digest := sha256.Sum256(ca)
	if hex.EncodeToString(digest[:]) != c.Cluster.CASHA256 {
		return nil, ErrRejected
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrRejected
	}
	paths := map[string]bool{"/api/v1/namespaces/kube-system": true}
	for _, r := range inventory {
		parts := strings.Split(r.subject, ":")
		if r.trustClass != "irsa" || len(parts) != 4 {
			continue
		}
		if !dnsPattern.MatchString(parts[2]) || !dnsPattern.MatchString(parts[3]) {
			return nil, ErrRejected
		}
		paths["/api/v1/namespaces/"+parts[2]+"/serviceaccounts/"+parts[3]] = true
		if c.Selected != nil && c.Selected.Purpose == r.purpose {
			if !dnsPattern.MatchString(c.Selected.PodName) {
				return nil, ErrRejected
			}
			paths["/api/v1/namespaces/"+parts[2]+"/pods/"+c.Selected.PodName] = true
		}
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname()}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: true}
	return &awsKubernetesIdentityReader{endpoint: endpoint, transport: tr, client: &http.Client{Transport: tr, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRejected }}, token: token, paths: paths}, nil
}
func (r *awsKubernetesIdentityReader) Close() {
	if r != nil && r.transport != nil {
		r.transport.CloseIdleConnections()
	}
}
func (r *awsKubernetesIdentityReader) get(ctx context.Context, path string) ([]byte, error) {
	b, _, e := r.getObserved(ctx, path)
	return b, e
}
func (r *awsKubernetesIdentityReader) getObserved(ctx context.Context, path string) ([]byte, bool, error) {
	if r == nil || ctx == nil || !r.paths[path] {
		return nil, false, ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	token, e := r.token(child)
	if e != nil {
		clear(token)
		return nil, false, ErrRejected
	}
	defer clear(token)
	if !validCredentialValue(string(token), 16, 16384) {
		return nil, false, ErrRejected
	}
	req, e := http.NewRequestWithContext(child, http.MethodGet, r.endpoint+path, nil)
	if e != nil {
		return nil, false, ErrRejected
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/json")
	out, e := r.client.Do(req)
	if e != nil {
		return nil, true, ErrRejected
	}
	defer out.Body.Close()
	if out.StatusCode == 401 || out.StatusCode == 403 {
		return nil, true, &awsKubernetesOutcomeError{outcome: "denied"}
	}
	if out.StatusCode != 200 {
		return nil, true, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
	}
	if out.Header.Get("Content-Type") != "application/json" {
		return nil, true, &awsKubernetesOutcomeError{outcome: "malformed"}
	}
	b, e := io.ReadAll(io.LimitReader(out.Body, 1<<20+1))
	if e != nil || child.Err() != nil {
		clear(b)
		return nil, true, ErrRejected
	}
	if len(b) > 1<<20 || !uniqueProviderJSON(b) || !exactKubernetesAuthorityKeys(b, "") {
		clear(b)
		return nil, true, &awsKubernetesOutcomeError{outcome: "malformed"}
	}
	return b, true, nil
}

// Unknown extension keys (including null) may be present, but spelling aliases
// of known authority fields must never populate encoding/json's typed fields.
func exactKubernetesAuthorityKeys(raw []byte, path string) bool {
	if string(raw) == "null" {
		return true
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return false
	}
	known := map[string][]string{"": {"apiVersion", "kind", "metadata", "spec", "status"}, "metadata": {"name", "namespace", "uid", "annotations", "deletionTimestamp"}, "spec": {"serviceAccountName", "volumes"}, "status": {"phase"}, "volume": {"projected"}, "projected": {"sources"}, "source": {"serviceAccountToken"}, "serviceAccountToken": {"audience"}}
	for key, value := range obj {
		for _, name := range known[path] {
			if strings.EqualFold(key, name) && key != name {
				return false
			}
		}
		next := ""
		recurse := false
		if path == "" && (key == "metadata" || key == "spec" || key == "status") {
			next = key
			recurse = true
		}
		if path == "volume" && key == "projected" {
			next = "projected"
			recurse = true
		}
		if path == "source" && key == "serviceAccountToken" {
			next = "serviceAccountToken"
			recurse = true
		}
		if recurse && !exactKubernetesAuthorityKeys(value, next) {
			return false
		}
		if path == "spec" && key == "volumes" || path == "projected" && key == "sources" {
			var items []json.RawMessage
			if json.Unmarshal(value, &items) != nil {
				return false
			}
			itemPath := "volume"
			if path == "projected" {
				itemPath = "source"
			}
			for _, item := range items {
				if !exactKubernetesAuthorityKeys(item, itemPath) {
					return false
				}
			}
		}
	}
	return true
}

type kubernetesIdentityMetadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	Annotations       map[string]string `json:"annotations"`
	DeletionTimestamp *string           `json:"deletionTimestamp"`
}
type kubernetesIdentityObject struct {
	APIVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   kubernetesIdentityMetadata `json:"metadata"`
	Spec       struct {
		ServiceAccountName string `json:"serviceAccountName"`
		Volumes            []struct {
			Projected *struct {
				Sources []struct {
					ServiceAccountToken *struct {
						Audience string `json:"audience"`
					} `json:"serviceAccountToken"`
				} `json:"sources"`
			} `json:"projected"`
		} `json:"volumes"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

func (r *awsKubernetesIdentityReader) object(ctx context.Context, path, kind, ns, name string) (kubernetesIdentityObject, error) {
	var o kubernetesIdentityObject
	b, e := r.get(ctx, path)
	if e != nil {
		return o, e
	}
	defer clear(b)
	if json.Unmarshal(b, &o) != nil {
		return kubernetesIdentityObject{}, &awsKubernetesOutcomeError{outcome: "malformed"}
	}
	if o.APIVersion != "v1" || o.Kind != kind || o.Metadata.Name != name || o.Metadata.Namespace != ns || len(o.Metadata.UID) != 36 {
		return kubernetesIdentityObject{}, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
	}
	return o, nil
}
func (r *awsKubernetesIdentityReader) ClusterUID(ctx context.Context) (string, error) {
	o, e := r.object(ctx, "/api/v1/namespaces/kube-system", "Namespace", "", "kube-system")
	if e != nil {
		return "", e
	}
	if o.Metadata.DeletionTimestamp != nil {
		return "", &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
	}
	return o.Metadata.UID, nil
}
func (r *awsKubernetesIdentityReader) ServiceAccount(ctx context.Context, ns, name string) (KubernetesServiceAccountBinding, error) {
	o, e := r.object(ctx, "/api/v1/namespaces/"+ns+"/serviceaccounts/"+name, "ServiceAccount", ns, name)
	if e != nil {
		return KubernetesServiceAccountBinding{}, e
	}
	return KubernetesServiceAccountBinding{Namespace: ns, Name: name, UID: o.Metadata.UID, RoleARN: o.Metadata.Annotations["eks.amazonaws.com/role-arn"], Deleting: o.Metadata.DeletionTimestamp != nil}, nil
}
func (r *awsKubernetesIdentityReader) Pod(ctx context.Context, ns, name string) (KubernetesWorkloadBinding, error) {
	o, e := r.object(ctx, "/api/v1/namespaces/"+ns+"/pods/"+name, "Pod", ns, name)
	if e != nil {
		return KubernetesWorkloadBinding{}, e
	}
	audience := ""
	for _, v := range o.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, s := range v.Projected.Sources {
			if s.ServiceAccountToken != nil && s.ServiceAccountToken.Audience == "sts.amazonaws.com" {
				audience = "sts.amazonaws.com"
			}
		}
	}
	return KubernetesWorkloadBinding{Namespace: ns, Name: name, UID: o.Metadata.UID, ServiceAccount: o.Spec.ServiceAccountName, Phase: o.Status.Phase, ProjectedAudience: audience, Deleting: o.Metadata.DeletionTimestamp != nil}, nil
}
