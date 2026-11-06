package sensoradapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// CoverageHTTPReader permits only configured read-only Kubernetes resources.
// Its token callback is the caller's existing explicit credential authority.
type CoverageHTTPReader struct {
	origin    *url.URL
	client    *http.Client
	token     func(context.Context) ([]byte, error)
	selection NodeCoverageSelection
	transport *http.Transport
}

func NewCoverageHTTPReader(endpoint string, ca []byte, token func(context.Context) ([]byte, error), s NodeCoverageSelection) (*CoverageHTTPReader, error) {
	u, e := url.Parse(endpoint)
	pool := x509.NewCertPool()
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(ca) < 1 || len(ca) > 1<<20 || !pool.AppendCertsFromPEM(ca) || token == nil || s.Validate() != nil {
		return nil, ErrNodeCoverage
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true, MaxIdleConnsPerHost: 2}
	return &CoverageHTTPReader{origin: u, client: &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrNodeCoverage }}, token: token, selection: s, transport: tr}, nil
}
func (r *CoverageHTTPReader) Close() {
	if r != nil && r.transport != nil {
		r.transport.CloseIdleConnections()
	}
}
func (r *CoverageHTTPReader) get(ctx context.Context, path string, q url.Values, out any) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return ErrNodeCoverage
	}
	u := *r.origin
	u.Path = path
	u.RawQuery = q.Encode()
	token, e := r.token(ctx)
	if e != nil || len(token) < 16 || len(token) > 16384 {
		return ErrNodeCoverage
	}
	defer clear(token)
	request, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return ErrNodeCoverage
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Accept", "application/json")
	response, e := r.client.Do(request)
	request.Header.Del("Authorization")
	if e != nil || response == nil {
		return ErrNodeCoverage
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return ErrNodeCoverage
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 8<<20+1))
	defer clear(b)
	if e != nil || len(b) > 8<<20 || json.Unmarshal(b, out) != nil {
		return ErrNodeCoverage
	}
	return nil
}
func (r *CoverageHTTPReader) ClusterUID(ctx context.Context) (string, error) {
	var v struct {
		Metadata CoverageMeta `json:"metadata"`
		Status   struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	e := r.get(ctx, "/api/v1/namespaces/kube-system", nil, &v)
	if e != nil || v.Metadata.Name != "kube-system" || v.Metadata.DeletionTimestamp != nil || v.Status.Phase != "Active" || !validCoverageUUID(v.Metadata.UID) {
		return "", ErrNodeCoverage
	}
	return v.Metadata.UID, nil
}
func (r *CoverageHTTPReader) DaemonSet(ctx context.Context, t CoverageTarget) (CoverageDaemonSet, error) {
	var v CoverageDaemonSet
	if t != r.selection.Sensor && t != r.selection.Tetragon {
		return v, ErrNodeCoverage
	}
	e := r.get(ctx, "/apis/apps/v1/namespaces/"+t.Namespace+"/daemonsets/"+t.Name, nil, &v)
	return v, e
}
func (r *CoverageHTTPReader) Nodes(ctx context.Context, selector string) ([]CoverageNode, error) {
	if selector != CoverageSelector(r.selection.MatchLabels) {
		return nil, ErrNodeCoverage
	}
	var out []CoverageNode
	var next string
	seen := map[string]bool{}
	version := ""
	for page := 0; page < 6; page++ {
		var v struct {
			Metadata struct {
				Continue        string `json:"continue"`
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
			Items []CoverageNode `json:"items"`
		}
		q := url.Values{"labelSelector": {selector}, "limit": {"200"}}
		if next != "" {
			q.Set("continue", next)
		}
		if r.get(ctx, "/api/v1/nodes", q, &v) != nil {
			return nil, ErrNodeCoverage
		}
		if page == 0 {
			version = v.Metadata.ResourceVersion
		} else if version == "" || v.Metadata.ResourceVersion != version {
			return nil, ErrNodeCoverage
		}
		out = append(out, v.Items...)
		if len(out) > 1000 {
			return nil, ErrNodeCoverage
		}
		next = v.Metadata.Continue
		if next == "" {
			return out, nil
		}
		if len(next) > 4096 || seen[next] {
			return nil, ErrNodeCoverage
		}
		seen[next] = true
	}
	return nil, ErrNodeCoverage
}
func (r *CoverageHTTPReader) Pods(ctx context.Context, namespace, selector string) ([]CoveragePod, error) {
	if namespace != r.selection.Sensor.Namespace && namespace != r.selection.Tetragon.Namespace {
		return nil, ErrNodeCoverage
	}
	var out []CoveragePod
	next := ""
	seen := map[string]bool{}
	version := ""
	for page := 0; page < 11; page++ {
		var v struct {
			Metadata struct {
				Continue        string `json:"continue"`
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
			Items []CoveragePod `json:"items"`
		}
		q := url.Values{"labelSelector": {selector}, "limit": {"200"}}
		if next != "" {
			q.Set("continue", next)
		}
		if r.get(ctx, "/api/v1/namespaces/"+namespace+"/pods", q, &v) != nil {
			return nil, ErrNodeCoverage
		}
		if page == 0 {
			version = v.Metadata.ResourceVersion
		} else if version == "" || v.Metadata.ResourceVersion != version {
			return nil, ErrNodeCoverage
		}
		out = append(out, v.Items...)
		if len(out) > 2000 {
			return nil, ErrNodeCoverage
		}
		next = v.Metadata.Continue
		if next == "" {
			return out, nil
		}
		if len(next) > 4096 || seen[next] {
			return nil, ErrNodeCoverage
		}
		seen[next] = true
	}
	return nil, ErrNodeCoverage
}
func (r *CoverageHTTPReader) Reports(ctx context.Context, namespace, selector string) ([]CoverageLease, error) {
	if namespace != r.selection.Sensor.Namespace || selector != CoverageReportSelector(r.selection.EnrollmentBinding) {
		return nil, ErrNodeCoverage
	}
	var out []CoverageLease
	next := ""
	seen := map[string]bool{}
	version := ""
	for page := 0; page < 11; page++ {
		var v struct {
			Metadata struct {
				Continue        string `json:"continue"`
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
			Items []CoverageLease `json:"items"`
		}
		q := url.Values{"labelSelector": {selector}, "limit": {"200"}}
		if next != "" {
			q.Set("continue", next)
		}
		if r.get(ctx, "/apis/coordination.k8s.io/v1/namespaces/"+namespace+"/leases", q, &v) != nil {
			return nil, ErrNodeCoverage
		}
		if page == 0 {
			version = v.Metadata.ResourceVersion
		} else if version == "" || v.Metadata.ResourceVersion != version {
			return nil, ErrNodeCoverage
		}
		out = append(out, v.Items...)
		if len(out) > 2000 {
			return nil, ErrNodeCoverage
		}
		next = v.Metadata.Continue
		if next == "" {
			return out, nil
		}
		if len(next) > 4096 || seen[next] {
			return nil, ErrNodeCoverage
		}
		seen[next] = true
	}
	return nil, ErrNodeCoverage
}
