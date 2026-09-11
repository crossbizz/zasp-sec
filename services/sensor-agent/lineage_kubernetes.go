package main

import (
	"context"
	"mime"
	"net/http"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const maximumLineageIdentityResponse = 1 << 20

type lineageKubernetesAPI struct {
	nodeName   string
	nodes      typedcorev1.NodeInterface
	namespaces typedcorev1.NamespaceInterface
	transport  *lineageIdentityTransport
}

// The caller supplies trusted in-cluster TLS configuration, not user-selected
// endpoints. This client permits only the two required GET paths. That isn't
// server-side per-node RBAC: a shared DaemonSet identity needs Node GET permission
// across the cluster unless separate per-node identities are provisioned.
func newLineageKubernetesAPI(config *rest.Config, nodeName string) (*lineageKubernetesAPI, error) {
	if config == nil || !validKubernetesName(nodeName) || config.Insecure || config.Transport != nil || config.WrapTransport != nil || config.ExecProvider != nil || config.AuthProvider != nil || config.Username != "" || config.Password != "" {
		return nil, errLineageIdentity
	}
	origin, err := url.Parse(config.Host)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errLineageIdentity
	}
	bounded := rest.CopyConfig(config)
	bounded.Timeout = 5 * time.Second
	bounded.QPS, bounded.Burst = 5, 10
	bounded.UserAgent = "zasp-sensor-lineage/v1"
	bounded.ContentType, bounded.AcceptContentTypes = "application/json", "application/json"
	bounded.DisableCompression = true
	bounded.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	var transport *lineageIdentityTransport
	bounded.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
		// Own this client's sockets; don't mutate or close the shared client-go
		// transport cache used by the existing heartbeat/lease client.
		if standard, ok := base.(*http.Transport); ok {
			owned := standard.Clone()
			owned.MaxResponseHeaderBytes = 16 << 10
			owned.DisableCompression = true
			base = owned
		}
		transport = &lineageIdentityTransport{base: base, origin: origin.Host, nodePath: "/api/v1/nodes/" + nodeName}
		return transport
	}
	client, err := rest.HTTPClientFor(bounded)
	if err != nil || transport == nil {
		return nil, errLineageIdentity
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	core, err := typedcorev1.NewForConfigAndClient(bounded, client)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errLineageIdentity
	}
	return &lineageKubernetesAPI{nodeName: nodeName, nodes: core.Nodes(), namespaces: core.Namespaces(), transport: transport}, nil
}

func (api *lineageKubernetesAPI) GetNode(ctx context.Context) (*corev1.Node, error) {
	if api == nil || ctx == nil || ctx.Err() != nil {
		return nil, errLineageIdentity
	}
	value, err := api.nodes.Get(ctx, api.nodeName, metav1.GetOptions{})
	if err != nil || ctx.Err() != nil {
		return nil, errLineageIdentity
	}
	return value, nil
}

func (api *lineageKubernetesAPI) GetClusterNamespace(ctx context.Context) (*corev1.Namespace, error) {
	if api == nil || ctx == nil || ctx.Err() != nil {
		return nil, errLineageIdentity
	}
	value, err := api.namespaces.Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || ctx.Err() != nil {
		return nil, errLineageIdentity
	}
	return value, nil
}

func (api *lineageKubernetesAPI) Close() {
	if api != nil && api.transport != nil {
		api.transport.CloseIdleConnections()
	}
}

type lineageIdentityTransport struct {
	base             http.RoundTripper
	origin, nodePath string
}

func (transport *lineageIdentityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// client-go serializes its configured HTTP timeout into this exact query.
	if request == nil || request.URL == nil || request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host != transport.origin || request.Host != "" && request.Host != transport.origin || request.URL.User != nil || request.URL.RawQuery != "timeout=5s" || request.URL.ForceQuery || request.URL.Fragment != "" || request.URL.EscapedPath() != request.URL.Path || request.URL.Path != transport.nodePath && request.URL.Path != "/api/v1/namespaces/kube-system" {
		return nil, errLineageIdentity
	}
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, errLineageIdentity
	}
	if response == nil || response.Body == nil {
		return nil, errLineageIdentity
	}
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.ContentLength > maximumLineageIdentityResponse || response.Header.Get("Content-Encoding") != "" || mediaErr != nil || media != "application/json" {
		response.Body.Close()
		return nil, errLineageIdentity
	}
	response.Body = http.MaxBytesReader(nil, response.Body, maximumLineageIdentityResponse)
	return response, nil
}

func (transport *lineageIdentityTransport) CloseIdleConnections() {
	if closer, ok := transport.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
