package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

func TestLineageKubernetesActualTLSIdentityReads(t *testing.T) {
	reader, _ := fixtureBootReader(t)
	fixture := newLineageIdentityAPIFixture()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.RawQuery != "timeout=5s" || r.Header.Get("Authorization") != "Bearer synthetic-kubernetes-test-token" {
			t.Error("unexpected identity request")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/nodes/node-a":
			_ = json.NewEncoder(w).Encode(fixture.node)
		case "/api/v1/namespaces/kube-system":
			_ = json.NewEncoder(w).Encode(fixture.namespace)
		default:
			t.Error("unexpected Kubernetes path")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-kubernetes-test-token", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	api, err := newLineageKubernetesAPI(config, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	identity, err := resolveLineageIdentity(context.Background(), "node-a", api, reader)
	if err != nil || identity.BootID != fixtureHostBootID || calls.Load() != 4 {
		t.Fatal("actual verified TLS identity lookup", identity, err, calls.Load())
	}
	if config.Timeout != 0 || config.QPS != 0 || config.WrapTransport != nil {
		t.Fatal("identity client changed caller configuration")
	}
}

func TestLineageKubernetesRejectsUnsafeTransportAndResponses(t *testing.T) {
	for _, name := range []string{"oversized", "truncated", "redirect", "denied", "wrong content type", "compressed", "canceled"} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch name {
				case "oversized":
					_, _ = w.Write([]byte(`{"padding":"` + strings.Repeat("x", (1<<20)+1) + `"}`))
				case "truncated":
					_, _ = w.Write([]byte(`{"metadata":`))
				case "redirect":
					w.Header().Set("Location", "/api/v1/namespaces/kube-system")
					w.WriteHeader(302)
				case "denied":
					w.WriteHeader(403)
				case "wrong content type":
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte(`{}`))
				case "compressed":
					if r.Header.Get("Accept-Encoding") != "" {
						t.Error("identity client negotiated compression")
					}
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write([]byte(`{}`))
				case "canceled":
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			api, err := newLineageKubernetesAPI(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, "node-a")
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			timeout := 5 * time.Second
			if name == "canceled" {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if node, err := api.GetNode(ctx); err != errLineageIdentity || node != nil {
				t.Fatal("unsafe response accepted", err)
			}
			if name != "canceled" && ctx.Err() != nil {
				t.Fatal("timeout masked response validation", ctx.Err())
			}
			if calls.Load() != 1 {
				t.Fatal("unexpected retry or redirect", calls.Load())
			}
		})
	}
	credentialURL := &url.URL{Scheme: "https", Host: "cluster.test", User: url.UserPassword("fixture-user", "not-a-secret")}
	for _, config := range []*rest.Config{nil, {Host: "http://cluster.test"}, {Host: "https://cluster.test", TLSClientConfig: rest.TLSClientConfig{Insecure: true}}, {Host: "https://cluster.test/path"}, {Host: credentialURL.String()}} {
		if api, err := newLineageKubernetesAPI(config, "node-a"); err != errLineageIdentity || api != nil {
			t.Fatal("unsafe client configuration accepted", err)
		}
	}
}

type lineageRoundTripFunc func(*http.Request) (*http.Response, error)

func (call lineageRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return call(request)
}

func TestLineageKubernetesTransportCannotExpandReadScope(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"mutation":            func(r *http.Request) { r.Method = http.MethodPost },
		"node listing":        func(r *http.Request) { r.URL.Path = "/api/v1/nodes" },
		"foreign node":        func(r *http.Request) { r.URL.Path = "/api/v1/nodes/node-b" },
		"foreign namespace":   func(r *http.Request) { r.URL.Path = "/api/v1/namespaces/default" },
		"scope query":         func(r *http.Request) { r.URL.RawQuery += "&labelSelector=x" },
		"foreign origin":      func(r *http.Request) { r.URL.Host = "other.test" },
		"foreign host header": func(r *http.Request) { r.Host = "other.test" },
		"plaintext":           func(r *http.Request) { r.URL.Scheme = "http" },
	} {
		t.Run(name, func(t *testing.T) {
			transport := &lineageIdentityTransport{origin: "cluster.test", nodePath: "/api/v1/nodes/node-a", base: lineageRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("rejected request reached network transport")
				return nil, nil
			})}
			request, err := http.NewRequest(http.MethodGet, "https://cluster.test/api/v1/nodes/node-a?timeout=5s", nil)
			if err != nil {
				t.Fatal(err)
			}
			mutate(request)
			if response, err := transport.RoundTrip(request); err != errLineageIdentity || response != nil {
				t.Fatal("expanded API scope accepted", err)
			}
		})
	}
}
