package preflight

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

type erasingBody struct {
	*bytes.Reader
	bytes []byte
}

func (b *erasingBody) Close() error { clear(b.bytes); return nil }

type boundedTransport struct{ base *http.Transport }

func (t boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, e := t.base.RoundTrip(req)
	if e != nil {
		return nil, ErrRejected
	}
	if response == nil || response.Body == nil {
		return nil, ErrRejected
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	ce := response.Body.Close()
	if e != nil || ce != nil || len(body) > 65536 {
		clear(body)
		return nil, ErrRejected
	}
	response.Body = &erasingBody{Reader: bytes.NewReader(body), bytes: body}
	return response, nil
}

// NewRunner creates only official SDK clients over the inherited proxy and system
// CA trust. Config cannot select an alternate provider endpoint or client.
func NewRunner(config Config) (*Runner, error) {
	if !validConfig(config) {
		return nil, ErrRejected
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384, MaxIdleConns: 8, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: true}
	return &Runner{config: config, http: &http.Client{Transport: boundedTransport{tr}, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRejected }}}, nil
}
func (r *Runner) Close() {
	if r == nil || r.http == nil {
		return
	}
	if tr, ok := r.http.Transport.(boundedTransport); ok {
		tr.base.CloseIdleConnections()
	}
}
