// Package devicehttp sends signed, operation-specific requests to the private control plane.
package devicehttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"io"
	"net/http"
	"net/url"
	"time"
)

var ErrUnavailable = errors.New("device request unavailable")

func ValidOrigin(origin string) bool {
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery
}
func New() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func Send(ctx context.Context, client *http.Client, origin, op, method, path, token string, binding endpointprotocol.Binding, key ed25519.PrivateKey, now time.Time, input, output any) error {
	if !ValidOrigin(origin) {
		return ErrUnavailable
	}
	var raw []byte
	var err error
	if input != nil {
		raw, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, origin+"/api/v1"+path, bytes.NewReader(raw))
	if err != nil {
		return ErrUnavailable
	}
	r.Header.Set("Authorization", "Bearer "+token)
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if err = endpointprotocol.Sign(r.Header, binding, op, raw, key, now); err != nil {
		return err
	}
	res, err := client.Do(r)
	if err != nil {
		return ErrUnavailable
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, (16<<10)+1))
	if err != nil || len(body) > 16<<10 || res.StatusCode != http.StatusOK || !endpointprotocol.Strict(body, output) {
		return ErrUnavailable
	}
	return nil
}
