// Package openbaoclient handles authenticated requests to one TLS-verified OpenBao origin.
package openbaoclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimesecret"
)

var (
	ErrVersionConflict = errors.New("OpenBao check-and-set version conflict")
	ErrNotFound        = errors.New("OpenBao object was not found")
	ErrUnavailable     = errors.New("OpenBao request failed")
	tokenPattern       = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	pathPattern        = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)
)

type Config struct {
	Address   string
	TokenFile string
	CAFile    string
}

func FromEnvironment(getenv func(string) string) Config {
	return Config{Address: getenv("ZASP_OPENBAO_ADDR"), TokenFile: getenv("ZASP_OPENBAO_TOKEN_FILE"), CAFile: getenv("ZASP_OPENBAO_CA_FILE")}
}

func absolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func (c Config) Valid() bool {
	u, err := url.Parse(c.Address)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.EscapedPath() == "" &&
		!strings.ContainsAny(c.Address, "?#") && absolutePath(c.TokenFile) && (c.CAFile == "" || absolutePath(c.CAFile))
}

type Client struct {
	config Config
	http   *http.Client
}

func readToken(name string) ([]byte, error) {
	b, err := runtimesecret.ReadPrivateFile(name, 16385)
	if err != nil {
		return nil, ErrUnavailable
	}
	token := bytes.TrimSuffix(b, []byte("\n"))
	if len(token) < 8 || len(token) > 16384 || !tokenPattern.Match(token) {
		clear(b)
		return nil, ErrUnavailable
	}
	return token, nil
}

func New(c Config, timeout time.Duration) (*Client, error) {
	if !c.Valid() || timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("OpenBao requires a verified HTTPS origin, absolute credential file paths and a bounded timeout")
	}
	token, err := readToken(c.TokenFile)
	if err != nil {
		return nil, errors.New("OpenBao token file must be a readable private regular file containing a token")
	}
	clear(token)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		s, err := runtimesecret.ReadTrustFile(c.CAFile, 1<<20)
		roots := x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(s) {
			return nil, errors.New("invalid OpenBao CA bundle")
		}
		tlsConfig.RootCAs = roots
	}
	tr := &http.Transport{TLSClientConfig: tlsConfig, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 1 << 16, IdleConnTimeout: 30 * time.Second}
	return &Client{config: c, http: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

func ValidPath(path string) bool {
	if len(path) > 1024 {
		return false
	}
	for _, component := range strings.Split(path, "/") {
		if !pathPattern.MatchString(component) || strings.HasSuffix(component, ".") {
			return false
		}
	}
	return true
}

// Do uses the supplied response's full API envelope. It deliberately drops raw
// errors and provider response bodies, which may contain credential material.
func (c *Client) Do(ctx context.Context, method, path string, input, output any) error {
	if ctx == nil || c == nil || !ValidPath(path) {
		return ErrUnavailable
	}
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil || len(body) > 128<<10 {
			return ErrUnavailable
		}
		defer clear(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.config.Address+"/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	token, err := readToken(c.config.TokenFile)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", string(token))
	clear(token)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode == http.StatusBadRequest {
		var reply struct{ Errors []string }
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
		defer clear(data)
		if err == nil && len(data) <= 4096 && json.Unmarshal(data, &reply) == nil && len(reply.Errors) == 1 && reply.Errors[0] == "check-and-set parameter did not match the current version" {
			return ErrVersionConflict
		}
		return ErrUnavailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrUnavailable
	}
	const limit = 1 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	defer clear(data)
	if err != nil || len(data) > limit {
		return ErrUnavailable
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		return ErrUnavailable
	}
	return nil
}
