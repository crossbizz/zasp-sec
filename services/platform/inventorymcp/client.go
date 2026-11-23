// Package inventorymcp reads one operator-assigned inventory record from a
// private, stateless MCP endpoint. No caller can supply a URL, tool, or token.
package inventorymcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const Tool = "external_inventory_status"
const maxBody = 16 << 10

var activeReads = make(chan struct{}, 4)

var ErrUnavailable = errors.New("private inventory status unavailable")
var host = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var fieldName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
var tokenFormat = regexp.MustCompile(`^[A-Za-z0-9_.~-]+$`)

type Target struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
	Agent        string `json:"agent_id"`
}

func (t Target) valid() bool {
	for _, v := range []string{t.Organization, t.Workspace, t.Environment, t.Agent} {
		if _, err := domain.ParseProductID(v); err != nil {
			return false
		}
	}
	return true
}

type config struct {
	Target
	Endpoint  string `json:"endpoint"`
	PrivateIP string `json:"private_ip"`
	Pin       string `json:"tls_spki_sha256"`
	CA        string `json:"ca_pem"`
	PublicKey []byte `json:"receipt_public_key"`
	Token     string `json:"read_token"`
}
type readRequest struct {
	Target
	Nonce string `json:"nonce"`
}
type receipt struct {
	readRequest
	Status    string `json:"status"`
	Observed  int64  `json:"observed_at"`
	Signature []byte `json:"signature"`
}
type Client struct {
	target   Target
	key      ed25519.PublicKey
	endpoint string
	http     *http.Client
}

// All protocol records are flat. Accept canonical field names exactly once
// before binding values with the typed schema.
func decode(raw []byte, v any) bool {
	scan := json.NewDecoder(bytes.NewReader(raw))
	first, err := scan.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for scan.More() {
		key, err := scan.Token()
		name, ok := key.(string)
		var scalar any
		if err != nil || !ok || seen[name] || !fieldName.MatchString(name) {
			return false
		}
		seen[name] = true
		scalar, err = scan.Token()
		if _, nested := scalar.(json.Delim); err != nil || nested {
			return false
		}
	}
	last, err := scan.Token()
	if err != nil || last != json.Delim('}') {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v) == nil && d.Decode(new(any)) == io.EOF
}

func Load(path string) (*Client, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBody+1))
	var c config
	if err != nil || len(raw) > maxBody || !decode(raw, &c) {
		return nil, ErrUnavailable
	}
	return newClient(c)
}
func newClient(c config) (*Client, error) {
	u, err := url.Parse(c.Endpoint)
	ip, ipErr := netip.ParseAddr(c.PrivateIP)
	pin, pinErr := hex.DecodeString(c.Pin)
	roots := x509.NewCertPool()
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.EscapedPath() != "/mcp" || !host.MatchString(u.Hostname()) ||
		u.Port() != "" && u.Port() != "443" || ipErr != nil || !ip.IsPrivate() || ip.Is4In6() || ip.Zone() != "" || !c.Target.valid() || len(c.Token) < 16 || len(c.Token) > 1024 || !tokenFormat.MatchString(c.Token) ||
		len(c.PublicKey) != ed25519.PublicKeySize || pinErr != nil || len(pin) != sha256.Size || !roots.AppendCertsFromPEM([]byte(c.CA)) {
		return nil, ErrUnavailable
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: u.Hostname(), RootCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return ErrUnavailable
		}
		sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
			return ErrUnavailable
		}
		return nil
	}}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), "443"))
		}}
	client := &http.Client{Transport: &privateTransport{endpoint: c.Endpoint, token: c.Token, next: transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{target: c.Target, key: c.PublicKey, endpoint: c.Endpoint, http: client}, nil
}

// Limit every response before the SDK parses it. The peer may not select a
// new origin, transport, service credential, server session, or callback.
type privateTransport struct {
	endpoint, token string
	next            http.RoundTripper
}

func (p *privateTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != "POST" || r.URL.String() != p.endpoint || r.Body == nil || r.Header.Get("Mcp-Session-Id") != "" {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	r.Body.Close()
	var msg struct {
		Method string `json:"method"`
	}
	if err != nil || len(raw) > maxBody || json.Unmarshal(raw, &msg) != nil || msg.Method != "initialize" && msg.Method != "notifications/initialized" && msg.Method != "tools/call" {
		return nil, ErrUnavailable
	}
	req := r.Clone(r.Context())
	req.Body = io.NopCloser(bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+p.token)
	resp, err := p.next.RoundTrip(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	mtype, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 && resp.StatusCode != 202 || resp.Header.Get("Mcp-Session-Id") != "" || resp.StatusCode == 200 && mtype != "application/json" {
		return nil, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return nil, ErrUnavailable
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}
func receiptInput(r receipt) []byte {
	return []byte(strings.Join([]string{"zasp.external-inventory.v1", r.Organization, r.Workspace, r.Environment, r.Agent, r.Nonce, r.Status, time.Unix(r.Observed, 0).UTC().Format(time.RFC3339)}, "\n"))
}
func verify(raw []byte, q readRequest, key ed25519.PublicKey, now time.Time) (string, error) {
	var out receipt
	age := now.Unix()
	if !decode(raw, &out) || out.readRequest != q || out.Observed > age || out.Observed < age-60 || out.Status != "present" && out.Status != "not_listed" && out.Status != "unknown" || !ed25519.Verify(key, receiptInput(out), out.Signature) {
		return "", ErrUnavailable
	}
	return out.Status, nil
}

// Status is one external inventory observation, never an activity receipt.
func (c *Client) Status(ctx context.Context, t Target) (string, error) {
	if c == nil || !t.valid() || t != c.target {
		return "", ErrUnavailable
	}
	select {
	case activeReads <- struct{}{}:
		defer func() { <-activeReads }()
	default:
		return "", ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ErrUnavailable
	}
	q := readRequest{Target: t, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:])}
	client := mcp.NewClient(&mcp.Implementation{Name: "zasp-studio-inventory", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: c.endpoint, HTTPClient: c.http, MaxRetries: -1, DisableStandaloneSSE: true, MaxEventSize: maxBody}, nil)
	if err != nil {
		return "", ErrUnavailable
	}
	defer session.Close()
	out, err := session.CallTool(ctx, &mcp.CallToolParams{Name: Tool, Arguments: q})
	if err != nil || out == nil || out.IsError || out.StructuredContent != nil || len(out.Content) != 1 {
		return "", ErrUnavailable
	}
	txt, ok := out.Content[0].(*mcp.TextContent)
	if !ok || len(txt.Text) > 4096 {
		return "", ErrUnavailable
	}
	return verify([]byte(txt.Text), q, c.key, time.Now())
}

func (c *Client) Available(scope domain.Scope) bool {
	return c != nil && scope.Validate() == nil && c.target.Organization == scope.OrganizationID().String() && c.target.Workspace == scope.WorkspaceID().String() && c.target.Environment == scope.EnvironmentID().String()
}
