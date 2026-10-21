// Package gatewaypodidentity verifies current Kubernetes Pod identity through an
// explicitly configured Kubernetes API. It does not grant product authority.
package gatewaypodidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Profile = "kubernetes-tokenreview-pod-v1"
const MaximumCalls = 13
const MaximumStageDuration = 5 * time.Second

var ErrDenied = errors.New("pod identity denied")
var productPattern = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var uidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
var namespacePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var methodPattern = regexp.MustCompile("^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$")

// Config contains operator-selected trust. ReviewerCredentialFile is reread for
// each verification and must be a protected current-user-owned regular file.
type Config struct {
	IntegrationID          string
	Endpoint               string
	CABundlePEM            []byte
	AllowedCIDRs           []string
	ClusterUID             string
	Issuer                 string
	Audience               string
	Namespace              string
	ReviewerCredentialFile string
}

// RequestBinding binds the observation digest to the exact caller request.
type RequestBinding struct{ RequestID, Method, ExactTarget, BodySHA256 string }

// Proof has no token accessor. All formatting is redacted.
type Proof struct {
	token   []byte
	binding RequestBinding
}

func (Proof) String() string                { return "[redacted pod proof]" }
func (Proof) GoString() string              { return "[redacted pod proof]" }
func (Proof) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte("[redacted pod proof]")) }
func NewProof(token []byte, binding RequestBinding) (Proof, error) {
	u, err := url.ParseRequestURI(binding.ExactTarget)
	if !bearer(token, 16384) || !productPattern.MatchString(binding.RequestID) || !methodPattern.MatchString(binding.Method) || !hashPattern.MatchString(binding.BodySHA256) || len(binding.ExactTarget) > 8192 || !strings.HasPrefix(binding.ExactTarget, "/") || strings.HasPrefix(binding.ExactTarget, "//") || err != nil || u.IsAbs() || u.Fragment != "" || !ascii(binding.ExactTarget, 1, 8192) {
		return Proof{}, ErrDenied
	}
	return Proof{bytes.Clone(token), binding}, nil
}

type VerifiedPod struct {
	Profile, IntegrationID, ClusterUID, Namespace          string
	ServiceAccountName, ServiceAccountUID, PodName, PodUID string
	ReplicaSetUID, DeploymentUID, NodeUID, BootID          string
	ObservedAt, TokenExpiresAt, ExpiresAt                  time.Time
	FactsSHA256                                            string
}

// Verifier owns the pinned transport. Closing it prevents further observations.
type Verifier struct {
	config    Config
	client    *http.Client
	transport *http.Transport
	mu        sync.RWMutex
	closed    bool
}

func validUID(s string) bool {
	return uidPattern.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}
func ascii(s string, lo, hi int) bool {
	if len(s) < lo || len(s) > hi {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func bearer(s []byte, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for _, b := range s {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~+/=", rune(b))) {
			return false
		}
	}
	return true
}
func origin(s string) (*url.URL, bool) {
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" || strings.Contains(u.Hostname(), "%") || !ascii(u.Host, 1, 253) {
		return nil, false
	}
	if u.Port() != "" {
		n, e := strconv.Atoi(u.Port())
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != u.Port() {
			return nil, false
		}
	}
	return u, true
}
func New(config Config) (*Verifier, error) {
	u, ok := origin(config.Endpoint)
	issuer, e := url.Parse(config.Issuer)
	if !ok || !productPattern.MatchString(config.IntegrationID) || !validUID(config.ClusterUID) || !namespacePattern.MatchString(config.Namespace) || !ascii(config.Audience, 1, 256) || e != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" || issuer.Opaque != "" || !ascii(config.Issuer, 1, 2048) || len(config.AllowedCIDRs) < 1 || len(config.AllowedCIDRs) > 32 {
		return nil, ErrDenied
	}
	ranges := make([]*net.IPNet, 0, len(config.AllowedCIDRs))
	seen := map[string]bool{}
	for _, s := range config.AllowedCIDRs {
		ip, n, e := net.ParseCIDR(s)
		if e != nil || ip == nil || n.String() != s || seen[s] {
			return nil, ErrDenied
		}
		ones, bits := n.Mask.Size()
		if bits == 32 && ones < 8 || bits == 128 && ones < 32 {
			return nil, ErrDenied
		}
		seen[s] = true
		ranges = append(ranges, n)
	}
	if len(config.CABundlePEM) < 64 || len(config.CABundlePEM) > 32768 {
		return nil, ErrDenied
	}
	pool := x509.NewCertPool()
	rest := bytes.TrimSpace(config.CABundlePEM)
	count := 0
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrDenied
		}
		b, next := pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return nil, ErrDenied
		}
		cert, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			return nil, ErrDenied
		}
		pool.AddCert(cert)
		count++
		rest = bytes.TrimSpace(next)
	}
	if count < 1 || count > 32 {
		return nil, ErrDenied
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: MaximumStageDuration, KeepAlive: -1}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host}, TLSHandshakeTimeout: MaximumStageDuration, ResponseHeaderTimeout: MaximumStageDuration, MaxResponseHeaderBytes: 65536}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		h, p, e := net.SplitHostPort(address)
		if e != nil || h != host || p != port || network != "tcp" {
			return nil, ErrDenied
		}
		answers, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil || len(answers) < 1 || len(answers) > 16 {
			return nil, ErrDenied
		}
		ips := []string{}
		seen := map[string]bool{}
		for _, a := range answers {
			allowed := false
			for _, n := range ranges {
				if n.Contains(a.IP) {
					allowed = true
				}
			}
			s := a.IP.String()
			if a.IP == nil || a.Zone != "" || !allowed || seen[s] {
				return nil, ErrDenied
			}
			seen[s] = true
			ips = append(ips, s)
		}
		sort.Strings(ips)
		c, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ips[0], port))
		if e != nil {
			return nil, ErrDenied
		}
		return c, nil
	}
	config.Endpoint = "https://" + u.Host
	config.CABundlePEM = nil
	config.AllowedCIDRs = append([]string(nil), config.AllowedCIDRs...)
	v := &Verifier{config: config, transport: tr, client: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}}
	if v.Ready(context.Background()) != nil {
		tr.CloseIdleConnections()
		return nil, ErrDenied
	}
	return v, nil
}

// Ready checks local configuration/credential readiness, without a provider call.
func (v *Verifier) Ready(ctx context.Context) error {
	if v == nil || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed || v.client == nil || v.transport == nil {
		return ErrDenied
	}
	secret, e := reviewerCredential(v.config.ReviewerCredentialFile)
	clear(secret)
	if e != nil {
		return ErrDenied
	}
	return nil
}
func (v *Verifier) Close() error {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	if v.transport != nil {
		v.transport.CloseIdleConnections()
	}
	return nil
}

type reviewIdentity struct{ namespace, sa, saUID, pod, podUID string }

func (v *Verifier) Verify(ctx context.Context, proof Proof) (VerifiedPod, error) {
	if v == nil || ctx == nil || ctx.Err() != nil {
		return VerifiedPod{}, ErrDenied
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed || v.client == nil || v.transport == nil {
		return VerifiedPod{}, ErrDenied
	}
	checked, proofError := NewProof(proof.token, proof.binding)
	clear(checked.token)
	if proofError != nil {
		return VerifiedPod{}, ErrDenied
	}
	bounded, cancel := context.WithTimeout(ctx, MaximumStageDuration)
	defer cancel()
	secret, e := reviewerCredential(v.config.ReviewerCredentialFile)
	if e != nil {
		return VerifiedPod{}, ErrDenied
	}
	defer clear(secret)
	request := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Token     string   `json:"token"`
			Audiences []string `json:"audiences"`
		} `json:"spec"`
	}{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}
	request.Spec.Token = string(proof.token)
	request.Spec.Audiences = []string{v.config.Audience}
	body, _ := json.Marshal(request)
	request.Spec.Token = ""
	defer clear(body)
	raw, e := v.read(bounded, secret, http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", body, 65536)
	if e != nil {
		return VerifiedPod{}, ErrDenied
	}
	review, e := parseJSON(raw)
	clear(raw)
	if e != nil {
		return VerifiedPod{}, ErrDenied
	}
	// Kubernetes may echo spec.token. Discard that field immediately; only
	// selected authenticated status facts survive this request.
	delete(review, "spec")
	identity, ok := reviewed(review, v.config)
	if !ok {
		return VerifiedPod{}, ErrDenied
	}
	expiry, ok := projectedClaims(proof.token, identity, v.config)
	if !ok {
		return VerifiedPod{}, ErrDenied
	}
	var first chainFacts
	for pass := 0; pass < 2; pass++ {
		facts, e := v.readChain(bounded, secret, identity)
		if e != nil {
			return VerifiedPod{}, ErrDenied
		}
		if pass == 0 {
			first = facts
		} else if first != facts {
			return VerifiedPod{}, ErrDenied
		}
	}
	observed := time.Now().UTC().Truncate(time.Microsecond)
	if bounded.Err() != nil || !expiry.After(observed) {
		return VerifiedPod{}, ErrDenied
	}
	result := first.VerifiedPod
	result.Profile = Profile
	result.IntegrationID = v.config.IntegrationID
	result.ObservedAt = observed
	result.TokenExpiresAt = expiry
	result.ExpiresAt = minTime(expiry, observed.Add(MaximumStageDuration))
	encoded, digestError := json.Marshal(struct {
		Facts   VerifiedPod
		Request RequestBinding
	}{result, proof.binding})
	if digestError != nil {
		return VerifiedPod{}, ErrDenied
	}
	digest := sha256.Sum256(append([]byte("zasp-kubernetes-pod-facts-v1\n"), encoded...))
	result.FactsSHA256 = hex.EncodeToString(digest[:])
	return result, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (v *Verifier) read(ctx context.Context, secret []byte, method, path string, body []byte, limit int64) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, method, v.config.Endpoint+path, bytes.NewReader(body))
	if e != nil {
		return nil, ErrDenied
	}
	req.Close = true
	req.Header.Set("Authorization", "Bearer "+string(secret))
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	res, e := v.client.Do(req)
	if e != nil {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
		return nil, ErrDenied
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && !(method == http.MethodPost && res.StatusCode == http.StatusCreated) {
		return nil, ErrDenied
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if e != nil || int64(len(raw)) > limit || ctx.Err() != nil {
		clear(raw)
		return nil, ErrDenied
	}
	return raw, nil
}
func reviewed(o map[string]any, c Config) (reviewIdentity, bool) {
	s := obj(o, "status")
	user := obj(s, "user")
	extra := obj(user, "extra")
	ns := c.Namespace
	prefix := "system:serviceaccount:" + ns + ":"
	username := str(user, "username")
	sa := strings.TrimPrefix(username, prefix)
	pod, ok := single(extra["authentication.kubernetes.io/pod-name"])
	podUID, ok2 := single(extra["authentication.kubernetes.io/pod-uid"])
	uid := str(user, "uid")
	authenticated, _ := s["authenticated"].(bool)
	_, audienceArray := s["audiences"].([]any)
	if str(o, "apiVersion") != "authentication.k8s.io/v1" || str(o, "kind") != "TokenReview" || !authenticated || !emptyError(s) || !audienceArray || !containsAudience(s["audiences"], c.Audience) || !strings.HasPrefix(username, prefix) || !namePattern.MatchString(sa) || !validUID(uid) || !ok || !ok2 || !namePattern.MatchString(pod) || !validUID(podUID) {
		return reviewIdentity{}, false
	}
	return reviewIdentity{ns, sa, uid, pod, podUID}, true
}
func projectedClaims(token []byte, id reviewIdentity, c Config) (time.Time, bool) {
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	var payload []byte
	for i, p := range parts {
		if len(p) == 0 {
			return time.Time{}, false
		}
		raw, e := base64.RawURLEncoding.Strict().DecodeString(p)
		if e != nil || base64.RawURLEncoding.EncodeToString(raw) != p {
			return time.Time{}, false
		}
		if i == 1 {
			payload = raw
		} else {
			clear(raw)
		}
	}
	defer clear(payload)
	o, e := parseJSON(payload)
	if e != nil {
		return time.Time{}, false
	}
	n, ok := o["exp"].(json.Number)
	if !ok {
		return time.Time{}, false
	}
	seconds, e := strconv.ParseInt(string(n), 10, 64)
	if e != nil || seconds < 1 || seconds > 253402300799 {
		return time.Time{}, false
	}
	expiry := time.Unix(seconds, 0).UTC()
	k := obj(o, "kubernetes.io")
	sa := obj(k, "serviceaccount")
	pod := obj(k, "pod")
	if !expiry.After(time.Now()) || str(o, "iss") != c.Issuer || !containsAudience(o["aud"], c.Audience) || str(o, "sub") != "system:serviceaccount:"+id.namespace+":"+id.sa || str(k, "namespace") != id.namespace || str(sa, "name") != id.sa || str(sa, "uid") != id.saUID || str(pod, "name") != id.pod || str(pod, "uid") != id.podUID {
		return time.Time{}, false
	}
	return expiry, true
}
func containsAudience(v any, want string) bool {
	if s, ok := v.(string); ok {
		return s == want
	}
	a, ok := v.([]any)
	if !ok || len(a) < 1 || len(a) > 32 {
		return false
	}
	found := false
	seen := map[string]bool{}
	for _, v := range a {
		s, ok := v.(string)
		if !ok || !ascii(s, 1, 256) || seen[s] {
			return false
		}
		seen[s] = true
		found = found || s == want
	}
	return found
}
func single(v any) (string, bool) {
	a, ok := v.([]any)
	if !ok || len(a) != 1 {
		return "", false
	}
	s, ok := a[0].(string)
	return s, ok
}
func obj(o map[string]any, k string) map[string]any { v, _ := o[k].(map[string]any); return v }
func str(o map[string]any, k string) string         { v, _ := o[k].(string); return v }

func emptyError(s map[string]any) bool {
	v, exists := s["error"]
	if !exists {
		return true
	}
	text, ok := v.(string)
	return ok && text == ""
}
