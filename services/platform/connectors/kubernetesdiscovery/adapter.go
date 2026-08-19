package kubernetesdiscovery

import (
	"context"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("Kubernetes connector input rejected")
var ErrDenied = errors.New("Kubernetes connector capability denied")
var referencePattern = regexp.MustCompile(`^ref:kubernetes/[a-z0-9][a-z0-9_./:-]{3,507}$`)
var contextPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var versionPattern = regexp.MustCompile(`^v1\.[0-9]{1,3}\.[0-9]{1,3}$`)

type Config struct{ Endpoint, CAReference, CredentialReference, Context string }
type ProbeRequest struct{ Endpoint, CAReference, CredentialReference, Context string }
type ProbeResult struct {
	ClusterID, ServerVersion string
	AllowedVerbs             []string
}
type ProbeClient interface {
	Probe(context.Context, ProbeRequest) (ProbeResult, error)
}
type Adapter struct {
	client  ProbeClient
	timeout time.Duration
}

func NewAdapter(client ProbeClient, timeout time.Duration) (*Adapter, error) {
	if client == nil || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, ErrInvalid
	}
	return &Adapter{client: client, timeout: timeout}, nil
}

func (adapter *Adapter) TestConnection(ctx context.Context, config Config) (ProbeResult, error) {
	if adapter == nil || adapter.client == nil || ctx == nil || ctx.Err() != nil || !validConfig(config) {
		return ProbeResult{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	result, err := adapter.client.Probe(bounded, ProbeRequest(config))
	if err != nil || bounded.Err() != nil || len(result.ClusterID) < 1 || len(result.ClusterID) > 256 || !versionPattern.MatchString(result.ServerVersion) || !hasExactCapabilities(result.AllowedVerbs) {
		return ProbeResult{}, ErrDenied
	}
	result.AllowedVerbs = append([]string(nil), result.AllowedVerbs...)
	return result, nil
}

func validConfig(config Config) bool {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" && parsed.Port() != "443" || !referencePattern.MatchString(config.CAReference) || !referencePattern.MatchString(config.CredentialReference) || !contextPattern.MatchString(config.Context) {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	ip := net.ParseIP(host)
	return ip == nil && host != "localhost" && !strings.HasSuffix(host, ".localhost") && !strings.HasSuffix(host, ".local") && !strings.HasSuffix(host, ".internal")
}

func hasExactCapabilities(values []string) bool {
	if len(values) < 3 || len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "get" && value != "list" && value != "watch" && value != "api-discovery" {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	for _, required := range []string{"get", "list", "watch"} {
		if _, exists := seen[required]; !exists {
			return false
		}
	}
	return true
}
