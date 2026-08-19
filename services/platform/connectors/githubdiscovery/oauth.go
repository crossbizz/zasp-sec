package githubdiscovery

import (
	"context"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("GitHub connector input rejected")
var ErrProvider = errors.New("GitHub connector provider rejected")
var clientIDPattern = regexp.MustCompile(`^Iv1\.[A-Za-z0-9]{16}$`)
var referencePattern = regexp.MustCompile(`^ref:github/[a-z0-9][a-z0-9_./:-]{3,507}$`)
var oauthValuePattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{8,512}$`)
var pkcePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)

type Config struct{ ClientID, ClientSecretReference, CallbackURL string }
type ExchangeRequest struct {
	Code, ClientID, ClientSecretReference, CallbackURL string
	PKCEVerifier                                       []byte
}
type Connection struct {
	Reference, AccountLogin, RepositorySelection string
	InstallationID                               int64
	Permissions                                  map[string]string
}
type ExchangeClient interface {
	Exchange(context.Context, ExchangeRequest) (Connection, error)
}
type Adapter struct {
	config  Config
	client  ExchangeClient
	timeout time.Duration
}

func NewAdapter(config Config, client ExchangeClient, timeout time.Duration) (*Adapter, error) {
	if client == nil || !validConfig(config) || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, ErrInvalid
	}
	return &Adapter{config: config, client: client, timeout: timeout}, nil
}

func (adapter *Adapter) AuthorizationURL(state, challenge string) (string, error) {
	if adapter == nil || !validConfig(adapter.config) || !pkcePattern.MatchString(state) || !pkcePattern.MatchString(challenge) {
		return "", ErrInvalid
	}
	query := url.Values{}
	query.Set("client_id", adapter.config.ClientID)
	query.Set("redirect_uri", adapter.config.CallbackURL)
	query.Set("scope", "read:org repo")
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	return "https://github.com/login/oauth/authorize?" + query.Encode(), nil
}

func (adapter *Adapter) Complete(ctx context.Context, code string, verifier []byte) (Connection, error) {
	if adapter == nil || adapter.client == nil || ctx == nil || ctx.Err() != nil || !oauthValuePattern.MatchString(code) || !pkcePattern.Match(verifier) {
		return Connection{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	verifierCopy := append([]byte(nil), verifier...)
	request := ExchangeRequest{Code: code, ClientID: adapter.config.ClientID, ClientSecretReference: adapter.config.ClientSecretReference, CallbackURL: adapter.config.CallbackURL, PKCEVerifier: verifierCopy}
	connection, err := adapter.client.Exchange(bounded, request)
	clear(verifierCopy)
	if err != nil || bounded.Err() != nil || !validConnection(connection) {
		return Connection{}, ErrProvider
	}
	connection.Permissions = clonePermissions(connection.Permissions)
	return connection, nil
}

func validConfig(config Config) bool {
	parsed, err := url.Parse(config.CallbackURL)
	if err != nil || !clientIDPattern.MatchString(config.ClientID) || !referencePattern.MatchString(config.ClientSecretReference) || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "/api/v1/integrations/oauth/callback" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return net.ParseIP(host) == nil && host != "localhost" && !strings.HasSuffix(host, ".localhost") && !strings.HasSuffix(host, ".local")
}

func validConnection(value Connection) bool {
	if !referencePattern.MatchString(value.Reference) || value.InstallationID < 1 || value.InstallationID > 1<<53 || len(value.AccountLogin) < 1 || len(value.AccountLogin) > 100 || value.RepositorySelection != "all" && value.RepositorySelection != "selected" || len(value.Permissions) < 2 || len(value.Permissions) > 32 {
		return false
	}
	for key, permission := range value.Permissions {
		if len(key) < 1 || len(key) > 64 || permission != "read" {
			return false
		}
	}
	return value.Permissions["contents"] == "read" && value.Permissions["metadata"] == "read"
}

func clonePermissions(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, permission := range value {
		result[key] = permission
	}
	return result
}
