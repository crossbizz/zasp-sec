package idpdiscovery

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("Okta connector input rejected")
var ErrProvider = errors.New("Okta connector provider rejected")
var ErrOutcomeNotFound = errors.New("Okta connector outcome not found")
var issuerPattern = regexp.MustCompile(`^https://([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.okta\.com$`)
var clientIDPattern = regexp.MustCompile(`^0oa[A-Za-z0-9]{16}$`)
var referencePattern = regexp.MustCompile(`^ref:okta/[a-z0-9][a-z0-9_./:-]{3,507}$`)
var oauthValuePattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{8,512}$`)
var pkcePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)
var subjectPattern = regexp.MustCompile(`^00u[A-Za-z0-9]{16,64}$`)

var requiredScopes = []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}

type Config struct{ Issuer, ClientID, ClientSecretReference, CallbackURL string }
type ExchangeRequest struct {
	EffectID, Code, Issuer, ClientID, ClientSecretReference, CallbackURL string
	PKCEVerifier                                                         []byte
}
type Connection struct {
	Reference, Subject, Tenant string
	Scopes                     []string
}
type ExchangeClient interface {
	Exchange(context.Context, ExchangeRequest) (Connection, error)
}
type EffectClient interface {
	ExchangeClient
	Recover(context.Context, string) (Connection, error)
	Discard(context.Context, string, bool) error
	Revoke(context.Context, string, Config) error
}
type OktaAdapter struct {
	config  Config
	client  ExchangeClient
	timeout time.Duration
}

func NewOktaAdapter(config Config, client ExchangeClient, timeout time.Duration) (*OktaAdapter, error) {
	if client == nil || !validConfig(config) || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, ErrInvalid
	}
	return &OktaAdapter{config: config, client: client, timeout: timeout}, nil
}

func (adapter *OktaAdapter) AuthorizationURL(state, challenge string) (string, error) {
	if adapter == nil || !validConfig(adapter.config) || !pkcePattern.MatchString(state) || !pkcePattern.MatchString(challenge) {
		return "", ErrInvalid
	}
	query := url.Values{}
	query.Set("client_id", adapter.config.ClientID)
	query.Set("redirect_uri", adapter.config.CallbackURL)
	query.Set("response_type", "code")
	query.Set("response_mode", "query")
	query.Set("scope", strings.Join(requiredScopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	return adapter.config.Issuer + "/oauth2/v1/authorize?" + query.Encode(), nil
}

func (adapter *OktaAdapter) Complete(ctx context.Context, effectID, code string, verifier []byte) (Connection, error) {
	if adapter == nil || adapter.client == nil || ctx == nil || ctx.Err() != nil || !referencePattern.MatchString("ref:okta/effect/"+effectID) || !oauthValuePattern.MatchString(code) || !pkcePattern.Match(verifier) {
		return Connection{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	verifierCopy := append([]byte(nil), verifier...)
	connection, err := adapter.client.Exchange(bounded, ExchangeRequest{EffectID: effectID, Code: code, Issuer: adapter.config.Issuer, ClientID: adapter.config.ClientID, ClientSecretReference: adapter.config.ClientSecretReference, CallbackURL: adapter.config.CallbackURL, PKCEVerifier: verifierCopy})
	clear(verifierCopy)
	if err != nil || bounded.Err() != nil || !validConnection(adapter.config, connection) {
		return Connection{}, ErrProvider
	}
	connection.Scopes = append([]string(nil), connection.Scopes...)
	return connection, nil
}

func (adapter *OktaAdapter) Recover(ctx context.Context, effectID string) (Connection, error) {
	client, ok := adapter.client.(EffectClient)
	if adapter == nil || !ok || ctx == nil || ctx.Err() != nil || !referencePattern.MatchString("ref:okta/effect/"+effectID) {
		return Connection{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	connection, err := client.Recover(bounded, effectID)
	if errors.Is(err, ErrOutcomeNotFound) {
		return Connection{}, ErrOutcomeNotFound
	}
	if err != nil || bounded.Err() != nil || !validConnection(adapter.config, connection) {
		return Connection{}, ErrProvider
	}
	connection.Scopes = append([]string(nil), connection.Scopes...)
	return connection, nil
}

func (adapter *OktaAdapter) Discard(ctx context.Context, effectID string, revoke bool) error {
	client, ok := adapter.client.(EffectClient)
	if adapter == nil || !ok || ctx == nil || ctx.Err() != nil || !referencePattern.MatchString("ref:okta/effect/"+effectID) {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	if err := client.Discard(bounded, effectID, revoke); err != nil || bounded.Err() != nil {
		return ErrProvider
	}
	return nil
}

func (adapter *OktaAdapter) Revoke(ctx context.Context, reference string) error {
	client, ok := adapter.client.(EffectClient)
	if adapter == nil || !ok || ctx == nil || ctx.Err() != nil || !referencePattern.MatchString(reference) {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	if err := client.Revoke(bounded, reference, adapter.config); err != nil || bounded.Err() != nil {
		return ErrProvider
	}
	return nil
}

func validConfig(config Config) bool {
	issuerMatch := issuerPattern.FindStringSubmatch(config.Issuer)
	callback, err := url.Parse(config.CallbackURL)
	return len(issuerMatch) == 2 && clientIDPattern.MatchString(config.ClientID) && referencePattern.MatchString(config.ClientSecretReference) && err == nil && callback.Scheme == "https" && callback.Host != "" && callback.User == nil && callback.Path == "/api/v1/integrations/oauth/callback" && callback.RawQuery == "" && callback.Fragment == ""
}

func validConnection(config Config, value Connection) bool {
	issuer := issuerPattern.FindStringSubmatch(config.Issuer)
	if len(issuer) != 2 || !referencePattern.MatchString(value.Reference) || !subjectPattern.MatchString(value.Subject) || value.Tenant != issuer[1]+".okta.com" || len(value.Scopes) != len(requiredScopes) {
		return false
	}
	for index := range requiredScopes {
		if value.Scopes[index] != requiredScopes[index] {
			return false
		}
	}
	return true
}
