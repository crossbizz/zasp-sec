package runtimeservices

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	fga "github.com/openfga/go-sdk/client"
)

// Authorization-only processes have no Temporal identity or network access.
// Full runtime Config.Validate and Connect keep their original requirements.
func (c Config) ValidateAuthorizationOnly() error {
	if !c.Enabled || c.Environment != "production" && c.Environment != "development" && c.Environment != "test" || c.Timeout <= 0 || c.Timeout > 30*time.Second || !ulidPattern.MatchString(c.StoreID) || !ulidPattern.MatchString(c.ModelID) || !filepath.IsAbs(c.FGATokenFile) || c.FGACAFile != "" && !filepath.IsAbs(c.FGACAFile) {
		return ErrConfiguration
	}
	if c.TemporalAddress != "" || c.Namespace != "" || c.TaskQueue != "" || c.DiscoveryTaskQueue != "" || c.TemporalCAFile != "" || c.TemporalCertFile != "" || c.TemporalKeyFile != "" {
		return ErrConfiguration
	}
	u, err := url.Parse(c.FGAURL)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !privateHost(u.Hostname()) || u.Port() != "" && !validPort(u.Port()) || u.Scheme != "https" && !(c.Environment != "production" && loopback(u.Hostname()) && u.Scheme == "http") {
		return ErrConfiguration
	}
	return nil
}

func LoadAuthorizationOnly(getenv func(string) string) (Config, error) {
	if getenv == nil {
		return Config{}, ErrConfiguration
	}
	switch getenv("ZASP_RUNTIME_SERVICES_ENABLED") {
	case "", "false":
		return Config{}, nil
	case "true":
	default:
		return Config{}, ErrConfiguration
	}
	timeout, err := time.ParseDuration(getenv("ZASP_RUNTIME_SERVICES_TIMEOUT"))
	if err != nil {
		return Config{}, ErrConfiguration
	}
	c := Config{Enabled: true, Environment: getenv("ZASP_ENVIRONMENT"), FGAURL: getenv("ZASP_OPENFGA_URL"), StoreID: getenv("ZASP_OPENFGA_STORE_ID"), ModelID: getenv("ZASP_OPENFGA_MODEL_ID"), FGATokenFile: getenv("ZASP_OPENFGA_TOKEN_FILE"), FGACAFile: getenv("ZASP_OPENFGA_TLS_CA_FILE"), Timeout: timeout}
	return c, c.ValidateAuthorizationOnly()
}

type AuthorizationClient struct {
	FGA       *fga.OpenFgaClient
	config    Config
	transport *http.Transport
	once      sync.Once
}

func ConnectAuthorizationOnly(ctx context.Context, c Config) (*AuthorizationClient, error) {
	if ctx == nil || ctx.Err() != nil || c.ValidateAuthorizationOnly() != nil {
		return nil, ErrConfiguration
	}
	client, transport, err := newFGA(c)
	if err != nil {
		return nil, err
	}
	result := &AuthorizationClient{FGA: client, config: c, transport: transport}
	if err := result.Ready(ctx); err != nil {
		result.Close()
		return nil, err
	}
	return result, nil
}
func (c *AuthorizationClient) Ready(ctx context.Context) error {
	if c == nil || c.FGA == nil || ctx == nil {
		return ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	response, err := c.FGA.ReadAuthorizationModel(bounded).Execute()
	if err != nil || response == nil {
		return ErrUnavailable
	}
	model := response.GetAuthorizationModel()
	if model.GetId() != c.config.ModelID {
		return ErrUnavailable
	}
	return nil
}
func (c *AuthorizationClient) Close() error {
	if c != nil {
		c.once.Do(func() {
			if c.transport != nil {
				c.transport.CloseIdleConnections()
			}
		})
	}
	return nil
}
