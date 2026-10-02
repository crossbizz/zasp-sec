package runtimeservices

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"

	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
)

var ErrUnavailable = errors.New("runtime services unavailable")

type Clients struct {
	Temporal  client.Client
	FGA       *fga.OpenFgaClient
	config    Config
	transport *http.Transport
	once      sync.Once
}

// Connect verifies both services before returning usable clients. Failures are
// deliberately redacted: SDK errors may include URLs or response bodies.
func Connect(ctx context.Context, c Config) (*Clients, error) {
	if ctx == nil || c.Validate() != nil {
		return nil, ErrConfiguration
	}
	if !c.Enabled {
		return nil, nil
	}
	fgaClient, transport, err := newFGA(c)
	if err != nil {
		return nil, ErrUnavailable
	}
	result := &Clients{config: c, FGA: fgaClient, transport: transport}
	opts := client.Options{HostPort: c.TemporalAddress, Namespace: c.Namespace, Logger: quietLogger{}}
	if c.TemporalCAFile != "" {
		roots, err := loadRoots(c.TemporalCAFile)
		if err != nil {
			result.Close()
			return nil, ErrUnavailable
		}
		certificate, err := tls.LoadX509KeyPair(c.TemporalCertFile, c.TemporalKeyFile)
		if err != nil {
			result.Close()
			return nil, ErrUnavailable
		}
		opts.ConnectionOptions.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}
	}
	bounded, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	result.Temporal, err = client.DialContext(bounded, opts)
	if err != nil {
		result.Close()
		return nil, ErrUnavailable
	}
	if err := result.Ready(bounded); err != nil {
		result.Close()
		return nil, err
	}
	return result, nil
}

func newFGA(c Config) (*fga.OpenFgaClient, *http.Transport, error) {
	data, err := os.ReadFile(c.FGATokenFile)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 8 || len(token) > 8192 || strings.ContainsAny(token, "\r\n\t ") {
		return nil, nil, ErrConfiguration
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Private dependency endpoints must never be sent through an ambient proxy.
	transport.Proxy = nil
	transport.MaxIdleConns = 8
	transport.MaxIdleConnsPerHost = 8
	transport.MaxConnsPerHost = 16
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.FGACAFile != "" {
		roots, err := loadRoots(c.FGACAFile)
		if err != nil {
			return nil, nil, ErrUnavailable
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: c.FGAURL, StoreId: c.StoreID, AuthorizationModelId: c.ModelID, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, ErrUnavailable
	}
	return client, transport, nil
}
func loadRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, ErrConfiguration
	}
	return roots, nil
}
func (c *Clients) fgaReady(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	if _, err := c.FGA.ReadAuthorizationModel(bounded).Execute(); err != nil {
		return ErrUnavailable
	}
	return nil
}
func (c *Clients) Ready(ctx context.Context) error {
	if c == nil || c.Temporal == nil || c.FGA == nil || ctx == nil {
		return ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	if _, err := c.Temporal.WorkflowService().DescribeNamespace(bounded, &workflowservice.DescribeNamespaceRequest{Namespace: c.config.Namespace}); err != nil {
		return ErrUnavailable
	}
	return c.fgaReady(bounded)
}
func (c *Clients) Close() error {
	if c != nil {
		c.once.Do(func() {
			if c.Temporal != nil {
				c.Temporal.Close()
			}
			if c.transport != nil {
				c.transport.CloseIdleConnections()
			}
		})
	}
	return nil
}

// Service diagnostics flow through redacted application readiness. SDK payload
// logging stays off; history payload policy is owned by the workflow packets.
type quietLogger struct{}

func (quietLogger) Debug(string, ...interface{}) {}
func (quietLogger) Info(string, ...interface{})  {}
func (quietLogger) Warn(string, ...interface{})  {}
func (quietLogger) Error(string, ...interface{}) {}
