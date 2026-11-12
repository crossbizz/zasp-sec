// Package localcloud lets a development or test deployment point every AWS
// client at a local emulator such as LocalStack. It is one explicit setting,
// it only accepts a loopback or private plaintext endpoint, and a production
// environment refuses to start with it set. Nothing here changes credentials,
// signing or authorization: the product code paths are the production ones,
// talking to a different host.
package localcloud

import (
	"errors"
	"net"
	"net/url"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	// EndpointVariable names the emulator endpoint, for example
	// http://127.0.0.1:4566.
	EndpointVariable = "ZASP_LOCAL_CLOUD_ENDPOINT"
	// EnvironmentVariable is the deployment environment every service reads.
	EnvironmentVariable = "ZASP_ENVIRONMENT"
)

// ErrConfiguration means the setting is present but not permitted.
var ErrConfiguration = errors.New("local cloud configuration rejected")

// Settings is the validated emulator endpoint, or disabled.
type Settings struct{ endpoint string }

// Load validates the setting. An unset or empty endpoint is disabled. A set
// endpoint is accepted only outside production and only for a plaintext
// loopback or private address with an explicit port.
func Load(getenv func(string) string) (Settings, error) {
	if getenv == nil {
		return Settings{}, ErrConfiguration
	}
	raw := getenv(EndpointVariable)
	if raw == "" {
		return Settings{}, nil
	}
	environment := getenv(EnvironmentVariable)
	if environment != "development" && environment != "test" {
		return Settings{}, ErrConfiguration
	}
	if !localEndpoint(raw) {
		return Settings{}, ErrConfiguration
	}
	return Settings{endpoint: raw}, nil
}

func localEndpoint(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.String() != raw || parsed.Scheme != "http" || parsed.User != nil || parsed.Port() == "" ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	address := net.ParseIP(parsed.Hostname())
	return address != nil && (address.IsLoopback() || address.IsPrivate())
}

// Enabled reports whether an emulator endpoint is configured.
func (settings Settings) Enabled() bool { return settings.endpoint != "" }

// Endpoint returns the emulator endpoint, or "" when disabled.
func (settings Settings) Endpoint() string { return settings.endpoint }

// Apply points every client built from base at the emulator. Disabled
// settings leave base untouched.
func (settings Settings) Apply(base *aws.Config) {
	if base == nil || !settings.Enabled() {
		return
	}
	base.BaseEndpoint = aws.String(settings.endpoint)
}

// S3 is an option for s3.NewFromConfig. Emulators serve buckets by path, not
// by virtual host.
func (settings Settings) S3(options *s3.Options) {
	if options != nil && settings.Enabled() {
		options.UsePathStyle = true
	}
}

// AllowsEndpoint reports whether a service endpoint that production requires
// to be an AWS host may instead be this local plaintext address. It is false
// whenever the emulator is disabled.
func (settings Settings) AllowsEndpoint(raw string) bool {
	return settings.Enabled() && localEndpoint(raw)
}

var (
	current     Settings
	currentErr  error
	currentOnce sync.Once
)

// Current returns the process settings, loaded once from the environment.
// Call Require at startup; Current treats an invalid setting as disabled so a
// refused configuration can never silently redirect a client.
func Current() Settings {
	currentOnce.Do(func() { current, currentErr = Load(os.Getenv) })
	if currentErr != nil {
		return Settings{}
	}
	return current
}

// Require returns ErrConfiguration when the process environment carries a
// local cloud endpoint it may not use. Every binary calls it before building
// clients.
func Require() error {
	Current()
	return currentErr
}
