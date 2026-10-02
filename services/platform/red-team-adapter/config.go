package main

import (
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

const (
	targetListenAddress = ":8443"
	healthListenAddress = ":8081"
)

var databaseUserRE = regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`)

type runtimeConfig struct {
	Authorization                      runtimeservices.Config
	CompensationDatabaseURL            string
	WorkerKeyFile, CompensationKeyFile string
	DatabaseURL                        string
	DatabaseAuthority                  string
	AWS                                redteamadapter.CloudConfig
	AllowedTargetCIDRs                 []string
	WorkerTokenFile                    string
	TLSCertificateFile                 string
	TLSPrivateKeyFile                  string
	MaximumRequestBytes                int64
	RequestTimeout                     time.Duration
	ShutdownTimeout                    time.Duration
}

func loadRuntimeConfig(getenv func(string) string) (runtimeConfig, error) {
	if getenv == nil {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	requestTimeout, requestErr := time.ParseDuration(getenv("ZASP_RED_TEAM_ADAPTER_REQUEST_TIMEOUT"))
	authority, authorityErr := runtimeservices.LoadAuthorizationOnly(getenv)
	shutdownTimeout, shutdownErr := time.ParseDuration(getenv("ZASP_RED_TEAM_ADAPTER_SHUTDOWN_TIMEOUT"))
	config := runtimeConfig{
		Authorization:           authority,
		CompensationDatabaseURL: getenv("ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN"),
		WorkerKeyFile:           getenv("ZASP_AUTHORIZATION_WORKER_KEY_FILE"),
		CompensationKeyFile:     getenv("ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE"),
		DatabaseURL:             getenv("ZASP_DATABASE_URL"),
		DatabaseAuthority:       getenv("ZASP_DATABASE_AUTHORITY"),
		AWS: redteamadapter.CloudConfig{
			Region: getenv("ZASP_AWS_REGION"), RoleARN: getenv("ZASP_RED_TEAM_ADAPTER_ROLE_ARN"),
			RoleSessionName: "zasp-red-team-adapter", WebIdentityTokenFile: getenv("ZASP_RED_TEAM_ADAPTER_WEB_IDENTITY_TOKEN_FILE"), SecretPrefix: "zasp/red-team/targets", ReadinessCredentialReference: getenv("ZASP_RED_TEAM_READINESS_CREDENTIAL_REFERENCE"),
			Timeout: requestTimeout, Clock: func() time.Time { return time.Now().UTC() },
		},
		AllowedTargetCIDRs:  splitExactCSV(getenv("ZASP_RED_TEAM_ALLOWED_TARGET_CIDRS")),
		WorkerTokenFile:     getenv("ZASP_RED_TEAM_ADAPTER_TOKEN_FILE"),
		TLSCertificateFile:  getenv("ZASP_RED_TEAM_ADAPTER_TLS_CERT_FILE"),
		TLSPrivateKeyFile:   getenv("ZASP_RED_TEAM_ADAPTER_TLS_KEY_FILE"),
		MaximumRequestBytes: 64 << 10,
		RequestTimeout:      requestTimeout,
		ShutdownTimeout:     shutdownTimeout,
	}
	if authorityErr != nil || requestErr != nil || shutdownErr != nil || !validRuntimeConfig(config) {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	return config, nil
}

func validRuntimeConfig(config runtimeConfig) bool {
	if !validWorkerAdapterConfiguration(config) {
		return false
	}
	parsed, err := url.Parse(config.DatabaseURL)
	return err == nil && parsed.String() == config.DatabaseURL && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") && parsed.User != nil && databaseUserRE.MatchString(parsed.User.Username()) && parsed.Hostname() != "" && net.ParseIP(parsed.Hostname()) == nil && (parsed.Port() == "" || parsed.Port() == "5432") && parsed.Path == "/zasp" && parsed.RawQuery == "sslmode=verify-full" && parsed.Fragment == "" &&
		config.DatabaseAuthority == "zasp_red_team_adapter" && config.WorkerTokenFile == "/var/run/secrets/zasp/red-team-adapter/token" && config.TLSCertificateFile == "/var/run/secrets/zasp/red-team-adapter-tls/tls.crt" && config.TLSPrivateKeyFile == "/var/run/secrets/zasp/red-team-adapter-tls/tls.key" &&
		redteamadapter.ValidTargetCIDRs(config.AllowedTargetCIDRs) && redteamadapter.ValidCloudConfig(config.AWS) && config.MaximumRequestBytes == 64<<10 && config.RequestTimeout >= time.Second && config.RequestTimeout <= 30*time.Second && config.ShutdownTimeout >= time.Second && config.ShutdownTimeout <= 30*time.Second
}

func validWorkerAdapterConfiguration(c runtimeConfig) bool {
	if !c.Authorization.Enabled {
		return c.Authorization == (runtimeservices.Config{}) && c.CompensationDatabaseURL == "" && c.WorkerKeyFile == "" && c.CompensationKeyFile == ""
	}
	if c.Authorization.ValidateAuthorizationOnly() != nil || !filepath.IsAbs(c.WorkerKeyFile) || !filepath.IsAbs(c.CompensationKeyFile) || filepath.Clean(c.WorkerKeyFile) != c.WorkerKeyFile || filepath.Clean(c.CompensationKeyFile) != c.CompensationKeyFile || c.WorkerKeyFile == c.CompensationKeyFile {
		return false
	}
	forward, err := url.Parse(c.DatabaseURL)
	if err != nil || forward.User == nil {
		return false
	}
	comp, err := url.Parse(c.CompensationDatabaseURL)
	return err == nil && comp.String() == c.CompensationDatabaseURL && (comp.Scheme == "postgres" || comp.Scheme == "postgresql") && comp.User != nil && databaseUserRE.MatchString(comp.User.Username()) && comp.User.Username() != forward.User.Username() && comp.Host == forward.Host && comp.Path == "/zasp" && comp.RawQuery == "sslmode=verify-full" && comp.Fragment == ""
}

func splitExactCSV(value string) []string {
	if value == "" || strings.TrimSpace(value) != value {
		return nil
	}
	parts := strings.Split(value, ",")
	for index := range parts {
		if parts[index] == "" || strings.TrimSpace(parts[index]) != parts[index] {
			return nil
		}
	}
	return parts
}
