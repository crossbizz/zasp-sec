package main

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/attacklabproxy"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

var errRuntimeUnavailable = errors.New("attack lab proxy unavailable")

type runtimeConfig struct {
	DatabaseURL          string
	DatabaseAuthority    string
	AWS                  redteamadapter.CloudConfig
	AllowedTargetCIDRs   []string
	SigningKeyFile       string
	TLSCertificateFile   string
	TLSPrivateKeyFile    string
	MaximumRequestBytes  int64
	MaximumResponseBytes int64
	RequestTimeout       time.Duration
	ShutdownTimeout      time.Duration
}

func loadRuntimeConfig(getenv func(string) string) (runtimeConfig, error) {
	if getenv == nil {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	requestTimeout, requestErr := time.ParseDuration(getenv("ZASP_ATTACK_LAB_PROXY_REQUEST_TIMEOUT"))
	shutdownTimeout, shutdownErr := time.ParseDuration(getenv("ZASP_ATTACK_LAB_PROXY_SHUTDOWN_TIMEOUT"))
	config := runtimeConfig{
		DatabaseURL: getenv("ZASP_DATABASE_URL"), DatabaseAuthority: getenv("ZASP_DATABASE_AUTHORITY"),
		AWS:                redteamadapter.CloudConfig{Region: getenv("ZASP_AWS_REGION"), RoleARN: getenv("ZASP_ATTACK_LAB_PROXY_ROLE_ARN"), RoleSessionName: "zasp-attack-lab-proxy", WebIdentityTokenFile: getenv("ZASP_ATTACK_LAB_PROXY_WEB_IDENTITY_TOKEN_FILE"), SecretPrefix: "zasp/red-team/targets", ReadinessCredentialReference: getenv("ZASP_ATTACK_LAB_READINESS_CREDENTIAL_REFERENCE"), Timeout: requestTimeout, Clock: func() time.Time { return time.Now().UTC() }},
		AllowedTargetCIDRs: splitProxyCSV(getenv("ZASP_ATTACK_LAB_ALLOWED_TARGET_CIDRS")), SigningKeyFile: getenv("ZASP_ATTACK_LAB_EGRESS_SIGNING_KEY_FILE"),
		TLSCertificateFile: getenv("ZASP_ATTACK_LAB_PROXY_TLS_CERT_FILE"), TLSPrivateKeyFile: getenv("ZASP_ATTACK_LAB_PROXY_TLS_KEY_FILE"),
		MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, RequestTimeout: requestTimeout, ShutdownTimeout: shutdownTimeout,
	}
	if requestErr != nil || shutdownErr != nil || !validRuntimeConfig(config) {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	return config, nil
}

func validRuntimeConfig(config runtimeConfig) bool {
	parsed, err := url.Parse(config.DatabaseURL)
	return err == nil && parsed.String() == config.DatabaseURL && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") && parsed.User != nil && regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`).MatchString(parsed.User.Username()) && parsed.Hostname() != "" && net.ParseIP(parsed.Hostname()) == nil && (parsed.Port() == "" || parsed.Port() == "5432") && parsed.Path == "/zasp" && parsed.RawQuery == "sslmode=verify-full" && parsed.Fragment == "" &&
		config.DatabaseAuthority == "zasp_attack_lab_proxy" && redteamadapter.ValidCloudConfig(config.AWS) && attacklabproxy.ValidTargetCIDRs(config.AllowedTargetCIDRs) && config.SigningKeyFile == "/var/run/secrets/zasp-attack-lab/egress-signing-key" &&
		config.TLSCertificateFile == "/var/run/secrets/zasp-attack-lab-proxy-tls/tls.crt" && config.TLSPrivateKeyFile == "/var/run/secrets/zasp-attack-lab-proxy-tls/tls.key" &&
		config.MaximumRequestBytes == 32<<10 && config.MaximumResponseBytes == 32<<10 && config.RequestTimeout >= time.Second && config.RequestTimeout <= 30*time.Second && config.ShutdownTimeout >= time.Second && config.ShutdownTimeout <= 30*time.Second
}

func splitProxyCSV(value string) []string {
	if value == "" || strings.TrimSpace(value) != value {
		return nil
	}
	parts := strings.Split(value, ",")
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part {
			return nil
		}
	}
	return parts
}
