// Package runtimeservices owns the staged Temporal/OpenFGA connection contract.
// Enabling connections does not activate workflow routing or authorization.
package runtimeservices

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrConfiguration = errors.New("runtime services configuration rejected")

type Config struct {
	ConnectorMaintenanceProfileChecksum                                    string
	ApprovalMaintenanceProfileChecksum                                     string
	Enabled                                                                bool
	Environment, TemporalAddress, Namespace, TaskQueue, DiscoveryTaskQueue string
	TemporalCAFile, TemporalCertFile, TemporalKeyFile                      string
	FGAURL, StoreID, ModelID, FGATokenFile, FGACAFile                      string
	Timeout                                                                time.Duration
}

func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		return Config{}, ErrConfiguration
	}
	switch getenv("ZASP_RUNTIME_SERVICES_ENABLED") {
	case "", "false":
		if getenv("ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM") != "" || getenv("ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM") != "" {
			return Config{}, ErrConfiguration
		}
		return Config{}, nil
	case "true":
	default:
		return Config{}, ErrConfiguration
	}
	timeout, err := time.ParseDuration(getenv("ZASP_RUNTIME_SERVICES_TIMEOUT"))
	if err != nil {
		return Config{}, ErrConfiguration
	}
	c := Config{ConnectorMaintenanceProfileChecksum: getenv("ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM"), ApprovalMaintenanceProfileChecksum: getenv("ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM"), Enabled: true, Environment: getenv("ZASP_ENVIRONMENT"), TemporalAddress: getenv("ZASP_TEMPORAL_ADDRESS"), Namespace: getenv("ZASP_TEMPORAL_NAMESPACE"), TaskQueue: getenv("ZASP_TEMPORAL_TASK_QUEUE"), DiscoveryTaskQueue: getenv("ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE"), TemporalCAFile: getenv("ZASP_TEMPORAL_TLS_CA_FILE"), TemporalCertFile: getenv("ZASP_TEMPORAL_TLS_CERT_FILE"), TemporalKeyFile: getenv("ZASP_TEMPORAL_TLS_KEY_FILE"), FGAURL: getenv("ZASP_OPENFGA_URL"), StoreID: getenv("ZASP_OPENFGA_STORE_ID"), ModelID: getenv("ZASP_OPENFGA_MODEL_ID"), FGATokenFile: getenv("ZASP_OPENFGA_TOKEN_FILE"), FGACAFile: getenv("ZASP_OPENFGA_TLS_CA_FILE"), Timeout: timeout}
	return c, c.Validate()
}

var approvalMaintenanceChecksumPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,127}$`)
var ulidPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func (c Config) Validate() error {
	if !c.Enabled {
		if c != (Config{}) {
			return ErrConfiguration
		}
		return nil
	}
	if c.ConnectorMaintenanceProfileChecksum != "" && !approvalMaintenanceChecksumPattern.MatchString(c.ConnectorMaintenanceProfileChecksum) {
		return ErrConfiguration
	}
	if c.ApprovalMaintenanceProfileChecksum != "" && !approvalMaintenanceChecksumPattern.MatchString(c.ApprovalMaintenanceProfileChecksum) {
		return ErrConfiguration
	}
	if c.Environment != "production" && c.Environment != "development" && c.Environment != "test" {
		return ErrConfiguration
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second || !namePattern.MatchString(c.Namespace) || !namePattern.MatchString(c.TaskQueue) || !namePattern.MatchString(c.DiscoveryTaskQueue) || c.TaskQueue == c.DiscoveryTaskQueue || !ulidPattern.MatchString(c.StoreID) || !ulidPattern.MatchString(c.ModelID) || !filepath.IsAbs(c.FGATokenFile) {
		return ErrConfiguration
	}
	host, port, err := net.SplitHostPort(c.TemporalAddress)
	if err != nil || !validPort(port) || !privateHost(host) {
		return ErrConfiguration
	}
	u, err := url.Parse(c.FGAURL)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !privateHost(u.Hostname()) {
		return ErrConfiguration
	}
	if u.Port() != "" && !validPort(u.Port()) {
		return ErrConfiguration
	}
	local := c.Environment != "production" && loopback(host) && loopback(u.Hostname())
	if u.Scheme != "https" && !(local && u.Scheme == "http") {
		return ErrConfiguration
	}
	anyTLS := c.TemporalCAFile != "" || c.TemporalCertFile != "" || c.TemporalKeyFile != ""
	if !local || anyTLS {
		if !filepath.IsAbs(c.TemporalCAFile) || !filepath.IsAbs(c.TemporalCertFile) || !filepath.IsAbs(c.TemporalKeyFile) {
			return ErrConfiguration
		}
	}
	if c.FGACAFile != "" && !filepath.IsAbs(c.FGACAFile) {
		return ErrConfiguration
	}
	return nil
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535 && strconv.Itoa(port) == value
}
func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}
func privateHost(host string) bool {
	ip := net.ParseIP(host)
	return loopback(host) || ip != nil && ip.IsPrivate() || strings.HasSuffix(host, ".svc.cluster.local") || strings.HasSuffix(host, ".internal")
}
