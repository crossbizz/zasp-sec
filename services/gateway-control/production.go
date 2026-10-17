package main

import (
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/url"
	"strconv"
	"time"
)

type productionControlConfig struct {
	EnrollmentEnabled           bool
	EnrollmentProfileChecksum   string
	InstallationACKEnabled      bool
	InstallationProfileChecksum string
	DatabaseURL                 string
	MaximumBodyBytes            int64
	OperationTimeout            time.Duration
	ReadinessTTL                time.Duration
	ShutdownTimeout             time.Duration
}

func loadProductionControlConfig(getenv func(string) string) (productionControlConfig, error) {
	if getenv == nil {
		return productionControlConfig{}, errControlUnavailable
	}
	maximumBodyBytes, bodyErr := strconv.ParseInt(getenv("ZASP_GATEWAY_CONTROL_MAX_BODY_BYTES"), 10, 64)
	operationTimeout, operationErr := time.ParseDuration(getenv("ZASP_GATEWAY_CONTROL_OPERATION_TIMEOUT"))
	readinessTTL, readinessErr := time.ParseDuration(getenv("ZASP_GATEWAY_CONTROL_READINESS_TTL"))
	shutdownTimeout, shutdownErr := time.ParseDuration(getenv("ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT"))
	enrollmentFlag := getenv("ZASP_GATEWAY_ENROLLMENT_ENABLED")
	if enrollmentFlag != "" && enrollmentFlag != "false" && enrollmentFlag != "true" {
		return productionControlConfig{}, errControlUnavailable
	}
	flag := getenv("ZASP_GATEWAY_INSTALLATION_ACK_ENABLED")
	if flag != "" && flag != "false" && flag != "true" {
		return productionControlConfig{}, errControlUnavailable
	}
	config := productionControlConfig{EnrollmentEnabled: enrollmentFlag == "true", EnrollmentProfileChecksum: getenv("ZASP_GATEWAY_ENROLLMENT_PROFILE_CHECKSUM"), InstallationACKEnabled: flag == "true", InstallationProfileChecksum: getenv("ZASP_GATEWAY_INSTALLATION_PROFILE_CHECKSUM"),
		DatabaseURL: getenv("ZASP_DATABASE_URL"), MaximumBodyBytes: maximumBodyBytes,
		OperationTimeout: operationTimeout, ReadinessTTL: readinessTTL, ShutdownTimeout: shutdownTimeout,
	}
	if bodyErr != nil || operationErr != nil || readinessErr != nil || shutdownErr != nil || !validProductionControlConfig(config) {
		return productionControlConfig{}, errControlUnavailable
	}
	return config, nil
}

func validProductionControlConfig(config productionControlConfig) bool {
	if config.EnrollmentEnabled {
		if !migrations.IsGatewayBootstrapProfileChecksum(config.EnrollmentProfileChecksum) {
			return false
		}
	} else if config.EnrollmentProfileChecksum != "" {
		return false
	}
	if config.InstallationACKEnabled {
		if !migrations.IsGatewayInstallationProfileChecksum(config.InstallationProfileChecksum) {
			return false
		}
	} else if config.InstallationProfileChecksum != "" {
		return false
	}
	database, err := url.Parse(config.DatabaseURL)
	if err != nil || database.String() != config.DatabaseURL || database.Scheme != "postgres" && database.Scheme != "postgresql" || database.User == nil || database.User.Username() == "" || database.Hostname() == "" || database.Path == "" || database.Fragment != "" {
		return false
	}
	query := database.Query()
	return len(query) == 1 && len(query["sslmode"]) == 1 && query.Get("sslmode") == "verify-full" &&
		config.MaximumBodyBytes >= 1024 && config.MaximumBodyBytes <= 64*1024 &&
		config.OperationTimeout >= 50*time.Millisecond && config.OperationTimeout <= 10*time.Second &&
		config.ReadinessTTL >= time.Second && config.ReadinessTTL <= 5*time.Minute &&
		config.ShutdownTimeout >= time.Second && config.ShutdownTimeout <= time.Minute
}
