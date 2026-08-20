package main

import (
	"net/url"
	"strconv"
	"time"
)

type productionControlConfig struct {
	DatabaseURL      string
	MaximumBodyBytes int64
	OperationTimeout time.Duration
	ReadinessTTL     time.Duration
	ShutdownTimeout  time.Duration
}

func loadProductionControlConfig(getenv func(string) string) (productionControlConfig, error) {
	if getenv == nil {
		return productionControlConfig{}, errControlUnavailable
	}
	maximumBodyBytes, bodyErr := strconv.ParseInt(getenv("ZASP_GATEWAY_CONTROL_MAX_BODY_BYTES"), 10, 64)
	operationTimeout, operationErr := time.ParseDuration(getenv("ZASP_GATEWAY_CONTROL_OPERATION_TIMEOUT"))
	readinessTTL, readinessErr := time.ParseDuration(getenv("ZASP_GATEWAY_CONTROL_READINESS_TTL"))
	shutdownTimeout, shutdownErr := time.ParseDuration(getenv("ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT"))
	config := productionControlConfig{
		DatabaseURL: getenv("ZASP_DATABASE_URL"), MaximumBodyBytes: maximumBodyBytes,
		OperationTimeout: operationTimeout, ReadinessTTL: readinessTTL, ShutdownTimeout: shutdownTimeout,
	}
	if bodyErr != nil || operationErr != nil || readinessErr != nil || shutdownErr != nil || !validProductionControlConfig(config) {
		return productionControlConfig{}, errControlUnavailable
	}
	return config, nil
}

func validProductionControlConfig(config productionControlConfig) bool {
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
