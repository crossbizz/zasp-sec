package main

import (
	"errors"
	"net/url"
	"path/filepath"
	"strconv"
	"time"
)

var errSensorConfig = errors.New("sensor agent configuration rejected")

type sensorAgentConfig struct {
	ControlPlaneURL  string
	TokenFile        string
	LogFile          string
	CursorFile       string
	BatchSize        int
	MaximumProcesses int
	PollInterval     time.Duration
	OperationTimeout time.Duration
	ShutdownTimeout  time.Duration
}

func loadSensorAgentConfig(getenv func(string) string) (sensorAgentConfig, error) {
	if getenv == nil {
		return sensorAgentConfig{}, errSensorConfig
	}
	config := sensorAgentConfig{
		ControlPlaneURL: getenv("ZASP_SENSOR_CONTROL_PLANE_URL"), TokenFile: getenv("ZASP_SENSOR_TOKEN_FILE"),
		LogFile: getenv("ZASP_TETRAGON_LOG_FILE"), CursorFile: getenv("ZASP_SENSOR_CURSOR_FILE"),
	}
	var err error
	if config.BatchSize, err = parseBoundedInteger(getenv("ZASP_SENSOR_BATCH_SIZE"), 1, 1000); err != nil {
		return sensorAgentConfig{}, errSensorConfig
	}
	if config.MaximumProcesses, err = parseBoundedInteger(getenv("ZASP_SENSOR_MAX_PROCESSES"), 1, 100_000); err != nil {
		return sensorAgentConfig{}, errSensorConfig
	}
	if config.PollInterval, err = parseBoundedDuration(getenv("ZASP_SENSOR_POLL_INTERVAL"), 50*time.Millisecond, 30*time.Second); err != nil {
		return sensorAgentConfig{}, errSensorConfig
	}
	if config.OperationTimeout, err = parseBoundedDuration(getenv("ZASP_SENSOR_OPERATION_TIMEOUT"), time.Second, 30*time.Second); err != nil {
		return sensorAgentConfig{}, errSensorConfig
	}
	if config.ShutdownTimeout, err = parseBoundedDuration(getenv("ZASP_SENSOR_SHUTDOWN_TIMEOUT"), 5*time.Second, time.Minute); err != nil {
		return sensorAgentConfig{}, errSensorConfig
	}
	if !validSensorAgentConfig(config) {
		return sensorAgentConfig{}, errSensorConfig
	}
	return config, nil
}

func validSensorAgentConfig(config sensorAgentConfig) bool {
	parsed, err := url.Parse(config.ControlPlaneURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Port() != "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if !validAbsolute(config.TokenFile) || !validAbsolute(config.LogFile) || !validAbsolute(config.CursorFile) {
		return false
	}
	if config.TokenFile == config.LogFile || config.TokenFile == config.CursorFile || config.LogFile == config.CursorFile {
		return false
	}
	return config.BatchSize >= 1 && config.BatchSize <= 1000 && config.MaximumProcesses >= 1 && config.MaximumProcesses <= 100_000 && config.PollInterval >= 50*time.Millisecond && config.PollInterval <= 30*time.Second && config.OperationTimeout >= time.Second && config.OperationTimeout <= 30*time.Second && config.ShutdownTimeout >= 5*time.Second && config.ShutdownTimeout <= time.Minute
}

func validAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && filepath.Base(value) != "." && filepath.Base(value) != string(filepath.Separator)
}

func parseBoundedInteger(value string, minimum, maximum int) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || strconv.Itoa(parsed) != value || parsed < minimum || parsed > maximum {
		return 0, errSensorConfig
	}
	return parsed, nil
}

func parseBoundedDuration(value string, minimum, maximum time.Duration) (time.Duration, error) {
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed.String() != value || parsed < minimum || parsed > maximum {
		return 0, errSensorConfig
	}
	return parsed, nil
}
