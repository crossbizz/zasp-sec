package main

import (
	"regexp"
	"strconv"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var globalRequestIDPattern = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var globalCorrelationPattern = regexp.MustCompile(`^[!-~]{1,128}$`)

func loadGlobalExecutionControlRequest(getenv func(string) string) (migrations.GlobalExecutionControlRequest, error) {
	if getenv == nil {
		return migrations.GlobalExecutionControlRequest{}, errInvalidMigrationCommand
	}
	enabled := getenv("ZASP_SECURITY_AGENT_GLOBAL_ENABLED")
	version := getenv("ZASP_SECURITY_AGENT_GLOBAL_EXPECTED_VERSION")
	request := migrations.GlobalExecutionControlRequest{Enabled: enabled == "true", RequestID: getenv("ZASP_SECURITY_AGENT_GLOBAL_REQUEST_ID"), CorrelationID: getenv("ZASP_SECURITY_AGENT_GLOBAL_CORRELATION_ID")}
	number, err := strconv.ParseInt(version, 10, 64)
	if err != nil || number < 1 || number == 1<<63-1 || strconv.FormatInt(number, 10) != version || (enabled != "true" && enabled != "false") || !globalRequestIDPattern.MatchString(request.RequestID) || !globalCorrelationPattern.MatchString(request.CorrelationID) {
		return migrations.GlobalExecutionControlRequest{}, errInvalidMigrationCommand
	}
	request.ExpectedVersion = number
	return request, nil
}

func parseGlobalExecutionControlCommand(arguments []string, getenv func(string) string) (*migrations.GlobalExecutionControlRequest, error) {
	if len(arguments) != 1 {
		return nil, errInvalidMigrationCommand
	}
	switch arguments[0] {
	case "security-agent-global-read":
		return nil, nil
	case "security-agent-global-set":
		request, err := loadGlobalExecutionControlRequest(getenv)
		if err != nil {
			return nil, err
		}
		return &request, nil
	default:
		return nil, errInvalidMigrationCommand
	}
}
