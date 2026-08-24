package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/attacklabrunner"
)

var errRuntimeUnavailable = errors.New("attack lab runner unavailable")

type runtimeConfig struct {
	Runner          attacklabrunner.Config
	ProxyCAFile     string
	TerminationPath string
}

func loadRuntimeConfig(getenv func(string) string) (runtimeConfig, error) {
	if getenv == nil {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	timeout, timeoutErr := time.ParseDuration(getenv("ZASP_ATTACK_LAB_REQUEST_TIMEOUT"))
	var sideEffects []string
	rawSideEffects := []byte(getenv("ZASP_ATTACK_LAB_EXPECTED_SIDE_EFFECTS"))
	decoder := json.NewDecoder(bytes.NewReader(rawSideEffects))
	if decoder.Decode(&sideEffects) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	config := runtimeConfig{Runner: attacklabrunner.Config{
		OrganizationID: getenv("ZASP_ATTACK_LAB_ORGANIZATION_ID"), WorkspaceID: getenv("ZASP_ATTACK_LAB_WORKSPACE_ID"), EnvironmentID: getenv("ZASP_ATTACK_LAB_ENVIRONMENT_ID"), RunID: getenv("ZASP_ATTACK_LAB_RUN_ID"), Destination: getenv("ZASP_ATTACK_LAB_DESTINATION"),
		SuccessCriterion: getenv("ZASP_ATTACK_LAB_SUCCESS_CRITERION"), ExpectedSideEffects: sideEffects, InputDigest: getenv("ZASP_ATTACK_LAB_INPUT_DIGEST"), ProxyEndpoint: getenv("ZASP_ATTACK_LAB_EGRESS_PROXY"), EgressToken: getenv("ZASP_ATTACK_LAB_EGRESS_TOKEN"), Timeout: timeout,
	}, ProxyCAFile: getenv("ZASP_ATTACK_LAB_EGRESS_PROXY_CA_FILE"), TerminationPath: getenv("ZASP_ATTACK_LAB_TERMINATION_PATH")}
	if timeoutErr != nil || !validRuntimeConfig(config) {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	return config, nil
}

func validRuntimeConfig(config runtimeConfig) bool {
	return attacklabrunner.ValidConfig(config.Runner) && config.ProxyCAFile == "/var/run/secrets/zasp-attack-lab/proxy-ca.crt" && config.TerminationPath == "/dev/termination-log"
}
