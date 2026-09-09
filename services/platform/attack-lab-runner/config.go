package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/attacklabrunner"
)

var errRuntimeUnavailable = errors.New("attack lab runner unavailable")

type runtimeConfig struct {
	TestRoleARN       string
	IdentityTokenFile string
	AWSRegion         string
	RegionalSTS       bool
	MetadataDisabled  bool
	Runner            attacklabrunner.Config
	ProxyCAFile       string
	TerminationPath   string
}

func loadRuntimeConfig(getenv func(string) string) (runtimeConfig, error) {
	if getenv == nil {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS"} {
		if getenv(name) != "" {
			return runtimeConfig{}, errRuntimeUnavailable
		}
	}
	timeout, timeoutErr := time.ParseDuration(getenv("ZASP_ATTACK_LAB_REQUEST_TIMEOUT"))
	var sideEffects []string
	rawSideEffects := []byte(getenv("ZASP_ATTACK_LAB_EXPECTED_SIDE_EFFECTS"))
	decoder := json.NewDecoder(bytes.NewReader(rawSideEffects))
	if decoder.Decode(&sideEffects) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	config := runtimeConfig{TestRoleARN: getenv("AWS_ROLE_ARN"), IdentityTokenFile: getenv("AWS_WEB_IDENTITY_TOKEN_FILE"), AWSRegion: getenv("AWS_REGION"), RegionalSTS: getenv("AWS_STS_REGIONAL_ENDPOINTS") == "regional", MetadataDisabled: getenv("AWS_EC2_METADATA_DISABLED") == "true", Runner: attacklabrunner.Config{
		OrganizationID: getenv("ZASP_ATTACK_LAB_ORGANIZATION_ID"), WorkspaceID: getenv("ZASP_ATTACK_LAB_WORKSPACE_ID"), EnvironmentID: getenv("ZASP_ATTACK_LAB_ENVIRONMENT_ID"), RunID: getenv("ZASP_ATTACK_LAB_RUN_ID"), Destination: getenv("ZASP_ATTACK_LAB_DESTINATION"),
		SuccessCriterion: getenv("ZASP_ATTACK_LAB_SUCCESS_CRITERION"), ExpectedSideEffects: sideEffects, InputDigest: getenv("ZASP_ATTACK_LAB_INPUT_DIGEST"), ProxyEndpoint: getenv("ZASP_ATTACK_LAB_EGRESS_PROXY"), EgressToken: getenv("ZASP_ATTACK_LAB_EGRESS_TOKEN"), Timeout: timeout,
	}, ProxyCAFile: getenv("ZASP_ATTACK_LAB_EGRESS_PROXY_CA_FILE"), TerminationPath: getenv("ZASP_ATTACK_LAB_TERMINATION_PATH")}
	if timeoutErr != nil || !validRuntimeConfig(config) {
		return runtimeConfig{}, errRuntimeUnavailable
	}
	return config, nil
}

func validRuntimeConfig(config runtimeConfig) bool {
	if !regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]+-attack-lab-runner-test$`).MatchString(config.TestRoleARN) || config.IdentityTokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || !regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$`).MatchString(config.AWSRegion) || !config.RegionalSTS || !config.MetadataDisabled {
		return false
	}
	return attacklabrunner.ValidConfig(config.Runner) && config.ProxyCAFile == "/var/run/secrets/zasp-attack-lab/proxy-ca.crt" && config.TerminationPath == "/dev/termination-log"
}
