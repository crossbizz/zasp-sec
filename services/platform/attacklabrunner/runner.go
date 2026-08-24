package attacklabrunner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/attacklabproxy"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrRunner = errors.New("attack lab runner failed")

type Config struct {
	OrganizationID, WorkspaceID, EnvironmentID string
	RunID, Destination                         string
	SuccessCriterion                           string
	ExpectedSideEffects                        []string
	InputDigest                                string
	ProxyEndpoint, EgressToken                 string
	Timeout                                    time.Duration
}

type Outcome struct {
	SchemaVersion     string `json:"schema_version"`
	CriterionObserved bool   `json:"criterion_observed"`
	CanaryTouched     bool   `json:"canary_touched"`
	GatewayEvidence   string `json:"gateway_evidence"`
	EgressEvidence    string `json:"egress_evidence"`
	CloudEvidence     string `json:"cloud_evidence"`
}

type canaryRequest struct {
	SchemaVersion       string   `json:"schema_version"`
	OrganizationID      string   `json:"organization_id"`
	WorkspaceID         string   `json:"workspace_id"`
	EnvironmentID       string   `json:"environment_id"`
	RunID               string   `json:"run_id"`
	Destination         string   `json:"destination"`
	InputDigest         string   `json:"input_digest"`
	SuccessCriterion    string   `json:"success_criterion"`
	ExpectedSideEffects []string `json:"expected_side_effects"`
}

type canaryResponse struct {
	SchemaVersion     string `json:"schema_version"`
	OrganizationID    string `json:"organization_id"`
	WorkspaceID       string `json:"workspace_id"`
	EnvironmentID     string `json:"environment_id"`
	RunID             string `json:"run_id"`
	InputDigest       string `json:"input_digest"`
	CriterionObserved bool   `json:"criterion_observed"`
	CanaryTouched     bool   `json:"canary_touched"`
	Evidence          string `json:"evidence"`
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Runner struct {
	config Config
	client HTTPClient
}

func New(config Config, client HTTPClient) (*Runner, error) {
	if !validConfig(config) || client == nil {
		return nil, ErrRunner
	}
	config.ExpectedSideEffects = append([]string(nil), config.ExpectedSideEffects...)
	return &Runner{config: config, client: client}, nil
}

func (runner *Runner) Run(ctx context.Context) (Outcome, error) {
	if runner == nil || ctx == nil || ctx.Err() != nil || !validConfig(runner.config) || runner.client == nil {
		return Outcome{}, ErrRunner
	}
	canaryBody, err := json.Marshal(canaryRequest{
		SchemaVersion: "attack-lab-canary-request-v1", OrganizationID: runner.config.OrganizationID, WorkspaceID: runner.config.WorkspaceID, EnvironmentID: runner.config.EnvironmentID,
		RunID: runner.config.RunID, Destination: runner.config.Destination, InputDigest: runner.config.InputDigest, SuccessCriterion: runner.config.SuccessCriterion, ExpectedSideEffects: append([]string(nil), runner.config.ExpectedSideEffects...),
	})
	if err != nil || len(canaryBody) > 16<<10 {
		return Outcome{}, ErrRunner
	}
	envelope, err := json.Marshal(attacklabproxy.Request{Path: "/v1/attack-lab/canary", ContentType: "application/json", BodyBase64: base64.RawURLEncoding.EncodeToString(canaryBody)})
	if err != nil || len(envelope) > 32<<10 {
		return Outcome{}, ErrRunner
	}
	bounded, cancel := context.WithTimeout(ctx, runner.config.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodPost, runner.config.ProxyEndpoint, bytes.NewReader(envelope))
	if err != nil {
		return Outcome{}, ErrRunner
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+runner.config.EgressToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "zasp-attack-lab-runner/1")
	response, err := runner.client.Do(request)
	if err != nil || bounded.Err() != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return Outcome{}, ErrRunner
	}
	defer response.Body.Close()
	mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if mediaErr != nil || mediaType != "application/json" || len(parameters) != 0 || response.StatusCode != http.StatusOK || readErr != nil || len(responseBody) < 2 || len(responseBody) > 64<<10 {
		clear(responseBody)
		return Outcome{}, ErrRunner
	}
	defer clear(responseBody)
	var proxyResponse attacklabproxy.Response
	if !decodeExactRunnerJSON(responseBody, &proxyResponse) || proxyResponse.StatusCode != http.StatusOK || proxyResponse.ContentType != "application/json" || len(proxyResponse.BodyBase64) < 2 || len(proxyResponse.BodyBase64) > 48<<10 {
		return Outcome{}, ErrRunner
	}
	targetBody, err := base64.RawURLEncoding.DecodeString(proxyResponse.BodyBase64)
	if err != nil || len(targetBody) < 2 || len(targetBody) > 32<<10 {
		clear(targetBody)
		return Outcome{}, ErrRunner
	}
	defer clear(targetBody)
	var target canaryResponse
	if !decodeExactRunnerJSON(targetBody, &target) || target.SchemaVersion != "attack-lab-canary-v1" || target.OrganizationID != runner.config.OrganizationID || target.WorkspaceID != runner.config.WorkspaceID || target.EnvironmentID != runner.config.EnvironmentID || target.RunID != runner.config.RunID || target.InputDigest != runner.config.InputDigest || !validRunnerText(target.Evidence, 256) {
		return Outcome{}, ErrRunner
	}
	return Outcome{SchemaVersion: "attack-lab-outcome-v1", CriterionObserved: target.CriterionObserved, CanaryTouched: target.CanaryTouched, GatewayEvidence: "proxy authorized the exact run and destination", EgressEvidence: "one HTTPS POST reached " + runner.config.Destination, CloudEvidence: target.Evidence}, nil
}

func validConfig(config Config) bool {
	for _, value := range []string{config.OrganizationID, config.WorkspaceID, config.EnvironmentID, config.RunID} {
		id, err := domain.ParseProductID(value)
		if err != nil || id.IsZero() {
			return false
		}
	}
	organization, _ := domain.ParseProductID(config.OrganizationID)
	workspace, _ := domain.ParseProductID(config.WorkspaceID)
	environment, _ := domain.ParseProductID(config.EnvironmentID)
	if _, err := domain.NewScope(organization, workspace, environment); err != nil {
		return false
	}
	digest, err := hex.DecodeString(config.InputDigest)
	validDigest := err == nil && len(digest) == 32 && !bytes.Equal(digest, make([]byte, 32)) && strings.ToLower(config.InputDigest) == config.InputDigest
	clear(digest)
	if !validDigest || !validRunnerDestination(config.Destination) || config.ProxyEndpoint != "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress" || !validRunnerSecret(config.EgressToken, 16, 4096) || !validRunnerText(config.SuccessCriterion, 512) || len(config.ExpectedSideEffects) < 1 || len(config.ExpectedSideEffects) > 16 || config.Timeout < time.Second || config.Timeout > 30*time.Second {
		return false
	}
	for _, value := range config.ExpectedSideEffects {
		if !validRunnerText(value, 256) {
			return false
		}
	}
	return true
}

func ValidConfig(config Config) bool { return validConfig(config) }

func decodeExactRunnerJSON(raw []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination) == nil && errors.Is(decoder.Decode(new(any)), io.EOF)
}

func validRunnerText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validRunnerSecret(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.TrimSpace(value) == value && !regexp.MustCompile(`[[:space:][:cntrl:]]`).MatchString(value)
}

func validRunnerDestination(value string) bool {
	if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}
