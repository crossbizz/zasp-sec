package attacklabproxy

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
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklab"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrUnavailable = errors.New("attack lab proxy unavailable")

type Config struct {
	SigningKey           []byte
	MaximumRequestBytes  int64
	MaximumResponseBytes int64
	Clock                func() time.Time
}

type Request struct {
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	BodyBase64  string `json:"body_base64"`
}

type Response struct {
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type"`
	BodyBase64  string `json:"body_base64"`
}

type canaryForwardBody struct {
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

type ForwardRequest struct {
	Destination         string
	CredentialReference string
	RunID               string
	Method              string
	Path                string
	ContentType         string
	Body                []byte
}

type ForwardResult struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

type EgressResolver interface {
	Ready(context.Context) error
	ResolveAttackLabEgress(context.Context, domain.Scope, string, string) (apiserver.AttackLabEgressAuthority, error)
}

type Forwarder interface {
	Forward(context.Context, ForwardRequest) (ForwardResult, error)
}

type Handler struct {
	keyMu     sync.RWMutex
	closed    bool
	config    Config
	resolver  EgressResolver
	forwarder Forwarder
}

func NewHandler(config Config, resolver EgressResolver, forwarder Forwarder) (*Handler, error) {
	if !validConfig(config) || resolver == nil || forwarder == nil {
		return nil, ErrUnavailable
	}
	config.SigningKey = append([]byte(nil), config.SigningKey...)
	return &Handler{config: config, resolver: resolver, forwarder: forwarder}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setProxyResponseHeaders(response.Header())
	if handler == nil || request == nil || request.Context().Err() != nil || request.Method != http.MethodPost || request.URL.Path != "/v1/egress" || request.URL.RawQuery != "" || request.Host == "" {
		writeProxyError(response, http.StatusNotFound)
		return
	}
	mediaType, parameters, mediaErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
	authorization := request.Header.Get("Authorization")
	if mediaErr != nil || mediaType != "application/json" || len(parameters) != 0 || !strings.HasPrefix(authorization, "Bearer ") || strings.Count(authorization, " ") != 1 {
		writeProxyError(response, http.StatusForbidden)
		return
	}
	now := handler.config.Clock()
	handler.keyMu.RLock()
	if handler.closed {
		handler.keyMu.RUnlock()
		writeProxyError(response, http.StatusForbidden)
		return
	}
	grant, err := attacklab.VerifyEgressCapability(handler.config.SigningKey, strings.TrimPrefix(authorization, "Bearer "), now)
	handler.keyMu.RUnlock()
	if err != nil {
		writeProxyError(response, http.StatusForbidden)
		return
	}
	// Token expiry bounds all work, including a blocked durable resolver.
	capabilityCtx, cancelCapability := context.WithTimeout(request.Context(), grant.ExpiresAt.Sub(now))
	defer cancelCapability()
	request = request.WithContext(capabilityCtx)
	body, err := io.ReadAll(io.LimitReader(request.Body, handler.config.MaximumRequestBytes+1))
	if err != nil || int64(len(body)) > handler.config.MaximumRequestBytes {
		writeProxyError(response, http.StatusRequestEntityTooLarge)
		return
	}
	var input Request
	if !decodeExactJSON(body, &input) || input.Path != "/v1/attack-lab/canary" || input.ContentType != "application/json" || len(input.BodyBase64) < 2 || len(input.BodyBase64) > 24<<10 {
		writeProxyError(response, http.StatusBadRequest)
		return
	}
	forwardBody, decodeErr := base64.RawURLEncoding.DecodeString(input.BodyBase64)
	if decodeErr != nil || len(forwardBody) < 2 || len(forwardBody) > 16<<10 || !json.Valid(forwardBody) || !validCanaryForwardBody(forwardBody, grant) {
		clear(forwardBody)
		writeProxyError(response, http.StatusBadRequest)
		return
	}
	defer clear(forwardBody)
	authority, resolveErr := handler.resolver.ResolveAttackLabEgress(request.Context(), grant.Scope, grant.RunID, grant.Destination)
	current := handler.config.Clock()
	if resolveErr != nil || request.Context().Err() != nil || current.Before(now) || !grant.ExpiresAt.After(current) || !authorityMatchesGrant(authority, grant, current) {
		writeProxyError(response, http.StatusForbidden)
		return
	}
	// Durable lease authority can expire before the signed capability. Credential
	// retrieval, DNS and HTTP must share that shorter remaining budget.
	forwardCtx, cancelForward := context.WithTimeout(request.Context(), authority.ExpiresAt.Sub(current))
	defer cancelForward()
	result, forwardErr := handler.forwarder.Forward(forwardCtx, ForwardRequest{Destination: grant.Destination, CredentialReference: authority.CredentialReference, RunID: grant.RunID, Method: http.MethodPost, Path: input.Path, ContentType: input.ContentType, Body: append([]byte(nil), forwardBody...)})
	completed := handler.config.Clock()
	if forwardErr != nil || forwardCtx.Err() != nil || completed.Before(current) || !authority.ExpiresAt.After(completed) || !grant.ExpiresAt.After(completed) || !validForwardResult(result, handler.config.MaximumResponseBytes) {
		writeProxyError(response, http.StatusBadGateway)
		return
	}
	responseBody := append([]byte(nil), result.Body...)
	defer clear(responseBody)
	output, marshalErr := json.Marshal(Response{StatusCode: result.StatusCode, ContentType: result.ContentType, BodyBase64: base64.RawURLEncoding.EncodeToString(responseBody)})
	if marshalErr != nil || int64(len(output)) > handler.config.MaximumResponseBytes*2 {
		writeProxyError(response, http.StatusBadGateway)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(output)
}

func validCanaryForwardBody(raw []byte, grant attacklab.EgressGrant) bool {
	var body canaryForwardBody
	if !decodeExactJSON(raw, &body) || body.SchemaVersion != "attack-lab-canary-request-v1" || body.OrganizationID != grant.Scope.OrganizationID().String() || body.WorkspaceID != grant.Scope.WorkspaceID().String() || body.EnvironmentID != grant.Scope.EnvironmentID().String() || body.RunID != grant.RunID || body.Destination != grant.Destination || body.InputDigest != hex.EncodeToString(grant.InputDigest[:]) || !validProxyText(body.SuccessCriterion, 512) || len(body.ExpectedSideEffects) < 1 || len(body.ExpectedSideEffects) > 16 {
		return false
	}
	for _, value := range body.ExpectedSideEffects {
		if !validProxyText(value, 256) {
			return false
		}
	}
	return true
}

func validProxyText(value string, maximum int) bool {
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

func (handler *Handler) Close() {
	if handler != nil {
		handler.keyMu.Lock()
		defer handler.keyMu.Unlock()
		handler.closed = true
		clear(handler.config.SigningKey)
	}
}

func validConfig(config Config) bool {
	if config.MaximumRequestBytes != 32<<10 || config.MaximumResponseBytes != 32<<10 || config.Clock == nil || len(config.SigningKey) < 32 || len(config.SigningKey) > 64 {
		return false
	}
	now := config.Clock()
	if now.IsZero() || now.Location() != time.UTC {
		return false
	}
	var different byte
	for _, value := range config.SigningKey[1:] {
		different |= value ^ config.SigningKey[0]
	}
	return different != 0
}

func authorityMatchesGrant(authority apiserver.AttackLabEgressAuthority, grant attacklab.EgressGrant, now time.Time) bool {
	return authority.OrganizationID == grant.Scope.OrganizationID().String() && authority.WorkspaceID == grant.Scope.WorkspaceID().String() && authority.EnvironmentID == grant.Scope.EnvironmentID().String() && authority.RunID == grant.RunID && authority.Destination == grant.Destination && targetCredentialReferenceRE.MatchString(authority.CredentialReference) && len(authority.Methods) == 1 && authority.Methods[0] == "POST" && !authority.ExpiresAt.IsZero() && authority.ExpiresAt.Location() == time.UTC && authority.ExpiresAt.After(now) && !authority.ExpiresAt.After(grant.ExpiresAt)
}

func validForwardResult(result ForwardResult, maximum int64) bool {
	mediaType, parameters, err := mime.ParseMediaType(result.ContentType)
	return result.StatusCode >= 200 && result.StatusCode <= 599 && mediaType == "application/json" && len(parameters) == 0 && len(result.Body) >= 2 && int64(len(result.Body)) <= maximum && json.Valid(result.Body) && err == nil
}

func decodeExactJSON(raw []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination) == nil && errors.Is(decoder.Decode(new(any)), io.EOF)
}

func setProxyResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
}

func writeProxyError(response http.ResponseWriter, status int) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	body, _ := json.Marshal(struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}{Type: "about:blank", Title: "Attack Lab egress rejected", Status: status})
	_, _ = response.Write(body)
}
