package gatewaycontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const (
	requestSignaturePrefix = "ZaspGatewayV1 "
	requestSigningContext  = "zasp-runtime-gateway-request-v1"
	maximumResponseBytes   = 1024 * 1024
	maximumClockSkew       = 30 * time.Second
)

var errHTTPControl = errors.New("gateway control unavailable")

type HTTPHandlerConfig struct {
	Repository       Repository
	Clock            func() time.Time
	OperationTimeout time.Duration
	MaximumBodyBytes int64
}

type httpHandler struct {
	repository       Repository
	clock            func() time.Time
	timeout          time.Duration
	maximumBodyBytes int64
}

type authorityPayload struct {
	OrganizationID       string    `json:"organization_id"`
	WorkspaceID          string    `json:"workspace_id"`
	EnvironmentID        string    `json:"environment_id"`
	DeviceID             string    `json:"device_id"`
	DeviceVersion        uint64    `json:"device_version"`
	ReplayFloor          uint64    `json:"replay_floor"`
	CredentialID         string    `json:"credential_id"`
	CredentialGeneration uint64    `json:"credential_generation"`
	KeyID                string    `json:"key_id"`
	Algorithm            string    `json:"algorithm"`
	PublicKey            string    `json:"public_key"`
	Audience             string    `json:"audience"`
	ExpiresAt            time.Time `json:"expires_at"`
}

func NewHTTPHandler(config HTTPHandlerConfig) (http.Handler, error) {
	if config.Repository == nil || config.Clock == nil || config.OperationTimeout < 50*time.Millisecond || config.OperationTimeout > 10*time.Second || config.MaximumBodyBytes < 1024 || config.MaximumBodyBytes > 64*1024 {
		return nil, errHTTPControl
	}
	return &httpHandler{repository: config.Repository, clock: config.Clock, timeout: config.OperationTimeout, maximumBodyBytes: config.MaximumBodyBytes}, nil
}

func (handler *httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.repository == nil || request == nil || request.URL == nil || request.URL.EscapedPath() != request.URL.Path {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	readyOperation, readyCancel := context.WithTimeout(request.Context(), handler.timeout)
	readyErr := handler.repository.Ready(readyOperation)
	readyContextErr := readyOperation.Err()
	readyCancel()
	if readyErr != nil || readyContextErr != nil {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	body, ok := handler.readBody(writer, request)
	if !ok {
		return
	}
	authority, ok := handler.authenticate(request, body)
	if !ok {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	operation, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	switch {
	case request.Method == http.MethodGet && request.URL.Path == AuthorityPath && request.URL.RawQuery == "" && len(body) == 0:
		handler.writeAuthority(writer, authority)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, PolicyPathPrefix) && len(body) == 0:
		handler.writePolicy(operation, writer, request, authority)
	case request.Method == http.MethodPost && request.URL.Path == DecisionPath && request.URL.RawQuery == "" && request.Header.Get("Content-Type") == JSONMediaType:
		handler.writeDecision(operation, writer, body, authority)
	default:
		writeError(writer, http.StatusNotFound, "not_found")
	}
}

func (handler *httpHandler) readBody(writer http.ResponseWriter, request *http.Request) ([]byte, bool) {
	if request.Method == http.MethodGet {
		if request.Body == nil {
			return nil, true
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 1))
		if err != nil || len(body) != 0 {
			writeError(writer, http.StatusBadRequest, "invalid_request")
			return nil, false
		}
		return nil, true
	}
	request.Body = http.MaxBytesReader(writer, request.Body, handler.maximumBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) == 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return body, true
}

func (handler *httpHandler) authenticate(request *http.Request, body []byte) (Authority, bool) {
	if request.Context().Err() != nil || hasForbiddenScopeHeader(request.Header) ||
		len(request.Header.Values(AuthorizationHeader)) != 1 || len(request.Header.Values(TimestampHeader)) != 1 ||
		len(request.Header.Values(ContentSHA256Header)) != 1 || len(request.Header.Values(SignatureHeader)) != 1 {
		return Authority{}, false
	}
	authorization := request.Header.Get(AuthorizationHeader)
	if !strings.HasPrefix(authorization, requestSignaturePrefix) {
		return Authority{}, false
	}
	credentialID := strings.TrimPrefix(authorization, requestSignaturePrefix)
	if !validProductID(credentialID) {
		return Authority{}, false
	}
	timestamp, err := time.Parse(time.RFC3339, request.Header.Get(TimestampHeader))
	now := handler.clock()
	if err != nil || timestamp.Location() != time.UTC || timestamp.Nanosecond() != 0 || timestamp.Format(time.RFC3339) != request.Header.Get(TimestampHeader) || !validTime(now) || timestamp.Before(now.Add(-maximumClockSkew)) || timestamp.After(now.Add(maximumClockSkew)) {
		return Authority{}, false
	}
	bodyDigest := sha256.Sum256(body)
	digestText := hex.EncodeToString(bodyDigest[:])
	providedDigest := request.Header.Get(ContentSHA256Header)
	if len(providedDigest) != sha256.Size*2 || subtle.ConstantTimeCompare([]byte(providedDigest), []byte(digestText)) != 1 {
		return Authority{}, false
	}
	operation, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	authority, err := handler.repository.Authority(operation, credentialID)
	if err != nil || !validAuthority(authority, credentialID, now) {
		return Authority{}, false
	}
	signatureText := request.Header.Get(SignatureHeader)
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != signatureText {
		return Authority{}, false
	}
	canonical, err := canonicalRequest(request, credentialID, timestamp, digestText)
	if err != nil || !ed25519.Verify(authority.PublicKey, canonical, signature) {
		return Authority{}, false
	}
	return cloneAuthority(authority), true
}

func (handler *httpHandler) writeAuthority(writer http.ResponseWriter, authority Authority) {
	payload := authorityPayload{
		OrganizationID: authority.OrganizationID, WorkspaceID: authority.WorkspaceID, EnvironmentID: authority.EnvironmentID,
		DeviceID: authority.DeviceID, DeviceVersion: authority.DeviceVersion, ReplayFloor: authority.ReplayFloor,
		CredentialID: authority.CredentialID, CredentialGeneration: authority.CredentialGeneration, KeyID: authority.KeyID,
		Algorithm: authority.Algorithm, PublicKey: base64.RawURLEncoding.EncodeToString(authority.PublicKey), Audience: authority.Audience, ExpiresAt: authority.ExpiresAt,
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (handler *httpHandler) writePolicy(ctx context.Context, writer http.ResponseWriter, request *http.Request, authority Authority) {
	environmentID := strings.TrimPrefix(request.URL.Path, PolicyPathPrefix)
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || query.Encode() != request.URL.RawQuery || len(query) != 1 || len(query["after_sequence"]) != 1 || environmentID != authority.EnvironmentID {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	after, err := strconv.ParseUint(query.Get("after_sequence"), 10, 63)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	envelope, err := handler.repository.Policy(ctx, authority.CredentialID, after)
	if err != nil || ctx.Err() != nil {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if envelope == nil {
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if envelope.OrganizationID != authority.OrganizationID || envelope.WorkspaceID != authority.WorkspaceID || envelope.EnvironmentID != authority.EnvironmentID || envelope.DeviceID != authority.DeviceID || envelope.Audience != PolicyAudience || envelope.Sequence <= after {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, envelope)
}

func (handler *httpHandler) writeDecision(ctx context.Context, writer http.ResponseWriter, body []byte, authority Authority) {
	var event DecisionEvent
	if strictJSON(body, &event) != nil || !validDecisionEvent(event) || event.CredentialID != authority.CredentialID || event.DeviceID != authority.DeviceID {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := handler.repository.Record(ctx, cloneDecisionEvent(event)); errors.Is(err, ErrRecordExpired) && ctx.Err() == nil {
		writeError(writer, http.StatusUnprocessableEntity, "record_window_expired")
		return
	} else if err != nil || ctx.Err() != nil {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func SignRequest(request *http.Request, body []byte, credentialID string, privateKey ed25519.PrivateKey, now time.Time) error {
	if request == nil || request.URL == nil || !validProductID(credentialID) || len(privateKey) != ed25519.PrivateKeySize || !validTime(now) {
		return errHTTPControl
	}
	digest := sha256.Sum256(body)
	digestText := hex.EncodeToString(digest[:])
	canonical, err := canonicalRequest(request, credentialID, now, digestText)
	if err != nil {
		return errHTTPControl
	}
	signature := ed25519.Sign(privateKey, canonical)
	request.Header.Set(AuthorizationHeader, requestSignaturePrefix+credentialID)
	request.Header.Set(TimestampHeader, now.Format(time.RFC3339))
	request.Header.Set(ContentSHA256Header, digestText)
	request.Header.Set(SignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	return nil
}

func canonicalRequest(request *http.Request, credentialID string, timestamp time.Time, digest string) ([]byte, error) {
	if request == nil || request.URL == nil {
		return nil, errHTTPControl
	}
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPost || request.URL.EscapedPath() != request.URL.Path ||
		!boundedText(authority, 253) || strings.Contains(authority, "@") || request.URL.Fragment != "" || !validProductID(credentialID) || !validTime(timestamp) || len(digest) != sha256.Size*2 {
		return nil, errHTTPControl
	}
	target := request.URL.Path
	if request.URL.RawQuery != "" {
		target += "?" + request.URL.RawQuery
	}
	return []byte(strings.Join([]string{requestSigningContext, request.Method, authority, target, credentialID, timestamp.Format(time.RFC3339), digest}, "\n")), nil
}

func hasForbiddenScopeHeader(header http.Header) bool {
	for _, name := range []string{"X-Zasp-Organization", "X-Zasp-Workspace", "X-Zasp-Environment", "X-Zasp-Scope", "X-Zasp-Organization-ID", "X-Zasp-Workspace-ID", "X-Zasp-Environment-ID", "X-Organization-ID", "X-Workspace-ID", "X-Environment-ID", "X-Scope", "X-Tenant", "X-Tenant-ID", "X-Forwarded-Authorization"} {
		if len(header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func strictJSON(raw []byte, destination any) error {
	if len(raw) == 0 || len(raw) > maximumResponseBytes || destination == nil {
		return errHTTPControl
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errHTTPControl
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errHTTPControl
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", JSONMediaType)
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code string) {
	writeJSON(writer, status, map[string]string{"error": code})
}

var _ = policy.GatewayPolicyEnvelope{}
