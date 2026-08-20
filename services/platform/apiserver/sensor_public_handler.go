package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

type SensorPublicAuthority interface {
	ListSensors(context.Context, domain.Scope, string, int) (SensorPage, error)
	GetSensor(context.Context, domain.Scope, string) (ProductSensor, error)
	GetSensorCoverage(context.Context, domain.Scope, string) (SensorCoverage, error)
	GetSensorTokenAuthority(context.Context, domain.Scope, string) (SensorTokenAuthority, error)
	CreateSensor(context.Context, RequestIdentity, SensorCreateMutation) (SensorMutationResult, error)
	UpdateSensor(context.Context, RequestIdentity, SensorUpdateMutation) (SensorMutationResult, error)
	DeleteSensor(context.Context, RequestIdentity, SensorDeleteMutation) (SensorMutationResult, error)
	RotateSensorToken(context.Context, RequestIdentity, SensorRotateMutation) (SensorMutationResult, error)
}

type SensorPublicHandlerConfig struct {
	NewProductID       func() (string, error)
	NewTokenCredential func() (*sensor.TokenCredential, error)
	NewSalt            func() ([]byte, error)
	Clock              func() time.Time
	TokenTTL           time.Duration
}

type sensorPublicHTTPHandler struct {
	repository SensorPublicAuthority
	signingKey []byte
	config     SensorPublicHandlerConfig
}

type sensorCursor struct {
	Version        int    `json:"v"`
	OrganizationID string `json:"o"`
	WorkspaceID    string `json:"w"`
	EnvironmentID  string `json:"e"`
	Limit          int    `json:"l"`
	AfterID        string `json:"a"`
}

type sensorEnrollment struct {
	ProductSensor
	Token string `json:"token"`
}

func NewSensorPublicHTTPHandler(repository SensorPublicAuthority, signingKey []byte, configured ...SensorPublicHandlerConfig) (http.Handler, error) {
	if nilInterface(repository) || len(signingKey) < 32 || len(signingKey) > 4096 || len(configured) > 1 {
		return nil, ErrRepositoryConfiguration
	}
	config := SensorPublicHandlerConfig{
		NewProductID:       newWorkflowProductID,
		NewTokenCredential: func() (*sensor.TokenCredential, error) { return sensor.GenerateTokenCredential(rand.Reader) },
		NewSalt: func() ([]byte, error) {
			value := make([]byte, sha256.Size)
			if _, err := rand.Read(value); err != nil {
				clear(value)
				return nil, ErrRepositoryUnavailable
			}
			return value, nil
		},
		Clock:    func() time.Time { return time.Now().UTC() },
		TokenTTL: 30 * 24 * time.Hour,
	}
	if len(configured) == 1 {
		config = configured[0]
	}
	if config.NewProductID == nil || config.NewTokenCredential == nil || config.NewSalt == nil || config.Clock == nil || config.TokenTTL < time.Minute || config.TokenTTL > 90*24*time.Hour {
		return nil, ErrRepositoryConfiguration
	}
	return &sensorPublicHTTPHandler{repository: repository, signingKey: append([]byte(nil), signingKey...), config: config}, nil
}

func (handler *sensorPublicHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	if !identityOK || !routedOK || !validRequestIdentity(identity, false) {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	sensorID := routed.PathParameters["id"]
	if sensorID != "" && !validProductID(sensorID) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	switch routed.OperationID {
	case "listSensors":
		handler.list(writer, request, identity)
	case "createSensorEnrollment":
		handler.create(writer, request, identity)
	case "getSensor":
		handler.get(writer, request, identity, sensorID)
	case "updateSensor":
		handler.update(writer, request, identity, sensorID)
	case "deleteSensor":
		handler.delete(writer, request, identity, sensorID)
	case "rotateSensorToken":
		handler.rotate(writer, request, identity, sensorID)
	case "getSensorCoverage":
		handler.coverage(writer, request, identity, sensorID)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

func (handler *sensorPublicHTTPHandler) list(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	if request.Method != http.MethodGet {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"cursor": 512, "limit": 3})
	if !ok {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	limit, ok := workflowPageLimit(query)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	after := ""
	if values, exists := query["cursor"]; exists {
		after, ok = handler.decodeCursor(values[0], identity.Scope, limit)
		if !ok {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
	}
	page, err := handler.repository.ListSensors(request.Context(), identity.Scope, after, limit)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	pageInfo := map[string]any{"has_more": false, "next_cursor": nil}
	if page.NextID != "" {
		pageInfo["has_more"] = true
		pageInfo["next_cursor"] = handler.encodeCursor(identity.Scope, limit, page.NextID)
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": page.Items, "page_info": pageInfo}, nil)
}

func (handler *sensorPublicHTTPHandler) get(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, sensorID string) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	value, err := handler.repository.GetSensor(request.Context(), identity.Scope, sensorID)
	if err == nil {
		writer.Header().Set("ETag", quoteVersion(value.Version))
	}
	writeJSONValue(writer, request, http.StatusOK, value, err)
}

func (handler *sensorPublicHTTPHandler) coverage(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, sensorID string) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	value, err := handler.repository.GetSensorCoverage(request.Context(), identity.Scope, sensorID)
	writeJSONValue(writer, request, http.StatusOK, value, err)
}

func (handler *sensorPublicHTTPHandler) create(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	var input struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		Mode string `json:"mode"`
	}
	idempotencyKey, valid := sensorMutationHeaders(request, false)
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || !valid || !validSensorFreshAuthority(request, identity) || decodeProductionJSON(request, &input) != nil || !validSensorName(input.Name) || !stringIn(input.Kind, "tetragon", "otlp") || !validSensorMode(input.Mode) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	digest, ok := sensorIntentDigest(identity, "createSensorEnrollment", "", 0, idempotencyKey, map[string]any{"kind": input.Kind, "mode": input.Mode, "name": input.Name})
	if !ok {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	handler.withFreshCredential(writer, request, identity, 0, func(tokenID string, generation int64, locatorDigest, salt, tokenHash []byte, expires time.Time) (SensorMutationResult, error) {
		sensorID, err := handler.config.NewProductID()
		if err != nil || !validProductID(sensorID) || sensorID == tokenID {
			return SensorMutationResult{}, ErrRepositoryUnavailable
		}
		return handler.repository.CreateSensor(request.Context(), identity, SensorCreateMutation{SensorID: sensorID, Name: input.Name, Kind: input.Kind, Mode: input.Mode, IdempotencyKey: idempotencyKey, RequestDigest: digest, TokenID: tokenID, TokenGeneration: generation, LocatorDigest: locatorDigest, Salt: salt, TokenHash: tokenHash, TokenExpiresAt: expires})
	}, http.StatusCreated)
}

func (handler *sensorPublicHTTPHandler) update(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, sensorID string) {
	var input struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	}
	idempotencyKey, expectedVersion, valid := sensorVersionedMutationHeaders(request)
	if request.Method != http.MethodPatch || request.URL.RawQuery != "" || !valid || decodeProductionJSON(request, &input) != nil || !validSensorName(input.Name) || !validSensorMode(input.Mode) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	digest, ok := sensorIntentDigest(identity, "updateSensor", sensorID, expectedVersion, idempotencyKey, map[string]any{"mode": input.Mode, "name": input.Name})
	if !ok {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := handler.repository.UpdateSensor(request.Context(), identity, SensorUpdateMutation{SensorID: sensorID, Name: input.Name, Mode: input.Mode, ExpectedVersion: expectedVersion, IdempotencyKey: idempotencyKey, RequestDigest: digest})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Sensor.Version))
	writeJSONValue(writer, request, http.StatusOK, result.Sensor, nil)
}

func (handler *sensorPublicHTTPHandler) delete(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, sensorID string) {
	idempotencyKey, expectedVersion, valid := sensorVersionedMutationHeaders(request)
	if request.Method != http.MethodDelete || request.URL.RawQuery != "" || !valid || request.Body != nil && request.ContentLength != 0 {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	digest, ok := sensorIntentDigest(identity, "deleteSensor", sensorID, expectedVersion, idempotencyKey, map[string]any{})
	if !ok {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := handler.repository.DeleteSensor(request.Context(), identity, SensorDeleteMutation{SensorID: sensorID, ExpectedVersion: expectedVersion, IdempotencyKey: idempotencyKey, RequestDigest: digest})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Sensor.Version))
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *sensorPublicHTTPHandler) rotate(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, sensorID string) {
	idempotencyKey, expectedVersion, valid := sensorVersionedMutationHeaders(request)
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || !valid || !validSensorFreshAuthority(request, identity) || decodeEmptyInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	authority, err := handler.repository.GetSensorTokenAuthority(request.Context(), identity.Scope, sensorID)
	if err != nil || authority.SensorVersion != expectedVersion || authority.Generation < 1 || authority.Generation == int64(^uint64(0)>>1) {
		writeProductionError(writer, request, firstError(err, ErrRepositoryConflict))
		return
	}
	digest, ok := sensorIntentDigest(identity, "rotateSensorToken", sensorID, expectedVersion, idempotencyKey, map[string]any{})
	if !ok {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	handler.withFreshCredential(writer, request, identity, authority.Generation+1, func(tokenID string, generation int64, locatorDigest, salt, tokenHash []byte, expires time.Time) (SensorMutationResult, error) {
		return handler.repository.RotateSensorToken(request.Context(), identity, SensorRotateMutation{SensorID: sensorID, ExpectedVersion: expectedVersion, IdempotencyKey: idempotencyKey, RequestDigest: digest, TokenID: tokenID, TokenGeneration: generation, LocatorDigest: locatorDigest, Salt: salt, TokenHash: tokenHash, TokenExpiresAt: expires})
	}, http.StatusOK)
}

func (handler *sensorPublicHTTPHandler) withFreshCredential(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, requestedGeneration int64, mutate func(string, int64, []byte, []byte, []byte, time.Time) (SensorMutationResult, error), status int) {
	tokenID, err := handler.config.NewProductID()
	if err != nil || !validProductID(tokenID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	credential, err := handler.config.NewTokenCredential()
	if err != nil || credential == nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	defer credential.Destroy()
	salt, err := handler.config.NewSalt()
	if err != nil || len(salt) != sha256.Size {
		clear(salt)
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	defer clear(salt)
	generation := requestedGeneration
	if generation == 0 {
		generation = 1
	}
	parsedTokenID, err := domain.ParseProductID(tokenID)
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	locatorDigest, err := credential.LocatorDigest()
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	tokenHash, err := credential.Hash(sensor.SensorTokenAudienceEventIngest, parsedTokenID, uint64(generation), salt)
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	now := handler.config.Clock().UTC()
	expires := now.Add(handler.config.TokenTTL)
	if now.IsZero() || !validSensorTime(now) || !validSensorTime(expires) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := mutate(tokenID, generation, locatorDigest[:], salt, tokenHash[:], expires)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if result.Replayed {
		writeProductionError(writer, request, ErrRepositoryConflict)
		return
	}
	wire, err := credential.Wire()
	if err != nil || result.TokenID != tokenID || result.TokenGeneration != generation || result.TokenExpiresAt == nil || !result.TokenExpiresAt.Equal(expires) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Sensor.Version))
	writer.Header().Set("Pragma", "no-cache")
	writeJSONValue(writer, request, status, sensorEnrollment{ProductSensor: result.Sensor, Token: wire}, nil)
}

func sensorMutationHeaders(request *http.Request, versioned bool) (string, bool) {
	keys := request.Header.Values("Idempotency-Key")
	versions := request.Header.Values("If-Match")
	return firstString(keys), len(keys) == 1 && validPublicIdempotency(keys[0]) && (versioned || len(versions) == 0)
}

func sensorVersionedMutationHeaders(request *http.Request) (string, int64, bool) {
	key, version, valid := discoveryMutationHeaders(request, false)
	return key, version, valid
}

func validSensorFreshAuthority(request *http.Request, identity RequestIdentity) bool {
	values := request.Header.Values("X-Zasp-Fresh-Auth")
	if identity.CredentialKind == CredentialBearerToken {
		return len(values) == 0
	}
	return identity.CredentialKind == CredentialBrowserSession && identity.FreshAuthenticated && exactHeaderValue(values, "confirmed")
}

func sensorIntentDigest(identity RequestIdentity, operation, sensorID string, expectedVersion int64, idempotencyKey string, body map[string]any) ([]byte, bool) {
	payload, err := json.Marshal(map[string]any{
		"body": body, "expected_version": expectedVersion, "idempotency_key": idempotencyKey, "operation": operation, "principal_id": identity.PrincipalID.String(), "sensor_id": sensorID,
		"scope": map[string]string{"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String()},
	})
	if err != nil {
		return nil, false
	}
	digest := sha256.Sum256(payload)
	return digest[:], true
}

func (handler *sensorPublicHTTPHandler) encodeCursor(scope domain.Scope, limit int, afterID string) string {
	payload, _ := json.Marshal(sensorCursor{Version: 1, OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), Limit: limit, AfterID: afterID})
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
}

func (handler *sensorPublicHTTPHandler) decodeCursor(value string, scope domain.Scope, limit int) (string, bool) {
	if len(value) < 2 || len(value) > 512 {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || len(decoded) <= sha256.Size {
		return "", false
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return "", false
	}
	var raw map[string]json.RawMessage
	var cursor sensorCursor
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 6 || json.Unmarshal(payload, &cursor) != nil || cursor.Version != 1 || cursor.OrganizationID != scope.OrganizationID().String() || cursor.WorkspaceID != scope.WorkspaceID().String() || cursor.EnvironmentID != scope.EnvironmentID().String() || cursor.Limit != limit || !validProductID(cursor.AfterID) {
		return "", false
	}
	return cursor.AfterID, true
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
