package apiserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type GatewayBootstrapEnrollment struct {
	ID              string     `json:"id"`
	DeviceID        string     `json:"device_id"`
	TokenGeneration int64      `json:"token_generation"`
	DeviceVersion   int64      `json:"device_version"`
	Audience        string     `json:"audience"`
	IssuedAt        time.Time  `json:"issued_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	ConsumedAt      *time.Time `json:"consumed_at"`
	RevokedAt       *time.Time `json:"revoked_at"`
}
type GatewayBootstrapStatus struct {
	Device                   GatewayDeviceRecord         `json:"device"`
	LatestEnrollment         *GatewayBootstrapEnrollment `json:"latest_enrollment"`
	NextCredentialGeneration int64                       `json:"next_credential_generation"`
	IssuanceState            string                      `json:"issuance_state"`
}
type GatewayBootstrapMutation struct {
	DeviceID, DeviceName, EnrollmentID, IdempotencyKey              string
	ExpectedVersion, TTLSeconds                                     int64
	RequestDigest, LocatorDigest, Salt, TokenHash, EnrollmentSecret []byte
	ExpiresAt                                                       time.Time
}
type GatewayBootstrapMutationResult struct {
	Operation            string                      `json:"operation"`
	Device               GatewayDeviceRecord         `json:"device"`
	Enrollment           *GatewayBootstrapEnrollment `json:"enrollment"`
	CredentialGeneration int64                       `json:"credential_generation"`
	Replayed             bool                        `json:"replayed"`
	NewMutation          bool                        `json:"new_mutation"`
}
type GatewayBootstrapAuthority interface {
	MutateGateway(context.Context, RequestIdentity, string, GatewayBootstrapMutation) (GatewayBootstrapMutationResult, error)
	GetGateway(context.Context, domain.Scope, string) (GatewayBootstrapStatus, error)
}
type GatewayBootstrapHandlerConfig struct {
	NewProductID          func() (string, error)
	NewEnrollmentMaterial func() ([]byte, []byte, []byte, error)
	Clock                 func() time.Time
}
type gatewayBootstrapHandler struct {
	repository GatewayBootstrapAuthority
	config     GatewayBootstrapHandlerConfig
}

func NewGatewayBootstrapHTTPHandler(repository GatewayBootstrapAuthority, configured ...GatewayBootstrapHandlerConfig) (http.Handler, error) {
	if nilInterface(repository) || len(configured) > 1 {
		return nil, ErrRepositoryConfiguration
	}
	c := GatewayBootstrapHandlerConfig{NewProductID: newWorkflowProductID, Clock: func() time.Time { return time.Now().UTC() }, NewEnrollmentMaterial: func() ([]byte, []byte, []byte, error) {
		b := make([]byte, 80)
		if _, e := rand.Read(b); e != nil {
			clear(b)
			return nil, nil, nil, ErrRepositoryUnavailable
		}
		return b[:16], b[16:48], b[48:], nil
	}}
	if len(configured) == 1 {
		c = configured[0]
	}
	if c.NewProductID == nil || c.NewEnrollmentMaterial == nil || c.Clock == nil {
		return nil, ErrRepositoryConfiguration
	}
	return &gatewayBootstrapHandler{repository, c}, nil
}

// Closed decoder rejects aliases and duplicate members before typed decoding.
func decodeGatewayBootstrapJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 16384 || !utf8.Valid(raw) || !gatewayBootstrapSurrogatesValid(raw) {
		return ErrRepositoryOperation
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if !gatewayBootstrapScanJSON(d, 0) {
		return ErrRepositoryOperation
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrRepositoryOperation
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrRepositoryOperation
	}
	canonical, e := json.Marshal(out)
	if e != nil {
		return ErrRepositoryOperation
	}
	var original, typed any
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&original) != nil {
		return ErrRepositoryOperation
	}
	d = json.NewDecoder(bytes.NewReader(canonical))
	d.UseNumber()
	if d.Decode(&typed) != nil {
		return ErrRepositoryOperation
	}
	// The closed internal receipt deliberately uses nullable generation outside
	// issue; Go's existing result type represents that null as zero internally.
	om, ook := original.(map[string]any)
	tm, tok := typed.(map[string]any)
	if !ook || !tok {
		return ErrRepositoryOperation
	}
	if value, exists := om["credential_generation"]; exists && value == nil && tm["credential_generation"] == json.Number("0") && (tm["operation"] == "createGatewayDevice" || tm["operation"] == "revokeGatewayEnrollment") {
		tm["credential_generation"] = nil
	}
	if !gatewayBootstrapMetadataTimes(original) || !reflect.DeepEqual(original, typed) {
		return ErrRepositoryOperation
	}
	return nil
}
func gatewayBootstrapMetadataTimes(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if stringIn(key, "created_at", "issued_at", "expires_at", "consumed_at", "revoked_at", "enrollment_expires_at") && item != nil {
				s, ok := item.(string)
				if !ok {
					return false
				}
				instant, e := time.Parse(time.RFC3339Nano, s)
				if e != nil || instant.Nanosecond()%1000 != 0 || instant.UTC().Format(time.RFC3339Nano) != s {
					return false
				}
			}
			if !gatewayBootstrapMetadataTimes(item) {
				return false
			}
		}
	case []any:
		for _, item := range v {
			if !gatewayBootstrapMetadataTimes(item) {
				return false
			}
		}
	}
	return true
}

func gatewayBootstrapScanJSON(d *json.Decoder, depth int) bool {
	if depth > 12 {
		return false
	}
	token, e := d.Token()
	if e != nil {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			s, ok := key.(string)
			if e != nil || !ok || seen[s] || len(seen) > 128 {
				return false
			}
			seen[s] = true
			if !gatewayBootstrapScanJSON(d, depth+1) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim('}')
	case '[':
		count := 0
		for d.More() {
			count++
			if count > 128 || !gatewayBootstrapScanJSON(d, depth+1) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim(']')
	}
	return false
}
func gatewayBootstrapSurrogatesValid(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		value, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if value >= 0xDC00 && value <= 0xDFFF {
			return false
		}
		if value >= 0xD800 && value <= 0xDBFF {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}

func (h *gatewayBootstrapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	identity, ok := IdentityFromRequest(r)
	route, routed := RoutedOperationFromRequest(r)
	if !ok || !routed || !validRequestIdentity(identity, false) {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	id := route.PathParameters["id"]
	if id != "" && !validProductID(id) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	if route.OperationID == "getGatewayDevice" {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength != 0 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		v, e := h.repository.GetGateway(r.Context(), identity.Scope, id)
		writeJSONValue(w, r, http.StatusOK, v, e)
		return
	}
	if !stringIn(route.OperationID, "createGatewayDevice", "issueGatewayEnrollment", "revokeGatewayEnrollment") || r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("If-Match")) != 0 || !validSensorFreshAuthority(r, identity) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	key, valid := sensorMutationHeaders(r, false)
	if !valid {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 16385))
	if e != nil {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	defer clear(raw)
	in := GatewayBootstrapMutation{DeviceID: id, IdempotencyKey: key}
	intent := map[string]any{}
	switch route.OperationID {
	case "createGatewayDevice":
		var body struct {
			Name string `json:"name"`
		}
		if decodeGatewayBootstrapJSON(raw, &body) != nil || len(body.Name) < 1 || len(body.Name) > 128 || body.Name != strings.TrimSpace(body.Name) || strings.ContainsAny(body.Name, "\r\n\t\x00") {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		in.DeviceName = body.Name
		intent["name"] = body.Name
		in.DeviceID, e = h.config.NewProductID()
	case "issueGatewayEnrollment":
		var body struct {
			ExpectedVersion int64 `json:"expected_version"`
			TTLSeconds      int64 `json:"ttl_seconds"`
		}
		if decodeGatewayBootstrapJSON(raw, &body) != nil || body.ExpectedVersion < 1 || body.TTLSeconds < 60 || body.TTLSeconds > 86400 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		in.ExpectedVersion = body.ExpectedVersion
		in.TTLSeconds = body.TTLSeconds
		intent["expected_version"] = body.ExpectedVersion
		intent["ttl_seconds"] = body.TTLSeconds
		in.EnrollmentID, e = h.config.NewProductID()
		in.ExpiresAt = h.config.Clock().UTC().Truncate(time.Second).Add(time.Duration(body.TTLSeconds) * time.Second)
	case "revokeGatewayEnrollment":
		var body struct {
			ExpectedVersion int64 `json:"expected_version"`
		}
		if decodeGatewayBootstrapJSON(raw, &body) != nil || body.ExpectedVersion < 1 || !validProductID(route.PathParameters["enrollmentId"]) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		in.ExpectedVersion = body.ExpectedVersion
		in.EnrollmentID = route.PathParameters["enrollmentId"]
		intent["expected_version"] = body.ExpectedVersion
		intent["enrollment_id"] = in.EnrollmentID
	}
	if e != nil || !validProductID(in.DeviceID) || route.OperationID == "issueGatewayEnrollment" && (!validProductID(in.EnrollmentID) || in.EnrollmentID == in.DeviceID) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	canonical, _ := json.Marshal(map[string]any{"scope": map[string]string{"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String()}, "actor": identity.PrincipalID.String(), "operation": route.OperationID, "device_id": id, "idempotency_key": key, "body": intent})
	digest := sha256.Sum256(canonical)
	in.RequestDigest = digest[:]
	var locator, secret, salt []byte
	if route.OperationID == "issueGatewayEnrollment" {
		locator, secret, salt, e = h.config.NewEnrollmentMaterial()
		if e != nil || len(locator) != 16 || len(secret) != 32 || len(salt) != 32 {
			clear(locator)
			clear(secret)
			clear(salt)
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		defer clear(locator)
		defer clear(secret)
		defer clear(salt)
		hash := sha256.Sum256(locator)
		in.LocatorDigest = hash[:]
		in.Salt = salt
		in.EnrollmentSecret = secret
	}
	result, e := h.repository.MutateGateway(r.Context(), identity, route.OperationID, in)
	if e != nil {
		writeProductionError(w, r, e)
		return
	}
	if result.Operation != route.OperationID || !validProductID(result.Device.ID) || result.NewMutation == result.Replayed {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	out := map[string]any{"device": result.Device, "replayed": result.Replayed}
	status := http.StatusOK
	if route.OperationID == "createGatewayDevice" {
		if !result.Replayed && result.Device.ID != in.DeviceID {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		if !result.Replayed {
			status = http.StatusCreated
		}
	}
	if route.OperationID != "createGatewayDevice" {
		if result.Device.ID != id || result.Enrollment == nil || result.Enrollment.DeviceID != id {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		out["enrollment"] = result.Enrollment
	}
	if route.OperationID == "issueGatewayEnrollment" && result.NewMutation && !result.Replayed {
		if result.Enrollment.ID != in.EnrollmentID || !result.Enrollment.ExpiresAt.Equal(in.ExpiresAt) || result.Enrollment.TokenGeneration < 1 || result.CredentialGeneration < 1 {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		out["token_bundle"] = map[string]any{"schema": "gateway-enrollment-token-v1", "organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "device_id": id, "enrollment_id": in.EnrollmentID, "token_generation": result.Enrollment.TokenGeneration, "credential_generation": result.CredentialGeneration, "enrollment_expires_at": in.ExpiresAt, "locator": base64.RawURLEncoding.EncodeToString(locator), "secret": base64.RawURLEncoding.EncodeToString(secret)}
		status = http.StatusCreated
	}
	writeJSONValue(w, r, status, out, nil)
}

type gatewayBootstrapSurface struct{ fallback, gateways http.Handler }

func (s *gatewayBootstrapSurface) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op, ok := RoutedOperationFromRequest(r)
	if ok && stringIn(op.OperationID, "createGatewayDevice", "getGatewayDevice", "issueGatewayEnrollment", "revokeGatewayEnrollment") {
		s.gateways.ServeHTTP(w, r)
		return
	}
	s.fallback.ServeHTTP(w, r)
}
