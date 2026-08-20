package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	PrivateHeartbeatPath          = "/internal/v1/sensor/heartbeat"
	PrivateHeartbeatMediaType     = "application/vnd.zasp.sensor-heartbeat+json"
	PrivateHeartbeatSchemaHeader  = "X-Zasp-Schema-Version"
	PrivateHeartbeatSchemaVersion = "sensor-heartbeat-v1"
	maximumPrivateHeartbeatBytes  = 16 * 1024
)

var privateHeartbeatFields = map[string]struct{}{
	"sequence": {}, "status": {}, "capabilities": {}, "kernel": {}, "btf": {}, "event_rate": {}, "drops": {},
}

// PrivateHeartbeat is the exact private-wire report. Scope and sensor identity
// are deliberately absent: the v15 token authority derives both atomically.
type PrivateHeartbeat struct {
	Sequence     int64    `json:"sequence"`
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
	Kernel       string   `json:"kernel"`
	BTF          bool     `json:"btf"`
	EventRate    uint64   `json:"event_rate"`
	Drops        uint64   `json:"drops"`
}

// PrivateHeartbeatAuthority must authenticate credential and persist report in
// one transaction. Implementations must not split token lookup from the write.
type PrivateHeartbeatAuthority interface {
	RecordAuthenticatedHeartbeat(context.Context, *TokenCredential, PrivateHeartbeat) error
}

type PrivateHeartbeatHandler struct {
	authority PrivateHeartbeatAuthority
}

func NewPrivateHeartbeatHandler(authority PrivateHeartbeatAuthority) (*PrivateHeartbeatHandler, error) {
	if authority == nil {
		return nil, ErrInvalid
	}
	return &PrivateHeartbeatHandler{authority: authority}, nil
}

func (handler *PrivateHeartbeatHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if writer == nil {
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	if handler == nil || handler.authority == nil || request == nil || request.URL == nil {
		writePrivateHeartbeatError(writer, http.StatusServiceUnavailable, "unavailable", true)
		return
	}
	if request.Method != http.MethodPost || request.URL.EscapedPath() != PrivateHeartbeatPath || request.URL.Path != PrivateHeartbeatPath {
		writePrivateHeartbeatError(writer, http.StatusNotFound, "not_found", false)
		return
	}
	if request.URL.RawQuery != "" || hasPrivateScopeAuthority(request.Header) || !exactHeader(request.Header, "Content-Type", PrivateHeartbeatMediaType) || !exactHeader(request.Header, PrivateHeartbeatSchemaHeader, PrivateHeartbeatSchemaVersion) || len(request.Header.Values("Content-Encoding")) != 0 {
		writePrivateHeartbeatError(writer, http.StatusBadRequest, "invalid_request", false)
		return
	}
	report, err := decodePrivateHeartbeat(request)
	if err != nil {
		writePrivateHeartbeatError(writer, http.StatusBadRequest, "invalid_request", false)
		return
	}
	credential, err := privateHeartbeatCredential(request.Header)
	if err != nil {
		writePrivateHeartbeatError(writer, http.StatusUnauthorized, "unauthorized", false)
		return
	}
	defer credential.Destroy()
	err = safeRecordPrivateHeartbeat(request.Context(), handler.authority, credential, report)
	switch {
	case err == nil:
		writer.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrNotFound):
		writePrivateHeartbeatError(writer, http.StatusUnauthorized, "unauthorized", false)
	case errors.Is(err, ErrConflict):
		writePrivateHeartbeatError(writer, http.StatusConflict, "conflict", false)
	default:
		writePrivateHeartbeatError(writer, http.StatusServiceUnavailable, "unavailable", true)
	}
}

func privateHeartbeatCredential(header http.Header) (*TokenCredential, error) {
	values := header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || strings.Count(values[0], " ") != 1 || strings.Contains(values[0], ",") {
		return nil, ErrForbidden
	}
	return ParseTokenCredential(strings.TrimPrefix(values[0], "Bearer "))
}

func decodePrivateHeartbeat(request *http.Request) (PrivateHeartbeat, error) {
	if request.Body == nil || request.ContentLength > maximumPrivateHeartbeatBytes {
		return PrivateHeartbeat{}, ErrInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximumPrivateHeartbeatBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumPrivateHeartbeatBytes || !utf8.Valid(payload) || !exactPrivateHeartbeatObject(payload) {
		return PrivateHeartbeat{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var report PrivateHeartbeat
	if decoder.Decode(&report) != nil {
		return PrivateHeartbeat{}, ErrInvalid
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || !validPrivateHeartbeat(report) {
		return PrivateHeartbeat{}, ErrInvalid
	}
	report.Capabilities = append([]string(nil), report.Capabilities...)
	return report, nil
}

func exactPrivateHeartbeatObject(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	delimiter, ok := token.(json.Delim)
	if err != nil || !ok || delimiter != '{' {
		return false
	}
	seen := make(map[string]struct{}, len(privateHeartbeatFields))
	for decoder.More() {
		token, err = decoder.Token()
		key, keyOK := token.(string)
		if err != nil || !keyOK {
			return false
		}
		if _, allowed := privateHeartbeatFields[key]; !allowed {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
	}
	token, err = decoder.Token()
	delimiter, ok = token.(json.Delim)
	if err != nil || !ok || delimiter != '}' || len(seen) != len(privateHeartbeatFields) {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func validPrivateHeartbeat(report PrivateHeartbeat) bool {
	if report.Sequence < 0 || (report.Status != "healthy" && report.Status != "degraded") || !privateHeartbeatText(report.Kernel, 128) || report.EventRate > 1_000_000_000 || report.Drops > 1_000_000_000 || len(report.Capabilities) == 0 || len(report.Capabilities) > 32 {
		return false
	}
	normalized := normalizedCapabilities(report.Capabilities)
	if len(normalized) != len(report.Capabilities) {
		return false
	}
	for index := range normalized {
		if normalized[index] != report.Capabilities[index] {
			return false
		}
	}
	return true
}

func privateHeartbeatText(value string, maximum int) bool {
	if !bounded(value, maximum) || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func hasPrivateScopeAuthority(header http.Header) bool {
	for _, name := range []string{"X-Zasp-Organization-ID", "X-Zasp-Workspace-ID", "X-Zasp-Environment-ID", "X-Zasp-Scope", "X-Organization-ID", "X-Workspace-ID", "X-Environment-ID", "X-Scope", "X-Tenant", "X-Tenant-ID", "X-Forwarded-Authorization"} {
		if len(header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func exactHeader(header http.Header, name, wanted string) bool {
	values := header.Values(name)
	return len(values) == 1 && values[0] == wanted
}

func safeRecordPrivateHeartbeat(ctx context.Context, authority PrivateHeartbeatAuthority, credential *TokenCredential, report PrivateHeartbeat) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	if ctx == nil || authority == nil || credential == nil {
		return ErrUnavailable
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return ErrUnavailable
	}
	return authority.RecordAuthenticatedHeartbeat(ctx, credential, report)
}

func writePrivateHeartbeatError(writer http.ResponseWriter, status int, code string, retryable bool) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="sensor", error="invalid_token"`)
	}
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": code, "message": "Request rejected", "retryable": retryable})
}
