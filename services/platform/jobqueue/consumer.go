package jobqueue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const maximumEnvelopeBytes = 262_144

var (
	ErrEnvelopeConsumerConfiguration = errors.New("queue envelope consumer configuration rejected")
	ErrEnvelope                      = errors.New("queue envelope rejected")
	ErrEnvelopeProcessing            = errors.New("queue envelope processing failed")
)

type EnvelopeKind string

const (
	EnvelopeBackground    EnvelopeKind = "background"
	EnvelopeRuntimeEvents EnvelopeKind = "runtime_events"
	EnvelopeTests         EnvelopeKind = "tests"
)

type EnvelopeMessage struct {
	kind  EnvelopeKind
	scope domain.Scope
	body  []byte
}

func (message EnvelopeMessage) Kind() EnvelopeKind {
	return message.kind
}

func (message EnvelopeMessage) Scope() domain.Scope {
	return message.scope
}

func (message EnvelopeMessage) Bytes() []byte {
	return bytes.Clone(message.body)
}

type EnvelopeHandler interface {
	HandleEnvelope(context.Context, EnvelopeMessage) error
}

type EnvelopeConsumer struct {
	organizationID domain.ProductID
	handler        EnvelopeHandler
}

func NewEnvelopeConsumer(organizationID domain.ProductID, handler EnvelopeHandler) (*EnvelopeConsumer, error) {
	if organizationID.IsZero() || nilInterface(handler) {
		return nil, ErrEnvelopeConsumerConfiguration
	}
	return &EnvelopeConsumer{organizationID: organizationID, handler: handler}, nil
}

func (consumer *EnvelopeConsumer) ConsumeEnvelope(ctx context.Context, kind EnvelopeKind, body []byte) error {
	if consumer == nil || consumer.organizationID.IsZero() || nilInterface(consumer.handler) || ctx == nil || ctx.Err() != nil {
		return ErrEnvelope
	}
	ownedBody := bytes.Clone(body)
	scope, ok := parseEnvelope(kind, ownedBody)
	if !ok || scope.OrganizationID() != consumer.organizationID || ctx.Err() != nil {
		return ErrEnvelope
	}
	message := EnvelopeMessage{kind: kind, scope: scope, body: ownedBody}
	if callEnvelopeHandler(consumer.handler, ctx, message) != nil || ctx.Err() != nil {
		return ErrEnvelopeProcessing
	}
	return nil
}

func callEnvelopeHandler(handler EnvelopeHandler, ctx context.Context, message EnvelopeMessage) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrEnvelopeProcessing
		}
	}()
	if err := handler.HandleEnvelope(ctx, message); err != nil {
		return ErrEnvelopeProcessing
	}
	return nil
}

func parseEnvelope(kind EnvelopeKind, body []byte) (domain.Scope, bool) {
	if len(body) == 0 || len(body) > maximumEnvelopeBytes || !utf8.Valid(body) {
		return domain.Scope{}, false
	}
	fields, ok := decodeEnvelopeObject(body)
	if !ok || !exactEnvelopeFields(kind, fields) || !exactVersion(fields["version"]) {
		return domain.Scope{}, false
	}
	organizationID, ok := exactProductID(fields["organization_id"])
	if !ok {
		return domain.Scope{}, false
	}
	workspaceID, ok := exactProductID(fields["workspace_id"])
	if !ok {
		return domain.Scope{}, false
	}
	environmentID, ok := exactProductID(fields["environment_id"])
	if !ok {
		return domain.Scope{}, false
	}
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil || !validKindFields(kind, fields) {
		return domain.Scope{}, false
	}
	return scope, true
}

func decodeEnvelopeObject(body []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage, 7)
	for decoder.More() {
		keyStart := decoder.InputOffset()
		keyToken, err := decoder.Token()
		keyEnd := decoder.InputOffset()
		key, ok := keyToken.(string)
		if err != nil || !ok || !exactJSONKey(body[keyStart:keyEnd], key) {
			return nil, false
		}
		if _, exists := fields[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		fields[key] = bytes.Clone(value)
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || requireJSONEnd(decoder) != nil {
		return nil, false
	}
	return fields, true
}

func exactJSONKey(raw []byte, key string) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == ',' {
		raw = bytes.TrimSpace(raw[1:])
	}
	canonical, err := json.Marshal(key)
	return err == nil && bytes.Equal(raw, canonical)
}

func exactEnvelopeFields(kind EnvelopeKind, fields map[string]json.RawMessage) bool {
	var expected []string
	switch kind {
	case EnvelopeBackground:
		expected = []string{"version", "organization_id", "workspace_id", "environment_id", "job_id", "kind", "payload"}
	case EnvelopeRuntimeEvents:
		expected = []string{"version", "organization_id", "workspace_id", "environment_id", "batch_id", "event_count", "events"}
	case EnvelopeTests:
		expected = []string{"version", "organization_id", "workspace_id", "environment_id", "test_run_id", "kind", "payload"}
	default:
		return false
	}
	if len(fields) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, exists := fields[key]; !exists {
			return false
		}
	}
	return true
}

func exactVersion(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("1"))
}

func exactProductID(raw json.RawMessage) (domain.ProductID, bool) {
	text, ok := exactJSONString(raw)
	if !ok {
		return domain.ProductID{}, false
	}
	productID, err := domain.ParseProductID(text)
	return productID, err == nil
}

func exactJSONString(raw json.RawMessage) (string, bool) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", false
	}
	canonical, err := json.Marshal(text)
	return text, err == nil && bytes.Equal(bytes.TrimSpace(raw), canonical)
}

func validKindFields(kind EnvelopeKind, fields map[string]json.RawMessage) bool {
	switch kind {
	case EnvelopeBackground:
		return validProductIdentityAndPayload(fields["job_id"], fields["kind"], fields["payload"])
	case EnvelopeTests:
		return validProductIdentityAndPayload(fields["test_run_id"], fields["kind"], fields["payload"])
	case EnvelopeRuntimeEvents:
		if _, ok := exactProductID(fields["batch_id"]); !ok {
			return false
		}
		count, ok := exactNonnegativeInteger(fields["event_count"])
		if !ok || len(bytes.TrimSpace(fields["events"])) == 0 || bytes.TrimSpace(fields["events"])[0] != '[' {
			return false
		}
		var events []json.RawMessage
		return json.Unmarshal(fields["events"], &events) == nil && count == len(events)
	default:
		return false
	}
}

func validProductIdentityAndPayload(identity, kind, payload json.RawMessage) bool {
	if _, ok := exactProductID(identity); !ok {
		return false
	}
	kindText, ok := exactJSONString(kind)
	return ok && kindPattern.MatchString(kindText) && len(payload) > 0 && json.Valid(payload)
}

func exactNonnegativeInteger(raw json.RawMessage) (int, bool) {
	text := string(bytes.TrimSpace(raw))
	if text == "" || (text != "0" && (text[0] < '1' || text[0] > '9')) {
		return 0, false
	}
	for _, digit := range text {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	value, err := strconv.Atoi(text)
	return value, err == nil && value >= 0
}
