package jobqueue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recordingEnvelopeHandler struct {
	calls    atomic.Int64
	mu       sync.Mutex
	messages []EnvelopeMessage
	handle   func(context.Context, EnvelopeMessage) error
}

func (handler *recordingEnvelopeHandler) HandleEnvelope(ctx context.Context, message EnvelopeMessage) error {
	handler.calls.Add(1)
	handler.mu.Lock()
	handler.messages = append(handler.messages, message)
	handler.mu.Unlock()
	if handler.handle != nil {
		return handler.handle(ctx, message)
	}
	return nil
}

func (handler *recordingEnvelopeHandler) snapshot() []EnvelopeMessage {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return append([]EnvelopeMessage(nil), handler.messages...)
}

func TestEnvelopeConsumerAcceptsExactEnvelopeFamilies(t *testing.T) {
	organizationID := envelopeProductID(t, 1)
	handler := &recordingEnvelopeHandler{}
	consumer, err := NewEnvelopeConsumer(organizationID, handler)
	if err != nil {
		t.Fatalf("NewEnvelopeConsumer() error = %v", err)
	}

	tests := []struct {
		name string
		kind EnvelopeKind
		body []byte
	}{
		{name: "background", kind: EnvelopeBackground, body: envelopeFixture(t, EnvelopeBackground, organizationID)},
		{name: "runtime events", kind: EnvelopeRuntimeEvents, body: envelopeFixture(t, EnvelopeRuntimeEvents, organizationID)},
		{name: "tests", kind: EnvelopeTests, body: envelopeFixture(t, EnvelopeTests, organizationID)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := bytes.Clone(test.body)
			if err := consumer.ConsumeEnvelope(context.Background(), test.kind, test.body); err != nil {
				t.Fatalf("ConsumeEnvelope() error = %v", err)
			}
			for index := range test.body {
				test.body[index] = 'x'
			}
			message := handler.snapshot()[int(handler.calls.Load())-1]
			if message.Kind() != test.kind || message.Scope().OrganizationID() != organizationID || !bytes.Equal(message.Bytes(), original) {
				t.Fatalf("handler message = %#v", message)
			}
			copyFromAccessor := message.Bytes()
			copyFromAccessor[0] = 'x'
			if !bytes.Equal(message.Bytes(), original) {
				t.Fatal("EnvelopeMessage.Bytes returned mutable retained state")
			}
		})
	}
	if handler.calls.Load() != int64(len(tests)) {
		t.Fatalf("handler calls = %d", handler.calls.Load())
	}
}

func TestEnvelopeConsumerAcceptsOnlySemanticMemberOrderAndWhitespaceVariation(t *testing.T) {
	organizationID := envelopeProductID(t, 1)
	handler := &recordingEnvelopeHandler{}
	consumer, err := NewEnvelopeConsumer(organizationID, handler)
	if err != nil {
		t.Fatalf("NewEnvelopeConsumer() error = %v", err)
	}
	body := []byte(fmt.Sprintf("  { \"payload\" : {\"safe\":true}, \"kind\" : \"inventory.sync\", \"job_id\" : \"%s\", \"environment_id\" : \"%s\", \"workspace_id\" : \"%s\", \"organization_id\" : \"%s\", \"version\" : 1 } \n", envelopeProductID(t, 5), envelopeProductID(t, 4), envelopeProductID(t, 3), organizationID))
	if err := consumer.ConsumeEnvelope(context.Background(), EnvelopeBackground, body); err != nil {
		t.Fatalf("ConsumeEnvelope() error = %v", err)
	}
	if handler.calls.Load() != 1 || !bytes.Equal(handler.snapshot()[0].Bytes(), body) {
		t.Fatal("semantic JSON variation was not preserved exactly")
	}
}

func TestEnvelopeConsumerRejectsMissingOrForeignOrganizationBeforeSideEffects(t *testing.T) {
	organizationA := envelopeProductID(t, 1)
	organizationB := envelopeProductID(t, 2)
	handler := &recordingEnvelopeHandler{}
	consumer, err := NewEnvelopeConsumer(organizationA, handler)
	if err != nil {
		t.Fatalf("NewEnvelopeConsumer() error = %v", err)
	}

	for _, kind := range []EnvelopeKind{EnvelopeBackground, EnvelopeRuntimeEvents, EnvelopeTests} {
		foreign := envelopeFixture(t, kind, organizationB)
		if err := consumer.ConsumeEnvelope(context.Background(), kind, foreign); !errors.Is(err, ErrEnvelope) {
			t.Fatalf("foreign %s error = %v", kind, err)
		}
		missing := bytes.Replace(envelopeFixture(t, kind, organizationA), []byte(fmt.Sprintf("\"organization_id\":\"%s\",", organizationA)), nil, 1)
		if err := consumer.ConsumeEnvelope(context.Background(), kind, missing); !errors.Is(err, ErrEnvelope) {
			t.Fatalf("missing %s error = %v", kind, err)
		}
	}
	if handler.calls.Load() != 0 {
		t.Fatalf("rejected envelopes caused %d side effects", handler.calls.Load())
	}
}

func TestEnvelopeConsumerRejectsSchemaAndRepresentationDrift(t *testing.T) {
	organizationID := envelopeProductID(t, 1)
	handler := &recordingEnvelopeHandler{}
	consumer, err := NewEnvelopeConsumer(organizationID, handler)
	if err != nil {
		t.Fatalf("NewEnvelopeConsumer() error = %v", err)
	}
	background := envelopeFixture(t, EnvelopeBackground, organizationID)
	runtimeEvents := envelopeFixture(t, EnvelopeRuntimeEvents, organizationID)
	testsEnvelope := envelopeFixture(t, EnvelopeTests, organizationID)

	tests := map[string]struct {
		kind EnvelopeKind
		body []byte
	}{
		"unknown kind":              {kind: EnvelopeKind("background_alias"), body: background},
		"empty":                     {kind: EnvelopeBackground, body: nil},
		"oversize":                  {kind: EnvelopeBackground, body: bytes.Repeat([]byte{'x'}, maximumEnvelopeBytes+1)},
		"invalid utf8":              {kind: EnvelopeBackground, body: []byte{'{', 0xff, '}'}},
		"array root":                {kind: EnvelopeBackground, body: []byte(`[]`)},
		"trailing document":         {kind: EnvelopeBackground, body: append(bytes.Clone(background), []byte(`{}`)...)},
		"unknown field":             {kind: EnvelopeBackground, body: bytes.Replace(background, []byte(`"payload":`), []byte(`"unknown":true,"payload":`), 1)},
		"missing field":             {kind: EnvelopeBackground, body: bytes.Replace(background, []byte(`"payload":{"safe":true}`), []byte(`"payload_missing":{"safe":true}`), 1)},
		"duplicate field":           {kind: EnvelopeBackground, body: bytes.Replace(background, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)},
		"alternate case":            {kind: EnvelopeBackground, body: bytes.Replace(background, []byte(`"organization_id"`), []byte(`"Organization_ID"`), 1)},
		"escaped key alias":         {kind: EnvelopeBackground, body: bytes.Replace(background, []byte(`"organization_id"`), []byte(`"\u006frganization_id"`), 1)},
		"version string":            {kind: EnvelopeBackground, body: bytes.Replace(background, []byte(`"version":1`), []byte(`"version":"1"`), 1)},
		"version bool":              {kind: EnvelopeBackground, body: bytes.Replace(background, []byte(`"version":1`), []byte(`"version":true`), 1)},
		"escaped organization":      {kind: EnvelopeBackground, body: bytes.Replace(background, []byte(`"organization_id":"pid_`), []byte(`"organization_id":"\u0070id_`), 1)},
		"malformed organization":    {kind: EnvelopeBackground, body: replaceEnvelopeString(background, "organization_id", "pid_bad")},
		"zero organization":         {kind: EnvelopeBackground, body: replaceEnvelopeString(background, "organization_id", "")},
		"duplicate scope ids":       {kind: EnvelopeBackground, body: replaceEnvelopeString(background, "workspace_id", organizationID.String())},
		"malformed primary id":      {kind: EnvelopeBackground, body: replaceEnvelopeString(background, "job_id", "pid_bad")},
		"invalid job kind":          {kind: EnvelopeBackground, body: replaceEnvelopeString(background, "kind", "Bad Kind")},
		"missing job payload":       {kind: EnvelopeBackground, body: bytes.Replace(background, []byte(`{"safe":true}`), nil, 1)},
		"malformed test run id":     {kind: EnvelopeTests, body: replaceEnvelopeString(testsEnvelope, "test_run_id", "pid_bad")},
		"invalid test kind":         {kind: EnvelopeTests, body: replaceEnvelopeString(testsEnvelope, "kind", "Bad Kind")},
		"event count float":         {kind: EnvelopeRuntimeEvents, body: bytes.Replace(runtimeEvents, []byte(`"event_count":2`), []byte(`"event_count":2.0`), 1)},
		"event count bool":          {kind: EnvelopeRuntimeEvents, body: bytes.Replace(runtimeEvents, []byte(`"event_count":2`), []byte(`"event_count":true`), 1)},
		"event count negative":      {kind: EnvelopeRuntimeEvents, body: bytes.Replace(runtimeEvents, []byte(`"event_count":2`), []byte(`"event_count":-1`), 1)},
		"event count negative zero": {kind: EnvelopeRuntimeEvents, body: bytes.Replace(runtimeEvents, []byte(`"event_count":2`), []byte(`"event_count":-0`), 1)},
		"event count mismatch":      {kind: EnvelopeRuntimeEvents, body: bytes.Replace(runtimeEvents, []byte(`"event_count":2`), []byte(`"event_count":1`), 1)},
		"events not array":          {kind: EnvelopeRuntimeEvents, body: bytes.Replace(runtimeEvents, []byte(`"events":[{"safe":true},{"safe":false}]`), []byte(`"events":null`), 1)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := consumer.ConsumeEnvelope(context.Background(), test.kind, test.body); !errors.Is(err, ErrEnvelope) {
				t.Fatalf("ConsumeEnvelope() error = %v", err)
			}
		})
	}
	if handler.calls.Load() != 0 {
		t.Fatalf("rejected drift caused %d handler calls", handler.calls.Load())
	}
}

func TestEnvelopeConsumerConfigurationContextAndHandlerFailuresAreFixed(t *testing.T) {
	organizationID := envelopeProductID(t, 1)
	var typedNil *recordingEnvelopeHandler
	for name, handler := range map[string]EnvelopeHandler{"nil": nil, "typed nil": typedNil} {
		t.Run(name, func(t *testing.T) {
			if consumer, err := NewEnvelopeConsumer(organizationID, handler); !errors.Is(err, ErrEnvelopeConsumerConfiguration) || consumer != nil {
				t.Fatalf("NewEnvelopeConsumer() = %#v, %v", consumer, err)
			}
		})
	}
	if consumer, err := NewEnvelopeConsumer(domain.ProductID{}, &recordingEnvelopeHandler{}); !errors.Is(err, ErrEnvelopeConsumerConfiguration) || consumer != nil {
		t.Fatalf("zero Organization constructor = %#v, %v", consumer, err)
	}
	if ErrEnvelopeConsumerConfiguration.Error() != "queue envelope consumer configuration rejected" ||
		ErrEnvelope.Error() != "queue envelope rejected" || ErrEnvelopeProcessing.Error() != "queue envelope processing failed" {
		t.Fatal("fixed error text changed")
	}

	body := envelopeFixture(t, EnvelopeBackground, organizationID)
	handler := &recordingEnvelopeHandler{}
	consumer, err := NewEnvelopeConsumer(organizationID, handler)
	if err != nil {
		t.Fatalf("NewEnvelopeConsumer() error = %v", err)
	}
	var nilConsumer *EnvelopeConsumer
	if err := nilConsumer.ConsumeEnvelope(context.Background(), EnvelopeBackground, body); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("nil consumer error = %v", err)
	}
	if err := consumer.ConsumeEnvelope(nil, EnvelopeBackground, body); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("nil context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := consumer.ConsumeEnvelope(cancelled, EnvelopeBackground, body); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("cancelled context error = %v", err)
	}
	if handler.calls.Load() != 0 {
		t.Fatalf("invalid contexts caused %d handler calls", handler.calls.Load())
	}

	handler.handle = func(context.Context, EnvelopeMessage) error { return errors.New("private handler detail") }
	if err := consumer.ConsumeEnvelope(context.Background(), EnvelopeBackground, body); !errors.Is(err, ErrEnvelopeProcessing) || strings.Contains(err.Error(), "private") {
		t.Fatalf("handler error = %v", err)
	}
	handler.handle = func(context.Context, EnvelopeMessage) error { panic("private handler panic") }
	if err := consumer.ConsumeEnvelope(context.Background(), EnvelopeBackground, body); !errors.Is(err, ErrEnvelopeProcessing) || strings.Contains(err.Error(), "private") {
		t.Fatalf("handler panic error = %v", err)
	}
	duringHandler, cancelDuringHandler := context.WithCancel(context.Background())
	handler.handle = func(context.Context, EnvelopeMessage) error {
		cancelDuringHandler()
		return nil
	}
	if err := consumer.ConsumeEnvelope(duringHandler, EnvelopeBackground, body); !errors.Is(err, ErrEnvelopeProcessing) {
		t.Fatalf("during-handler cancellation error = %v", err)
	}
}

func TestEnvelopeMessageZeroValueExposesNoState(t *testing.T) {
	var message EnvelopeMessage
	if message.Kind() != "" || !message.Scope().IsZero() || message.Bytes() != nil {
		t.Fatalf("zero message exposed state: kind=%q scope=%#v bytes=%#v", message.Kind(), message.Scope(), message.Bytes())
	}
}

func TestEnvelopeConsumerConcurrentCallsDoNotRetainOrganizationState(t *testing.T) {
	organizationA := envelopeProductID(t, 1)
	organizationB := envelopeProductID(t, 2)
	handler := &recordingEnvelopeHandler{handle: func(_ context.Context, message EnvelopeMessage) error {
		if message.Scope().OrganizationID() != organizationA {
			return errors.New("foreign Organization reached handler")
		}
		return nil
	}}
	consumer, err := NewEnvelopeConsumer(organizationA, handler)
	if err != nil {
		t.Fatalf("NewEnvelopeConsumer() error = %v", err)
	}

	const calls = 64
	errorsByCall := make(chan error, calls)
	for index := range calls {
		go func() {
			organizationID := organizationA
			want := error(nil)
			if index%2 == 1 {
				organizationID = organizationB
				want = ErrEnvelope
			}
			err := consumer.ConsumeEnvelope(context.Background(), EnvelopeTests, envelopeFixture(t, EnvelopeTests, organizationID))
			if !errors.Is(err, want) || (want == nil && err != nil) {
				errorsByCall <- fmt.Errorf("call %d error = %v, want %v", index, err, want)
				return
			}
			errorsByCall <- nil
		}()
	}
	for range calls {
		if err := <-errorsByCall; err != nil {
			t.Fatal(err)
		}
	}
	if handler.calls.Load() != calls/2 {
		t.Fatalf("handler calls = %d, want %d", handler.calls.Load(), calls/2)
	}
}

func envelopeFixture(t *testing.T, kind EnvelopeKind, organizationID domain.ProductID) []byte {
	t.Helper()
	workspaceID := envelopeProductID(t, 3)
	environmentID := envelopeProductID(t, 4)
	primaryID := envelopeProductID(t, 5)
	switch kind {
	case EnvelopeBackground:
		return []byte(fmt.Sprintf(`{"version":1,"organization_id":"%s","workspace_id":"%s","environment_id":"%s","job_id":"%s","kind":"inventory.sync","payload":{"safe":true}}`, organizationID, workspaceID, environmentID, primaryID))
	case EnvelopeRuntimeEvents:
		return []byte(fmt.Sprintf(`{"version":1,"organization_id":"%s","workspace_id":"%s","environment_id":"%s","batch_id":"%s","event_count":2,"events":[{"safe":true},{"safe":false}]}`, organizationID, workspaceID, environmentID, primaryID))
	case EnvelopeTests:
		return []byte(fmt.Sprintf(`{"version":1,"organization_id":"%s","workspace_id":"%s","environment_id":"%s","test_run_id":"%s","kind":"redteam.run","payload":{"safe":true}}`, organizationID, workspaceID, environmentID, primaryID))
	default:
		t.Fatalf("unsupported fixture kind %q", kind)
		return nil
	}
}

func envelopeProductID(t *testing.T, suffix int) domain.ProductID {
	t.Helper()
	parsed, err := domain.ParseProductID(fmt.Sprintf("pid_00000000-0000-4000-8000-%012x", suffix))
	if err != nil {
		t.Fatalf("ParseProductID() error = %v", err)
	}
	return parsed
}

func replaceEnvelopeString(body []byte, key, value string) []byte {
	start := bytes.Index(body, []byte(`"`+key+`":"`))
	if start < 0 {
		return body
	}
	valueStart := start + len(key) + 4
	valueEnd := valueStart + bytes.IndexByte(body[valueStart:], '"')
	result := make([]byte, 0, len(body)-valueEnd+valueStart+len(value))
	result = append(result, body[:valueStart]...)
	result = append(result, value...)
	result = append(result, body[valueEnd:]...)
	return result
}
