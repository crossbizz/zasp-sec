package domain

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func mustCorrelationID(t *testing.T, text string) CorrelationID {
	t.Helper()
	productID := mustProductID(t, text)
	correlationID, err := NewCorrelationID(productID)
	if err != nil {
		t.Fatalf("NewCorrelationID returned error: %v", err)
	}
	return correlationID
}

func TestProductCorrelationIDIsDistinctAndCanonical(t *testing.T) {
	productID := mustProductID(t, "pid_60000000-0000-4000-8000-000000000006")
	correlationID, err := NewCorrelationID(productID)
	if err != nil {
		t.Fatalf("NewCorrelationID returned error: %v", err)
	}
	if correlationID.IsZero() || correlationID.ProductID() != productID || correlationID.String() != productID.String() {
		t.Fatalf("correlation ID = %#v", correlationID)
	}
	if reflect.TypeOf(correlationID) == reflect.TypeOf(productID) {
		t.Fatal("correlation and generic product IDs share a concrete type")
	}
	if got := map[CorrelationID]string{correlationID: "present"}[correlationID]; got != "present" {
		t.Fatalf("comparable correlation ID lookup = %q", got)
	}
	for name, id := range map[string]ProductID{
		"zero":      {},
		"malformed": {value: [16]byte{0, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0, 0, 0, 0, 1}},
	} {
		t.Run(name, func(t *testing.T) {
			invalid, err := NewCorrelationID(id)
			if !errors.Is(err, ErrInvalidCorrelationID) || !invalid.IsZero() {
				t.Fatalf("NewCorrelationID = %#v, %v", invalid, err)
			}
		})
	}
}

func TestProductErrorEnvelopeExactJSONSnapshot(t *testing.T) {
	code, err := ParseProductErrorCode("scope_invalid")
	if err != nil {
		t.Fatal(err)
	}
	correlationID := mustCorrelationID(t, "pid_60000000-0000-4000-8000-000000000006")
	envelope, err := NewProductErrorEnvelope(code, "Scope is invalid.", correlationID, false)
	if err != nil {
		t.Fatalf("NewProductErrorEnvelope returned error: %v", err)
	}
	if envelope.IsZero() || envelope.Code() != code || envelope.Message() != "Scope is invalid." || envelope.CorrelationID() != correlationID || envelope.Retryable() {
		t.Fatalf("envelope accessors = %#v", envelope)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	const want = `{"code":"scope_invalid","message":"Scope is invalid.","correlation_id":"pid_60000000-0000-4000-8000-000000000006","retryable":false}`
	if string(encoded) != want {
		t.Fatalf("JSON = %s, want %s", encoded, want)
	}
	if got := map[ProductErrorEnvelope]string{envelope: "present"}[envelope]; got != "present" {
		t.Fatalf("comparable envelope lookup = %q", got)
	}
	for index := 0; index < reflect.TypeOf(ProductErrorEnvelope{}).NumField(); index++ {
		if reflect.TypeOf(ProductErrorEnvelope{}).Field(index).IsExported() {
			t.Fatalf("ProductErrorEnvelope field %q is exported", reflect.TypeOf(ProductErrorEnvelope{}).Field(index).Name)
		}
	}
}

func TestProductErrorEnvelopeRetryableAndEscapingSnapshot(t *testing.T) {
	code, err := ParseProductErrorCode("dependency_unavailable")
	if err != nil {
		t.Fatal(err)
	}
	correlationID := mustCorrelationID(t, "pid_60000000-0000-4000-8000-000000000006")
	envelope, err := NewProductErrorEnvelope(code, `Try "later" <safely>.`, correlationID, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"code":"dependency_unavailable","message":"Try \"later\" \u003csafely\u003e.","correlation_id":"pid_60000000-0000-4000-8000-000000000006","retryable":true}`
	if string(encoded) != want {
		t.Fatalf("JSON = %s, want %s", encoded, want)
	}
}

func TestProductErrorCodeRejectsNonCanonicalValues(t *testing.T) {
	for name, value := range map[string]string{
		"empty":               "",
		"uppercase":           "AccessDeniedException",
		"leading underscore":  "_scope_invalid",
		"trailing underscore": "scope_invalid_",
		"double underscore":   "scope__invalid",
		"hyphen":              "scope-invalid",
		"dot":                 "provider.access_denied",
		"whitespace":          "scope invalid",
		"oversize":            "a" + strings.Repeat("b", 64),
	} {
		t.Run(name, func(t *testing.T) {
			code, err := ParseProductErrorCode(value)
			if !errors.Is(err, ErrInvalidProductErrorCode) || !code.IsZero() {
				t.Fatalf("ParseProductErrorCode(%q) = %#v, %v", value, code, err)
			}
		})
	}
	if got := (ProductErrorCode{value: "critical"}).String(); got != "critical" {
		t.Fatalf("valid direct code String = %q", got)
	}
	if got := (ProductErrorCode{value: "Invalid"}).String(); got != "" {
		t.Fatalf("invalid direct code rendered as %q", got)
	}
}

func TestProductErrorEnvelopeRejectsInvalidMessagesAndCorrelationIDs(t *testing.T) {
	code, err := ParseProductErrorCode("operation_failed")
	if err != nil {
		t.Fatal(err)
	}
	correlationID := mustCorrelationID(t, "pid_60000000-0000-4000-8000-000000000006")
	for name, message := range map[string]string{
		"empty":          "",
		"leading space":  " Product failure.",
		"trailing space": "Product failure. ",
		"control":        "Product\nfailure.",
		"invalid UTF-8":  string([]byte{0xff}),
		"oversize":       strings.Repeat("x", 513),
	} {
		t.Run(name, func(t *testing.T) {
			envelope, err := NewProductErrorEnvelope(code, message, correlationID, false)
			if !errors.Is(err, ErrInvalidProductErrorEnvelope) || !envelope.IsZero() {
				t.Fatalf("NewProductErrorEnvelope = %#v, %v", envelope, err)
			}
			if err != nil && message != "" && strings.Contains(err.Error(), message) {
				t.Fatal("fixed error disclosed rejected message")
			}
		})
	}
	for name, id := range map[string]CorrelationID{
		"zero":      {},
		"malformed": {productID: ProductID{value: [16]byte{0, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0, 0, 0, 0, 1}}},
	} {
		t.Run(name, func(t *testing.T) {
			envelope, err := NewProductErrorEnvelope(code, "Product failure.", id, false)
			if !errors.Is(err, ErrInvalidProductErrorEnvelope) || !envelope.IsZero() {
				t.Fatalf("NewProductErrorEnvelope = %#v, %v", envelope, err)
			}
		})
	}
}

func TestProductErrorEnvelopeRejectsZeroAndMalformedDirectState(t *testing.T) {
	code, err := ParseProductErrorCode("operation_failed")
	if err != nil {
		t.Fatal(err)
	}
	correlationID := mustCorrelationID(t, "pid_60000000-0000-4000-8000-000000000006")
	for name, envelope := range map[string]ProductErrorEnvelope{
		"zero":            {},
		"invalid code":    {code: ProductErrorCode{value: "Invalid"}, message: "Product failure.", correlationID: correlationID},
		"invalid message": {code: code, message: "", correlationID: correlationID},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(envelope)
			if !errors.Is(err, ErrInvalidProductErrorEnvelope) {
				t.Fatalf("json.Marshal error = %v", err)
			}
			if encoded != nil {
				t.Fatalf("rejected JSON = %q", encoded)
			}
		})
	}
}
