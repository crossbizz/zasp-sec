package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	productErrorCodeByteLimit    = 64
	productErrorMessageByteLimit = 512
)

var (
	ErrInvalidProductErrorCode     = errors.New("invalid product error code")
	ErrInvalidCorrelationID        = errors.New("invalid correlation ID")
	ErrInvalidProductErrorEnvelope = errors.New("invalid product error envelope")
)

type ProductErrorCode struct {
	value string
}

func ParseProductErrorCode(text string) (ProductErrorCode, error) {
	code := ProductErrorCode{value: text}
	if !code.valid() {
		return ProductErrorCode{}, ErrInvalidProductErrorCode
	}
	return code, nil
}

func (code ProductErrorCode) valid() bool {
	if len(code.value) == 0 || len(code.value) > productErrorCodeByteLimit || code.value[0] < 'a' || code.value[0] > 'z' {
		return false
	}
	previousUnderscore := false
	for _, character := range []byte(code.value[1:]) {
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			previousUnderscore = false
		case character == '_' && !previousUnderscore:
			previousUnderscore = true
		default:
			return false
		}
	}
	return !previousUnderscore
}

func (code ProductErrorCode) IsZero() bool {
	return code == ProductErrorCode{}
}

func (code ProductErrorCode) String() string {
	if !code.valid() {
		return ""
	}
	return code.value
}

type CorrelationID struct {
	productID ProductID
}

func NewCorrelationID(productID ProductID) (CorrelationID, error) {
	correlationID := CorrelationID{productID: productID}
	if !correlationID.valid() {
		return CorrelationID{}, ErrInvalidCorrelationID
	}
	return correlationID, nil
}

func (correlationID CorrelationID) valid() bool {
	return correlationID.productID.valid()
}

func (correlationID CorrelationID) IsZero() bool {
	return correlationID == CorrelationID{}
}

func (correlationID CorrelationID) ProductID() ProductID {
	return correlationID.productID
}

func (correlationID CorrelationID) String() string {
	if !correlationID.valid() {
		return ""
	}
	return correlationID.productID.String()
}

type ProductErrorEnvelope struct {
	code          ProductErrorCode
	message       string
	correlationID CorrelationID
	retryable     bool
}

func NewProductErrorEnvelope(code ProductErrorCode, message string, correlationID CorrelationID, retryable bool) (ProductErrorEnvelope, error) {
	envelope := ProductErrorEnvelope{
		code:          code,
		message:       message,
		correlationID: correlationID,
		retryable:     retryable,
	}
	if err := envelope.Validate(); err != nil {
		return ProductErrorEnvelope{}, ErrInvalidProductErrorEnvelope
	}
	return envelope, nil
}

func (envelope ProductErrorEnvelope) Validate() error {
	if !envelope.code.valid() || !validProductErrorMessage(envelope.message) || !envelope.correlationID.valid() {
		return ErrInvalidProductErrorEnvelope
	}
	return nil
}

func validProductErrorMessage(message string) bool {
	if message == "" || len(message) > productErrorMessageByteLimit || !utf8.ValidString(message) || strings.TrimSpace(message) != message {
		return false
	}
	for _, character := range message {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (envelope ProductErrorEnvelope) IsZero() bool {
	return envelope == ProductErrorEnvelope{}
}

func (envelope ProductErrorEnvelope) Code() ProductErrorCode {
	return envelope.code
}

func (envelope ProductErrorEnvelope) Message() string {
	return envelope.message
}

func (envelope ProductErrorEnvelope) CorrelationID() CorrelationID {
	return envelope.correlationID
}

func (envelope ProductErrorEnvelope) Retryable() bool {
	return envelope.retryable
}

func (envelope ProductErrorEnvelope) MarshalJSON() ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, ErrInvalidProductErrorEnvelope
	}
	payload := struct {
		Code          string `json:"code"`
		Message       string `json:"message"`
		CorrelationID string `json:"correlation_id"`
		Retryable     bool   `json:"retryable"`
	}{
		Code:          envelope.code.String(),
		Message:       envelope.message,
		CorrelationID: envelope.correlationID.String(),
		Retryable:     envelope.retryable,
	}
	return json.Marshal(payload)
}
