package domain

import (
	"crypto/rand"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	productIDPrefix     = "pid_"
	externalIDByteLimit = 512
)

var (
	ErrInvalidProductID         = errors.New("invalid product ID")
	ErrProductIDGeneration      = errors.New("product ID generation failed")
	ErrInvalidExternalSourceRef = errors.New("invalid external source reference")
	tokenPattern                = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
)

type ProductID struct {
	value [16]byte
}

func NewProductID() (ProductID, error) {
	return newProductID(rand.Reader)
}

func newProductID(reader io.Reader) (ProductID, error) {
	if reader == nil {
		return ProductID{}, ErrProductIDGeneration
	}
	var value [16]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return ProductID{}, ErrProductIDGeneration
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	if zeroUUIDPayload(value) {
		return ProductID{}, ErrProductIDGeneration
	}
	return ProductID{value: value}, nil
}

func ParseProductID(text string) (ProductID, error) {
	if len(text) != len(productIDPrefix)+36 || !strings.HasPrefix(text, productIDPrefix) {
		return ProductID{}, ErrInvalidProductID
	}
	uuidText := text[len(productIDPrefix):]
	for _, index := range []int{8, 13, 18, 23} {
		if uuidText[index] != '-' {
			return ProductID{}, ErrInvalidProductID
		}
	}

	var value [16]byte
	byteIndex := 0
	for index := 0; index < len(uuidText); {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			index++
			continue
		}
		high, ok := lowercaseHexNibble(uuidText[index])
		if !ok || index+1 >= len(uuidText) {
			return ProductID{}, ErrInvalidProductID
		}
		low, ok := lowercaseHexNibble(uuidText[index+1])
		if !ok {
			return ProductID{}, ErrInvalidProductID
		}
		value[byteIndex] = high<<4 | low
		byteIndex++
		index += 2
	}
	if byteIndex != len(value) || value[6]>>4 != 4 || value[8]&0xc0 != 0x80 || zeroUUIDPayload(value) {
		return ProductID{}, ErrInvalidProductID
	}
	return ProductID{value: value}, nil
}

func lowercaseHexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}

func zeroUUIDPayload(value [16]byte) bool {
	value[6] &= 0x0f
	value[8] &= 0x3f
	for _, part := range value {
		if part != 0 {
			return false
		}
	}
	return true
}

func (id ProductID) IsZero() bool {
	return id == ProductID{}
}

func (id ProductID) valid() bool {
	return !id.IsZero() && id.value[6]>>4 == 4 && id.value[8]&0xc0 == 0x80 && !zeroUUIDPayload(id.value)
}

func (id ProductID) String() string {
	if id.IsZero() {
		return ""
	}
	const digits = "0123456789abcdef"
	encoded := [40]byte{'p', 'i', 'd', '_'}
	textIndex := len(productIDPrefix)
	for index, part := range id.value {
		if index == 4 || index == 6 || index == 8 || index == 10 {
			encoded[textIndex] = '-'
			textIndex++
		}
		encoded[textIndex] = digits[part>>4]
		encoded[textIndex+1] = digits[part&0x0f]
		textIndex += 2
	}
	return string(encoded[:])
}

func (id ProductID) MarshalText() ([]byte, error) {
	if id.IsZero() {
		return nil, ErrInvalidProductID
	}
	return []byte(id.String()), nil
}

func (id *ProductID) UnmarshalText(text []byte) error {
	if id == nil {
		return ErrInvalidProductID
	}
	*id = ProductID{}
	parsed, err := ParseProductID(string(text))
	if err != nil {
		return ErrInvalidProductID
	}
	*id = parsed
	return nil
}

type ExternalID struct {
	value string
}

func (id ExternalID) String() string {
	return id.value
}

type ExternalSourceRef struct {
	source     string
	kind       string
	externalID ExternalID
}

func NewExternalSourceRef(source, kind, externalID string) (ExternalSourceRef, error) {
	if !tokenPattern.MatchString(source) || !tokenPattern.MatchString(kind) || !validExternalID(externalID) {
		return ExternalSourceRef{}, ErrInvalidExternalSourceRef
	}
	return ExternalSourceRef{
		source:     source,
		kind:       kind,
		externalID: ExternalID{value: externalID},
	}, nil
}

func validExternalID(value string) bool {
	if value == "" || len(value) > externalIDByteLimit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (ref ExternalSourceRef) Source() string {
	return ref.source
}

func (ref ExternalSourceRef) Kind() string {
	return ref.kind
}

func (ref ExternalSourceRef) ExternalID() ExternalID {
	return ref.externalID
}
