package domain

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestProductIDGenerationUsesCanonicalUUIDv4(t *testing.T) {
	id, err := newProductID(strings.NewReader(string([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	})))
	if err != nil {
		t.Fatalf("newProductID returned error: %v", err)
	}
	if id.IsZero() {
		t.Fatal("generated ID is zero")
	}
	if got, want := id.String(), "pid_00010203-0405-4607-8809-0a0b0c0d0e0f"; got != want {
		t.Fatalf("ID = %q, want %q", got, want)
	}
}

func TestProductIDTextRoundTrip(t *testing.T) {
	const encoded = "pid_00010203-0405-4607-8809-0a0b0c0d0e0f"
	id, err := ParseProductID(encoded)
	if err != nil {
		t.Fatalf("ParseProductID returned error: %v", err)
	}
	text, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText returned error: %v", err)
	}
	if string(text) != encoded {
		t.Fatalf("MarshalText = %q, want %q", text, encoded)
	}

	var decoded ProductID
	if err := decoded.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText returned error: %v", err)
	}
	if decoded != id {
		t.Fatalf("decoded ID = %v, want %v", decoded, id)
	}
}

func TestProductIDRejectsNonCanonicalValues(t *testing.T) {
	for name, value := range map[string]string{
		"empty":          "",
		"missing prefix": "00010203-0405-4607-8809-0a0b0c0d0e0f",
		"uppercase":      "pid_00010203-0405-4607-8809-0A0B0C0D0E0F",
		"nil UUID":       "pid_00000000-0000-4000-8000-000000000000",
		"wrong version":  "pid_00010203-0405-1607-8809-0a0b0c0d0e0f",
		"wrong variant":  "pid_00010203-0405-4607-7809-0a0b0c0d0e0f",
		"invalid digit":  "pid_00010203-0405-4607-8809-0a0b0c0d0e0g",
		"short":          "pid_00010203-0405-4607-8809-0a0b0c0d0e0",
		"trailing":       "pid_00010203-0405-4607-8809-0a0b0c0d0e0f-extra",
	} {
		t.Run(name, func(t *testing.T) {
			id, err := ParseProductID(value)
			if !errors.Is(err, ErrInvalidProductID) {
				t.Fatalf("error = %v, want ErrInvalidProductID", err)
			}
			if !id.IsZero() {
				t.Fatalf("rejected ID = %q, want zero", id.String())
			}
		})
	}
}

func TestProductIDUnmarshalClearsPriorValueAndRejectsNilReceiver(t *testing.T) {
	id, err := ParseProductID("pid_00010203-0405-4607-8809-0a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	if err := id.UnmarshalText([]byte("vendor-id")); !errors.Is(err, ErrInvalidProductID) {
		t.Fatalf("error = %v, want ErrInvalidProductID", err)
	}
	if !id.IsZero() {
		t.Fatalf("receiver retained rejected ID %q", id.String())
	}

	var nilID *ProductID
	if err := nilID.UnmarshalText([]byte("pid_00010203-0405-4607-8809-0a0b0c0d0e0f")); !errors.Is(err, ErrInvalidProductID) {
		t.Fatalf("nil receiver error = %v, want ErrInvalidProductID", err)
	}
	if _, err := (ProductID{}).MarshalText(); !errors.Is(err, ErrInvalidProductID) {
		t.Fatalf("zero marshal error = %v, want ErrInvalidProductID", err)
	}
}

func TestProductIDGenerationContainsEntropyFailures(t *testing.T) {
	for name, reader := range map[string]interface{ Read([]byte) (int, error) }{
		"error": failingReader{},
		"short": strings.NewReader("short"),
		"zero":  strings.NewReader(string(make([]byte, 16))),
	} {
		t.Run(name, func(t *testing.T) {
			id, err := newProductID(reader)
			if !errors.Is(err, ErrProductIDGeneration) {
				t.Fatalf("error = %v, want ErrProductIDGeneration", err)
			}
			if !id.IsZero() {
				t.Fatalf("failed ID = %q, want zero", id.String())
			}
		})
	}
}

func TestExternalSourceRefPreservesExactBoundedIdentity(t *testing.T) {
	const external = "arn:aws:iam::000000000000:role/shared-fixture-role"
	ref, err := NewExternalSourceRef("aws", "iam.role", external)
	if err != nil {
		t.Fatalf("NewExternalSourceRef returned error: %v", err)
	}
	if ref.Source() != "aws" || ref.Kind() != "iam.role" || ref.ExternalID().String() != external {
		t.Fatalf("reference = %q/%q/%q", ref.Source(), ref.Kind(), ref.ExternalID().String())
	}
}

func TestExternalSourceRefRejectsInvalidFields(t *testing.T) {
	validID := "external-1"
	for name, fields := range map[string][3]string{
		"empty source":      {"", "iam.role", validID},
		"uppercase source":  {"AWS", "iam.role", validID},
		"long source":       {"a" + strings.Repeat("b", 63), "iam.role", validID},
		"empty kind":        {"aws", "", validID},
		"invalid kind":      {"aws", "iam/role", validID},
		"empty external":    {"aws", "iam.role", ""},
		"trimmed external":  {"aws", "iam.role", " external-1"},
		"control external":  {"aws", "iam.role", "external\n1"},
		"invalid UTF-8":     {"aws", "iam.role", string([]byte{0xff})},
		"oversize external": {"aws", "iam.role", strings.Repeat("x", 513)},
	} {
		t.Run(name, func(t *testing.T) {
			source, kind, external := fields[0], fields[1], fields[2]
			ref, err := NewExternalSourceRef(source, kind, external)
			if !errors.Is(err, ErrInvalidExternalSourceRef) {
				t.Fatalf("error = %v, want ErrInvalidExternalSourceRef", err)
			}
			if ref.Source() != "" || ref.Kind() != "" || ref.ExternalID().String() != "" {
				t.Fatalf("rejected reference was partially retained: %#v", ref)
			}
		})
	}
}

func TestExternalVendorIDCannotBecomeProductPrimaryID(t *testing.T) {
	for _, vendorID := range []string{
		"arn:aws:iam::000000000000:role/shared-fixture-role",
		"00010203-0405-4607-8809-0a0b0c0d0e0f",
	} {
		ref, err := NewExternalSourceRef("aws", "iam.role", vendorID)
		if err != nil {
			t.Fatalf("NewExternalSourceRef(%q): %v", vendorID, err)
		}
		if _, err := ParseProductID(ref.ExternalID().String()); !errors.Is(err, ErrInvalidProductID) {
			t.Fatalf("vendor ID %q parsed as a product ID", vendorID)
		}
		if reflect.TypeOf(ref.ExternalID()) == reflect.TypeOf(ProductID{}) {
			t.Fatal("external and product IDs share a concrete type")
		}
	}
}
