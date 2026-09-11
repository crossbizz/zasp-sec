package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestEnrollmentBindingPinsEveryScopeDimensionAndSensor(t *testing.T) {
	ids := make([]domain.ProductID, 5)
	for index, raw := range []string{
		"pid_78950001-0000-4000-8000-000000000001",
		"pid_78950002-0000-4000-8000-000000000002",
		"pid_78950003-0000-4000-8000-000000000003",
		"pid_78950004-0000-4000-8000-000000000004",
		"pid_78950005-0000-4000-8000-000000000005",
	} {
		var err error
		ids[index], err = domain.ParseProductID(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	binding, err := EnrollmentBinding(scope, ids[3])
	expected := sha256.Sum256([]byte("zasp.sensor-enrollment.v1\x00" + strings.Join([]string{ids[0].String(), ids[1].String(), ids[2].String(), ids[3].String()}, "\x00")))
	if err != nil || binding != hex.EncodeToString(expected[:]) || len(binding) != 64 {
		t.Fatalf("binding=%q error=%v", binding, err)
	}
	for dimension := 0; dimension < 4; dimension++ {
		changed := append([]domain.ProductID(nil), ids...)
		changed[dimension] = ids[4]
		changedScope, err := domain.NewScope(changed[0], changed[1], changed[2])
		if err != nil {
			t.Fatal(err)
		}
		other, err := EnrollmentBinding(changedScope, changed[3])
		if err != nil || other == binding {
			t.Fatalf("dimension %d did not change binding: %q, %v", dimension, other, err)
		}
	}
	if repeated, err := EnrollmentBinding(scope, ids[3]); err != nil || repeated != binding {
		t.Fatal("same enrollment changed binding")
	}
	if value, err := EnrollmentBinding(domain.Scope{}, ids[3]); err == nil || value != "" {
		t.Fatal("invalid scope accepted")
	}
	if value, err := EnrollmentBinding(scope, domain.ProductID{}); err == nil || value != "" {
		t.Fatal("empty sensor accepted")
	}
}
