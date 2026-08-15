package domain

import (
	"errors"
	"reflect"
	"testing"
)

func TestEvidenceRefRoundTripsCanonicalProductIdentity(t *testing.T) {
	artifactID := mustProductID(t, "pid_50000000-0000-4000-8000-000000000005")
	reference, err := NewEvidenceRef(artifactID)
	if err != nil {
		t.Fatalf("NewEvidenceRef returned error: %v", err)
	}
	if reference.IsZero() || reference.ArtifactID() != artifactID || reference.String() != artifactID.String() {
		t.Fatalf("reference = %#v", reference)
	}
	text, err := reference.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText returned error: %v", err)
	}
	parsed, err := ParseEvidenceRef(string(text))
	if err != nil || parsed != reference {
		t.Fatalf("ParseEvidenceRef = %#v, %v", parsed, err)
	}
	var decoded EvidenceRef
	if err := decoded.UnmarshalText(text); err != nil || decoded != reference {
		t.Fatalf("UnmarshalText = %#v, %v", decoded, err)
	}
	if got := map[EvidenceRef]string{reference: "present"}[reference]; got != "present" {
		t.Fatalf("comparable evidence reference lookup = %q", got)
	}
	for index := 0; index < reflect.TypeOf(EvidenceRef{}).NumField(); index++ {
		if reflect.TypeOf(EvidenceRef{}).Field(index).IsExported() {
			t.Fatalf("EvidenceRef field %q is exported", reflect.TypeOf(EvidenceRef{}).Field(index).Name)
		}
	}
}

func TestEvidenceRefRejectsZeroMalformedAndExternalIdentity(t *testing.T) {
	malformed := ProductID{value: [16]byte{0, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0, 0, 0, 0, 1}}
	for name, id := range map[string]ProductID{"zero": {}, "malformed": malformed} {
		t.Run(name, func(t *testing.T) {
			reference, err := NewEvidenceRef(id)
			if !errors.Is(err, ErrInvalidEvidenceRef) || !reference.IsZero() {
				t.Fatalf("NewEvidenceRef = %#v, %v", reference, err)
			}
		})
	}
	for _, value := range []string{"", "arn:aws:s3:::evidence", "50000000-0000-4000-8000-000000000005"} {
		reference, err := ParseEvidenceRef(value)
		if !errors.Is(err, ErrInvalidEvidenceRef) || !reference.IsZero() {
			t.Fatalf("ParseEvidenceRef(%q) = %#v, %v", value, reference, err)
		}
	}
	if _, err := (EvidenceRef{}).MarshalText(); !errors.Is(err, ErrInvalidEvidenceRef) {
		t.Fatalf("zero MarshalText error = %v", err)
	}
}

func TestEvidenceRefUnmarshalClearsReceiverAndRejectsNil(t *testing.T) {
	artifactID := mustProductID(t, "pid_50000000-0000-4000-8000-000000000005")
	reference, err := NewEvidenceRef(artifactID)
	if err != nil {
		t.Fatal(err)
	}
	if err := reference.UnmarshalText([]byte("external-evidence")); !errors.Is(err, ErrInvalidEvidenceRef) {
		t.Fatalf("error = %v, want ErrInvalidEvidenceRef", err)
	}
	if !reference.IsZero() {
		t.Fatalf("receiver retained rejected reference %#v", reference)
	}
	var nilReference *EvidenceRef
	if err := nilReference.UnmarshalText([]byte(artifactID.String())); !errors.Is(err, ErrInvalidEvidenceRef) {
		t.Fatalf("nil receiver error = %v", err)
	}
}

func TestEvidenceConfidenceExactRoundTrips(t *testing.T) {
	values := []EvidenceConfidence{
		EvidenceConfidenceExact,
		EvidenceConfidenceStrong,
		EvidenceConfidenceProbable,
		EvidenceConfidenceUnattributed,
	}
	for _, value := range values {
		t.Run(value.String(), func(t *testing.T) {
			parsed, err := ParseEvidenceConfidence(value.String())
			if err != nil || parsed != value {
				t.Fatalf("ParseEvidenceConfidence = %q, %v", parsed, err)
			}
			text, err := value.MarshalText()
			if err != nil || string(text) != value.String() {
				t.Fatalf("MarshalText = %q, %v", text, err)
			}
			var decoded EvidenceConfidence
			if err := decoded.UnmarshalText(text); err != nil || decoded != value {
				t.Fatalf("UnmarshalText = %q, %v", decoded, err)
			}
		})
	}
}

func TestEvidenceConfidenceRejectsAliasesSeverityAndReceiverMisuse(t *testing.T) {
	for _, value := range []string{"", "Exact", " exact", "exact ", "high", "critical", "unknown"} {
		parsed, err := ParseEvidenceConfidence(value)
		if !errors.Is(err, ErrInvalidEvidenceConfidence) || parsed != "" {
			t.Fatalf("ParseEvidenceConfidence(%q) = %q, %v", value, parsed, err)
		}
	}
	confidence := EvidenceConfidenceExact
	if err := confidence.UnmarshalText([]byte("critical")); !errors.Is(err, ErrInvalidEvidenceConfidence) || confidence != "" {
		t.Fatalf("rejected confidence retained %q with %v", confidence, err)
	}
	var nilConfidence *EvidenceConfidence
	if err := nilConfidence.UnmarshalText([]byte("exact")); !errors.Is(err, ErrInvalidEvidenceConfidence) {
		t.Fatalf("nil receiver error = %v", err)
	}
	if _, err := (EvidenceConfidence("")).MarshalText(); !errors.Is(err, ErrInvalidEvidenceConfidence) {
		t.Fatalf("zero MarshalText error = %v", err)
	}
	type FindingSeverity string
	if reflect.TypeOf(EvidenceConfidenceExact) == reflect.TypeOf(FindingSeverity("high")) {
		t.Fatal("evidence confidence shares the finding-severity type")
	}
}

func TestCapabilityPathStateExactRoundTrips(t *testing.T) {
	values := []CapabilityPathState{
		CapabilityPathStateConfigured,
		CapabilityPathStateReachable,
		CapabilityPathStateObserved,
		CapabilityPathStateVerified,
		CapabilityPathStateBlocked,
	}
	for _, value := range values {
		t.Run(value.String(), func(t *testing.T) {
			parsed, err := ParseCapabilityPathState(value.String())
			if err != nil || parsed != value {
				t.Fatalf("ParseCapabilityPathState = %q, %v", parsed, err)
			}
			text, err := value.MarshalText()
			if err != nil || string(text) != value.String() {
				t.Fatalf("MarshalText = %q, %v", text, err)
			}
			var decoded CapabilityPathState
			if err := decoded.UnmarshalText(text); err != nil || decoded != value {
				t.Fatalf("UnmarshalText = %q, %v", decoded, err)
			}
		})
	}
}

func TestCapabilityPathStateRejectsAliasesAndReceiverMisuse(t *testing.T) {
	for _, value := range []string{"", "Verified", " verified", "verified ", "verify", "critical", "unknown"} {
		parsed, err := ParseCapabilityPathState(value)
		if !errors.Is(err, ErrInvalidCapabilityPathState) || parsed != "" {
			t.Fatalf("ParseCapabilityPathState(%q) = %q, %v", value, parsed, err)
		}
	}
	state := CapabilityPathStateObserved
	if err := state.UnmarshalText([]byte("critical")); !errors.Is(err, ErrInvalidCapabilityPathState) || state != "" {
		t.Fatalf("rejected state retained %q with %v", state, err)
	}
	var nilState *CapabilityPathState
	if err := nilState.UnmarshalText([]byte("observed")); !errors.Is(err, ErrInvalidCapabilityPathState) {
		t.Fatalf("nil receiver error = %v", err)
	}
	if _, err := (CapabilityPathState("")).MarshalText(); !errors.Is(err, ErrInvalidCapabilityPathState) {
		t.Fatalf("zero MarshalText error = %v", err)
	}
}

func TestEvidenceEnumsDoNotRenderInvalidDirectCasts(t *testing.T) {
	if got := EvidenceConfidence("critical").String(); got != "" {
		t.Fatalf("invalid confidence rendered as %q", got)
	}
	if got := CapabilityPathState("unknown").String(); got != "" {
		t.Fatalf("invalid capability/path state rendered as %q", got)
	}
}
