package domain

import "errors"

var (
	ErrInvalidEvidenceRef         = errors.New("invalid evidence reference")
	ErrInvalidEvidenceConfidence  = errors.New("invalid evidence confidence")
	ErrInvalidCapabilityPathState = errors.New("invalid capability path state")
)

type EvidenceRef struct {
	artifactID ProductID
}

func NewEvidenceRef(artifactID ProductID) (EvidenceRef, error) {
	reference := EvidenceRef{artifactID: artifactID}
	if err := reference.Validate(); err != nil {
		return EvidenceRef{}, ErrInvalidEvidenceRef
	}
	return reference, nil
}

func ParseEvidenceRef(text string) (EvidenceRef, error) {
	artifactID, err := ParseProductID(text)
	if err != nil {
		return EvidenceRef{}, ErrInvalidEvidenceRef
	}
	return NewEvidenceRef(artifactID)
}

func (reference EvidenceRef) Validate() error {
	if !reference.artifactID.valid() {
		return ErrInvalidEvidenceRef
	}
	return nil
}

func (reference EvidenceRef) IsZero() bool {
	return reference == EvidenceRef{}
}

func (reference EvidenceRef) ArtifactID() ProductID {
	return reference.artifactID
}

func (reference EvidenceRef) String() string {
	if reference.Validate() != nil {
		return ""
	}
	return reference.artifactID.String()
}

func (reference EvidenceRef) MarshalText() ([]byte, error) {
	if reference.Validate() != nil {
		return nil, ErrInvalidEvidenceRef
	}
	return []byte(reference.String()), nil
}

func (reference *EvidenceRef) UnmarshalText(text []byte) error {
	if reference == nil {
		return ErrInvalidEvidenceRef
	}
	*reference = EvidenceRef{}
	parsed, err := ParseEvidenceRef(string(text))
	if err != nil {
		return ErrInvalidEvidenceRef
	}
	*reference = parsed
	return nil
}

type EvidenceConfidence string

const (
	EvidenceConfidenceExact        EvidenceConfidence = "exact"
	EvidenceConfidenceStrong       EvidenceConfidence = "strong"
	EvidenceConfidenceProbable     EvidenceConfidence = "probable"
	EvidenceConfidenceUnattributed EvidenceConfidence = "unattributed"
)

func ParseEvidenceConfidence(text string) (EvidenceConfidence, error) {
	value := EvidenceConfidence(text)
	if !value.valid() {
		return "", ErrInvalidEvidenceConfidence
	}
	return value, nil
}

func (confidence EvidenceConfidence) valid() bool {
	switch confidence {
	case EvidenceConfidenceExact, EvidenceConfidenceStrong, EvidenceConfidenceProbable, EvidenceConfidenceUnattributed:
		return true
	default:
		return false
	}
}

func (confidence EvidenceConfidence) String() string {
	if !confidence.valid() {
		return ""
	}
	return string(confidence)
}

func (confidence EvidenceConfidence) MarshalText() ([]byte, error) {
	if !confidence.valid() {
		return nil, ErrInvalidEvidenceConfidence
	}
	return []byte(confidence), nil
}

func (confidence *EvidenceConfidence) UnmarshalText(text []byte) error {
	if confidence == nil {
		return ErrInvalidEvidenceConfidence
	}
	*confidence = ""
	parsed, err := ParseEvidenceConfidence(string(text))
	if err != nil {
		return ErrInvalidEvidenceConfidence
	}
	*confidence = parsed
	return nil
}

type CapabilityPathState string

const (
	CapabilityPathStateConfigured CapabilityPathState = "configured"
	CapabilityPathStateReachable  CapabilityPathState = "reachable"
	CapabilityPathStateObserved   CapabilityPathState = "observed"
	CapabilityPathStateVerified   CapabilityPathState = "verified"
	CapabilityPathStateBlocked    CapabilityPathState = "blocked"
)

func ParseCapabilityPathState(text string) (CapabilityPathState, error) {
	value := CapabilityPathState(text)
	if !value.valid() {
		return "", ErrInvalidCapabilityPathState
	}
	return value, nil
}

func (state CapabilityPathState) valid() bool {
	switch state {
	case CapabilityPathStateConfigured, CapabilityPathStateReachable, CapabilityPathStateObserved,
		CapabilityPathStateVerified, CapabilityPathStateBlocked:
		return true
	default:
		return false
	}
}

func (state CapabilityPathState) String() string {
	if !state.valid() {
		return ""
	}
	return string(state)
}

func (state CapabilityPathState) MarshalText() ([]byte, error) {
	if !state.valid() {
		return nil, ErrInvalidCapabilityPathState
	}
	return []byte(state), nil
}

func (state *CapabilityPathState) UnmarshalText(text []byte) error {
	if state == nil {
		return ErrInvalidCapabilityPathState
	}
	*state = ""
	parsed, err := ParseCapabilityPathState(string(text))
	if err != nil {
		return ErrInvalidCapabilityPathState
	}
	*state = parsed
	return nil
}
