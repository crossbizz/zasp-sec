package migrations

import (
	"crypto/sha256"
	"encoding/hex"
)

// These identities hash the original unbound source, exactly as the metadata
// constructors do. Readiness never needs to render ancestor SQL. Recompute on
// every call; no cached identity can hide a changed source.

func TemporalDomainChecksum() string {
	sum := sha256.Sum256([]byte(temporalDomainBaseSQL + "\x00" + temporalDomainUpSQL))
	return hex.EncodeToString(sum[:])
}

func TemporalExecutorChecksum() string {
	sum := sha256.Sum256([]byte(temporalExecutorSource()))
	return hex.EncodeToString(sum[:])
}

func TemporalWorkflowChecksum() string {
	sum := sha256.Sum256([]byte(temporalWorkflowSQL))
	return hex.EncodeToString(sum[:])
}

func TemporalCompatibilityChecksum() string {
	sum := sha256.Sum256([]byte(temporalCompatibilitySQL))
	return hex.EncodeToString(sum[:])
}

func TemporalLegacyTestsChecksum() string {
	sum := sha256.Sum256([]byte(temporalLegacyTestsSQL))
	return hex.EncodeToString(sum[:])
}

func TemporalDiscoveryChecksum() string {
	sum := sha256.Sum256([]byte(temporalDiscoverySQL))
	return hex.EncodeToString(sum[:])
}

func TemporalAdmissionChecksum() string {
	sum := sha256.Sum256([]byte(temporalAdmissionSQL))
	return hex.EncodeToString(sum[:])
}

func TemporalTestExecutorChecksum() string {
	sum := sha256.Sum256([]byte(temporalTestExecutorSource()))
	return hex.EncodeToString(sum[:])
}

func TemporalTestSelectorChecksum() string {
	sum := sha256.Sum256([]byte(temporalTestSelectorSQL))
	return hex.EncodeToString(sum[:])
}

func TemporalHumanAdmissionChecksum() string {
	sum := sha256.Sum256([]byte(temporalHumanAdmissionSQL))
	return hex.EncodeToString(sum[:])
}
