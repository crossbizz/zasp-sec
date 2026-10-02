package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const AuthorizationRuntimeProfileName = "canonical61-temporal78-authorization79-80-runtime-v1"

//go:embed sql/0080_authorization_runtime_profile.sql
var authorizationRuntimeProfileSQL string

//go:embed sql/0080_authorization_runtime_projection.sql
var authorizationRuntimeProjectionSQL string

// AuthorizationRuntimeProfileChecksum binds the fixed current-only adapters.
// It is independent of payload codec selection and canonical migration pins.
func AuthorizationRuntimeProfileChecksum() string {
	_, checksum := authorizationRuntimeProfileSource()
	return checksum
}

func authorizationRuntimeProfileSource() (string, string) {
	source := strings.NewReplacer(
		"-- runtime projection writer definitions", authorizationRuntimeProjectionSQL,
		"-- runtime source48 checksum", ProductionRuntimeAcceptance().Checksum(),
		"-- runtime source48 fingerprint", ProductionRuntimeAcceptanceSemanticFingerprint(),
		"-- runtime source50 checksum", ProductionRuntimeSandboxBinding().Checksum(),
		"-- runtime source50 fingerprint", ProductionRuntimeSandboxBindingSemanticFingerprint(),
		"-- runtime source51 checksum", ProductionRuntimePrecision().Checksum(),
		"-- runtime source51 fingerprint", ProductionRuntimePrecisionSemanticFingerprint(),
		"-- runtime authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(),
	).Replace(authorizationRuntimeProfileSQL)
	digest := sha256.Sum256([]byte(source))
	checksum := hex.EncodeToString(digest[:])
	return strings.ReplaceAll(source, "-- runtime profile checksum", checksum), checksum
}
