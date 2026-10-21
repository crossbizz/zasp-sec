package preflight

import (
	"path/filepath"
	"regexp"
	"strings"
)

// These fields select intended provider targets. They never carry observations.
type NeonConfig struct {
	CredentialFile    string `json:"credential_file"`
	ExpectedHost      string `json:"expected_host"`
	ExpectedDatabase  string `json:"expected_database"`
	ExpectedPrincipal string `json:"expected_principal"`
	ProfileRecipe     string `json:"profile_recipe"`
}
type StytchConfig struct {
	Origin          string `json:"origin"`
	CredentialFile  string `json:"credential_file"`
	OrganizationID  string `json:"organization_id"`
	MemberID        string `json:"member_id"`
	MemberSessionID string `json:"member_session_id"`
}
type CoreDependencies struct {
	Neon   *NeonConfig
	Stytch *StytchConfig
}

var neonHost = regexp.MustCompile(`^ep-[a-z0-9-]+-pooler\.[a-z0-9.-]+\.neon\.tech$`)
var postgresIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)
var providerUUID = `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`

func validStytchID(value, prefix, environment string) bool {
	return regexp.MustCompile("^" + prefix + "-" + environment + "-" + providerUUID + "$").MatchString(value)
}
func validNeon(c *NeonConfig) bool {
	return c == nil || filepath.IsAbs(c.CredentialFile) && len(c.CredentialFile) <= 4096 && len(c.ExpectedHost) <= 253 && neonHost.MatchString(c.ExpectedHost) && !strings.Contains(c.ExpectedHost, "..") && postgresIdentifier.MatchString(c.ExpectedDatabase) && postgresIdentifier.MatchString(c.ExpectedPrincipal) && (c.ProfileRecipe == "worker-v1" || c.ProfileRecipe == "audit-identity-worker-v1")
}
func validStytch(c *StytchConfig) bool {
	if c == nil {
		return true
	}
	environment := "test"
	if c.Origin == "https://api.stytch.com" {
		environment = "live"
	} else if c.Origin != "https://test.stytch.com" {
		return false
	}
	return filepath.IsAbs(c.CredentialFile) && len(c.CredentialFile) <= 4096 && validStytchID(c.OrganizationID, "organization", environment) && validStytchID(c.MemberID, "member", environment) && validStytchID(c.MemberSessionID, "member-session", environment)
}
func validCoreDependencies(c CoreDependencies) bool {
	return validNeon(c.Neon) && validStytch(c.Stytch)
}
