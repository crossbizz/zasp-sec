package attacklab

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrInvalidEgressCapability = errors.New("attack lab egress capability invalid")

type EgressGrant struct {
	Scope       domain.Scope
	RunID       string
	Destination string
	Methods     []string
	ExpiresAt   time.Time
	InputDigest [sha256.Size]byte
}

type egressClaims struct {
	SchemaVersion  string   `json:"schema_version"`
	OrganizationID string   `json:"organization_id"`
	WorkspaceID    string   `json:"workspace_id"`
	EnvironmentID  string   `json:"environment_id"`
	RunID          string   `json:"run_id"`
	Destination    string   `json:"destination"`
	Methods        []string `json:"methods"`
	IssuedAt       int64    `json:"issued_at"`
	ExpiresAt      int64    `json:"expires_at"`
	InputDigest    string   `json:"input_digest"`
}

func SignEgressCapability(key []byte, grant EgressGrant, now time.Time) (string, error) {
	if !validEgressKey(key) || !validEgressGrant(grant, now, true) {
		return "", ErrInvalidEgressCapability
	}
	claims := egressClaims{
		SchemaVersion: "attack-lab-egress-v1", OrganizationID: grant.Scope.OrganizationID().String(), WorkspaceID: grant.Scope.WorkspaceID().String(), EnvironmentID: grant.Scope.EnvironmentID().String(),
		RunID: grant.RunID, Destination: grant.Destination, Methods: append([]string(nil), grant.Methods...), IssuedAt: now.Unix(), ExpiresAt: grant.ExpiresAt.Unix(), InputDigest: hex.EncodeToString(grant.InputDigest[:]),
	}
	payload, err := json.Marshal(claims)
	if err != nil || len(payload) > 2048 {
		return "", ErrInvalidEgressCapability
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifyEgressCapability(key []byte, token string, now time.Time) (EgressGrant, error) {
	parts := strings.Split(token, ".")
	if !validEgressKey(key) || len(token) < 64 || len(token) > 4096 || len(parts) != 2 || now.IsZero() || now.Location() != time.UTC {
		return EgressGrant{}, ErrInvalidEgressCapability
	}
	signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[1])
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0]))
	if signatureErr != nil || len(signature) != sha256.Size || !hmac.Equal(signature, mac.Sum(nil)) {
		return EgressGrant{}, ErrInvalidEgressCapability
	}
	payload, payloadErr := base64.RawURLEncoding.DecodeString(parts[0])
	var claims egressClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if payloadErr != nil || len(payload) > 2048 || decoder.Decode(&claims) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return EgressGrant{}, ErrInvalidEgressCapability
	}
	canonical, marshalErr := json.Marshal(claims)
	if marshalErr != nil || !bytes.Equal(canonical, payload) || claims.SchemaVersion != "attack-lab-egress-v1" || len(claims.Methods) != 1 || claims.Methods[0] != "POST" || claims.IssuedAt > now.Unix() || claims.ExpiresAt <= now.Unix() || claims.ExpiresAt-claims.IssuedAt < 1 || claims.ExpiresAt-claims.IssuedAt > int64((5*time.Minute)/time.Second) {
		return EgressGrant{}, ErrInvalidEgressCapability
	}
	organization, organizationErr := domain.ParseProductID(claims.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(claims.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(claims.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	digest, digestErr := hex.DecodeString(claims.InputDigest)
	var inputDigest [sha256.Size]byte
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || scopeErr != nil || digestErr != nil || len(digest) != sha256.Size {
		clear(digest)
		return EgressGrant{}, ErrInvalidEgressCapability
	}
	copy(inputDigest[:], digest)
	clear(digest)
	grant := EgressGrant{Scope: scope, RunID: claims.RunID, Destination: claims.Destination, Methods: append([]string(nil), claims.Methods...), ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(), InputDigest: inputDigest}
	if !validEgressGrant(grant, time.Unix(claims.IssuedAt, 0).UTC(), true) {
		return EgressGrant{}, ErrInvalidEgressCapability
	}
	return grant, nil
}

func validEgressKey(key []byte) bool {
	if len(key) < 32 || len(key) > 64 {
		return false
	}
	var different byte
	for _, value := range key[1:] {
		different |= value ^ key[0]
	}
	return different != 0
}

func validEgressGrant(grant EgressGrant, now time.Time, requireBoundedExpiry bool) bool {
	if grant.Scope.Validate() != nil || now.IsZero() || now.Location() != time.UTC || grant.InputDigest == [sha256.Size]byte{} || len(grant.Methods) != 1 || grant.Methods[0] != "POST" || !validEgressDestination(grant.Destination) || grant.ExpiresAt.IsZero() || grant.ExpiresAt.Location() != time.UTC || !grant.ExpiresAt.After(now) || requireBoundedExpiry && grant.ExpiresAt.After(now.Add(5*time.Minute)) {
		return false
	}
	run, err := domain.ParseProductID(grant.RunID)
	return err == nil && !run.IsZero()
}

func validEgressDestination(value string) bool {
	if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}
