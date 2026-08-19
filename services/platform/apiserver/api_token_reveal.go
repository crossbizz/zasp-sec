package apiserver

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"
)

const apiTokenRevealLifetime = 10 * time.Minute

type apiTokenRevealEnvelope struct {
	GrantID           string `json:"grant_id"`
	TokenID           string `json:"token_id"`
	Operation         string `json:"operation"`
	ExpiresAt         string `json:"expires_at"`
	Ciphertext        string `json:"ciphertext"`
	Nonce             string `json:"nonce"`
	AuthenticationTag string `json:"authentication_tag"`
}

func prepareAPITokenReveal(identity RequestIdentity, mutation *administrationMutation, operation, raw string, now time.Time) error {
	if mutation == nil || len(raw) == 0 || len(mutation.GrantID) == 0 || len(mutation.ID) == 0 && len(mutation.ReplacementID) == 0 {
		return ErrRepositoryOperation
	}
	tokenID := mutation.ID
	if operation == "rotateAPIToken" {
		tokenID = mutation.ReplacementID
	}
	mutation.GrantExpiresAt = now.UTC().Add(apiTokenRevealLifetime).Truncate(time.Second)
	digest := sha256.Sum256([]byte(raw))
	mutation.TokenDigest = append([]byte(nil), digest[:]...)
	return encryptAPITokenReveal(identity, mutation, operation, tokenID, raw)
}

func encryptAPITokenReveal(identity RequestIdentity, mutation *administrationMutation, operation, tokenID, raw string) error {
	block, err := aes.NewCipher(mutation.revealKey)
	if err != nil {
		return ErrRepositoryConfiguration
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return ErrRepositoryConfiguration
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ErrRepositoryUnavailable
	}
	aad := apiTokenRevealAAD(identity, operation, tokenID, mutation.GrantID, mutation.GrantExpiresAt)
	sealed := aead.Seal(nil, nonce, []byte(raw), aad)
	tagStart := len(sealed) - aead.Overhead()
	mutation.Ciphertext = append([]byte(nil), sealed[:tagStart]...)
	mutation.Nonce = append([]byte(nil), nonce...)
	mutation.AuthenticationTag = append([]byte(nil), sealed[tagStart:]...)
	return nil
}

func decryptAPITokenReveal(key []byte, identity RequestIdentity, envelope apiTokenRevealEnvelope) (string, error) {
	if len(key) != 32 || !validAdministrationProductID(envelope.GrantID) || !validAdministrationProductID(envelope.TokenID) || envelope.Operation != "createAPIToken" && envelope.Operation != "rotateAPIToken" {
		return "", ErrRepositoryNotFound
	}
	expires, err := time.Parse(time.RFC3339Nano, envelope.ExpiresAt)
	if err != nil || expires.Format(time.RFC3339Nano) != envelope.ExpiresAt {
		return "", ErrRepositoryNotFound
	}
	ciphertext, cipherErr := decodeCanonicalRevealBytes(envelope.Ciphertext)
	nonce, nonceErr := decodeCanonicalRevealBytes(envelope.Nonce)
	tag, tagErr := decodeCanonicalRevealBytes(envelope.AuthenticationTag)
	block, blockErr := aes.NewCipher(key)
	if cipherErr != nil || nonceErr != nil || tagErr != nil || blockErr != nil || len(nonce) != 12 || len(tag) != 16 || len(ciphertext) == 0 {
		return "", ErrRepositoryNotFound
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrRepositoryNotFound
	}
	sealed := append(append([]byte(nil), ciphertext...), tag...)
	opened, err := aead.Open(nil, nonce, sealed, apiTokenRevealAAD(identity, envelope.Operation, envelope.TokenID, envelope.GrantID, expires))
	if err != nil || len(opened) < len("zasp_pat_")+32 || string(opened[:len("zasp_pat_")]) != "zasp_pat_" {
		return "", ErrRepositoryNotFound
	}
	return string(opened), nil
}

func decodeCanonicalRevealBytes(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrRepositoryNotFound
	}
	return decoded, nil
}

func apiTokenRevealAAD(identity RequestIdentity, operation, tokenID, grantID string, expires time.Time) []byte {
	value, _ := json.Marshal([]string{
		"zasp-api-token-reveal-v1", identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(),
		identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), operation, tokenID, grantID,
		expires.UTC().Format(time.RFC3339Nano),
	})
	return value
}
