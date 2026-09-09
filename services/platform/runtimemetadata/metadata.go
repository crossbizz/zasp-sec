// Package runtimemetadata carries bounded, content-free investigation selectors.
// Digests minimize retained provider content; they are not encryption and do not
// establish principal ownership, correlation confidence, or authorization.
package runtimemetadata

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrInput = errors.New("runtime search metadata rejected")

// Fields are observed selectors, not authenticated identity assertions. Agent
// and session attribution continues to come only from the correlation stage.
type Fields struct {
	PrincipalID    string `json:"principal_id,omitempty"`
	ProcessDigest  string `json:"process_digest,omitempty"`
	FileDigest     string `json:"file_digest,omitempty"`
	DomainDigest   string `json:"domain_digest,omitempty"`
	CredentialID   string `json:"credential_id,omitempty"`
	ResourceDigest string `json:"resource_digest,omitempty"`
	Decision       string `json:"decision,omitempty"`
}

func (fields Fields) Valid(source string) bool {
	if source != "otlp" && source != "tetragon" {
		return false
	}
	// Tetragon provides process/file/network observations. Never infer semantic
	// principal, credential, DNS, or gateway policy decisions from kernel events.
	if source == "tetragon" && (fields.PrincipalID != "" || fields.DomainDigest != "" || fields.CredentialID != "" || fields.Decision != "") {
		return false
	}
	for _, value := range []string{fields.PrincipalID, fields.CredentialID} {
		if value != "" {
			if _, err := domain.ParseProductID(value); err != nil {
				return false
			}
		}
	}
	for _, value := range []string{fields.ProcessDigest, fields.FileDigest, fields.DomainDigest, fields.ResourceDigest} {
		if value == "" {
			continue
		}
		if len(value) != 64 || value != strings.ToLower(value) {
			return false
		}
		if _, err := hex.DecodeString(value); err != nil {
			return false
		}
	}
	return fields.Decision == "" || fields.Decision == "allow" || fields.Decision == "monitor" || fields.Decision == "block"
}

// DigestSelector is shared by trusted source normalization and exact-match
// search. Callers must not log the input. Credential material is never accepted
// here: credential filters use product reference IDs instead.
func DigestSelector(field, value string) (string, error) {
	if field != "process" && field != "file" && field != "domain" && field != "resource" || len(value) < 1 || len(value) > 4096 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return "", ErrInput
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", ErrInput
		}
	}
	if field == "domain" {
		value = strings.ToLower(value)
		if len(value) > 253 || strings.HasSuffix(value, ".") {
			return "", ErrInput
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", ErrInput
			}
			for _, character := range label {
				if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
					return "", ErrInput
				}
			}
		}
	}
	digest := sha256.Sum256([]byte("zasp.runtime-search-selector.v1\x00" + field + "\x00" + value))
	return hex.EncodeToString(digest[:]), nil
}
