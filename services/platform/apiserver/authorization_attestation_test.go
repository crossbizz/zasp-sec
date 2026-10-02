package apiserver

import (
	"bytes"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// A controlled signer for application-boundary fixtures, never a production key.
func authorizationFixtureAttestor(t *testing.T) *authorization.AttestationKey {
	t.Helper()
	key, err := authorization.NewAttestationKey(bytes.Repeat([]byte{0x94}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
