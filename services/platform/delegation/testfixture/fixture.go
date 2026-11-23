// Package testfixture reads the signed SDK delegation interoperability vector.
package testfixture

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
)

type Grant struct {
	Verifier delegation.Verifier
	Token    string
	Issued   int64
}

// Read reconstructs the original compact JWS from its signed JSON and detached
// signature. All SDKs verify the same known-answer bytes with a public test key.
func Read(t testing.TB, path string) Grant {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Verifier  delegation.Verifier `json:"verifier"`
		Issued    int64               `json:"issued_at"`
		Protected json.RawMessage     `json:"protected_header"`
		Claims    json.RawMessage     `json:"claims"`
		Signature string              `json:"signature"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	encode := func(data json.RawMessage) string {
		t.Helper()
		var compact bytes.Buffer
		if err := json.Compact(&compact, data); err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(compact.Bytes())
	}
	return Grant{
		Verifier: vector.Verifier, Issued: vector.Issued,
		Token: encode(vector.Protected) + "." + encode(vector.Claims) + "." + vector.Signature,
	}
}
