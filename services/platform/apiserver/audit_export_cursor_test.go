package apiserver

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const auditExportCursorTestID = "pid_72000001-0000-4000-8000-000000000001"

func auditExportCursorFixture(t *testing.T) (*auditExportCursorCodec, RequestIdentity, []byte, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{0x47}, 32)
	codec, err := newAuditExportCursorCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	return codec, fixtureRequestIdentity(t), key, bytes.Repeat([]byte{0xab}, 32)
}

func TestAuditExportCursorPreservesAuthenticatedPageBinding(t *testing.T) {
	codec, identity, key, digest := auditExportCursorFixture(t)
	token, err := codec.Encode(identity, auditExportCursorTestID, digest, 2)
	if err != nil || token == "" {
		t.Fatal("next page cursor refused", err)
	}
	ordinal, pin, err := codec.Decode(token, identity, auditExportCursorTestID)
	if err != nil || ordinal != 2 || !bytes.Equal(pin, digest) {
		t.Fatal("cursor lost ordinal or immutable manifest pin", err)
	}
	// Independent wire assertion: no CSRF/session token, permissions or object locator.
	wire, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"v":1,"o":"pid_10000001-0000-4000-8000-000000000001","w":"pid_10000002-0000-4000-8000-000000000002","e":"pid_10000003-0000-4000-8000-000000000003","p":"pid_10000004-0000-4000-8000-000000000004","op":"getAuditExport","x":"pid_72000001-0000-4000-8000-000000000001","m":"` + strings.Repeat("ab", 32) + `","n":2}`)
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	if !bytes.Equal(wire, append(payload, mac.Sum(nil)...)) {
		t.Fatal("cursor wire is not the closed canonical authenticated contract")
	}
	// Caller-owned slices cannot alter an existing codec or returned pin.
	key[0] ^= 1
	digest[0] ^= 1
	pin[0] ^= 1
	again, err := codec.Encode(identity, auditExportCursorTestID, bytes.Repeat([]byte{0xab}, 32), 2)
	if err != nil || again != token {
		t.Fatal("caller mutation changed deterministic cursor")
	}
	_, againPin, err := codec.Decode(token, identity, auditExportCursorTestID)
	if err != nil || hex.EncodeToString(againPin) != strings.Repeat("ab", 32) {
		t.Fatal("returned digest aliases shared state", err)
	}
}

func TestAuditExportCursorRejectsInvalidKeys(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 32), make([]byte, 4096), bytes.Repeat([]byte{1}, 4097)} {
		if codec, err := newAuditExportCursorCodec(key); !errors.Is(err, ErrRepositoryConfiguration) || codec != nil {
			t.Fatal("invalid signing key accepted")
		}
	}
}

func TestAuditExportCursorRejectsInvalidEncodingInputs(t *testing.T) {
	for _, kind := range []string{"nil codec", "zero codec", "scope", "principal", "export", "nil digest", "short digest", "zero digest", "first page", "negative ordinal", "unsafe ordinal"} {
		t.Run(kind, func(t *testing.T) {
			codec, identity, _, digest := auditExportCursorFixture(t)
			id, ordinal := auditExportCursorTestID, int64(2)
			switch kind {
			case "nil codec":
				codec = nil
			case "zero codec":
				codec = &auditExportCursorCodec{}
			case "scope":
				identity.Scope = domain.Scope{}
			case "principal":
				identity.PrincipalID = domain.ProductID{}
			case "export":
				id = "not-an-export"
			case "nil digest":
				digest = nil
			case "short digest":
				digest = digest[:31]
			case "zero digest":
				digest = make([]byte, 32)
			case "first page":
				ordinal = 1
			case "negative ordinal":
				ordinal = -1
			case "unsafe ordinal":
				ordinal = 1 << 53
			}
			if token, err := codec.Encode(identity, id, digest, ordinal); !errors.Is(err, ErrRepositoryOperation) || token != "" {
				t.Fatal("invalid page cursor emitted")
			}
		})
	}
}

func TestAuditExportCursorRejectsCrossBindingAndKeys(t *testing.T) {
	for _, kind := range []string{"organization", "workspace", "environment", "principal", "export", "key", "invalid identity", "nil codec", "zero codec"} {
		t.Run(kind, func(t *testing.T) {
			codec, identity, _, digest := auditExportCursorFixture(t)
			token, err := codec.Encode(identity, auditExportCursorTestID, digest, 2)
			if err != nil {
				t.Fatal(err)
			}
			other, _ := domain.ParseProductID("pid_72000099-0000-4000-8000-000000000099")
			id := auditExportCursorTestID
			org, workspace, environment := identity.Scope.OrganizationID(), identity.Scope.WorkspaceID(), identity.Scope.EnvironmentID()
			switch kind {
			case "organization":
				org = other
			case "workspace":
				workspace = other
			case "environment":
				environment = other
			case "principal":
				identity.PrincipalID = other
			case "export":
				id = other.String()
			case "key":
				codec, err = newAuditExportCursorCodec(bytes.Repeat([]byte{0x48}, 32))
				if err != nil {
					t.Fatal(err)
				}
			case "nil codec":
				codec = nil
			case "zero codec":
				codec = &auditExportCursorCodec{}
			}
			identity.Scope, err = domain.NewScope(org, workspace, environment)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "invalid identity" {
				identity.Scope = domain.Scope{}
			}
			if ordinal, pin, err := codec.Decode(token, identity, id); !errors.Is(err, ErrRepositoryOperation) || ordinal != 0 || pin != nil {
				t.Fatal("cursor crossed request binding", err)
			}
		})
	}
}

func TestAuditExportCursorRejectsAuthenticatedMalformedPayloads(t *testing.T) {
	codec, identity, key, digest := auditExportCursorFixture(t)
	token, err := codec.Encode(identity, auditExportCursorTestID, digest, 2)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	original := string(wire[:len(wire)-sha256.Size])
	for _, kind := range []string{"alias", "alias overwrite", "duplicate", "missing", "unknown", "wrong version", "wrong operation", "ordinal one", "ordinal zero", "ordinal negative", "unsafe ordinal", "fraction ordinal", "exponent ordinal", "null ordinal", "zero digest", "short digest", "upper digest", "null digest", "foreign org", "foreign principal", "foreign export", "whitespace", "reordered", "escaped key", "escaped value", "trailing", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			payload := original
			switch kind {
			case "alias":
				payload = strings.Replace(payload, `"op":`, `"OP":`, 1)
			case "alias overwrite":
				payload = strings.Replace(payload, `"op":`, `"op":"other","OP":`, 1)
			case "duplicate":
				payload = strings.Replace(payload, `"n":2`, `"n":3,"n":2`, 1)
			case "missing":
				payload = strings.Replace(payload, `,"op":"getAuditExport"`, "", 1)
			case "unknown":
				payload = strings.Replace(payload, `"v":1`, `"url":"https://not-authority.test","v":1`, 1)
			case "wrong version":
				payload = strings.Replace(payload, `"v":1`, `"v":2`, 1)
			case "wrong operation":
				payload = strings.Replace(payload, "getAuditExport", "listAuditEvents", 1)
			case "ordinal one":
				payload = strings.Replace(payload, `"n":2`, `"n":1`, 1)
			case "ordinal zero":
				payload = strings.Replace(payload, `"n":2`, `"n":0`, 1)
			case "ordinal negative":
				payload = strings.Replace(payload, `"n":2`, `"n":-1`, 1)
			case "unsafe ordinal":
				payload = strings.Replace(payload, `"n":2`, `"n":9007199254740992`, 1)
			case "fraction ordinal":
				payload = strings.Replace(payload, `"n":2`, `"n":2.0`, 1)
			case "exponent ordinal":
				payload = strings.Replace(payload, `"n":2`, `"n":2e0`, 1)
			case "null ordinal":
				payload = strings.Replace(payload, `"n":2`, `"n":null`, 1)
			case "zero digest":
				payload = strings.Replace(payload, strings.Repeat("ab", 32), strings.Repeat("0", 64), 1)
			case "short digest":
				payload = strings.Replace(payload, strings.Repeat("ab", 32), "ab", 1)
			case "upper digest":
				payload = strings.Replace(payload, strings.Repeat("ab", 32), strings.Repeat("AB", 32), 1)
			case "null digest":
				payload = strings.Replace(payload, `"`+strings.Repeat("ab", 32)+`"`, `null`, 1)
			case "foreign org":
				payload = strings.Replace(payload, identity.Scope.OrganizationID().String(), "pid_72000099-0000-4000-8000-000000000099", 1)
			case "foreign principal":
				payload = strings.Replace(payload, identity.PrincipalID.String(), "pid_72000099-0000-4000-8000-000000000099", 1)
			case "foreign export":
				payload = strings.Replace(payload, auditExportCursorTestID, "pid_72000099-0000-4000-8000-000000000099", 1)
			case "whitespace":
				payload = " " + payload
			case "reordered":
				payload = strings.Replace(payload, `"v":1,`, "", 1)
				payload = strings.TrimSuffix(payload, "}") + `,"v":1}`
			case "escaped key":
				payload = strings.Replace(payload, `"op":`, `"\u006fp":`, 1)
			case "escaped value":
				payload = strings.Replace(payload, "getAuditExport", `\u0067etAuditExport`, 1)
			case "trailing":
				payload += "{}"
			case "oversized":
				payload += strings.Repeat(" ", 1024)
			}
			if payload == original {
				t.Fatal("fixture did not change payload")
			}
			// A valid MAC must not excuse malformed or differently bound content.
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(payload))
			mutated := base64.RawURLEncoding.EncodeToString(append([]byte(payload), mac.Sum(nil)...))
			if ordinal, pin, err := codec.Decode(mutated, identity, auditExportCursorTestID); !errors.Is(err, ErrRepositoryOperation) || ordinal != 0 || pin != nil {
				t.Fatal("signed malformed cursor accepted", err)
			}
		})
	}
}

func TestAuditExportCursorRejectsTransportTampering(t *testing.T) {
	codec, identity, _, digest := auditExportCursorFixture(t)
	token, err := codec.Encode(identity, auditExportCursorTestID, digest, 2)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := base64.RawURLEncoding.DecodeString(token)
	signatureChange := bytes.Clone(wire)
	signatureChange[len(signatureChange)-1] ^= 1
	payloadChange := bytes.Clone(wire)
	payloadChange[1] ^= 1
	for _, value := range []string{"", "a", "https://example.test/page", strings.Repeat("a", 1025), token + "=", token + "\n", "%" + token, base64.RawURLEncoding.EncodeToString(wire[:32]), base64.RawURLEncoding.EncodeToString(signatureChange), base64.RawURLEncoding.EncodeToString(payloadChange)} {
		if ordinal, pin, err := codec.Decode(value, identity, auditExportCursorTestID); !errors.Is(err, ErrRepositoryOperation) || ordinal != 0 || pin != nil {
			t.Fatal("tampered transport accepted")
		}
	}
}

func TestAuditExportCursorMaximumAndCurrentSessionIndependence(t *testing.T) {
	key := bytes.Repeat([]byte{0x49}, 4096)
	codec, err := newAuditExportCursorCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	digest := bytes.Repeat([]byte{0xcc}, 32)
	const maximumOrdinal = int64(9007199254740991)
	token, err := codec.Encode(identity, auditExportCursorTestID, digest, maximumOrdinal)
	if err != nil || len(token) > 1024 {
		t.Fatal("bounded maximum cursor refused", err)
	}
	identity.FreshAuthenticated = false
	identity.CSRFToken = strings.Repeat("d", 32)
	identity.Permissions = []string{"view_audit"}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			ordinal, pin, err := codec.Decode(token, identity, auditExportCursorTestID)
			if err != nil || ordinal != maximumOrdinal || !bytes.Equal(pin, digest) {
				t.Error("stable identity binding depends on session secret or mutable shared state", err)
			}
		})
	}
	workers.Wait()
}
