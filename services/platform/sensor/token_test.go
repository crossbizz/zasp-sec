package sensor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestSensorTokenCredentialRoundTripHashAndDestroy(t *testing.T) {
	locator := bytes.Repeat([]byte{0x11}, sensorTokenLocatorBytes)
	secret := bytes.Repeat([]byte{0x22}, sensorTokenSecretBytes)
	credential, err := NewTokenCredential(locator, secret)
	if err != nil {
		t.Fatal(err)
	}
	if formatted := fmt.Sprintf("%v/%#v", credential, credential); formatted != "[REDACTED]/[REDACTED]" {
		t.Fatalf("credential formatting leaked authority: %s", formatted)
	}
	locator[0], secret[0] = 0xff, 0xff
	wire, err := credential.Wire()
	if err != nil {
		t.Fatal(err)
	}
	const expectedWire = "zasp_sensor_v1.EREREREREREREREREREREQ.IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
	if wire != expectedWire {
		t.Fatalf("wire=%q", wire)
	}
	parsed, err := ParseTokenCredential(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsedWire, err := parsed.Wire(); err != nil || parsedWire != expectedWire {
		t.Fatalf("parsed wire=%q err=%v", parsedWire, err)
	}
	digest, err := parsed.LocatorDigest()
	if err != nil || hex.EncodeToString(digest[:]) != "b8f12ea8c9a95d4b4641b03d9fa5a71ad30b44ed6cd4bf793bbe1a5801b986d4" {
		t.Fatalf("locator digest=%x err=%v", digest, err)
	}
	tokenID := tokenFixtureID(t, "pid_15000001-0000-4000-8000-000000000001")
	salt := bytes.Repeat([]byte{0x33}, sensorTokenSaltBytes)
	hash, err := parsed.Hash(SensorTokenAudienceEventIngest, tokenID, 7, salt)
	if err != nil || hex.EncodeToString(hash[:]) != "9025fba468cfe6ea3b40ec9c76968a1a63d4d9ff1fcc78bf1dc040fab0cd2587" {
		t.Fatalf("token hash=%x err=%v", hash, err)
	}

	partsLocator, partsSecret, err := parsed.Parts()
	if err != nil {
		t.Fatal(err)
	}
	partsLocator[0], partsSecret[0] = 0xff, 0xff
	secondLocator, secondSecret, err := parsed.Parts()
	if err != nil || secondLocator[0] != 0x11 || secondSecret[0] != 0x22 {
		t.Fatalf("credential aliases caller memory: locator=%x secret=%x err=%v", secondLocator, secondSecret, err)
	}
	parsed.Destroy()
	parsed.Destroy()
	if _, err := parsed.Wire(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("destroyed Wire error=%v", err)
	}
	if _, _, err := parsed.Parts(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("destroyed Parts error=%v", err)
	}
	if _, err := parsed.Hash(SensorTokenAudienceEventIngest, tokenID, 7, salt); !errors.Is(err, ErrInvalid) {
		t.Fatalf("destroyed Hash error=%v", err)
	}
}

func TestGenerateSensorTokenCredentialUsesExactEntropy(t *testing.T) {
	source := append(bytes.Repeat([]byte{0x44}, sensorTokenLocatorBytes), bytes.Repeat([]byte{0x55}, sensorTokenSecretBytes)...)
	credential, err := GenerateTokenCredential(bytes.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	wire, err := credential.Wire()
	if err != nil || wire != "zasp_sensor_v1.RERERERERERERERERERERA.VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU" {
		t.Fatalf("generated wire=%q err=%v", wire, err)
	}
	if _, err := GenerateTokenCredential(io.LimitReader(bytes.NewReader(source), int64(len(source)-1))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short entropy error=%v", err)
	}
}

func TestSensorTokenCredentialRejectsHostileAuthority(t *testing.T) {
	valid := "zasp_sensor_v1.EREREREREREREREREREREQ.IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
	for _, value := range []string{
		"", " " + valid, valid + " ", "Bearer " + valid, "sensor_token_EREREREREREREREREREREQ",
		"zasp_sensor_v2.EREREREREREREREREREREQ.IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
		"zasp_sensor_v1.EREREREREREREREREREREQ=.IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
		"zasp_sensor_v1.EREREREREREREREREREREQ.IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=",
		valid + ".extra", "zasp_sensor_v1.*.IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
	} {
		if credential, err := ParseTokenCredential(value); !errors.Is(err, ErrInvalid) || credential != nil {
			t.Fatalf("ParseTokenCredential(%q) credential=%v err=%v", value, credential, err)
		}
	}
	for _, parts := range []struct{ locator, secret []byte }{
		{bytes.Repeat([]byte{1}, sensorTokenLocatorBytes-1), bytes.Repeat([]byte{2}, sensorTokenSecretBytes)},
		{bytes.Repeat([]byte{1}, sensorTokenLocatorBytes), bytes.Repeat([]byte{2}, sensorTokenSecretBytes-1)},
		{bytes.Repeat([]byte{0}, sensorTokenLocatorBytes), bytes.Repeat([]byte{2}, sensorTokenSecretBytes)},
		{bytes.Repeat([]byte{1}, sensorTokenLocatorBytes), bytes.Repeat([]byte{0}, sensorTokenSecretBytes)},
	} {
		if credential, err := NewTokenCredential(parts.locator, parts.secret); !errors.Is(err, ErrInvalid) || credential != nil {
			t.Fatalf("NewTokenCredential credential=%v err=%v", credential, err)
		}
	}
}

func TestSensorTokenHashBindsEveryAuthorityField(t *testing.T) {
	credential, err := NewTokenCredential(bytes.Repeat([]byte{0x11}, sensorTokenLocatorBytes), bytes.Repeat([]byte{0x22}, sensorTokenSecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	id := tokenFixtureID(t, "pid_15000001-0000-4000-8000-000000000001")
	salt := bytes.Repeat([]byte{0x33}, sensorTokenSaltBytes)
	base, err := credential.Hash(SensorTokenAudienceEventIngest, id, 7, salt)
	if err != nil {
		t.Fatal(err)
	}
	otherID := tokenFixtureID(t, "pid_15000002-0000-4000-8000-000000000002")
	changed := make([][sha256.Size]byte, 0, 4)
	for _, input := range []struct {
		audience   string
		id         domain.ProductID
		generation uint64
		salt       []byte
	}{
		{SensorTokenAudienceEventIngest, otherID, 7, salt},
		{SensorTokenAudienceEventIngest, id, 8, salt},
		{SensorTokenAudienceEventIngest, id, 7, bytes.Repeat([]byte{0x34}, sensorTokenSaltBytes)},
	} {
		value, hashErr := credential.Hash(input.audience, input.id, input.generation, input.salt)
		if hashErr != nil {
			t.Fatal(hashErr)
		}
		changed = append(changed, value)
	}
	for _, value := range changed {
		if value == base {
			t.Fatal("hash does not bind authority")
		}
	}
	for _, invalid := range []struct {
		audience   string
		id         domain.ProductID
		generation uint64
		salt       []byte
	}{
		{"runtime-gateway", id, 7, salt},
		{SensorTokenAudienceEventIngest, domain.ProductID{}, 7, salt},
		{SensorTokenAudienceEventIngest, id, 0, salt},
		{SensorTokenAudienceEventIngest, id, 7, salt[:len(salt)-1]},
		{SensorTokenAudienceEventIngest, id, 7, bytes.Repeat([]byte{0}, sensorTokenSaltBytes)},
	} {
		if _, hashErr := credential.Hash(invalid.audience, invalid.id, invalid.generation, invalid.salt); !errors.Is(hashErr, ErrInvalid) {
			t.Fatalf("invalid hash authority error=%v", hashErr)
		}
	}
}

func tokenFixtureID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
