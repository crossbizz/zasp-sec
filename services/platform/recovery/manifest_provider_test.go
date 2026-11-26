package recovery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

type referenceSigner string

func (s referenceSigner) Sign(_ context.Context, payload []byte) (string, []byte, error) {
	digest := sha256.Sum256(payload)
	return string(s), digest[:], nil
}

func (s referenceSigner) Verify(_ context.Context, ref string, payload, signature []byte) error {
	digest := sha256.Sum256(payload)
	if ref != string(s) || !bytes.Equal(signature, digest[:]) {
		return ErrSignature
	}
	return nil
}

func TestManifestPersistsSeparateProviderAuthorityAndRejectsMixedReferences(t *testing.T) {
	const ref = "openbao:transit/v2/7b43428c-21d3-4b7e-98b4-4cf7af921142"
	const arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555"
	input := validManifestInput(t)
	for _, key := range []string{ref, arn} {
		ctx := context.Background()
		envelope, err := BuildSignedManifest(ctx, input, referenceSigner(key))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]string
		if err := json.Unmarshal(envelope, &fields); err != nil {
			t.Fatal(err)
		}
		if key == ref && (fields["signing_key_ref"] != ref || fields["signing_key_arn"] != "") {
			t.Fatal("invalid Transit wire shape")
		}
		if key == arn && (fields["signing_key_arn"] != arn || bytes.Contains(envelope, []byte("signing_key_ref"))) {
			t.Fatal("changed legacy AWS wire shape")
		}
		value, err := DecodeSignedManifest(ctx, bytes.NewReader(envelope), referenceSigner(key), input.CapturedAt)
		if err != nil || value.BackupID != input.BackupID {
			t.Fatal("valid provider envelope rejected", err)
		}
		fields["signing_key_arn"] = arn
		fields["signing_key_ref"] = ref
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeSignedManifest(ctx, bytes.NewReader(raw), referenceSigner(key), input.CapturedAt); !errors.Is(err, ErrManifest) {
			t.Fatal("mixed authority accepted", err)
		}
	}
	if _, err := BuildSignedManifest(context.Background(), input, referenceSigner("openbao:transit/v00/other")); !errors.Is(err, ErrSignature) {
		t.Fatal("unsupported signing key accepted")
	}
}

const historicalAWSARN = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555"

type historicalKey struct{ pub *ecdsa.PublicKey }

func (h historicalKey) Verify(_ context.Context, key string, payload, signature []byte) error {
	digest := sha256.Sum256(payload)
	if key != historicalAWSARN || !ecdsa.VerifyASN1(h.pub, digest[:], signature) {
		return ErrSignature
	}
	return nil
}

func TestDecodeHistoricalAWSFormatWithPinnedECDSASignature(t *testing.T) {
	// Generated offline over the established v1 canonical payload with a disposable
	// P-256 key. Only the public key and signature are retained here.
	const public = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESTvqfAaCNU+dk/CyQ4y6CYz4QsgRuosHYFdZPi0ZXRUQTK1dTEWqsfTqAVf2s7Es/UbPIuryCtzmgrV3anlzkw=="
	const signature = "MEUCIQCrm7q/sx3saKGE00b6IH+6LPfi+hW4PhBpgdwqf6ftvgIgcbTTqmFHG8wMUFOacIsXcRHuSsFKD9FwkJQVXFE9/kI"
	publicDER, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	input := validManifestInput(t)
	_, payload, err := BuildManifest(input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(testEnvelope{Schema: "recovery_signed_manifest_v1", KeyARN: historicalAWSARN,
		Payload: base64.RawStdEncoding.EncodeToString(payload), Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	value, err := DecodeSignedManifest(context.Background(), bytes.NewReader(raw), historicalKey{parsed.(*ecdsa.PublicKey)}, input.CapturedAt)
	if err != nil || value.BackupID != input.BackupID {
		t.Fatal("could not verify original AWS envelope", err)
	}
}
