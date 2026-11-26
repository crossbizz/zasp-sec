package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const testKey = "7b43428c-21d3-4b7e-98b4-4cf7af921142"

type protocolFunc func(context.Context, string, string, any, any) error

func (f protocolFunc) Do(ctx context.Context, method, path string, in, out any) error {
	return f(ctx, method, path, in, out)
}

func metadata() map[string]any {
	return map[string]any{"name": testKey, "type": "ecdsa-p256", "supports_signing": true,
		"latest_version": 1, "min_decryption_version": 1, "exportable": false,
		"allow_plaintext_backup": false, "deletion_allowed": false}
}

func response(out any, data any) error {
	raw, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func TestTransitSigningRotatesAndVerifiesPinnedVersions(t *testing.T) {
	keys := make(map[int]*ecdsa.PrivateKey)
	for i := 1; i <= 2; i++ {
		var err error
		keys[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	version, requests := 1, 0
	call := protocolFunc(func(_ context.Context, method, path string, in, out any) error {
		requests++
		if path == "transit/keys/"+testKey && method == http.MethodGet && in == nil {
			m := metadata()
			m["latest_version"] = version
			return response(out, m)
		}
		req, ok := in.(signingRequest)
		if !ok || method != http.MethodPost || req.MarshalingAlgorithm != "asn1" {
			t.Fatal("unexpected signing request", path)
		}
		payload, err := base64.StdEncoding.Strict().DecodeString(req.Input)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		switch path {
		case "transit/sign/" + testKey + "/sha2-256":
			if int(req.KeyVersion) != version {
				t.Fatal("signer did not pin key version")
			}
			sig, err := ecdsa.SignASN1(rand.Reader, keys[version], digest[:])
			if err != nil {
				t.Fatal(err)
			}
			return response(out, map[string]string{"signature": "vault:v" + strconv.Itoa(version) + ":" + base64.StdEncoding.EncodeToString(sig)})
		case "transit/verify/" + testKey + "/sha2-256":
			parts := strings.Split(req.Signature, ":")
			if len(parts) != 3 || parts[0] != "vault" || req.KeyVersion != 0 {
				t.Fatal("malformed Transit version")
			}
			i, err := strconv.Atoi(strings.TrimPrefix(parts[1], "v"))
			if err != nil || keys[i] == nil {
				return errors.New("unknown version")
			}
			sig, err := base64.StdEncoding.Strict().DecodeString(parts[2])
			return response(out, map[string]bool{"valid": err == nil && ecdsa.VerifyASN1(&keys[i].PublicKey, digest[:], sig)})
		default:
			t.Fatal("unexpected path", path)
			return nil
		}
	})
	a, err := New(call, testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	payload := []byte{0, 1, 255, 27}
	ref1, sig1, err := a.Sign(ctx, payload)
	if err != nil || ref1 != refPrefix+"1/"+testKey {
		t.Fatalf("v1 sign: ref=%q err=%v", ref1, err)
	}
	version = 2
	ref2, sig2, err := a.Sign(ctx, payload)
	if err != nil || ref2 != refPrefix+"2/"+testKey {
		t.Fatalf("v2 sign: ref=%q err=%v", ref2, err)
	}
	if a.Verify(ctx, ref1, payload, sig1) != nil || a.Verify(ctx, ref2, payload, sig2) != nil {
		t.Fatal("verification failed after rotation")
	}
	if a.Verify(ctx, ref2, payload, sig1) == nil || a.Verify(ctx, ref1, []byte{42}, sig1) == nil {
		t.Fatal("accepted wrong version or tampered payload")
	}
	before := requests
	for _, ref := range []string{refPrefix + "2/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", refPrefix + "02/" + testKey, refPrefix + "2147483648/" + testKey, refPrefix + "0/" + testKey, refPrefix + "1/../../other", "arn:aws:kms:us-west-2:123456789012:key/" + testKey} {
		if a.Verify(ctx, ref, payload, sig1) == nil {
			t.Fatal("accepted invalid reference", ref)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if a.Verify(cancelled, ref1, payload, sig1) == nil || a.Verify(ctx, ref1, payload, []byte("bad DER")) == nil || requests != before {
		t.Fatal("invalid input reached provider")
	}
}

func TestTransitRejectsUnsafeOrUnavailableKeys(t *testing.T) {
	for field, invalid := range map[string]any{
		"name": "another-key", "type": "ecdsa-p384", "supports_signing": false, "exportable": true, "latest_version": 0,
		"allow_plaintext_backup": true, "deletion_allowed": true, "min_decryption_version": 2,
	} {
		t.Run(field, func(t *testing.T) {
			d := metadata()
			d[field] = invalid
			a, err := New(protocolFunc(func(_ context.Context, _ string, _ string, _ any, out any) error { return response(out, d) }), testKey)
			if err != nil || a.Ready(context.Background()) == nil {
				t.Fatalf("accepted invalid %s", field)
			}
		})
	}
	if _, err := New(nil, testKey); err == nil {
		t.Fatal("nil client accepted")
	}
	if _, err := New(protocolFunc(nil), "../test"); err == nil {
		t.Fatal("unsafe key accepted")
	}
	offline, _ := New(protocolFunc(func(context.Context, string, string, any, any) error { return errors.New("provider secret") }), testKey)
	if _, _, err := offline.Sign(context.Background(), []byte("payload")); err != errAuthority {
		t.Fatal("did not redact provider failure")
	}
}

func TestTransitRejectsMalformedSignatures(t *testing.T) {
	for _, blob := range []string{"vault:v2:bad", "vault:v1:not base64", "vault:v1:AA==", "vault:v01:AA=="} {
		a, err := New(protocolFunc(func(_ context.Context, method, path string, _ any, out any) error {
			if method == http.MethodGet {
				return response(out, metadata())
			}
			return response(out, map[string]string{"signature": blob})
		}), testKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := a.Sign(context.Background(), []byte("data")); err == nil {
			t.Fatal("accepted malformed provider signature")
		}
	}
}
