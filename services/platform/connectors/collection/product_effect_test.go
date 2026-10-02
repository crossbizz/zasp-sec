package collection

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// New product effects must carry their identity through credential resolution;
// an old worker attempt cannot accidentally authenticate a new product effect.
func TestProductEffectIdentityBindsCredentialAndRejectsMixedAttempt(t *testing.T) {
	request := validRequest(t, ProviderAWS, CredentialAWSAssumeRole)
	request.Attempt = 0
	request.EffectID = strings.Repeat("a", 64)
	var seen CredentialRequest
	stop := errors.New("controlled credential boundary")
	adapter, err := NewProviderAdapter(ProviderAWS, CredentialAWSAssumeRole, resolverFunc(func(_ context.Context, r CredentialRequest) (*CredentialMaterial, error) { seen = r; return nil, stop }), providerClientFunc(func(context.Context, Request, []byte) (Outcome, error) {
		t.Fatal("provider ran without credential")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel, err := WithProductEffect(context.Background(), request.EffectID, time.Now().Add(time.Minute), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if _, err := adapter.Collect(ctx, request); err == nil || seen.EffectID != request.EffectID || seen.Attempt != 0 {
		t.Fatal("product effect not propagated", seen, err)
	}
	material, err := NewCredentialMaterial(seen, []byte("controlled-secret"), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	foreign := seen
	foreign.EffectID = strings.Repeat("b", 64)
	if err := material.Use(foreign, func([]byte) error { t.Fatal("different effect borrowed credential"); return nil }); err == nil {
		t.Fatal("effect identity ignored")
	}
	for _, bad := range []struct {
		attempt int
		effect  string
	}{{1, request.EffectID}, {0, ""}, {0, "invalid"}, {101, ""}} {
		request.Attempt, request.EffectID = bad.attempt, bad.effect
		if request.Validate() == nil {
			t.Fatal("mixed/invalid identity accepted", bad)
		}
		seen.Attempt, seen.EffectID = bad.attempt, bad.effect
		if material, err := NewCredentialMaterial(seen, []byte("controlled-secret"), time.Now().Add(time.Minute)); err == nil {
			material.Destroy()
			t.Fatal("invalid credential identity", bad)
		}
	}
}
