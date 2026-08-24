package attacklab

import (
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestEgressCapabilityBindsTenantRunDestinationMethodExpiryAndInput(t *testing.T) {
	scope := mustEgressScope(t)
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	grant := EgressGrant{Scope: scope, RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example", Methods: []string{"POST"}, ExpiresAt: now.Add(5 * time.Minute), InputDigest: sha256.Sum256([]byte("attack-lab-input"))}
	key := []byte("0123456789abcdef0123456789abcdef")
	token, err := SignEgressCapability(key, grant, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyEgressCapability(key, token, now.Add(time.Minute))
	if err != nil || !reflect.DeepEqual(verified, grant) {
		t.Fatalf("grant=%#v err=%v", verified, err)
	}
	for name, mutate := range map[string]func(string) string{
		"signature": func(value string) string { return value[:len(value)-1] + "A" },
		"payload":   func(value string) string { return "A" + value[1:] },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyEgressCapability(key, mutate(token), now.Add(time.Minute)); err == nil {
				t.Fatal("mutated capability accepted")
			}
		})
	}
	if _, err := VerifyEgressCapability(key, token, now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired capability accepted")
	}
	if _, err := VerifyEgressCapability([]byte(strings.Repeat("x", 32)), token, now.Add(time.Minute)); err == nil {
		t.Fatal("foreign signing authority accepted")
	}
}

func mustEgressScope(t *testing.T) domain.Scope {
	t.Helper()
	organization, _ := domain.ParseProductID("pid_7d100010-0000-4000-8000-000000000010")
	workspace, _ := domain.ParseProductID("pid_7d100011-0000-4000-8000-000000000011")
	environment, _ := domain.ParseProductID("pid_7d100012-0000-4000-8000-000000000012")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
