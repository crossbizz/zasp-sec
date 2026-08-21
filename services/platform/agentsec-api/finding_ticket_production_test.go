package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestProductionFindingTicketSecretResolverReadsOnlyExactWebhookReference(t *testing.T) {
	api := &connectorSecretsAPIStub{values: map[string][]byte{"zasp/webhook/ticket_prod": []byte("0123456789abcdef0123456789abcdef")}}
	resolver, err := newFindingTicketSecretResolver(&connectorSecretsDriver{client: api}, "zasp/oauth", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := resolver.ResolveFindingTicketSecret(context.Background(), "secret_ref_ticket_prod")
	if err != nil || string(secret) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("secret=(%q,%v)", secret, err)
	}
	for _, reference := range []string{"ref:github/app-secret", "secret_ref_../ticket", "secret_ref_ticket//prod", "secret_ref_ticket:prod", "secret_ref_" + strings.Repeat("x", 117)} {
		if value, err := resolver.ResolveFindingTicketSecret(context.Background(), reference); err == nil || value != nil {
			t.Fatalf("reference %q = (%q,%v)", reference, value, err)
		}
	}
}

func TestProductionFindingTicketGeneratorsReturnExactIndependentAuthority(t *testing.T) {
	firstID, err := newFindingTicketDeliveryID()
	secondID, secondErr := newFindingTicketDeliveryID()
	firstToken, tokenErr := newFindingTicketLeaseToken()
	secondToken, secondTokenErr := newFindingTicketLeaseToken()
	if err != nil || secondErr != nil || tokenErr != nil || secondTokenErr != nil || firstID == secondID || firstToken == secondToken || len(firstToken) != 64 || len(secondToken) != 64 || !strings.HasPrefix(firstID, "pid_") || !strings.HasPrefix(secondID, "pid_") {
		t.Fatalf("ids/tokens=(%q,%q,%q,%q) errors=(%v,%v,%v,%v)", firstID, secondID, firstToken, secondToken, err, secondErr, tokenErr, secondTokenErr)
	}
}
