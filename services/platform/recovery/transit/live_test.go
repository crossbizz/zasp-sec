package transit_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/openbaoclient"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery/transit"
)

// TestLiveTransitRecovery uses a dedicated, already provisioned test key.
func TestLiveTransitRecovery(t *testing.T) {
	if os.Getenv("ZASP_TEST_OPENBAO_TRANSIT") != "1" {
		t.Skip("set ZASP_TEST_OPENBAO_TRANSIT=1 with disposable OpenBao credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := openbaoclient.New(openbaoclient.FromEnvironment(os.Getenv), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	key := os.Getenv("ZASP_OPENBAO_TRANSIT_KEY")
	authority, err := transit.New(client, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	payload := []byte("Zasp disposable recovery check")
	ref, sig, err := authority.Sign(ctx, payload)
	if err != nil {
		t.Fatal(err)
	}
	if name, _, ok := transit.ParseReference(ref); !ok || name != key {
		t.Fatal("unexpected signing reference")
	}
	if err := authority.Verify(ctx, ref, payload, sig); err != nil {
		t.Fatal(err)
	}
	if err := authority.Verify(ctx, ref, []byte("modified recovery check"), sig); err == nil {
		t.Fatal("accepted altered payload")
	}
}
