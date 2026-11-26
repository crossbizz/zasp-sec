package openbaokv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/openbaoclient"
)

// TestLiveConnectorKV runs only against the loopback OpenBao instance and
// scoped, disposable token created by the disaster-recovery drill.
func TestLiveConnectorKV(t *testing.T) {
	if os.Getenv("ZASP_TEST_OPENBAO_KV") != "1" {
		t.Skip("requires the disposable OpenBao drill")
	}
	config := FromEnvironment(os.Getenv)
	u, err := url.Parse(config.Client.Address)
	if err != nil || u.Hostname() != "127.0.0.1" || config.Mount != "zasp-kv" {
		t.Fatal("requires the isolated loopback drill mount")
	}
	store, err := New(config, "zasp/pilot", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer store.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := store.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	name := "zasp/pilot/oauth/" + hex.EncodeToString(nonce)
	expected := []byte{0, 'd', 'r', 'i', 'l', 'l', 0xff}
	if err := store.Create(ctx, name, expected); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, name, []byte("replacement")); !errors.Is(err, openbaoclient.ErrVersionConflict) {
		t.Fatal("expected definite CAS conflict", err)
	}
	got, err := store.Read(ctx, name)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatal("binary credential differs after replay", err)
	}
	if err := store.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(ctx, name); !errors.Is(err, openbaoclient.ErrNotFound) {
		t.Fatal("deleted secret is readable", err)
	}
	if err := store.Create(ctx, name, expected); !errors.Is(err, openbaoclient.ErrVersionConflict) {
		t.Fatal("used grant ID was not protected", err)
	}
	if _, err := store.Read(ctx, "zasp/pilot/github/not-authorized"); !errors.Is(err, openbaoclient.ErrUnavailable) {
		t.Fatal("workload ACL did not deny the other namespace", err)
	}
}
