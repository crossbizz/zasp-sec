package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestContinueHandshake(t *testing.T) {
	for _, s := range []string{"", "continue", "continue\nextra", "other\n", strings.Repeat("x", 100)} {
		if awaitContinue(context.Background(), strings.NewReader(s)) == nil {
			t.Fatalf("accepted malformed handshake %q", s)
		}
	}
	if awaitContinue(context.Background(), strings.NewReader("continue\n")) != nil {
		t.Fatal("valid handshake refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if awaitContinue(ctx, strings.NewReader("continue\n")) == nil {
		t.Fatal("expired context accepted")
	}
}

func TestCompiledPinsAreClosedAndNeedNoRuntime(t *testing.T) {
	t.Setenv("ZASP_POSTGRES_DSN", "not a database")
	t.Setenv("ZASP_OPENFGA_URL", "not a runtime")
	p, e := pins()
	if e != nil || len(p) != 3 {
		t.Fatal("compiled pin inventory refused")
	}
	for _, k := range []string{"connector_profile_checksum", "approval_profile_checksum", "activation_profile_checksum"} {
		if len(p[k]) != 64 {
			t.Fatal("missing compiled profile pin")
		}
		for _, c := range p[k] {
			if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
				t.Fatal("invalid pin")
			}
		}
	}
}
