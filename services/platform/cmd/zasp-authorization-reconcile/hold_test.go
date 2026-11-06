package main

import (
	"context"
	"strings"
	"testing"
)

func TestHoldProtocol(t *testing.T) {
	if holdWriter(context.Background(), strings.NewReader("")) != nil {
		t.Fatal("owner EOF refused")
	}
	if holdWriter(context.Background(), strings.NewReader("continue\n")) == nil {
		t.Fatal("writer accepted unexpected owner input")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if holdWriter(ctx, strings.NewReader("")) == nil {
		t.Fatal("cancelled hold succeeded")
	}
	for _, endpoint := range []string{"https://example.com", "http://127.0.0.1.evil:8080", "http://user@127.0.0.1:8080", "http://127.0.0.1:8080/path"} {
		if controlledLoopback(endpoint) {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	if !controlledLoopback("http://127.0.0.1:8080") {
		t.Fatal("loopback refused")
	}
}
