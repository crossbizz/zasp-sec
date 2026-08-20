package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeProductionControlRunsPrivateAndHealthListenersAndCloses(t *testing.T) {
	config := validProductionControlConfigFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan struct {
		address  string
		listener net.Listener
	}, 2)
	listen := func(network, address string) (net.Listener, error) {
		listener, err := net.Listen(network, "127.0.0.1:0")
		opened <- struct {
			address  string
			listener net.Listener
		}{address: address, listener: listener}
		return listener, err
	}
	closeCalls := 0
	dependencies := productionControlDependencies{
		Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) }),
		Ready:   func(context.Context) error { return nil },
		Close:   func() error { closeCalls++; return nil },
	}
	var output bytes.Buffer
	result := make(chan error, 1)
	go func() { result <- serveProductionControl(ctx, &output, "1.2.3", config, dependencies, listen) }()
	listeners := map[string]net.Listener{}
	for len(listeners) < 2 {
		select {
		case value := <-opened:
			listeners[value.address] = value.listener
		case <-time.After(2 * time.Second):
			t.Fatal("listeners did not open")
		}
	}
	waitForControlStatus(t, "http://"+listeners[healthListenAddress].Addr().String()+"/readyz", http.StatusOK)
	response, err := http.Post("http://"+listeners[productionControlListenAddress].Addr().String()+"/anything", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("private status=%d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil || closeCalls != 1 || output.String() != "gateway-control build 1.2.3\n" {
			t.Fatalf("result=%v closes=%d output=%q", err, closeCalls, output.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("production server did not stop")
	}
}

func waitForControlStatus(t *testing.T, endpoint string, expected int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(endpoint)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == expected {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("endpoint %s did not return %d", endpoint, expected)
}
