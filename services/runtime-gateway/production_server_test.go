package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestServeProductionGatewayCanceledBeforeListenClosesDependencies(t *testing.T) {
	directory := t.TempDir()
	config := productionGatewayConfig{
		ControlPlaneURL: "https://gateway-control.zasp.example",
		OrganizationID:  gatewayRuntimeID(1), WorkspaceID: gatewayRuntimeID(2), EnvironmentID: gatewayRuntimeID(3), DeviceID: gatewayRuntimeID(4), CredentialID: gatewayRuntimeID(5),
		PrivateKeyFile: filepath.Join(directory, "credential.json"), PolicyKeysFile: filepath.Join(directory, "keys.json"), PolicyCacheFile: filepath.Join(directory, "cache.json"), EvidenceStoreDirectory: filepath.Join(directory, "evidence"), EvidenceMaximumBytes: 8 << 30, BootstrapFailureMode: "closed",
		MaximumRequestBytes: 16 * 1024, MaximumPendingEvents: 16, OperationTimeout: time.Second, SyncInterval: time.Second, ShutdownTimeout: time.Second,
	}
	closed := 0
	dependencies := productionGatewayDependencies{
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		Ready:   func(context.Context) error { return nil },
		Metrics: func() string { return "zasp_gateway_evidence_receipts 0\n" },
		Run:     func(context.Context) error { return nil },
		Drain:   func(context.Context) error { return nil },
		Close:   func() error { closed++; return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	listened := false
	err := serveProductionGateway(ctx, &bytes.Buffer{}, "dev", config, dependencies, func(string, string) (net.Listener, error) {
		listened = true
		return nil, errRuntimeUnavailable
	})
	if err != nil || listened || closed != 1 {
		t.Fatalf("err=%v listened=%t closed=%d", err, listened, closed)
	}
}

func TestServeProductionGatewayRejectsMissingOperationalMetrics(t *testing.T) {
	directory := t.TempDir()
	config := productionGatewayConfig{
		ControlPlaneURL: "https://gateway-control.zasp.example",
		OrganizationID:  gatewayRuntimeID(1), WorkspaceID: gatewayRuntimeID(2), EnvironmentID: gatewayRuntimeID(3), DeviceID: gatewayRuntimeID(4), CredentialID: gatewayRuntimeID(5),
		PrivateKeyFile: filepath.Join(directory, "credential.json"), PolicyKeysFile: filepath.Join(directory, "keys.json"), PolicyCacheFile: filepath.Join(directory, "cache.json"), EvidenceStoreDirectory: filepath.Join(directory, "evidence"), EvidenceMaximumBytes: 8 << 30, BootstrapFailureMode: "closed",
		MaximumRequestBytes: 16 * 1024, MaximumPendingEvents: 16, OperationTimeout: time.Second, SyncInterval: time.Second, ShutdownTimeout: time.Second,
	}
	dependencies := productionGatewayDependencies{
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		Ready:   func(context.Context) error { return nil },
		Run:     func(context.Context) error { return nil },
		Drain:   func(context.Context) error { return nil },
		Close:   func() error { return nil },
	}
	if err := serveProductionGateway(context.Background(), &bytes.Buffer{}, "dev", config, dependencies, func(string, string) (net.Listener, error) {
		return nil, errRuntimeUnavailable
	}); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("err=%v", err)
	}
}
