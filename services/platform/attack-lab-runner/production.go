package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/zasp-ai/zasp-sec/services/platform/attacklabrunner"
)

func newProductionHTTPClient(config runtimeConfig) (*http.Client, *http.Transport, error) {
	if !validRuntimeConfig(config) {
		return nil, nil, errRuntimeUnavailable
	}
	caBundle, ok := readRunnerPinnedCA(config.ProxyCAFile)
	if !ok {
		return nil, nil, errRuntimeUnavailable
	}
	defer clear(caBundle)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBundle) {
		return nil, nil, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: config.Runner.Timeout, KeepAlive: -1}).DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "agentsec-attack-lab-proxy.agentsec.svc.cluster.local"}, TLSHandshakeTimeout: config.Runner.Timeout, ResponseHeaderTimeout: config.Runner.Timeout, MaxResponseHeaderBytes: 32 << 10}
	client := &http.Client{Transport: transport, Timeout: config.Runner.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errRuntimeUnavailable }}
	return client, transport, nil
}

func readRunnerPinnedCA(path string) ([]byte, bool) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 64 || before.Size() > 32<<10 {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	opened, statErr := file.Stat()
	payload, readErr := io.ReadAll(io.LimitReader(file, 32<<10+1))
	closeErr := file.Close()
	after, afterErr := os.Lstat(path)
	valid := statErr == nil && readErr == nil && closeErr == nil && afterErr == nil && os.SameFile(before, opened) && os.SameFile(opened, after) && opened.Mode() == before.Mode() && after.Mode() == before.Mode() && int64(len(payload)) == before.Size()
	if !valid || !exactRunnerCertificates(payload) {
		clear(payload)
		return nil, false
	}
	return payload, true
}

func exactRunnerCertificates(raw []byte) bool {
	rest := append([]byte(nil), raw...)
	defer clear(rest)
	count := 0
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
		rest = remaining
	}
	return count >= 1 && count <= 8
}

func writeOutcome(path string, outcome attacklabrunner.Outcome) error {
	if path == "" || outcome.SchemaVersion != "attack-lab-outcome-v1" {
		return errRuntimeUnavailable
	}
	payload, err := json.Marshal(outcome)
	if err != nil || len(payload) < 2 || len(payload) > 4096 {
		return errRuntimeUnavailable
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return errRuntimeUnavailable
	}
	written, writeErr := file.Write(payload)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(payload) {
		return errRuntimeUnavailable
	}
	return nil
}

func runProduction(ctx context.Context, config runtimeConfig) error {
	client, transport, err := newProductionHTTPClient(config)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer transport.CloseIdleConnections()
	runner, err := attacklabrunner.New(config.Runner, client)
	if err != nil {
		return errRuntimeUnavailable
	}
	outcome, err := runner.Run(ctx)
	if err != nil || writeOutcome(config.TerminationPath, outcome) != nil {
		return errRuntimeUnavailable
	}
	return nil
}
