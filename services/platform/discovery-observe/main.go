package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.temporal.io/sdk/client"
)

func readRequest(r io.Reader) (request, error) {
	var q request
	if decodeBounded(r, &q) != nil {
		return q, errRefused
	}
	if _, _, err := requestIdentity(q); err != nil {
		return request{}, errRefused
	}
	return q, nil
}

func decodeBounded(r io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(r, 16385))
	if err != nil || len(data) > 16384 || len(data) == 0 {
		return errRefused
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return errRefused
	}
	return nil
}

// Configuration/TLS follows runtimeservices.Config.Validate and Connect, but
// deliberately never creates an FGA client or reads its token file. The SDK's
// connection handshake is bounded too; product RPCs are the three readService
// methods, never a list, query, signal, schedule mutation or workflow start.
func runObserver(ctx context.Context, q request) (observation, error) {
	if _, _, err := requestIdentity(q); err != nil {
		return observation{}, errRefused
	}
	opts := client.Options{HostPort: q.Config.TemporalAddress, Namespace: q.Config.Namespace, Logger: quietLogger{}, ConnectionOptions: client.ConnectionOptions{MaxPayloadSize: 262144, GetSystemInfoTimeout: 3 * time.Second}}
	if q.Config.TemporalCAFile != "" {
		data, err := os.ReadFile(q.Config.TemporalCAFile)
		if err != nil {
			return observation{}, errRefused
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return observation{}, errRefused
		}
		cert, err := tls.LoadX509KeyPair(q.Config.TemporalCertFile, q.Config.TemporalKeyFile)
		if err != nil {
			return observation{}, errRefused
		}
		opts.ConnectionOptions.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}
	}
	c, err := client.NewLazyClient(opts)
	if err != nil {
		return observation{}, errRefused
	}
	defer c.Close()
	return observe(ctx, q, c.WorkflowService())
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--validate-config" {
		var q struct {
			Format string                 `json:"format"`
			Config runtimeservices.Config `json:"config"`
		}
		if decodeBounded(os.Stdin, &q) != nil || q.Format != "zasp-discovery-config-validation-v1" || !q.Config.Enabled || q.Config.Timeout > 10*time.Second || q.Config.Validate() != nil {
			fmt.Fprintln(os.Stderr, "discovery observation refused")
			os.Exit(1)
		}
		// Pure shared configuration validation: no client, TLS file, token or RPC.
		fmt.Fprintln(os.Stdout, `{"format":"zasp-discovery-config-validation-v1","valid":true}`)
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "--observe" {
		fmt.Fprintln(os.Stderr, "discovery observation refused")
		os.Exit(1)
	}
	q, err := readRequest(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "discovery observation refused")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	bounded, stop := context.WithTimeout(ctx, 10*time.Second)
	o, err := runObserver(bounded, q)
	stop()
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "discovery observation refused")
		os.Exit(1)
	}
	data, err := json.Marshal(o)
	if err != nil || len(data) > 16384 {
		fmt.Fprintln(os.Stderr, "discovery observation refused")
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
		os.Exit(1)
	}
}

type quietLogger struct{}

func (quietLogger) Debug(string, ...interface{}) {}
func (quietLogger) Info(string, ...interface{})  {}
func (quietLogger) Warn(string, ...interface{})  {}
func (quietLogger) Error(string, ...interface{}) {}
