package runtimepostgres

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/net/websocket"
)

// TransportSetting selects how PostgreSQL connections are carried. Unset or
// "tcp" is the ordinary PostgreSQL protocol on the DSN's port. "websocket"
// carries the same protocol, unchanged, inside a TLS WebSocket on port 443 of
// the DSN's host (path /v2). Neon serves that endpoint; it exists for
// networks that allow only HTTPS egress. Sessions, transactions and
// authentication behave exactly as over TCP.
const TransportSetting = "ZASP_POSTGRES_TRANSPORT"

var errTransport = errors.New("postgres transport unavailable")

func websocketTransport() (bool, error) {
	switch os.Getenv(TransportSetting) {
	case "", "tcp":
		return false, nil
	case "websocket":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be tcp or websocket", TransportSetting)
	}
}

// Connect opens one connection with the configured transport.
func Connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if err := applyTransport(&config.Config); err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, config)
}

func applyTransport(config *pgconn.Config) error {
	enabled, err := websocketTransport()
	if err != nil || !enabled {
		return err
	}
	// The WebSocket is the encrypted channel, and its certificate is always
	// verified against the DSN's host, whatever sslmode asked for. A DSN that
	// asks for no TLS at all is refused rather than silently upgraded.
	if config.TLSConfig == nil {
		return fmt.Errorf("%s=websocket requires sslmode=require or stricter", TransportSetting)
	}
	host := config.Host
	if host == "" || net.ParseIP(host) != nil || host[0] == '/' {
		return fmt.Errorf("%s=websocket requires a DNS host", TransportSetting)
	}
	config.TLSConfig = nil
	config.Fallbacks = nil
	config.LookupFunc = func(context.Context, string) ([]string, error) { return []string{host}, nil }
	config.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) { return dialWebSocket(ctx, host) }
	return nil
}

func dialWebSocket(ctx context.Context, host string) (net.Conn, error) {
	target := net.JoinHostPort(host, "443")
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(30 * time.Second)
	}
	raw, err := dialThroughProxy(ctx, target)
	if err != nil {
		return nil, errTransport
	}
	_ = raw.SetDeadline(deadline)
	secured := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := secured.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, errTransport
	}
	wsConfig, err := websocket.NewConfig("wss://"+host+"/v2", "https://"+host)
	if err != nil {
		secured.Close()
		return nil, errTransport
	}
	conn, err := websocket.NewClient(wsConfig, secured)
	if err != nil {
		secured.Close()
		return nil, errTransport
	}
	conn.PayloadType = websocket.BinaryFrame
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// dialThroughProxy honours the standard HTTPS proxy environment, as the
// process's HTTP clients do, and otherwise dials directly.
func dialThroughProxy(ctx context.Context, target string) (net.Conn, error) {
	dialer := &net.Dialer{}
	proxy, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: target}})
	if err != nil {
		return nil, err
	}
	if proxy == nil {
		return dialer.DialContext(ctx, "tcp", target)
	}
	if proxy.Scheme != "http" {
		return nil, errTransport
	}
	address := proxy.Host
	if proxy.Port() == "" {
		address = net.JoinHostPort(proxy.Hostname(), "80")
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if proxy.User != nil {
		password, _ := proxy.User.Password()
		request.SetBasicAuth(proxy.User.Username(), password)
		request.Header.Set("Proxy-Authorization", request.Header.Get("Authorization"))
		request.Header.Del("Authorization")
	}
	if err := request.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != http.StatusOK || reader.Buffered() != 0 {
		conn.Close()
		return nil, errTransport
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
