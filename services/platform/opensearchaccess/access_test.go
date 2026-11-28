package opensearchaccess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type identity struct {
	cert            *x509.Certificate
	key             *ecdsa.PrivateKey
	certPEM, keyPEM []byte
}

func issue(t *testing.T, name string, parent *identity, usage x509.ExtKeyUsage) identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	signer, issuer := key, cert
	if parent == nil {
		cert.IsCA = true
		cert.KeyUsage |= x509.KeyUsageCertSign
	} else {
		signer, issuer = parent.key, parent.cert
		cert.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		if usage == x509.ExtKeyUsageServerAuth {
			cert.DNSNames = []string{name}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return identity{parsed, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: rawKey})}
}

func writeIdentity(t *testing.T, dir string, ca, client identity) {
	t.Helper()
	for name, data := range map[string][]byte{"ca.crt": ca.certPEM, "tls.crt": client.certPEM, "tls.key": client.keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrivateSearchUsesAndRotatesOnlyTheWorkloadCertificate(t *testing.T) {
	ca := issue(t, "Search CA", nil, 0)
	service := issue(t, Host, &ca, x509.ExtKeyUsageServerAuth)
	api := issue(t, "api-reader", &ca, x509.ExtKeyUsageClientAuth)
	dir := t.TempDir()
	writeIdentity(t, dir, ca, api)
	cert, err := tls.X509KeyPair(service.certPEM, service.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("private request included an AWS authorization header")
		}
		io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	config, err := MutualTLS.tlsConfig(Host, dir)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: config, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 2 * time.Second}
	check := func(want string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, Endpoint+"/_search", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = MutualTLS.Authorize(req.Context(), req, nil, "", time.Now().UTC(), nil, nil); err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil || string(data) != want {
			t.Fatalf("workload certificate: got %q, error %v", data, err)
		}
	}
	check("api-reader")
	transport.CloseIdleConnections()
	writeIdentity(t, dir, ca, issue(t, "renewed-api-reader", &ca, x509.ExtKeyUsageClientAuth))
	check("renewed-api-reader")
	transport.CloseIdleConnections()
	wrong := issue(t, "Foreign CA", nil, 0)
	writeIdentity(t, dir, wrong, api)
	config, err = MutualTLS.tlsConfig(Host, dir)
	if err != nil {
		t.Fatal(err)
	}
	other := transport.Clone()
	other.TLSClientConfig = config
	defer other.CloseIdleConnections()
	if resp, err := (&http.Client{Transport: other, Timeout: 2 * time.Second}).Get(Endpoint); err == nil {
		resp.Body.Close()
		t.Fatal("trusted another installation's search service")
	}
}

func TestPrivateModeRejectsUnknownTargetsAndMissingCredentials(t *testing.T) {
	if !MutualTLS.AllowsPrivateEndpoint(Endpoint, false) {
		t.Fatal("private endpoint rejected")
	}
	for _, bad := range []string{"http://" + Host + ":9200", "https://" + Host, Endpoint + "/", Endpoint + "?mode=test", "https://opensearch.staging.svc.cluster.local:9200"} {
		if MutualTLS.AllowsPrivateEndpoint(bad, false) {
			t.Fatal("accepted " + bad)
		}
	}
	if MutualTLS.AllowsPrivateEndpoint(Endpoint, true) || Mode("unknown").AllowsPrivateEndpoint(Endpoint, false) {
		t.Fatal("mixed endpoint authorities")
	}
	if _, err := MutualTLS.tlsConfig(Host, t.TempDir()); err == nil {
		t.Fatal("missing workload identity accepted")
	}
	for _, mode := range []Mode{"", MutualTLS, "unknown"} {
		req, _ := http.NewRequest(http.MethodGet, "https://unrelated.example", nil)
		if err := mode.Authorize(req.Context(), req, nil, "us-east-1", time.Now().UTC(), nil, nil); err == nil {
			t.Fatal("unauthenticated search accepted")
		}
	}
}
