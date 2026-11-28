// Package opensearchaccess binds search traffic to either the AWS signer or
// the workload certificate issued for the production cluster's search service.
package opensearchaccess

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type Mode string

const (
	MutualTLS Mode = "mtls"
	Host           = "opensearch.opensearch.svc.cluster.local"
	Endpoint       = "https://" + Host + ":9200"
	mount          = "/var/run/secrets/zasp-opensearch"
)

var errAccess = errors.New("invalid OpenSearch workload authority")

func (m Mode) AllowsPrivateEndpoint(endpoint string, loopback bool) bool {
	return m == MutualTLS && endpoint == Endpoint && !loopback
}

func (m Mode) TLSConfig(host string) (*tls.Config, error) {
	return m.tlsConfig(host, mount)
}

func (m Mode) tlsConfig(host, directory string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if m == "" {
		return config, nil
	}
	if m != MutualTLS || host != Host {
		return nil, errAccess
	}
	pem, err := os.ReadFile(filepath.Join(directory, "ca.crt"))
	if err != nil {
		return nil, errAccess
	}
	config.RootCAs = x509.NewCertPool()
	if !config.RootCAs.AppendCertsFromPEM(pem) {
		return nil, errAccess
	}
	loadIdentity := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		pair, err := tls.LoadX509KeyPair(filepath.Join(directory, "tls.crt"), filepath.Join(directory, "tls.key"))
		if err != nil {
			return nil, errAccess
		}
		return &pair, nil
	}
	if _, err := loadIdentity(nil); err != nil {
		return nil, err
	}
	// Kubernetes publishes renewed credentials by replacing the Secret volume's
	// symlink. Read the current client identity on each new TLS connection.
	config.GetClientCertificate = loadIdentity
	return config, nil
}

type Signer interface {
	SignHTTP(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time, ...func(*v4.SignerOptions)) error
}

func (m Mode) Authorize(ctx context.Context, request *http.Request, body []byte, region string, now time.Time, credentials aws.CredentialsProvider, signer Signer) (err error) {
	if ctx == nil || request == nil || request.URL == nil || ctx.Err() != nil || now.IsZero() || now.Location() != time.UTC {
		return errAccess
	}
	if m == MutualTLS {
		if request.URL.Scheme != "https" || request.URL.Host != Host+":9200" {
			return errAccess
		}
		return nil
	}
	if m != "" || credentials == nil || signer == nil {
		return errAccess
	}
	defer func() {
		if recover() != nil {
			err = errAccess
		}
	}()
	value, err := credentials.Retrieve(ctx)
	if err != nil || !value.HasKeys() || value.Expired() {
		return errAccess
	}
	digest := sha256.Sum256(body)
	return signer.SignHTTP(ctx, value, request, hex.EncodeToString(digest[:]), "es", region, now)
}
