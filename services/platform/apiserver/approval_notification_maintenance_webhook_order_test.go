package apiserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/approvalmaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Actual HTTPS delivery through the unchanged production webhook. The owned
// transport routes only the ORIGINAL captured hostname to a fresh TLS listener;
// its certificate has that hostname and is verified against an explicit CA.
func maintenanceOrderOwnedWebhook(t *testing.T, p approvalmaintenance.DeliveryPayload, status int, response string) (*findingTicketWebhook, *atomic.Int32) {
	t.Helper()
	secret := bytes.Repeat([]byte{0xa5}, 32)
	calls := new(atomic.Int32)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("owned TLS key setup")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal("owned TLS serial setup")
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "hooks.example.test"}, DNSNames: []string{"hooks.example.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal("owned TLS certificate setup")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("owned TLS certificate parse")
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 16385))
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(body)
		if err != nil || string(body) != p.Payload || r.Method != http.MethodPost || r.URL.Path != "/zasp" || r.Host != "hooks.example.test" || r.Header.Get("X-Zasp-Delivery-ID") != p.DeliveryID || r.Header.Get("X-Zasp-Payload-Digest") != p.PayloadDigest || r.Header.Get("X-Zasp-Event") != "security_agent.approval_required" || r.Header.Get("X-Zasp-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) || r.Header.Get("Content-Type") != "application/json" {
			t.Error("actual signed HTTPS notification changed original payload, idempotency or signature binding")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		if response != "" {
			_, _ = w.Write([]byte(response))
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "hooks.example.test:443" {
			return nil, ErrRepositoryUnavailable
		}
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	webhook, err := newFindingTicketWebhook(&http.Client{Transport: transport}, 2*time.Second)
	if err != nil {
		t.Fatal("actual webhook construction")
	}
	return webhook, calls
}

func maintenanceOrderPayload(t *testing.T) approvalmaintenance.DeliveryPayload {
	lease := maintenanceOrderOriginalLease(t)
	return approvalmaintenance.DeliveryPayload{Organization: lease.Scope.OrganizationID().String(), Workspace: lease.Scope.WorkspaceID().String(), Environment: lease.Scope.EnvironmentID().String(), DeliveryID: lease.DeliveryID, ApprovalID: lease.ApprovalID, RunID: lease.RunID, Payload: lease.Payload, PayloadDigest: lease.PayloadDigest, DestinationURL: lease.DestinationURL, SecretReference: lease.SecretReference, LeaseToken: lease.LeaseToken, LeaseExpiresAt: lease.LeaseExpiresAt, Attempt: 0}
}
func TestMaintenanceBoundaryDeliversOriginalSignedPayloadOverTLS(t *testing.T) {
	p := maintenanceOrderPayload(t)
	webhook, calls := maintenanceOrderOwnedWebhook(t, p, http.StatusNoContent, "")
	boundary := &authorizedApprovalBoundary{webhook: webhook, payload: p, reference: "owned-reference"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := boundary.Deliver(ctx, approvalmaintenance.Reservation{Reference: "owned-reference"}, bytes.Repeat([]byte{0xa5}, 32)); err != nil {
		t.Fatal("authorized boundary refused actual original signed HTTPS delivery", err)
	}
	if calls.Load() != 1 {
		t.Fatal("actual owned HTTPS delivery count is not one")
	}
}
func TestMaintenanceBoundaryUnsafeDeliveryDoesNotReachHTTP(t *testing.T) {
	original := maintenanceOrderPayload(t)
	webhook, calls := maintenanceOrderOwnedWebhook(t, original, http.StatusNoContent, "")
	for _, name := range []string{"foreign reference", "changed tenant", "changed delivery id", "changed payload", "expired lease", "insecure destination", "canceled context", "short secret"} {
		t.Run(name, func(t *testing.T) {
			p := original
			reference := "owned-reference"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			secret := bytes.Repeat([]byte{0xa5}, 32)
			switch name {
			case "foreign reference":
				reference = "foreign"
			case "changed tenant":
				p.Organization = "pid_10000001-0000-4000-8000-000000000002"
			case "changed delivery id":
				p.DeliveryID = "pid_76000001-0000-4000-8000-000000000002"
			case "changed payload":
				p.Payload += " "
			case "expired lease":
				p.LeaseExpiresAt = time.Now().Add(-time.Second)
			case "insecure destination":
				p.DestinationURL = "http://hooks.example.test/zasp"
			case "canceled context":
				cancel()
			case "short secret":
				secret = secret[:31]
			}
			boundary := &authorizedApprovalBoundary{webhook: webhook, payload: p, reference: "owned-reference"}
			if boundary.Deliver(ctx, approvalmaintenance.Reservation{Reference: reference}, secret) == nil {
				t.Fatal("unsafe delivery succeeded")
			}
			if calls.Load() != 0 {
				t.Fatal("unsafe delivery reached actual HTTP")
			}
		})
	}
}
func TestMaintenanceBoundaryRetainsActualProviderFailure(t *testing.T) {
	p := maintenanceOrderPayload(t)
	webhook, calls := maintenanceOrderOwnedWebhook(t, p, http.StatusServiceUnavailable, "")
	boundary := &authorizedApprovalBoundary{webhook: webhook, payload: p, reference: "owned-reference"}
	if boundary.Deliver(context.Background(), approvalmaintenance.Reservation{Reference: "owned-reference"}, bytes.Repeat([]byte{0xa5}, 32)) == nil {
		t.Fatal("real provider refusal admitted")
	}
	if calls.Load() != 1 {
		t.Fatal("provider refusal did not follow actual signed HTTPS request")
	}
}

func maintenanceOrderOriginalLease(t *testing.T) ApprovalNotificationLease {
	t.Helper()
	identity := maintenanceOrderOriginalIdentity(t)
	lease := ApprovalNotificationLease{
		Scope:           identity.Scope,
		DeliveryID:      "pid_76000001-0000-4000-8000-000000000001",
		ApprovalID:      "pid_76000002-0000-4000-8000-000000000002",
		RunID:           "pid_76000003-0000-4000-8000-000000000003",
		Payload:         `{"approval":{"id":"pid_76000002-0000-4000-8000-000000000002","run_id":"pid_76000003-0000-4000-8000-000000000003"},"delivery_id":"pid_76000001-0000-4000-8000-000000000001","event":"security_agent.approval_required","scope":{"environment_id":"` + identity.Scope.EnvironmentID().String() + `","organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `"},"version":1}`,
		DestinationURL:  "https://hooks.example.test/zasp",
		SecretReference: "secret_ref_approval_prod",
		LeaseToken:      strings.Repeat("b", 64),
		LeaseExpiresAt:  time.Now().UTC().Add(20 * time.Second),
		Attempt:         1,
	}
	digest := sha256.Sum256([]byte(lease.Payload))
	lease.PayloadDigest = "sha256:" + hex.EncodeToString(digest[:])
	return lease
}

func maintenanceOrderOriginalIdentity(t *testing.T) RequestIdentity {
	t.Helper()
	organization, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
	environment, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
	principal, _ := domain.ParseProductID("pid_10000004-0000-4000-8000-000000000004")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: []string{"view", "manage_findings"}, CSRFToken: strings.Repeat("c", 32), CredentialKind: CredentialBrowserSession, FreshAuthenticated: true}
}
