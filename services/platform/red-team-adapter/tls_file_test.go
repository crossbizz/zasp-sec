package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadPinnedTLSCertificateRejectsMutableOrIndirectPrivateMaterial(t *testing.T) {
	root := t.TempDir()
	certificatePath, keyPath := writeAdapterTLSFixture(t, root)
	if certificate, err := loadPinnedTLSCertificate(certificatePath, keyPath); err != nil || len(certificate.Certificate) != 1 {
		t.Fatalf("certificate=%#v err=%v", certificate, err)
	}
	if err := os.Chmod(keyPath, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPinnedTLSCertificate(certificatePath, keyPath); err == nil {
		t.Fatal("world-readable private key accepted")
	}
	if err := os.Chmod(keyPath, 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked.crt")
	if err := os.Symlink(certificatePath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPinnedTLSCertificate(link, keyPath); err == nil {
		t.Fatal("certificate symlink accepted")
	}
}

func writeAdapterTLSFixture(t *testing.T, root string) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agentsec-red-team-adapter.agentsec.svc.cluster.local"}, DNSNames: []string{"agentsec-red-team-adapter.agentsec.svc.cluster.local"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath, keyPath := filepath.Join(root, "tls.crt"), filepath.Join(root, "tls.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateBytes}), 0o400); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}
