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
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: proxyTLSHostname}, DNSNames: []string{proxyTLSHostname}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certificate, _ := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	privateBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	certificatePath, keyPath := filepath.Join(root, "tls.crt"), filepath.Join(root, "tls.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateBytes}), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPinnedTLSCertificate(certificatePath, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPinnedTLSCertificate(certificatePath, keyPath); err == nil {
		t.Fatal("world-readable key accepted")
	}
	link := filepath.Join(root, "linked.crt")
	if err := os.Symlink(certificatePath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPinnedTLSCertificate(link, keyPath); err == nil {
		t.Fatal("certificate symlink accepted")
	}
}
