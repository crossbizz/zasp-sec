package main

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The archive sets ownership before Neo4j starts. The private key never exists
// as a world-readable host file or container file.
func writeTLSFixture(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Base(directory) != "tls" || !strings.HasPrefix(filepath.Base(filepath.Dir(directory)), "zasp-m1-16-") {
		return errConfiguration
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errOwnership
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errOwnership
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		return errOwnership
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errOperation
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return errOperation
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ZASP disposable loopback graph"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return errOperation
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return errOperation
	}
	defer clear(keyDER)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(private)
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, entry := range []struct {
		name string
		body []byte
		mode int64
	}{
		{"bolt/", nil, 0755}, {"bolt/trusted/", nil, 0755}, {"bolt/revoked/", nil, 0755},
		{"bolt/private.key", private, 0600}, {"bolt/public.crt", public, 0644},
	} {
		header := &tar.Header{Name: entry.name, Mode: entry.mode, Uid: 7474, Gid: 7474, Size: int64(len(entry.body)), ModTime: now}
		if entry.body == nil {
			header.Typeflag = tar.TypeDir
		} else {
			header.Typeflag = tar.TypeReg
		}
		if writer.WriteHeader(header) != nil {
			return errOperation
		}
		if _, err := writer.Write(entry.body); err != nil {
			return errOperation
		}
	}
	if writer.Close() != nil {
		return errOperation
	}
	defer clear(archive.Bytes())
	for _, entry := range []struct {
		name string
		body []byte
	}{{"public.crt", public}, {"bundle.tar", archive.Bytes()}} {
		file, err := os.OpenFile(filepath.Join(directory, entry.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errOwnership
		}
		_, writeErr := file.Write(entry.body)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return errOperation
		}
	}
	return nil
}
