package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"time"
)

const proxyTLSHostname = "agentsec-attack-lab-proxy.zasp.svc.cluster.local"

func loadPinnedTLSCertificate(certificatePath, privateKeyPath string) (tls.Certificate, error) {
	certificatePEM, certificateOK := readProxyPinnedFile(certificatePath, 64, 128<<10)
	defer clear(certificatePEM)
	privateKeyPEM, keyOK := readProxyPinnedFile(privateKeyPath, 64, 32<<10)
	defer clear(privateKeyPEM)
	if !certificateOK || !keyOK {
		return tls.Certificate{}, errRuntimeUnavailable
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) < 1 || len(certificate.Certificate) > 8 {
		return tls.Certificate{}, errRuntimeUnavailable
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	now := time.Now().UTC()
	if err != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(proxyTLSHostname) != nil {
		return tls.Certificate{}, errRuntimeUnavailable
	}
	certificate.Leaf = leaf
	return certificate, nil
}

func readProxyPinnedFile(path string, minimum, maximum int64) ([]byte, bool) {
	before, err := os.Lstat(path)
	if err != nil || minimum < 1 || maximum < minimum || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o400 || before.Size() < minimum || before.Size() > maximum {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	opened, statErr := file.Stat()
	payload, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	after, afterErr := os.Lstat(path)
	valid := statErr == nil && readErr == nil && closeErr == nil && afterErr == nil && opened.Mode().IsRegular() && opened.Mode()&os.ModeSymlink == 0 && opened.Mode().Perm() == 0o400 && after.Mode().IsRegular() && after.Mode()&os.ModeSymlink == 0 && after.Mode().Perm() == 0o400 && os.SameFile(before, opened) && os.SameFile(opened, after) && opened.Size() == before.Size() && after.Size() == before.Size() && int64(len(payload)) == before.Size()
	if !valid {
		clear(payload)
		return nil, false
	}
	return payload, true
}
