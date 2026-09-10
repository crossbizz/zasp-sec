package main

import (
	"archive/tar"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSFixtureOwnsPrivateKeyAndVerifiedLoopbackCertificate(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "zasp-m1-16-test")
	directory := filepath.Join(parent, "tls")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTLSFixture(directory); err != nil {
		t.Fatal(err)
	}
	if writeTLSFixture(directory) == nil {
		t.Fatal("fixture overwrote existing material")
	}
	public, err := os.ReadFile(filepath.Join(directory, "public.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(public)
	if block == nil {
		t.Fatal("certificate missing")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA || certificate.CheckSignatureFrom(certificate) != nil || certificate.VerifyHostname("127.0.0.1") != nil || certificate.VerifyHostname("localhost") == nil || certificate.NotAfter.Sub(time.Now()) > 24*time.Hour {
		t.Fatal("certificate isn't short-lived and exact loopback")
	}
	archive, err := os.ReadFile(filepath.Join(directory, "bundle.tar"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(archive)
	reader := tar.NewReader(bytes.NewReader(archive))
	names := map[string]bool{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Uid != 7474 || header.Gid != 7474 || names[header.Name] {
			t.Fatal("archive lost unique Neo4j ownership")
		}
		names[header.Name] = true
		if header.Name == "bolt/private.key" && (header.Mode != 0600 || header.Typeflag != tar.TypeReg) {
			t.Fatal("private key permissions changed")
		}
		if header.Name == "bolt/public.crt" {
			body, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(body, public) {
				t.Fatal("archive certificate differs from trust root")
			}
		}
	}
	for _, name := range []string{"bolt/", "bolt/trusted/", "bolt/revoked/", "bolt/private.key", "bolt/public.crt"} {
		if !names[name] {
			t.Fatal("archive entry missing")
		}
	}
	if len(names) != 5 {
		t.Fatal("unexpected archive entry")
	}
	for _, name := range []string{"public.crt", "bundle.tar"} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("host fixture file permissions changed")
		}
	}
}

func TestTLSFixtureRejectsForeignOrLinkedDirectory(t *testing.T) {
	parent := t.TempDir()
	if writeTLSFixture(parent) == nil {
		t.Fatal("foreign directory accepted")
	}
	owned := filepath.Join(parent, "zasp-m1-16-linked")
	if err := os.Mkdir(owned, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent, filepath.Join(owned, "tls")); err != nil {
		t.Fatal(err)
	}
	if writeTLSFixture(filepath.Join(owned, "tls")) == nil {
		t.Fatal("linked directory accepted")
	}
}
