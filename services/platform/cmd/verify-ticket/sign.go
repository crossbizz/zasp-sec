package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

// A source operator uses its own role-specific key and its own local export.
// The CLI has no combined sign-bundle path and never opens a target.
func signSource(args []string, stdout, stderr io.Writer, now time.Time) int {
	if len(args) != 5 {
		fmt.Fprintln(stderr, "Usage: verify-ticket sign-source ROLE KEY_ID PRIVATE_KEY.pem SCENARIO.json SOURCE.json")
		return 2
	}
	role, keyID, keyPath := args[0], args[1], args[2]
	var scenario redteam.TicketScenario
	if err := readExport(args[3], &scenario); err != nil {
		fmt.Fprintln(stderr, "Invalid local scenario.")
		return 2
	}
	var source any
	switch role {
	case "adapter":
		var adapter redteam.TicketAdapterEvidence
		if readExport(args[4], &adapter) != nil {
			fmt.Fprintln(stderr, "Invalid local adapter export.")
			return 2
		}
		source = adapter
	case "recorder":
		var recorder redteam.TicketRecorderEvidence
		if readExport(args[4], &recorder) != nil {
			fmt.Fprintln(stderr, "Invalid local recorder export.")
			return 2
		}
		source = recorder
	default:
		fmt.Fprintln(stderr, "Expected adapter or recorder.")
		return 2
	}
	key, err := privateTicketKey(keyPath)
	if err != nil {
		fmt.Fprintln(stderr, "Expected a private regular Ed25519 PKCS#8 PEM file readable only by its owner.")
		return 2
	}
	a, err := redteam.SignTicketSource(scenario, role, keyID, now, source, key)
	if err != nil {
		fmt.Fprintln(stderr, "The export does not match the closed staging scenario and signing window.")
		return 2
	}
	if json.NewEncoder(stdout).Encode(a) != nil {
		return 2
	}
	return 0
}

func privateTicketKey(path string) (ed25519.PrivateKey, error) {
	invalid := errors.New("invalid signing key")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return nil, invalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(info, current) || current.Mode().Perm()&0077 != 0 {
		return nil, invalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, invalid
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, invalid
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, invalid
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, invalid
	}
	return ed, nil
}
