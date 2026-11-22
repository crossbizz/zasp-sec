// Command endpoint-policy signs one bounded staging ticket policy on an
// operator's machine. The issuer's Ed25519 private key never goes on a device.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func produce(args []string, out io.Writer, now time.Time) error {
	f := flag.NewFlagSet("endpoint-policy", flag.ContinueOnError)
	policyFile := f.String("policy", "", "path to a complete endpoint policy JSON")
	keyFile := f.String("key", "", "path to a private Ed25519 PKCS#8 PEM")
	if f.Parse(args) != nil || f.NArg() != 0 || *policyFile == "" || *keyFile == "" {
		return errors.New("expected --policy and --key")
	}
	info, err := os.Lstat(*keyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private key must be an owner-only regular file")
	}
	read := func(path string) ([]byte, error) {
		in, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer in.Close()
		data, err := io.ReadAll(io.LimitReader(in, 8193))
		if err != nil || len(data) > 8192 {
			return nil, errors.New("input exceeds limit")
		}
		return data, nil
	}
	rawKey, err := read(*keyFile)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(rawKey)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return errors.New("expected an Ed25519 PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return errors.New("invalid Ed25519 private key")
	}
	raw, err := read(*policyFile)
	if err != nil {
		return err
	}
	var p endpointprotocol.Policy
	if !endpointprotocol.Strict(raw, &p) || !endpointprotocol.Label.MatchString(p.Binding.Environment) || !endpointprotocol.Label.MatchString(p.Binding.Workspace) || !endpointprotocol.Label.MatchString(p.Binding.Organization) || !endpointprotocol.Label.MatchString(p.Binding.Device) || p.Binding.Generation == 0 {
		return errors.New("invalid endpoint policy or binding")
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return err
	}
	envelope := endpointprotocol.Signed{Payload: canonical, Signature: ed25519.Sign(key, canonical)}
	if _, ok := envelope.PolicyFor(key.Public().(ed25519.PublicKey), p.Binding, now); !ok {
		return errors.New("policy audience, scope, operation, or validity rejected")
	}
	return json.NewEncoder(out).Encode(envelope)
}
func main() {
	if err := produce(os.Args[1:], os.Stdout, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
