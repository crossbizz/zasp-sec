// Command endpoint-policy signs bounded staging ticket policies on an
// operator's machine. Only signed device envelopes leave the signer.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

const maxSafeInteger = (1 << 53) - 1

var cohortLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var policyField = regexp.MustCompile(`^[a-z_]+$`)

type planItem struct {
	Version uint64                  `json:"expected_device_version"`
	Policy  endpointprotocol.Policy `json:"policy"`
}
type cohortPlan struct {
	Schema   string     `json:"schema_version"`
	Cohort   string     `json:"cohort"`
	Phase    string     `json:"phase"`
	Revision *uint64    `json:"expected_rollout_revision"`
	Items    []planItem `json:"items"`
}
type bundleItem struct {
	Version uint64                  `json:"expected_device_version"`
	Bundle  endpointprotocol.Signed `json:"bundle"`
}
type cohortBundle struct {
	Schema   string       `json:"schema_version"`
	Cohort   string       `json:"cohort"`
	Phase    string       `json:"phase"`
	Revision uint64       `json:"expected_rollout_revision"`
	Items    []bundleItem `json:"items"`
}

func readFile(path string, limit int64, private bool) ([]byte, error) {
	inspect := os.Stat
	if private {
		inspect = os.Lstat
	}
	info, err := inspect(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	pinned, err := in.Stat()
	if err != nil || !pinned.Mode().IsRegular() || !os.SameFile(info, pinned) || private && pinned.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unavailable input or insecure private key permissions")
	}
	data, err := io.ReadAll(io.LimitReader(in, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("unreadable or oversized input")
	}
	return data, nil
}

// encoding/json matches case-insensitively and accepts repeated keys. Critical
// scope, device, mode and version fields must have one exact interpretation.
func exactJSON(raw []byte, out any) bool {
	if !endpointprotocol.Strict(raw, out) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) bool
	value = func(depth int) bool {
		token, err := d.Token()
		if err != nil || depth > 12 {
			return false
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				name, ok := k.(string)
				if err != nil || !ok || !policyField.MatchString(name) || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return true
		}
	}
	return value(0)
}

func signPolicy(p endpointprotocol.Policy, key ed25519.PrivateKey, now time.Time) (endpointprotocol.Signed, error) {
	var empty endpointprotocol.Signed
	b := p.Binding
	if !endpointprotocol.Label.MatchString(b.Environment) || !endpointprotocol.Label.MatchString(b.Workspace) || !endpointprotocol.Label.MatchString(b.Organization) || !endpointprotocol.Label.MatchString(b.Device) || b.Generation == 0 {
		return empty, errors.New("invalid endpoint policy binding")
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return empty, err
	}
	signed := endpointprotocol.Signed{Payload: canonical, Signature: ed25519.Sign(key, canonical)}
	if _, ok := signed.PolicyFor(key.Public().(ed25519.PublicKey), b, now); !ok {
		return empty, errors.New("policy audience, scope, operation or validity rejected")
	}
	return signed, nil
}
func signPlan(raw []byte, key ed25519.PrivateKey, now time.Time) (cohortBundle, error) {
	var plan cohortPlan
	var empty cohortBundle
	if !exactJSON(raw, &plan) || plan.Schema != "ticket-cohort-plan.v1" || !cohortLabel.MatchString(plan.Cohort) || plan.Revision == nil || *plan.Revision > 1000000 || len(plan.Items) < 1 || len(plan.Items) > 32 {
		return empty, errors.New("invalid cohort plan")
	}
	mode := "monitor"
	switch plan.Phase {
	case "canary", "promote":
		mode = "enforce"
	case "monitor", "rollback":
	default:
		return empty, errors.New("invalid cohort phase")
	}
	first := plan.Items[0].Policy
	result := cohortBundle{"ticket-cohort-bundle.v1", plan.Cohort, plan.Phase, *plan.Revision, make([]bundleItem, 0, len(plan.Items))}
	devices := map[string]bool{}
	for _, item := range plan.Items {
		b := item.Policy.Binding
		if item.Version == 0 || item.Version > maxSafeInteger || devices[b.Device] || item.Policy.Mode != mode || item.Policy.AllowedDestination != first.AllowedDestination || b.Environment != first.Binding.Environment || b.Workspace != first.Binding.Workspace || b.Organization != first.Binding.Organization {
			return empty, errors.New("inconsistent or repeated cohort item")
		}
		signed, err := signPolicy(item.Policy, key, now)
		if err != nil {
			return empty, err
		}
		devices[b.Device] = true
		result.Items = append(result.Items, bundleItem{item.Version, signed})
	}
	return result, nil
}
func produce(args []string, out io.Writer, now time.Time) error {
	f := flag.NewFlagSet("endpoint-policy", flag.ContinueOnError)
	policyFile := f.String("policy", "", "path to one endpoint policy JSON")
	planFile := f.String("cohort-plan", "", "path to one reviewed ticket-cohort-plan.v1 JSON")
	keyFile := f.String("key", "", "path to a private Ed25519 PKCS#8 PEM")
	if f.Parse(args) != nil || f.NArg() != 0 || *keyFile == "" || (*policyFile == "") == (*planFile == "") {
		return errors.New("expected --key and one of --policy or --cohort-plan")
	}
	rawKey, err := readFile(*keyFile, 8192, true)
	if err != nil {
		return err
	}
	defer clear(rawKey)
	block, rest := pem.Decode(rawKey)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return errors.New("expected an Ed25519 PKCS#8 PEM")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return errors.New("invalid Ed25519 private key")
	}
	defer clear(key)
	if *planFile != "" {
		raw, err := readFile(*planFile, 160<<10, false)
		if err != nil {
			return err
		}
		result, err := signPlan(raw, key, now)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(result)
	}
	raw, err := readFile(*policyFile, 8192, false)
	if err != nil {
		return err
	}
	var p endpointprotocol.Policy
	if !exactJSON(raw, &p) {
		return errors.New("invalid endpoint policy")
	}
	signed, err := signPolicy(p, key, now)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(signed)
}
func main() {
	if err := produce(os.Args[1:], os.Stdout, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
