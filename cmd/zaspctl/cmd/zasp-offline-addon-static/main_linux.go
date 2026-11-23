// zasp-offline-addon-static selects one preinstalled, operator-reviewed scanner
// image and records bounded observations for a content-verified local skill.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/addonsandbox"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func run(ctx context.Context, scanner, skill, version, output string, printProfile bool) error {
	p, err := getProfile(scanner, os.Getenv("ZASP_ADDON_SCANNER_IMAGE_ID"))
	if err != nil {
		return err
	}
	if printProfile {
		fmt.Println(p.digest())
		return nil
	}
	if skill == "" || output == "" {
		return errors.New("a local skill directory and new output directory are required")
	}
	scope := [3]string{os.Getenv("ZASP_ADDON_SCANNER_ORGANIZATION_ID"), os.Getenv("ZASP_ADDON_SCANNER_WORKSPACE_ID"), os.Getenv("ZASP_ADDON_SCANNER_ENVIRONMENT_ID")}
	for _, id := range []string{scope[0], scope[1], scope[2], version} {
		if _, err := domain.ParseProductID(id); err != nil {
			return errors.New("invalid configured scope or target version")
		}
	}
	ev, err := domain.NewProductID()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("/tmp", "zasp-offline-static-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(tmp, "skill")
	manifest, err := snapshotSkill(skill, src)
	if err != nil {
		return err
	}
	cfg := filepath.Join(tmp, "docker-config")
	if err = os.Mkdir(cfg, 0700); err != nil {
		return err
	}
	raw, err := runScanner(ctx, p, src, "zasp-offline-"+ev.String()[4:], cfg)
	if err != nil {
		return err
	}
	counts, codes, err := observations(scanner, raw)
	if err != nil {
		return err
	}
	t := time.Now().UTC().Truncate(time.Second)
	receipt := addonsandbox.Receipt{
		Schema: "zasp-offline-addon-observation.v1", Organization: scope[0], Workspace: scope[1], Environment: scope[2],
		Version: version, Manifest: manifest, Evidence: ev.String(), Scanner: p.Scanner, ProfileDigest: p.digest(),
		Isolation: "offline_static", ObservedAt: t, ExpiresAt: t.Add(24 * time.Hour), Indicators: codes,
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	var signature []byte
	if keyPath := os.Getenv("ZASP_ADDON_SCANNER_SIGNING_KEY_FILE"); keyPath != "" {
		signature, err = signReceipt(keyPath, data)
		if err != nil {
			return err
		}
	}
	// Stage all outputs together; rename only after successful validation.
	abs, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(abs); !os.IsNotExist(err) {
		return errors.New("output directory already exists or is inaccessible")
	}
	staged, err := os.MkdirTemp(filepath.Dir(abs), ".zasp-static-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged)
	rules, _ := json.Marshal(counts)
	for path, b := range map[string][]byte{"observation.json": data, "rule-counts.json": rules, "observation.sig": signature} {
		if b != nil {
			if err = os.WriteFile(filepath.Join(staged, path), b, 0600); err != nil {
				return err
			}
		}
	}
	return unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, abs, unix.RENAME_NOREPLACE)
}
func signReceipt(path string, b []byte) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("signing key unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 128 {
		return nil, errors.New("invalid signing key mount")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	seed, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid Ed25519 seed")
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	sig := ed25519.Sign(key, append([]byte(addonsandbox.SignatureContext), b...))
	return []byte(base64.StdEncoding.EncodeToString(sig)), nil
}
func main() {
	scanner := flag.String("scanner", "", "cisco_skill_scanner or nvidia_skillspector")
	skill := flag.String("skill", "", "local skill directory")
	version := flag.String("addon-version", "", "registered add-on version ID")
	output := flag.String("out", "", "new directory for local counts and signed evidence")
	show := flag.Bool("print-profile", false, "print the pinned scanner profile digest")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *scanner, *skill, *version, *output, *show); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
