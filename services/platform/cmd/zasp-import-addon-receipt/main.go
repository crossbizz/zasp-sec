// zasp-import-addon-receipt imports signed, digest-bound observations from an
// operator-configured offline scanner. It never receives or runs an add-on.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/addonsandbox"
	"io"
	"os"
	"strings"
	"time"
)

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("input unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("invalid receipt input")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("invalid receipt input")
	}
	return raw, nil
}
func readKey(path string) ([]byte, error) {
	b, err := readBounded(path, 1024)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(b)))
}
func run(receiptFile, signatureFile string) error {
	raw, err := readBounded(receiptFile, addonsandbox.MaxReceiptBytes)
	if err != nil {
		return err
	}
	sig, err := readKey(signatureFile)
	if err != nil {
		return err
	}
	key, err := readKey(os.Getenv("ZASP_ADDON_SCANNER_VERIFY_KEY_FILE"))
	if err != nil {
		return err
	}
	scope := [3]string{os.Getenv("ZASP_ADDON_SCANNER_ORGANIZATION_ID"), os.Getenv("ZASP_ADDON_SCANNER_WORKSPACE_ID"), os.Getenv("ZASP_ADDON_SCANNER_ENVIRONMENT_ID")}
	r, err := addonsandbox.Verify(raw, sig, key, scope, os.Getenv("ZASP_ADDON_SCANNER_PROFILE_DIGEST"), time.Now())
	if err != nil {
		return err
	}
	dsn := os.Getenv("ZASP_ADDON_SCANNER_DATABASE_URL")
	if dsn == "" {
		return errors.New("missing scanner database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return errors.New("scanner database unavailable")
	}
	defer conn.Close(ctx)
	var accepted bool
	if err := conn.QueryRow(ctx, "select public.zasp_import_addon_observation($1::jsonb,$2)", raw, fmt.Sprintf("sha256:%x", sha256.Sum256(raw))).Scan(&accepted); err != nil || !accepted {
		return errors.New("observation not imported")
	}
	fmt.Println(r.Evidence)
	return nil
}
func main() {
	receipt := flag.String("receipt", "", "signed observation JSON")
	sig := flag.String("signature", "", "detached base64 Ed25519 signature")
	flag.Parse()
	if err := run(*receipt, *sig); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
