package testopenfga

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsumerRequiresOwnersEndpointAndCredential(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "openfga.token")
	token := strings.Repeat("x", 32)
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	const url = "http://127.0.0.1:40401"
	t.Setenv("ZASP_P6_NATIVE_OPENFGA_URL", url)
	t.Setenv("ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE", path)
	got, err := ConsumerToken(context.Background(), url, path)
	if err != nil || got != token {
		t.Fatal("owned credential rejected", err)
	}
	for _, mismatch := range []struct{ url, path string }{{"http://127.0.0.1:40402", path}, {url, path + ".other"}, {"https://external.invalid", path}} {
		if got, err := ConsumerToken(context.Background(), mismatch.url, mismatch.path); err == nil || got != "" {
			t.Fatal("forwarded authority mismatch accepted")
		}
	}
	t.Setenv("ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE", "")
	if got, err := ConsumerToken(context.Background(), url, ""); err == nil || got != "" {
		t.Fatal("partial explicit configuration accepted")
	}
}
