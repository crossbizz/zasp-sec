package apiserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApprovalMaintenanceOwnedCredentialAdmission(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "token")
	token := strings.Repeat("n", 32)
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	legacyCalls := 0
	legacy := func() (approvalMaintenanceCredentials, error) {
		legacyCalls++
		return approvalMaintenanceCredentials{url: "http://127.0.0.1:8088", token: "legacy", tokenFile: "/test/in-memory-only"}, nil
	}
	get := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	t.Run("explicit_native", func(t *testing.T) {
		before := legacyCalls
		pins, err := resolveApprovalMaintenanceCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path}), legacy)
		if err != nil {
			t.Fatal(err)
		}
		if pins.url != "http://127.0.0.1:18088" || pins.token != token || pins.tokenFile != path || legacyCalls != before {
			t.Fatal("explicit native fixture was not selected")
		}
	})
	t.Run("legacy_unchanged", func(t *testing.T) {
		before := legacyCalls
		pins, err := resolveApprovalMaintenanceCredentials(get(nil), legacy)
		if err != nil || pins.url != "http://127.0.0.1:8088" || pins.token != "legacy" || legacyCalls != before+1 {
			t.Fatal("legacy fixture changed")
		}
	})
	t.Run("no_fallback_on_native_refusal", func(t *testing.T) {
		for _, v := range []map[string]string{
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088"},
			{"ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://remote.invalid:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088/path", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088?private=not-for-errors", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://u:secret@127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088#fragment", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:0", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:018088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:65536", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://::1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": "relative-token"},
		} {
			before := legacyCalls
			_, err := resolveApprovalMaintenanceCredentials(get(v), legacy)
			if err == nil || legacyCalls != before || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "not-for-errors") {
				t.Fatal("native refusal fell back or leaked input")
			}
		}
	})
	t.Run("private_token_only", func(t *testing.T) {
		for _, mode := range []os.FileMode{0644, 0640, 0000} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			before := legacyCalls
			_, err := resolveApprovalMaintenanceCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path}), legacy)
			if err == nil || legacyCalls != before {
				t.Fatal("unsafe native token was admitted")
			}
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "token-link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		_, err := resolveApprovalMaintenanceCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": link}), legacy)
		if err == nil {
			t.Fatal("symlink token admitted")
		}
	})
	t.Run("owned_readonly_ipv6", func(t *testing.T) {
		if err := os.WriteFile(path, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0400); err != nil {
			t.Fatal(err)
		}
		pins, err := resolveApprovalMaintenanceCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://[::1]:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path}), legacy)
		if err != nil || pins.url != "http://[::1]:18088" || pins.token != token {
			t.Fatal("owned readonly IPv6 fixture refused")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("nonexclusive_or_nonregular_token", func(t *testing.T) {
		alias := filepath.Join(root, "hardlink")
		if err := os.Link(path, alias); err != nil {
			t.Fatal(err)
		}
		for _, candidate := range []string{path, alias, root, filepath.Join(root, "missing")} {
			before := legacyCalls
			_, err := resolveApprovalMaintenanceCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": candidate}), legacy)
			if err == nil || legacyCalls != before {
				t.Fatal("nonexclusive or nonregular token admitted")
			}
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("invalid_token_bytes", func(t *testing.T) {
		for _, body := range []string{"short", strings.Repeat("n", 4097), "native token", "native\ntoken", "native,token"} {
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := resolveApprovalMaintenanceCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path}), legacy)
			if err == nil {
				t.Fatal("invalid native token admitted")
			}
		}
	})
}

func TestApprovalMaintenanceOwnedCredentialsRequireLiveInputs(t *testing.T) {
	refuse := func() (approvalMaintenanceCredentials, error) {
		return approvalMaintenanceCredentials{}, errors.New("explicit owned OpenFGA fixture required")
	}
	if _, err := resolveApprovalMaintenanceCredentials(func(string) string { return "" }, refuse); err == nil {
		t.Fatal("missing owned inputs selected a fabricated Docker fixture")
	}
}
