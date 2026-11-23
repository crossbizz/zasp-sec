package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/providerhooks"
)

// One explicitly provisioned provider tenant per configured ingress deployment.
// The mapping and workload credential stay on the server even when a callback
// supplies Authorization or identity headers of its own.
type claudeProviderFile struct {
	Integration   string `json:"integration_id"`
	Tenant        string `json:"tenant_id"`
	Organization  string `json:"organization_id"`
	Workspace     string `json:"workspace_id"`
	Environment   string `json:"environment_id"`
	Credential    string `json:"credential_id"`
	SigningSecret string `json:"webhook_signing_secret"`
	ReferenceKey  string `json:"reference_key_base64"`
	Token         string `json:"workload_token"`
}

func mountClaudeProvider(next, product http.Handler, path string, current bool) (http.Handler, error) {
	invalid := errors.New("invalid Claude Enterprise hook configuration")
	if next == nil || product == nil {
		return nil, invalid
	}
	var hook *providerhooks.Claude
	if path != "" {
		if !current || !filepath.IsAbs(path) {
			return nil, invalid
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, invalid
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 || info.Size() > 16384 {
			return nil, invalid
		}
		raw, err := io.ReadAll(io.LimitReader(f, 16385))
		if err != nil || len(raw) > 16384 {
			return nil, invalid
		}
		var cfg claudeProviderFile
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, invalid
		}
		admit, err := providerhooks.ProductAdmitter(product, cfg.Token)
		if err != nil {
			return nil, invalid
		}
		hook, err = providerhooks.NewClaude(providerhooks.Config{Integration: cfg.Integration, Tenant: cfg.Tenant, Secret: cfg.SigningSecret, ReferenceKey: cfg.ReferenceKey, Scope: providerhooks.Scope{Organization: cfg.Organization, Workspace: cfg.Workspace, Environment: cfg.Environment, Credential: cfg.Credential}}, admit)
		if err != nil {
			return nil, invalid
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, providerhooks.ClaudePath) {
			if hook == nil {
				http.NotFound(w, r)
				return
			}
			hook.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}), nil
}
