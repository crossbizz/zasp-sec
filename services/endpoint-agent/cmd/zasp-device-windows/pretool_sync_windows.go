//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/devicehttp"
	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/windowsinventory"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

var receiptName = regexp.MustCompile(`^[a-f0-9]{64}-[a-f0-9]{16}\.dpapi$`)

func syncPretool(ctx context.Context, httpClient *http.Client, root string, c windowsinventory.Config, key ed25519.PrivateKey, token string) error {
	cfg, err := pretoolConfigAt(root, key)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	send := func(op, method, path string, in, out any) error {
		return devicehttp.Send(ctx, httpClient, c.Origin, op, method, path, token, c.Binding, key, time.Now().UTC(), in, out)
	}
	base := "/devices/" + c.Binding.Device
	var fetched struct {
		Bundle *endpointprotocol.Signed `json:"bundle"`
	}
	now := time.Now().UTC()
	var prior endpointprotocol.PolicyV2
	previousRaw, err := loadSecret(root, "pretool-policy.dpapi")
	if err == nil {
		var priorSigned endpointprotocol.Signed
		if !endpointprotocol.Strict(previousRaw, &priorSigned) {
			return invalid
		}
		var ok bool
		prior, ok = priorSigned.AuthenticatedPolicyV2For(cfg.Public, c.Binding, now)
		if !ok {
			return invalid
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = send("fetchEndpointPolicy", "GET", base+"/policy-bundle", nil, &fetched); err != nil {
		return err
	}
	if fetched.Bundle != nil {
		p, ok := fetched.Bundle.PolicyV2For(cfg.Public, c.Binding, now)
		if !ok || p.Revision < prior.Revision {
			return invalid
		}
		raw, err := json.Marshal(fetched.Bundle)
		if err != nil {
			return err
		}
		if p.Revision == prior.Revision && !bytes.Equal(raw, previousRaw) {
			return invalid
		}
		if p.Revision > prior.Revision {
			if err = storeSecret(root, "pretool-policy.dpapi", raw); err != nil {
				return err
			}
		}
		prior = p
	}
	dir := filepath.Join(root, "pretool-receipts")
	file, err := checked(dir, true, nil)
	var files []os.DirEntry
	if err == nil {
		files, err = file.ReadDir(257)
		file.Close()
		if err != nil && err != io.EOF {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	var ack struct {
		Recorded bool `json:"recorded"`
	}
	for _, f := range files[:min(16, len(files))] {
		if !receiptName.MatchString(f.Name()) {
			return invalid
		}
		raw, e := loadSecret(dir, f.Name())
		if e != nil {
			return e
		}
		var signed endpointprotocol.Signed
		if !endpointprotocol.Strict(raw, &signed) {
			return invalid
		}
		if _, ok := signed.ObservationV2For(key.Public().(ed25519.PublicKey), c.Binding, now); !ok {
			return invalid
		}
		ack.Recorded = false
		if err = send("recordEndpointObservations", "POST", "/runtime/observations", map[string]any{"receipts": []endpointprotocol.Signed{signed}}, &ack); err != nil || !ack.Recorded {
			return invalid
		}
		if err = os.Remove(filepath.Join(dir, f.Name())); err != nil {
			return err
		}
	}
	return nil
}

// brokerHealth reports signed cache health separately from hook installation, which
// remains the MDM operator's responsibility. A nonresponsive broker cannot acknowledge.
type brokerHealth struct {
	Broker       string     `json:"broker"`
	PolicyStatus string     `json:"policy_status"`
	Revision     uint64     `json:"policy_revision"`
	Mode         string     `json:"mode,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Queued       int        `json:"queued_receipts"`
	Gaps         uint64     `json:"dropped_receipts"`
}

func readBrokerHealth(root string, c windowsinventory.Config, key ed25519.PrivateKey) *brokerHealth {
	cfg, err := pretoolConfigAt(root, key)
	if os.IsNotExist(err) {
		return nil
	}
	h := &brokerHealth{Broker: "unavailable", PolicyStatus: "state_unavailable"}
	if err != nil {
		return h
	}
	online, err := exchangePipe(pipeName, []byte(probeRequest))
	if err != nil || !bytes.Equal(online, brokerIdentity(c, cfg, key)) {
		return h
	}
	h.Broker = "responding"
	h.Gaps, err = readGaps(root)
	if err != nil {
		return h
	}
	f, err := checked(filepath.Join(root, "pretool-receipts"), true, nil)
	if err == nil {
		entries, e := f.ReadDir(257)
		f.Close()
		if e != nil && e != io.EOF || len(entries) > 256 {
			return h
		}
		h.Queued = len(entries)
	} else if !os.IsNotExist(err) {
		return h
	}
	raw, err := loadSecret(root, "pretool-policy.dpapi")
	if os.IsNotExist(err) {
		h.PolicyStatus = "policy_unavailable"
		return h
	}
	var signed endpointprotocol.Signed
	if err != nil || !endpointprotocol.Strict(raw, &signed) {
		return h
	}
	now := time.Now().UTC()
	p, ok := signed.AuthenticatedPolicyV2For(cfg.Public, c.Binding, now)
	if !ok {
		return h
	}
	h.Revision = p.Revision
	h.Mode = p.Mode
	h.ExpiresAt = &p.ExpiresAt
	h.PolicyStatus = "verified_cache"
	if !p.ExpiresAt.After(now) {
		h.PolicyStatus = "policy_expired"
	}
	return h
}
func windowsBeat(h *brokerHealth) endpointprotocol.Heartbeat {
	if h == nil {
		return endpointprotocol.Heartbeat{Adapter: "windows_inventory", PolicyStatus: "policy_unavailable"}
	}
	return endpointprotocol.Heartbeat{Adapter: "windows_claude_pretool_v2", PolicyStatus: h.PolicyStatus, Revision: h.Revision, Queued: h.Queued, Gaps: h.Gaps}
}
