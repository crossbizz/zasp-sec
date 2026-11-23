package main

import (
	"bytes"
	"context"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/devicehttp"
	"net/http"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

type remoteConfig struct {
	Origin          string `json:"origin"`
	TokenFile       string `json:"token_file,omitempty"`
	KeychainAccount string `json:"keychain_account,omitempty"`
	Inventory       bool   `json:"inventory_enabled"`
}

type remoteAgent struct {
	config remoteConfig
	client *http.Client
	b      *broker
}

func newRemote(c remoteConfig, b *broker) (*remoteAgent, error) {
	if !devicehttp.ValidOrigin(c.Origin) {
		return nil, errInvalid
	}
	if runtime.GOOS == "darwin" && (!safeID.MatchString(c.KeychainAccount) || c.TokenFile != "") || runtime.GOOS == "linux" && (!filepath.IsAbs(c.TokenFile) || c.KeychainAccount != "") {
		return nil, errInvalid
	}
	return &remoteAgent{config: c, b: b, client: devicehttp.New()}, nil
}

func (agent *remoteAgent) token() (string, error) {
	var raw []byte
	var err error
	if runtime.GOOS == "darwin" {
		raw, err = keychainSecret("ai.zasp.endpoint.transport.v1", agent.config.KeychainAccount)
	} else {
		if checkOwned(agent.config.TokenFile, false, 0600) != nil {
			return "", errInvalid
		}
		raw, err = readFile(agent.config.TokenFile, 4096)
	}
	token := strings.TrimSpace(string(raw))
	if err != nil || len(token) < 12 || len(token) > 4096 || strings.ContainsAny(token, " \n\r\t") {
		return "", errInvalid
	}
	return token, nil
}

func (a *remoteAgent) send(ctx context.Context, op, method, path, token string, input, output any) error {
	return devicehttp.Send(ctx, a.client, a.config.Origin, op, method, path, token, endpointprotocol.Binding(a.b.binding), a.b.key, a.b.now(), input, output)
}

func (a *remoteAgent) loop(ctx context.Context, mu *sync.Mutex) {
	for ctx.Err() == nil {
		started := time.Now()
		status := a.syncOnce(ctx, mu)
		mu.Lock()
		a.b.remoteState = status
		more := status == "connected" && (len(a.b.store.state.Decisions) > 0 || len(a.b.store.state.Inventory) > 0)
		mu.Unlock()
		if !more {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
			case <-a.b.syncRequested:
			}
		}
		// At most six background cycles per minute, including bursts of
		// employee-submitted events. The local decision never waits here.
		if delay := time.Until(started.Add(10 * time.Second)); delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}
}

func (a *remoteAgent) syncOnce(ctx context.Context, mu *sync.Mutex) string {
	token, err := a.token()
	if err != nil {
		return "transport_credential_unavailable"
	}
	var bound struct {
		Device     string `json:"device_id"`
		Generation uint64 `json:"credential_generation"`
		State      string `json:"state"`
	}
	b := a.b
	if a.send(ctx, "exchangeEndpointEnrollment", "POST", "/device-enrollments/exchange", token, struct{}{}, &bound) != nil || bound.Device != b.binding.Device || bound.Generation != b.binding.Generation || bound.State != "active" {
		return "enrollment_unavailable"
	}
	base := "/devices/" + b.binding.Device
	var fetched struct {
		Bundle *Signed `json:"bundle"`
	}
	policyState := "connected"
	if a.send(ctx, "fetchEndpointPolicy", "GET", base+"/policy-bundle", token, nil, &fetched) != nil {
		policyState = "policy_fetch_unavailable"
	}
	mu.Lock()
	if fetched.Bundle != nil {
		if err = b.admitRemote(*fetched.Bundle); err != nil {
			policyState = "policy_rejected"
		}
	}
	current := b.now().UTC()
	if current.Before(b.store.state.Latest) {
		current = b.store.state.Latest
	}
	p, status := b.policy(current)
	adapter := "linux_claude_ticket_test"
	if runtime.GOOS == "darwin" {
		adapter = "macos_claude_ticket"
	}
	if b.adapter != "" && (p.pretool != nil || p.Audience == "") {
		adapter = b.adapter
	}
	health := endpointprotocol.Heartbeat{Adapter: adapter, Revision: p.Revision, PolicyStatus: status, Queued: len(b.store.state.Decisions), Gaps: b.store.state.Gaps}
	receipts := make([]Signed, 0, 16)
	ids := map[string]string{}
	for id, stored := range b.store.state.Decisions {
		receipts = append(receipts, stored.Receipt)
		ids[id] = signatureID(stored.Receipt)
		if len(receipts) == 16 {
			break
		}
	}
	partitions := make([]string, 0, len(b.store.state.Inventory))
	for part := range b.store.state.Inventory {
		partitions = append(partitions, part)
	}
	sort.Strings(partitions)
	snaps := make([]endpointprotocol.Inventory, 0, 16)
	for _, part := range partitions {
		for _, v := range b.store.state.Inventory[part] {
			snaps = append(snaps, v)
			if len(snaps) >= 16 {
				break
			}
		}
		if len(snaps) >= 16 {
			break
		}
	}
	mu.Unlock()
	var ack struct {
		Recorded bool `json:"recorded"`
	}
	if a.send(ctx, "recordEndpointHeartbeat", "POST", base+"/heartbeat", token, health, &ack) != nil || !ack.Recorded {
		return "heartbeat_unavailable"
	}
	if len(receipts) > 0 {
		ack.Recorded = false
		if a.send(ctx, "recordEndpointObservations", "POST", "/runtime/observations", token, struct {
			Receipts []Signed `json:"receipts"`
		}{receipts}, &ack) != nil || !ack.Recorded {
			return "observations_pending"
		}
		mu.Lock()
		err = b.ackArchive(ids)
		mu.Unlock()
		if err != nil {
			return "receipt_ack_pending"
		}
	}
	for _, v := range snaps {
		ack.Recorded = false
		if a.send(ctx, "recordEndpointInventory", "POST", base+"/inventory-snapshots", token, v, &ack) != nil || !ack.Recorded {
			return "inventory_pending"
		}
		mu.Lock()
		err = b.ackInventory(v)
		mu.Unlock()
		if err != nil {
			return "inventory_ack_pending"
		}
	}
	return policyState
}

func (b *broker) admitRemote(s Signed) error {
	now := b.now().UTC()
	if now.Before(b.store.state.Latest) {
		now = b.store.state.Latest
	}
	p, err := s.policy(b.policyKey, b.binding, now)
	if err != nil || !p.ExpiresAt.After(now) || p.pretool != nil && !endpointprotocol.PretoolAdapter(b.adapter) {
		return errInvalid
	}
	old, err := b.store.state.Policy.policy(b.policyKey, b.binding, now)
	if err == nil {
		if p.Revision == old.Revision && bytes.Equal(s.Payload, b.store.state.Policy.Payload) {
			return nil
		}
		if p.Revision <= old.Revision {
			return errInvalid
		}
	}
	next := b.store.state
	next.Policy = s
	next.Latest = now
	return b.store.commit(next)
}
