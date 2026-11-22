// Package windowsinventory synchronizes metadata from the assigned user's scanner.
// It has no runtime hooks or policy-acknowledgment capability.
package windowsinventory

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/devicehttp"
	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/inventoryreport"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

var ErrInvalid = errors.New("invalid managed inventory configuration or state")

type Config struct {
	Origin  string                   `json:"origin"`
	Binding endpointprotocol.Binding `json:"binding"`
	// The scheduled user-context scanner submits the assigned scope only.
	Scope       string `json:"scope"`
	AssignedSID string `json:"assigned_sid"`
}

func (c Config) Valid() bool {
	b := c.Binding
	return devicehttp.ValidOrigin(c.Origin) && endpointprotocol.Label.MatchString(b.Organization) && endpointprotocol.Label.MatchString(b.Workspace) && endpointprotocol.Label.MatchString(b.Environment) && endpointprotocol.Label.MatchString(b.Device) && b.Generation > 0 && b.Generation < 1<<53 && (c.Scope == "personal" || c.Scope == "managed") && strings.HasPrefix(c.AssignedSID, "S-1-") && len(c.AssignedSID) < 185
}

type State struct {
	Binding      endpointprotocol.Binding     `json:"binding"`
	AssignedSID  string                       `json:"assigned_sid"`
	Scope        string                       `json:"scope"`
	Sequence     uint64                       `json:"sequence"`
	ReportDigest string                       `json:"report_digest"`
	Pending      []endpointprotocol.Inventory `json:"pending"`
	LastContact  time.Time                    `json:"last_contact"`
}

// Admit records a stable generation before network I/O. An interrupted upload
// can retry with identical generations. A partial root preserves its last complete report.
func (s *State) Admit(c Config, seed, report []byte) error {
	if !c.Valid() || len(seed) != ed25519.SeedSize {
		return ErrInvalid
	}
	if s.Binding != (endpointprotocol.Binding{}) && (s.Binding != c.Binding || s.AssignedSID != c.AssignedSID || s.Scope != c.Scope) {
		return ErrInvalid
	}
	if len(report) > 1<<20 {
		return ErrInvalid
	}
	next := *s
	next.Binding = c.Binding
	next.AssignedSID = c.AssignedSID
	next.Scope = c.Scope
	if len(report) > 0 {
		digest := sha256.Sum256(report)
		hash := hex.EncodeToString(digest[:])
		if s.ReportDigest != hash {
			var profile struct {
				Coverage struct {
					Roots []struct{ Scope string } `json:"roots"`
				} `json:"coverage"`
			}
			if json.Unmarshal(report, &profile) != nil {
				return ErrInvalid
			}
			for _, r := range profile.Coverage.Roots {
				if r.Scope != c.Scope {
					return ErrInvalid
				}
			}
			snapshots, seq, err := inventoryreport.Parse(report, "", seed, s.Sequence)
			if err != nil {
				return err
			}
			pending := make(map[string][]endpointprotocol.Inventory)
			for _, v := range s.Pending {
				pending[v.Partition] = append(pending[v.Partition], v)
			}
			for _, v := range snapshots {
				var keep []endpointprotocol.Inventory
				if !*v.Complete {
					for _, old := range pending[v.Partition] {
						if old.Complete != nil && *old.Complete {
							keep = append(keep, old)
						}
					}
				}
				pending[v.Partition] = append(keep, v)
			}
			if len(pending) > 128 {
				return ErrInvalid
			}
			var out []endpointprotocol.Inventory
			for _, list := range pending {
				out = append(out, list...)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Generation < out[j].Generation })
			raw, err := json.Marshal(out)
			if err != nil || len(raw) > 2<<20 {
				return ErrInvalid
			}
			next.ReportDigest = hash
			next.Sequence = seq
			next.Pending = out
		}
	}
	*s = next
	return nil
}

func Sync(ctx context.Context, client *http.Client, c Config, key ed25519.PrivateKey, token string, s State, save func(State) error) error {
	return SyncWithHeartbeat(ctx, client, c, key, token, s, save, nil)
}

// SyncWithHeartbeat performs one enrollment and one truthful heartbeat per sync.
// The optional reporter derives health from the installed, authenticated broker.
func SyncWithHeartbeat(ctx context.Context, client *http.Client, c Config, key ed25519.PrivateKey, token string, s State, save func(State) error, report func() endpointprotocol.Heartbeat) error {
	if !c.Valid() || s.Binding != c.Binding || s.Scope != c.Scope || s.AssignedSID != c.AssignedSID || len(key) != ed25519.PrivateKeySize || len(token) < 12 || len(token) > 4096 || strings.ContainsAny(token, " \r\n\t") {
		return ErrInvalid
	}
	send := func(op, path string, in, out any) error {
		return devicehttp.Send(ctx, client, c.Origin, op, http.MethodPost, path, token, c.Binding, key, time.Now(), in, out)
	}
	var enrolled struct {
		Device     string `json:"device_id"`
		Generation uint64 `json:"credential_generation"`
		State      string `json:"state"`
	}
	if err := send("exchangeEndpointEnrollment", "/device-enrollments/exchange", struct{}{}, &enrolled); err != nil {
		return err
	}
	if enrolled.Device != c.Binding.Device || enrolled.Generation != c.Binding.Generation || enrolled.State != "active" {
		return ErrInvalid
	}
	base := "/devices/" + c.Binding.Device
	var ack struct {
		Recorded bool `json:"recorded"`
	}
	beat := endpointprotocol.Heartbeat{Adapter: "windows_inventory", PolicyStatus: "policy_unavailable"}
	if report != nil {
		beat = report()
		if !beat.Valid() {
			return ErrInvalid
		}
	}
	if err := send("recordEndpointHeartbeat", base+"/heartbeat", beat, &ack); err != nil {
		return err
	}
	if !ack.Recorded {
		return ErrInvalid
	}
	s.LastContact = time.Now().UTC()
	if err := save(s); err != nil {
		return err
	}
	for range min(16, len(s.Pending)) {
		ack.Recorded = false
		if err := send("recordEndpointInventory", base+"/inventory-snapshots", s.Pending[0], &ack); err != nil {
			return err
		}
		if !ack.Recorded {
			return ErrInvalid
		}
		s.Pending = s.Pending[1:]
		if err := save(s); err != nil {
			return err
		}
	}
	return nil
}
