// Package device reads local endpoint health for the employee's own profile.
package device

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"time"
)

type health struct {
	PolicyStatus string `json:"policy_status"`
	Revision     uint64 `json:"policy_revision"`
	Mode         string `json:"mode,omitempty"`
	Queued       uint64 `json:"queued_receipts"`
	Dropped      uint64 `json:"dropped_receipts"`
	Remote       string `json:"remote_state,omitempty"`
}
type inventoryHealth struct {
	CheckedAt   time.Time  `json:"checked_at"`
	LastContact *time.Time `json:"last_contact"`
	Pending     int        `json:"pending_snapshots"`
	State       string     `json:"state"`
}

func (v *inventoryHealth) valid(now time.Time) bool {
	return v != nil && v.Pending >= 0 && v.Pending <= 256 && !v.CheckedAt.IsZero() && !v.CheckedAt.After(now.Add(time.Minute)) && (v.LastContact == nil || !v.LastContact.After(v.CheckedAt.Add(time.Minute))) && slices.Contains([]string{"connected", "sync_unavailable", "scan_unavailable"}, v.State)
}

type windowsPretool struct {
	Broker       string     `json:"broker"`
	PolicyStatus string     `json:"policy_status"`
	Revision     uint64     `json:"policy_revision"`
	Mode         string     `json:"mode,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Queued       int        `json:"queued_receipts"`
	Gaps         uint64     `json:"dropped_receipts"`
}

func (b *windowsPretool) valid() bool {
	if b == nil || !slices.Contains([]string{"responding", "unavailable"}, b.Broker) || b.Queued < 0 || b.Queued > 256 || b.Gaps > 1<<53 || b.Revision > 1<<53 {
		return false
	}
	switch b.PolicyStatus {
	case "verified_cache", "policy_expired":
		return b.Broker == "responding" && b.Revision > 0 && slices.Contains([]string{"monitor", "enforce"}, b.Mode) && b.ExpiresAt != nil && !b.ExpiresAt.IsZero()
	case "policy_unavailable", "state_unavailable":
		return b.Revision == 0 && b.Mode == "" && b.ExpiresAt == nil
	}
	return false
}

type result struct {
	Broker    *windowsPretool  `json:"pretool,omitempty"`
	Version   string           `json:"schema_version"`
	Status    string           `json:"status"`
	Coverage  string           `json:"coverage"`
	Inventory *inventoryHealth `json:"inventory,omitempty"`
	Local     *health          `json:"result,omitempty"`
	Next      []string         `json:"next_steps,omitempty"`
}

var unavailable = errors.New("local endpoint unavailable")
var remoteStates = []string{"", "connected", "enrollment_unavailable", "policy_fetch_unavailable", "policy_rejected", "heartbeat_unavailable", "observations_pending", "receipt_ack_pending", "inventory_pending", "inventory_ack_pending", "transport_credential_unavailable"}

func Status(args []string, out, diag io.Writer) int {
	return inspect(args, out, diag, queryEndpoint)
}
func inspect(args []string, out, diag io.Writer, query func() ([]byte, error)) int {
	flags := flag.NewFlagSet("device", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	asJSON := flags.Bool("json", false, "print a machine-readable result")
	if len(args) == 0 || !slices.Contains([]string{"status", "doctor"}, args[0]) || flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		fmt.Fprintln(diag, "Use zaspctl device status or zaspctl device doctor, optionally with --json.")
		return 2
	}
	r := result{Version: "zaspctl.device.v1", Status: "partial", Coverage: "local_unavailable"}
	raw, err := query()
	var reply struct {
		Broker    *windowsPretool  `json:"windows_pretool"`
		Status    *health          `json:"status"`
		Inventory *inventoryHealth `json:"windows_inventory"`
	}
	decoded := err == nil && len(raw) <= 2048 && json.Unmarshal(raw, &reply) == nil
	now := time.Now()
	if decoded && reply.Status == nil && reply.Inventory.valid(now) {
		r.Inventory = reply.Inventory
		r.Coverage = "windows_inventory_only"
		if r.Inventory.State == "connected" && r.Inventory.Pending == 0 && now.Sub(r.Inventory.CheckedAt) <= 15*time.Minute && r.Inventory.LastContact != nil && now.Sub(*r.Inventory.LastContact) <= 15*time.Minute {
			r.Status = "complete"
		} else {
			r.Next = []string{"Ask IT to check the assigned-user scan and device sync tasks, then retry after the next five-minute collection."}
		}
		if reply.Broker != nil {
			r.Coverage = "windows_inventory_and_managed_pretool"
			if !reply.Broker.valid() {
				r.Status = "partial"
				r.Next = append(r.Next, "Windows broker status is invalid. Ask IT to check the managed installation.")
			} else {
				r.Broker = reply.Broker
				if r.Broker.PolicyStatus == "verified_cache" && !r.Broker.ExpiresAt.After(now) {
					r.Broker.PolicyStatus = "policy_expired"
				}
				if r.Broker.PolicyStatus != "verified_cache" || r.Broker.Gaps > 0 || r.Broker.Queued > 0 {
					r.Status = "partial"
					r.Next = append(r.Next, "Ask IT to check the broker, signed policy and queued receipts.")
				}
			}
		}
	} else if decoded && reply.Inventory == nil && valid(reply.Status) {
		r.Local = reply.Status
		r.Coverage = "local_only"
		if reply.Status.PolicyStatus == "verified_cache" {
			r.Status = "complete"
		} else {
			r.Next = append(r.Next, "Ask IT to check delivery of a current signed policy for this device.")
		}
		switch reply.Status.Remote {
		case "connected":
		case "":
			r.Next = append(r.Next, "Hosted enrollment or transport has not been confirmed. Check the managed configuration for this profile.")
		default:
			r.Next = append(r.Next, "Check device network and enrollment with IT, then retry after the next sync.")
		}
		if reply.Status.Dropped > 0 {
			r.Next = append(r.Next, "Some receipts were dropped. Review this gap before relying on session evidence.")
		}
	} else {
		r.Next = []string{"On a managed device, ask IT to check the Zasp installation, service or scheduled tasks, and assigned user. Local scans remain available."}
	}
	if *asJSON {
		err = json.NewEncoder(out).Encode(r)
	} else {
		if r.Inventory != nil {
			last := "unconfirmed"
			if r.Inventory.LastContact != nil {
				last = r.Inventory.LastContact.UTC().Format(time.RFC3339)
			}
			label := "Windows inventory only."
			if r.Coverage == "windows_inventory_and_managed_pretool" {
				label = "Windows inventory and managed Claude pre-tool broker."
			}
			_, err = fmt.Fprintf(out, "%s Last confirmed device contact: %s. Pending snapshots: %d.\n", label, last, r.Inventory.Pending)
			if err == nil && r.Broker != nil {
				_, err = fmt.Fprintf(out, "Broker at last sync: %s. Policy: %s (revision %d, mode %s). Queued receipts: %d. Dropped: %d.\n", r.Broker.Broker, r.Broker.PolicyStatus, r.Broker.Revision, r.Broker.Mode, r.Broker.Queued, r.Broker.Gaps)
			}
		} else if r.Local == nil {
			_, err = fmt.Fprintln(out, "Local endpoint health is unavailable.")
		} else {
			remote := r.Local.Remote
			if remote == "" {
				remote = "unconfirmed"
			}
			_, err = fmt.Fprintf(out, "Local policy: %s (revision %d, mode %s)\nHosted sync: %s\nQueued receipts: %d. Dropped: %d.\n", r.Local.PolicyStatus, r.Local.Revision, r.Local.Mode, remote, r.Local.Queued, r.Local.Dropped)
		}
		if args[0] == "doctor" || r.Local == nil {
			for _, step := range r.Next {
				if err == nil {
					_, err = fmt.Fprintln(out, step)
				}
			}
			if err == nil && len(r.Next) == 0 && r.Local != nil {
				_, err = fmt.Fprintln(out, "Local service and signed policy are available.")
			}
		}
	}
	if err != nil {
		fmt.Fprintln(diag, "Could not write device diagnostics.")
		return 2
	}
	if r.Status == "partial" {
		return 3
	}
	return 0
}
func valid(v *health) bool {
	if v == nil || !slices.Contains(remoteStates, v.Remote) || !slices.Contains([]string{"", "monitor", "enforce"}, v.Mode) {
		return false
	}
	switch v.PolicyStatus {
	case "verified_cache":
		return v.Revision > 0 && v.Mode != ""
	case "state_unavailable", "policy_expired", "policy_unavailable":
		return true
	}
	return false
}
