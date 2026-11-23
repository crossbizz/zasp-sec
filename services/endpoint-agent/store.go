package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/inventoryreport"
	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/pretool"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

const maxReceipts = 256
const maxStateBytes = 4 << 20

type Observation struct {
	Audience       string    `json:"audience"`
	Binding        Binding   `json:"binding"`
	PeerUID        int       `json:"local_uid"`
	Action         string    `json:"action_id"`
	Session        string    `json:"session_ref"`
	ObservedAt     time.Time `json:"observed_at"`
	PolicyRevision uint64    `json:"policy_revision"`
	Mode           string    `json:"mode"`
	Tool           string    `json:"tool"`
	TargetClass    string    `json:"target_class"`
	Verdict        string    `json:"verdict"`
	WouldBlock     bool      `json:"would_block"`
	Reason         string    `json:"reason"`
	SkillUsage     string    `json:"skill_usage"`
	TargetEffect   string    `json:"target_effect"`
}

type storedDecision struct {
	InputDigest string `json:"input_digest"`
	Receipt     Signed `json:"receipt"`
}

type diskState struct {
	Inventory         map[string][]endpointprotocol.Inventory `json:"inventory,omitempty"`
	InventorySequence uint64                                  `json:"inventory_sequence,omitempty"`
	Binding           Binding                                 `json:"binding"`
	Latest            time.Time                               `json:"clock_floor"`
	Policy            Signed                                  `json:"policy"`
	Decisions         map[string]storedDecision               `json:"decisions"`
	Archived          map[string]time.Time                    `json:"archived_actions,omitempty"`
	Gaps              uint64                                  `json:"gaps"`
}

type store struct {
	dir    string
	cipher cipher.AEAD
	state  diskState
}

func openStore(dir string, seed []byte, binding Binding) (*store, error) {
	key, err := hkdf.Key(sha256.New, seed, nil, "zasp endpoint state v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	s := &store{dir: dir, cipher: aead, state: diskState{Binding: binding, Decisions: map[string]storedDecision{}}}
	raw, err := readFile(filepath.Join(dir, "state.enc"), maxStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	clear, err := aead.Open(nil, nil, raw, []byte(receiptAudience))
	if err != nil || strictJSON(clear, &s.state) != nil || s.state.Binding != binding || s.state.Decisions == nil || len(s.state.Decisions) > maxReceipts {
		return nil, errUnavailable
	}
	return s, nil
}

func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return boundedRead(f, limit)
}

func (s *store) commit(next diskState) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(raw)+s.cipher.Overhead() > maxStateBytes {
		return errUnavailable
	}
	data := s.cipher.Seal(nil, nil, raw, []byte(receiptAudience))
	f, err := os.CreateTemp(s.dir, ".write-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), filepath.Join(s.dir, "state.enc")); err != nil {
		return err
	}
	// The new file is visible even if directory durability subsequently fails.
	s.state = next
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type broker struct {
	adapter, home    string
	syncRequested    chan struct{}
	inventoryEnabled bool
	remoteState      string
	binding          Binding
	uid              int
	key              ed25519.PrivateKey
	policyKey        ed25519.PublicKey
	policyFile       string
	store            *store
	now              func() time.Time
}

func (b *broker) policy(now time.Time) (Policy, string) {
	previous, previousErr := b.store.state.Policy.policy(b.policyKey, b.binding, now)
	input, err := readFile(b.policyFile, 48<<10)
	var candidate Signed
	if err == nil && strictJSON(input, &candidate) == nil {
		policy, verifyErr := candidate.policy(b.policyKey, b.binding, now)
		if verifyErr == nil && (policy.pretool == nil || endpointprotocol.PretoolAdapter(b.adapter)) && (previousErr != nil || policy.Revision > previous.Revision) && policy.ExpiresAt.After(now) {
			next := b.store.state
			next.Policy = candidate
			next.Latest = now
			if b.store.commit(next) != nil {
				return Policy{}, "state_unavailable"
			}
			previous, previousErr = policy, nil
		}
	}
	if previousErr != nil || previous.pretool != nil && !endpointprotocol.PretoolAdapter(b.adapter) {
		return Policy{}, "policy_unavailable"
	}
	if !previous.ExpiresAt.After(now) {
		if b.store.state.Latest.Before(previous.ExpiresAt) {
			next := b.store.state
			next.Latest = now
			if b.store.commit(next) != nil {
				return Policy{}, "state_unavailable"
			}
		}
		return previous, "policy_expired"
	}
	return previous, "verified_cache"
}

type result struct {
	RuleID    string `json:"rule_id,omitempty"`
	Revision  uint64 `json:"policy_revision,omitempty"`
	NextStep  string `json:"next_step_hint,omitempty"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason"`
	ReceiptID string `json:"receipt_id,omitempty"`
}

func (b *broker) evaluate(raw []byte) (result, error) {
	return b.evaluateForAdapter(raw, b.adapter)
}
func (b *broker) evaluateForAdapter(raw []byte, adapter string) (result, error) {
	event, target, err := parseHook(raw)
	if err != nil {
		return result{}, err
	}
	now := b.now().UTC()
	if now.Before(b.store.state.Latest) {
		now = b.store.state.Latest
	}
	policy, status := b.policy(now)
	v2 := policy.pretool != nil || (policy.Audience == "" && endpointprotocol.PretoolAdapter(adapter))
	if !v2 && event.Tool != ticketTool {
		return result{Verdict: "continue", Reason: "out_of_scope"}, nil
	}
	action := inventoryreport.OpaqueID(b.key.Seed(), "action", event.Session, event.Call)
	if v2 {
		action = inventoryreport.OpaqueID(b.key.Seed(), "pretool-action", adapter, event.Session, event.Call)
	}
	// Canonicalize object order so transport formatting alone cannot cause conflicts.
	var fields any
	d := json.NewDecoder(bytes.NewReader(event.Input))
	d.UseNumber()
	if d.Decode(&fields) != nil {
		return result{}, errInvalid
	}
	canonical, err := json.Marshal(fields)
	if err != nil {
		return result{}, errInvalid
	}
	inputDigest := inventoryreport.OpaqueID(b.key.Seed(), "input", event.Tool, string(canonical))
	if v2 {
		inputDigest = inventoryreport.OpaqueID(b.key.Seed(), "pretool-input", event.Tool, event.CWD, string(canonical))
	}
	if stored, exists := b.store.state.Decisions[action]; exists {
		if stored.InputDigest != inputDigest {
			return result{Verdict: "deny", Reason: "action_id_conflict"}, nil
		}
		var cached result
		var old Observation
		var revision uint64
		if strictJSON(stored.Receipt.Payload, &old) == nil && old.Audience == receiptAudience {
			cached = result{Verdict: old.Verdict, Reason: old.Reason, ReceiptID: action}
			revision = old.PolicyRevision
		} else if receipt, ok := (endpointprotocol.Signed(stored.Receipt)).ObservationV2For(b.key.Public().(ed25519.PublicKey), endpointprotocol.Binding(b.binding), now); ok {
			cached = pretoolResult(receipt)
			revision = receipt.PolicyRevision
		} else {
			return result{}, errUnavailable
		}
		if cached.Verdict == "continue" && (status != "verified_cache" || revision != policy.Revision) {
			return result{Verdict: "deny", Reason: "action_replayed", ReceiptID: action}, nil
		}
		return cached, nil
	}
	if until, ok := b.store.state.Archived[action]; ok && until.After(now) {
		return result{Verdict: "deny", Reason: "action_replayed"}, nil
	}
	if v2 {
		obs := endpointprotocol.ObservationV2{Audience: endpointprotocol.ReceiptAudienceV2, Binding: endpointprotocol.Binding(b.binding), Action: action, Session: inventoryreport.OpaqueID(b.key.Seed(), "pretool-session", adapter, event.Session), ObservedAt: now, PolicyRevision: policy.Revision, Mode: policy.Mode, Adapter: adapter, Tool: endpointprotocol.ToolClass(event.Tool), TargetClass: "unknown", TargetEffect: "unknown", SkillUsage: "unknown", Verdict: "unavailable", Reason: status}
		if !endpointprotocol.PretoolAdapter(adapter) {
			return result{}, errUnavailable
		}
		if policy.pretool != nil {
			obs.Verdict = "continue"
			if status == "verified_cache" {
				match := pretool.Evaluate(*policy.pretool, event.Tool, event.Input, b.home, event.CWD)
				obs.RuleID, obs.Reason, obs.WouldBlock = match.RuleID, match.ReasonCode, match.WouldBlock
				if match.Unavailable {
					obs.WouldBlock = policy.Mode == "enforce" && policy.pretool.FailureMode == "closed"
				}
			} else {
				obs.WouldBlock = policy.Mode == "enforce" && policy.pretool.FailureMode == "closed"
			}
			if obs.WouldBlock && policy.Mode == "enforce" {
				obs.Verdict = "deny"
			}
		}
		decision := pretoolResult(obs)
		return b.recordDecision(now, action, inputDigest, obs, decision, policy.pretool)
	}
	o := Observation{Audience: receiptAudience, Binding: b.binding, PeerUID: b.uid, Action: action, Session: inventoryreport.OpaqueID(b.key.Seed(), "session", event.Session), ObservedAt: now, PolicyRevision: policy.Revision, Mode: policy.Mode, Tool: ticketTool, TargetClass: "unknown", Verdict: "unavailable", Reason: status, SkillUsage: "unknown", TargetEffect: "unknown"}
	if status == "verified_cache" {
		o.TargetClass = "outside_allowed_destination"
		if !safeID.MatchString(target) {
			o.TargetClass = "unknown"
		}
		if target == policy.AllowedDestination {
			o.TargetClass = "allowed_destination"
		}
		o.WouldBlock = o.TargetClass != "allowed_destination"
		o.Verdict = "continue"
		o.Reason = "within_scope"
		if o.WouldBlock {
			o.Reason = "destination_not_approved"
		}
		if o.WouldBlock && policy.Mode == "enforce" {
			o.Verdict = "deny"
		}
	}
	return b.recordDecision(now, action, inputDigest, o, result{Verdict: o.Verdict, Reason: o.Reason, ReceiptID: action}, nil)
}

func pretoolResult(o endpointprotocol.ObservationV2) result {
	hint := ""
	if o.RuleID != "" {
		hint = "review_endpoint_policy"
	} else if o.Reason != "within_scope" {
		hint = "contact_endpoint_admin"
	}
	return result{Verdict: o.Verdict, Reason: o.Reason, ReceiptID: o.Action, RuleID: o.RuleID, Revision: o.PolicyRevision, NextStep: hint}
}
func (b *broker) recordDecision(now time.Time, action, inputDigest string, o any, decision result, policy *endpointprotocol.PolicyV2) (result, error) {
	recordingFailed := func(reason string) (result, error) {
		decision.ReceiptID = ""
		if policy != nil {
			if decision.Verdict != "deny" {
				decision.Reason = reason
				decision.NextStep = "contact_endpoint_admin"
				if policy.Mode == "enforce" && policy.FailureMode == "closed" {
					decision.Verdict = "deny"
				}
			}
			return decision, nil
		}
		if decision.Verdict == "deny" {
			decision.Reason = "destination_not_approved_" + reason
			return decision, nil
		}
		return result{Verdict: "unavailable", Reason: reason}, nil
	}
	next := b.store.state
	next.Latest = now
	if len(next.Decisions) >= maxReceipts {
		if next.Gaps < math.MaxUint64 {
			next.Gaps++
		}
		if err := b.store.commit(next); err != nil {
			return recordingFailed("evidence_unavailable")
		}
		return recordingFailed("spool_full")
	}
	receipt, err := sign(o, b.key)
	if err != nil {
		return result{}, err
	}
	next.Decisions = make(map[string]storedDecision, len(b.store.state.Decisions)+1)
	for k, v := range b.store.state.Decisions {
		next.Decisions[k] = v
	}
	next.Decisions[action] = storedDecision{InputDigest: inputDigest, Receipt: receipt}
	if err = b.store.commit(next); err != nil {
		return recordingFailed("evidence_unavailable")
	}
	return decision, nil
}
