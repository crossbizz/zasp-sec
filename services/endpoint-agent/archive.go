package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func signatureID(r Signed) string {
	d := sha256.Sum256(r.Signature)
	return hex.EncodeToString(d[:])
}

func archiveReceipts(socket, path string) error {
	if path == "" {
		return errInvalid
	}
	reply, err := call(socket, request{Operation: "export"})
	if err != nil {
		return err
	}
	selected := make(map[string]string, len(reply.Receipts))
	for _, receipt := range reply.Receipts {
		var obs struct {
			Action   string `json:"action_id"`
			Audience string `json:"audience"`
		}
		if json.Unmarshal(receipt.Payload, &obs) != nil || !endpointprotocol.Digest.MatchString(obs.Action) || (obs.Audience != receiptAudience && obs.Audience != endpointprotocol.ReceiptAudienceV2) {
			return errInvalid
		}
		selected[obs.Action] = signatureID(receipt)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = json.NewEncoder(f).Encode(reply.Receipts); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errUnavailable
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return err
	}
	_, err = call(socket, request{Operation: "archive", Archived: selected})
	return err
}

func (b *broker) ackArchive(records map[string]string) error {
	if len(records) > maxReceipts {
		return errInvalid
	}
	next := b.store.state
	now := b.now().UTC()
	if now.Before(next.Latest) {
		now = next.Latest
	}
	next.Latest = now
	next.Archived = make(map[string]time.Time, len(b.store.state.Archived))
	for id, expiry := range b.store.state.Archived {
		if expiry.After(now) {
			next.Archived[id] = expiry
		}
	}
	next.Decisions = make(map[string]storedDecision, len(b.store.state.Decisions))
	for id, value := range b.store.state.Decisions {
		next.Decisions[id] = value
	}
	for id, sig := range records {
		r, ok := next.Decisions[id]
		if !ok || signatureID(r.Receipt) != sig {
			return errInvalid
		}
		delete(next.Decisions, id)
		next.Archived[id] = now.Add(24 * time.Hour)
	}
	// Keep an entire policy-validity window of replay protection. Backpressure
	// gives the operator a visible gap if this pilot exceeds its supported rate.
	if len(next.Archived) > 16*maxReceipts {
		return errUnavailable
	}
	return b.store.commit(next)
}
