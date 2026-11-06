package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

// This private sentinel is issued only after the mutation returned an accepted
// fixed DTO and its transaction COMMIT acknowledgement became uncertain.
var errRetentionJournalCommitUnknown = errors.New("retained journal commit unconfirmed")

type retentionJournalStatus struct {
	ExecutionID string          `json:"execution_id"`
	Kind        string          `json:"kind"`
	Binding     json.RawMessage `json:"binding"`
	State       string          `json:"state"`
	Admissions  []struct {
		Key   string          `json:"admission_key"`
		ID    string          `json:"admission_id"`
		Items json.RawMessage `json:"items"`
	} `json:"admissions"`
	Descriptor        json.RawMessage `json:"descriptor"`
	ReservationDigest *string         `json:"reservation_digest"`
	DispatchDigest    *string         `json:"dispatch_digest"`
	Terminal          json.RawMessage `json:"terminal"`
	Inventory         *struct {
		AdmissionIDs []string `json:"admission_ids"`
		RequestCount int      `json:"request_count"`
		Digest       string   `json:"inventory_digest"`
	} `json:"inventory"`
	InventoryDigest *string         `json:"inventory_digest"`
	Partition       json.RawMessage `json:"partition"`
	PartitionDigest *string         `json:"partition_digest"`
	SendPermitted   *bool           `json:"send_permitted"`
}

func sameRetentionJournalJSON(a, b any) bool {
	decode := func(v any) (any, bool) {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, false
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var out any
		if decoder.Decode(&out) != nil {
			return nil, false
		}
		return out, true
	}
	left, ok := decode(a)
	if !ok {
		return false
	}
	right, ok := decode(b)
	return ok && reflect.DeepEqual(left, right)
}
func normalizeRetentionJournalBinding(binding map[string]any, partition bool) json.RawMessage {
	token, ok := binding["lease_token"].(string)
	if !ok || token == "" {
		return nil
	}
	normalized := make(map[string]any, len(binding))
	for key, value := range binding {
		if key == "lease_token" || key == "lease_expires_at" || key == "lease_until" || partition && key == "admission_ids" {
			continue
		}
		normalized[key] = value
	}
	digest := sha256.Sum256([]byte(token))
	normalized["lease_token_digest"] = hexRetentionDigest(digest)
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil
	}
	return body
}
func (j *retentionWriterJournal) status(ctx context.Context) (retentionJournalStatus, error) {
	var status retentionJournalStatus
	if j == nil || j.owner == nil || ctx == nil {
		return status, errRuntimeUnavailable
	}
	lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	body, err := json.Marshal(map[string]string{"execution_id": j.executionID, "capability": j.capability})
	if err != nil {
		return status, errRuntimeUnavailable
	}
	defer clear(body)
	raw, err := j.owner.journal.CommitRetentionJournal(lookup, `SELECT zasp_retention_journal_v1.execution_status($1::jsonb)`, body, j.owner.journalPin)
	// A read-only lookup's accepted immutable snapshot needs no mutation commit
	// recovery; importantly, this never constructs a send permission.
	if err != nil && !errors.Is(err, errRetentionJournalCommitUnknown) {
		return status, errRuntimeUnavailable
	}
	if len(raw) == 0 || len(raw) > 1<<20 || decodeStrictWorkerJSON(raw, &status) != nil || status.ExecutionID != j.executionID || status.Kind != j.input.Kind || status.SendPermitted == nil || *status.SendPermitted || !sameRetentionJournalJSON(status.Binding, j.originalBinding) {
		return retentionJournalStatus{}, errRuntimeUnavailable
	}
	switch status.State {
	case "begun", "reserved", "dispatched", "terminal", "closed", "sealed":
	default:
		return retentionJournalStatus{}, errRuntimeUnavailable
	}
	for _, digest := range []*string{status.ReservationDigest, status.DispatchDigest, status.InventoryDigest, status.PartitionDigest} {
		if digest != nil && !retentionCycleKeyPattern.MatchString(*digest) {
			return retentionJournalStatus{}, errRuntimeUnavailable
		}
	}
	if len(status.Admissions) > 1000 {
		return retentionJournalStatus{}, errRuntimeUnavailable
	}
	keys, ids := map[string]bool{}, map[string]bool{}
	for _, admission := range status.Admissions {
		if !retentionCycleKeyPattern.MatchString(admission.Key) || !retentionCycleKeyPattern.MatchString(admission.ID) || keys[admission.Key] || ids[admission.ID] {
			return retentionJournalStatus{}, errRuntimeUnavailable
		}
		keys[admission.Key], ids[admission.ID] = true, true
	}
	return status, nil
}
func (j *retentionWriterJournal) confirmUnknownCommit(ctx context.Context, operation string, fields map[string]any, accepted json.RawMessage) bool {
	status, err := j.status(ctx)
	if err != nil {
		return false
	}
	switch operation {
	case "begin_execution":
		var response struct {
			ID    string `json:"execution_id"`
			State string `json:"state"`
		}
		binding, ok := fields["binding"].(map[string]any)
		return ok && decodeStrictWorkerJSON(accepted, &response) == nil && response.ID == j.executionID && response.State == "begun" && sameRetentionJournalJSON(status.Binding, normalizeRetentionJournalBinding(binding, false))
	case "admit_execution":
		var response struct {
			ID    string          `json:"admission_id"`
			Items json.RawMessage `json:"items"`
		}
		if decodeStrictWorkerJSON(accepted, &response) != nil {
			return false
		}
		for _, admission := range status.Admissions {
			if admission.Key == fields["admission_key"] {
				return admission.ID == response.ID && sameRetentionJournalJSON(admission.Items, response.Items)
			}
		}
		return false
	case "reserve_request":
		var response struct {
			Digest string `json:"reservation_digest"`
		}
		return decodeStrictWorkerJSON(accepted, &response) == nil && status.ReservationDigest != nil && response.Digest == *status.ReservationDigest && sameRetentionJournalJSON(status.Descriptor, fields["descriptor"])
	case "claim_send":
		// Even an exact committed dispatch lookup is status only. The accepted
		// precommit true bit can NEVER be reused to mint a volatile HTTP permit.
		return false
	case "append_terminal":
		var response struct {
			Recorded bool `json:"recorded"`
		}
		return decodeStrictWorkerJSON(accepted, &response) == nil && response.Recorded && sameRetentionJournalJSON(status.Terminal, fields["observation"])
	case "close_inventory":
		var response struct {
			Digest string `json:"inventory_digest"`
		}
		return decodeStrictWorkerJSON(accepted, &response) == nil && status.Inventory != nil && status.InventoryDigest != nil && response.Digest == *status.InventoryDigest && response.Digest == status.Inventory.Digest && sameRetentionJournalJSON(status.Inventory.AdmissionIDs, fields["admission_ids"]) && sameRetentionJournalJSON(status.Inventory.RequestCount, fields["request_count"])
	case "seal_partition":
		var response struct {
			Digest string `json:"partition_digest"`
		}
		partition, ok := fields["partition"].(map[string]any)
		return ok && decodeStrictWorkerJSON(accepted, &response) == nil && status.PartitionDigest != nil && response.Digest == *status.PartitionDigest && sameRetentionJournalJSON(status.Partition, normalizeRetentionJournalBinding(partition, true)) && status.Inventory != nil && sameRetentionJournalJSON(status.Inventory.AdmissionIDs, partition["admission_ids"])
	}
	return false
}
