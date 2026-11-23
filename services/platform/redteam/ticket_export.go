package redteam

import (
	"bytes"
	"encoding/json"
	"strings"
)

// DecodeTicketExport validates a bounded metadata export before decoding. A
// repeated key or case variant could otherwise erase a reported target write.
func DecodeTicketExport(data []byte, output any) error {
	if len(data) >= 64*1024 || !json.Valid(data) || !uniqueKeys(json.NewDecoder(bytes.NewReader(data)), 0) {
		return ErrRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

type TicketProofBundle struct {
	Scenario     TicketScenario         `json:"scenario"`
	Adapter      TicketAdapterEvidence  `json:"adapter"`
	Recorder     TicketRecorderEvidence `json:"recorder"`
	Attestations *TicketAttestations    `json:"attestations,omitempty"`
}

func uniqueKeys(decoder *json.Decoder, depth int) bool {
	token, err := decoder.Token()
	if err != nil || depth > 8 {
		return false
	}
	delim, compound := token.(json.Delim)
	if depth == 0 && (!compound || delim != '{') {
		return false
	}
	if !compound {
		return true
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			name, err := decoder.Token()
			key, ok := name.(string)
			if err != nil || !ok || key != strings.ToLower(key) || seen[key] {
				return false
			}
			seen[key] = true
		}
		if !uniqueKeys(decoder, depth+1) {
			return false
		}
	}
	_, err = decoder.Token()
	return err == nil
}

// Archivable restricts retained evidence to the two registered actions and the
// bound target. Missing evidence can be represented by an empty decisions or
// writes array, unknown capability, an unhealthy recorder or a missing watermark.
func (b TicketProofBundle) Archivable() bool {
	if b.Attestations != nil && (!b.Attestations.Adapter.wellFormed() || !b.Attestations.Recorder.wellFormed() || b.Attestations.Adapter.KeyID == b.Attestations.Recorder.KeyID || b.Scenario.Environment != "staging") {
		return false
	}
	s := b.Scenario
	a := b.Adapter
	r := b.Recorder
	if s.validate() != nil || a.Version != s.Version || r.Version != s.Version || a.TicketRunBinding != s.TicketRunBinding || r.TicketRunBinding != s.TicketRunBinding || a.AdapterID != s.AdapterID || a.CohortID != s.CohortID || !ticketOpaqueID.MatchString(a.PolicyRevision) || r.RecorderID != s.RecorderID || !contains([]string{"supported", "unsupported", "unknown"}, a.Capability) || a.Decisions == nil || r.Writes == nil || len(a.Decisions) > 64 || len(r.Writes) > 64 {
		return false
	}
	for _, d := range a.Decisions {
		if (d.ActionID != s.ControlActionID && d.ActionID != s.ProtectedActionID) || !ticketOpaqueID.MatchString(d.DecisionID) || !contains([]string{"allow", "block"}, d.Verdict) || !contains([]string{"monitor", "enforce"}, d.Mode) || d.DecidedAt.IsZero() {
			return false
		}
	}
	for _, w := range r.Writes {
		if (w.ActionID != s.ControlActionID && w.ActionID != s.ProtectedActionID) || !ticketOpaqueID.MatchString(w.ReceiptID) || w.RecordedAt.IsZero() {
			return false
		}
	}
	return true
}
