package securityagent

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

type evidenceModel struct {
	inputs []json.RawMessage
	reply  json.RawMessage
}

func (d *evidenceModel) Evaluate(_ context.Context, _ aigateway.Purpose, raw json.RawMessage) (json.RawMessage, error) {
	d.inputs = append(d.inputs, raw)
	return d.reply, nil
}

func TestInvestigatorRedactsQuestionsAndRejectsForeignReferences(t *testing.T) {
	known := "pid_d313339b-97cb-4644-a96e-cd6fdcfc587e"
	d := &evidenceModel{reply: json.RawMessage(`{"summary":"Review the missing return receipt.","evidence_ids":["` + known + `"]}`)}
	rows := []InvestigationAction{{known, "authenticated_workload", "outcome_unknown"}}
	result, err := InvestigateSession(context.Background(), d, "Missing evidence, customer-report-private?", rows)
	if err != nil || len(d.inputs) != 1 || bytes.Contains(d.inputs[0], []byte("customer-report")) || len(result.EvidenceIDs) != 1 {
		t.Fatalf("result=%+v err=%v call=%s", result, err, d.inputs)
	}
	d.reply = json.RawMessage(`{"summary":"Review.","evidence_ids":["unrelated"]}`)
	if _, err = InvestigateSession(context.Background(), d, "Missing?", rows); err == nil {
		t.Fatal("accepted unrelated evidence")
	}
	d.inputs = nil
	if _, err = InvestigateSession(context.Background(), d, "What was blocked?", rows); err != nil || len(d.inputs) != 0 {
		t.Fatal("called model for absent records", err)
	}
}
