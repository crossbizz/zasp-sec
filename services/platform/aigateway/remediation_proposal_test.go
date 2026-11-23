package aigateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
)

type measuredAdvisory struct{ changeTarget bool }

func (d measuredAdvisory) Evaluate(_ context.Context, p Purpose, input json.RawMessage) (json.RawMessage, error) {
	candidates, ok := admittedAdvisory(input)
	if !ok {
		return nil, ErrInvalidRequest
	}
	if len(candidates) > 0 && d.changeTarget {
		candidates[0].Target = "pid_11111111-1111-4111-8111-111111111111"
	}
	return json.Marshal(map[string]any{"steps": candidates})
}
func TestRemediationQualificationMeasuresOnlyAdmittedProposals(t *testing.T) {
	provider, _, err := NewBedrockForPurpose(PurposeRemediate, "vpce-test.bedrock-runtime.eu-west-1.vpce.amazonaws.com", netip.MustParseAddr("10.1.0.2"), modelSonnet, "secret_ref_planner/o/w/e/key", "local-synthetic-token", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Evaluate(context.Background(), PurposeRemediate, json.RawMessage(`{"candidates":[],"evidence_ids":[],"action":"outside_case"}`)); err == nil {
		t.Fatal("accepted undeclared input")
	}
	att := DeploymentAttestation{Purpose: PurposeRemediate}
	var corpus bytes.Buffer
	for n := 0; n < 100; n++ {
		id := fmt.Sprintf("pid_33333333-3333-4333-8333-%012x", n+1)
		steps := []advisoryStep{}
		if n%2 == 1 {
			steps = append(steps, advisoryStep{"isolate_session", id, "ttl_release"})
		}
		input := map[string]any{"candidates": steps, "evidence_ids": []string{id}}
		json.NewEncoder(&corpus).Encode(map[string]any{"input": input, "expected": map[string]any{"steps": steps}, "counterfeit_policy": n == 0})
	}
	sum := sha256.Sum256(corpus.Bytes())
	att.CorpusSHA256 = hex.EncodeToString(sum[:])
	for _, change := range []bool{false, true} {
		r, err := MeasureCloud(context.Background(), measuredAdvisory{change}, att, "sha256:"+att.CorpusSHA256, corpus.Bytes())
		if err != nil || r.Total != 100 || r.Qualified == change {
			t.Fatal(change, r, err)
		}
	}
}
