package apiserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Catch a changed truncation boundary or hashing the appended sha256 field:
// settlement consumes exact JSON bytes and a digest of the unsigned JSON object.
func TestAttackLabSettlementFixtureProofJSONAndDigest(t *testing.T) {
	execution := map[string]any{
		"run_id":       "execution-123",
		"attempt":      3,
		"input_digest": "input-digest",
		"verdict":      "inconclusive",
		"artifact": map[string]any{
			"bucket": "fixture-bucket",
			"key":    "evidence/receipt.json",
			"sha256": "artifact-digest",
		},
	}
	const preimage = `{"artifact":{"bucket":"fixture-bucket","key":"evidence/receipt.json","sha256":"artifact-digest"},"attempt":3,"cleanup_complete":true,"execution_id":"execution-123","input_digest":"input-digest","outcome":"cancelled","reason":"attack_lab_cancelled","schema_version":"security-agent-attack-lab-verification-v1","verdict":"inconclusive"}`
	digest := sha256.Sum256([]byte(preimage))
	wantDigest := hex.EncodeToString(digest[:])
	want := preimage[:len(preimage)-1] + `,"sha256":"` + wantDigest + `"}`
	proof := attackLabSettlementFixtureProof(t, execution, "cancelled", "attack_lab_cancelled")
	if string(proof) != want {
		t.Fatalf("settlement proof bytes changed:\n got %s\nwant %s", proof, want)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(proof, &decoded); err != nil {
		t.Fatalf("invalid proof JSON: %v", err)
	}
	var proofDigest string
	if err := json.Unmarshal(decoded["sha256"], &proofDigest); err != nil || proofDigest != wantDigest {
		t.Fatalf("proof digest=%q, want %q: %v", proofDigest, wantDigest, err)
	}
	delete(decoded, "sha256")
	unsigned, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(unsigned, []byte(preimage)) {
		t.Fatalf("unsigned proof preimage=%s: %v", unsigned, err)
	}
}
