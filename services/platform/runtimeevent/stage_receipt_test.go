package runtimeevent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func TestStageReceiptRoundTripsExactAuthority(t *testing.T) {
	receipt := StageReceipt{
		Stage: RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: fixtureScope(t, 51), BatchID: fixtureID(t, 55), Generation: 4,
		InputReference: "s3://zasp-evidence/runtime/v15/raw.json", InputVersionID: "version-raw", InputDigest: sha256.Sum256([]byte("raw")),
		ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "version-raw", ArchiveDigest: sha256.Sum256([]byte("raw")),
		EffectDigest: sha256.Sum256([]byte("index-effect")), ItemIDs: []string{"evt_" + repeatHex("a", 64), "evt_" + repeatHex("b", 64)},
	}
	body, digest, reference, err := EncodeStageReceipt(receipt)
	if err != nil || len(body) == 0 || digest != sha256.Sum256(body) || reference.Validate() != nil {
		t.Fatalf("body=%s digest=%x reference=%s err=%v", body, digest, reference.String(), err)
	}
	decoded, err := DecodeStageReceipt(body)
	if err != nil || decoded.Stage != receipt.Stage || decoded.Scope != receipt.Scope || decoded.BatchID != receipt.BatchID || decoded.Generation != receipt.Generation || decoded.InputDigest != receipt.InputDigest || decoded.ArchiveDigest != receipt.ArchiveDigest || decoded.EffectDigest != receipt.EffectDigest || len(decoded.ItemIDs) != 2 || decoded.ItemIDs[0] != receipt.ItemIDs[0] {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	decoded.ItemIDs[0] = "mutated"
	again, err := DecodeStageReceipt(body)
	if err != nil || again.ItemIDs[0] != receipt.ItemIDs[0] {
		t.Fatalf("mutable decode=%#v err=%v", again, err)
	}
}

func TestStageReceiptRejectsTamperingAndNonCanonicalJSON(t *testing.T) {
	receipt := StageReceipt{
		Stage: RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: fixtureScope(t, 51), BatchID: fixtureID(t, 55), Generation: 4,
		InputReference: "s3://zasp-evidence/runtime/v15/raw.json", InputVersionID: "version-raw", InputDigest: sha256.Sum256([]byte("raw")),
		ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "version-raw", ArchiveDigest: sha256.Sum256([]byte("raw")),
		EffectDigest: sha256.Sum256([]byte("index-effect")), ItemIDs: []string{"evt_" + repeatHex("a", 64)},
	}
	body, _, _, err := EncodeStageReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if json.Unmarshal(body, &object) != nil {
		t.Fatal("fixture decode")
	}
	object["unknown"] = "drift"
	unknown, _ := json.Marshal(object)
	duplicate := bytes.Replace(body, []byte(`"stage":"index"`), []byte(`"stage":"index","stage":"project"`), 1)
	for _, candidate := range [][]byte{unknown, duplicate, append(bytes.Clone(body), []byte(` {}`)...), bytes.Replace(body, []byte(receipt.ItemIDs[0]), []byte("evt_short"), 1)} {
		if decoded, err := DecodeStageReceipt(candidate); err != ErrPipeline || decoded.Stage != "" || decoded.ItemIDs != nil {
			t.Fatalf("decoded=%#v err=%v body=%s", decoded, err, candidate)
		}
	}
}

func repeatHex(value string, count int) string {
	return string(bytes.Repeat([]byte(value), count))
}
