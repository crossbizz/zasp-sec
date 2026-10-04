package authorization

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// All fixture bodies/keys below are public synthetic component inputs. No
// fixture Check, database hash, module checksum or provider receipt is native
// authority. Literal MACs were independently checked before scaffold authoring.
const currentFrameSeed = "0123456789abcdef0123456789abcdef"

func currentFrameNow() time.Time { return time.UnixMilli(1700000000000) }
func currentFrameKey(t *testing.T, p ComplianceCurrentPurpose) *ComplianceCurrentKey {
	t.Helper()
	k, e := NewComplianceCurrentKey(p, []byte(currentFrameSeed))
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func currentFrameChange(t *testing.T, body string, mutate func(map[string]any)) []byte {
	t.Helper()
	var v map[string]any
	d := json.NewDecoder(strings.NewReader(body))
	d.UseNumber()
	if e := d.Decode(&v); e != nil {
		t.Fatal(e)
	}
	mutate(v)
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func currentFrameEnvelope(t *testing.T, body, mac string, p ComplianceCurrentPurpose) []byte {
	t.Helper()
	raw, e := json.Marshal(struct {
		Body    []byte `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}{[]byte(body), currentFrameKey(t, p).Version(), mac})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestComplianceCurrentFrameLiteralMACs(t *testing.T) {
	for _, f := range []struct {
		name, body, mac string
		p               ComplianceCurrentPurpose
	}{
		{"no lease", currentFrameNoLease, currentFrameNoLeaseMAC, ComplianceCurrentExecution},
		{"acquire execute", currentFrameAcquireExecute, currentFrameAcquireExecuteMAC, ComplianceCurrentExecution},
		{"pre capture", currentFramePreCapture, currentFramePreCaptureMAC, ComplianceCurrentExecution},
		{"execute finish", currentFrameFinish, currentFrameFinishMAC, ComplianceCurrentExecution},
		{"cleanup debt", currentFrameCleanup, currentFrameCleanupMAC, ComplianceCurrentCleanup},
		{"acquire debt", currentFrameAcquireDebt, currentFrameAcquireDebtMAC, ComplianceCurrentCleanup},
	} {
		t.Run(f.name, func(t *testing.T) {
			k := currentFrameKey(t, f.p)
			got, e := signComplianceCurrentFrame(k, []byte(f.body), currentFrameNow())
			if e != nil {
				t.Fatalf("valid bound frame refused: error=%v", e)
			}
			if !bytes.Equal(got, currentFrameEnvelope(t, f.body, f.mac, f.p)) {
				t.Fatal("frame body/version/MAC differ from independent literal envelope")
			}
			verified, e := verifyComplianceCurrentFrame(k, got, []byte(f.body), currentFrameNow())
			if e != nil || !bytes.Equal(verified, []byte(f.body)) {
				t.Fatal("valid exact expected facts did not verify")
			}
			verified[0] = 'x'
			again, e := verifyComplianceCurrentFrame(k, got, []byte(f.body), currentFrameNow())
			if e != nil || !bytes.Equal(again, []byte(f.body)) {
				t.Fatal("verified byte output aliases retained frame")
			}
		})
	}
}
func TestComplianceCurrentFrameEveryExpectedSlotBound(t *testing.T) {
	env := currentFrameEnvelope(t, currentFrameFinish, currentFrameFinishMAC, ComplianceCurrentExecution)
	k := currentFrameKey(t, ComplianceCurrentExecution)
	var slots map[string]json.RawMessage
	if e := json.Unmarshal([]byte(currentFrameFinish), &slots); e != nil {
		t.Fatal(e)
	}
	for slot := range slots {
		t.Run(slot, func(t *testing.T) {
			changed := currentFrameChange(t, currentFrameFinish, func(v map[string]any) { delete(v, slot) })
			if _, e := verifyComplianceCurrentFrame(k, env, changed, currentFrameNow()); !errors.Is(e, ErrInvalid) {
				t.Fatal("different/missing expected slot admitted")
			}
		})
	}
	wrongBody := currentFrameChange(t, currentFrameFinish, func(v map[string]any) { v["arguments_sha256"] = strings.Repeat("0", 64) })
	forged := currentFrameEnvelope(t, string(wrongBody), currentFrameFinishMAC, ComplianceCurrentExecution)
	if _, e := verifyComplianceCurrentFrame(k, forged, wrongBody, currentFrameNow()); !errors.Is(e, ErrInvalid) {
		t.Fatal("tampered authenticated body admitted")
	}
	if _, e := verifyComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentCleanup), env, []byte(currentFrameFinish), currentFrameNow()); !errors.Is(e, ErrInvalid) {
		t.Fatal("cross-purpose verifier admitted")
	}
}
func TestComplianceCurrentFrameClosedShapesAndPurposes(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"unknown slot":         func(v map[string]any) { v["unexpected"] = "fixture-private-canary" },
		"wrong domain":         func(v map[string]any) { v["domain"] = "worker-forward" },
		"legacy purpose":       func(v map[string]any) { v["purpose"] = "worker-forward" },
		"wrong principal type": func(v map[string]any) { v["session_user"] = false },
		"role as principal":    func(v map[string]any) { v["session_user"] = "zasp_compliance_worker" },
		"missing database":     func(v map[string]any) { delete(v, "database_id") },
		"null checksum":        func(v map[string]any) { v["module_checksum"] = nil },
		"wrong profile":        func(v map[string]any) { v["profile"] = "caller-selected" },
		"cross lane":           func(v map[string]any) { v["lane"] = "cleanup" },
		"nolease token":        func(v map[string]any) { v["lease_token"] = strings.Repeat("1", 64) },
		"nolease expiry":       func(v map[string]any) { v["lease_expires_at"] = json.Number("1700000060000") },
		"unknown operation":    func(v map[string]any) { v["operation"] = "custom" },
	} {
		t.Run(name, func(t *testing.T) {
			raw := currentFrameChange(t, currentFrameNoLease, mutate)
			if _, e := signComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentExecution), raw, currentFrameNow()); !errors.Is(e, ErrInvalid) {
				t.Fatal("unrecognized frame shape/purpose admitted")
			}
		})
	}
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`null`), []byte(currentFrameNoLease + `{}`), []byte(strings.Replace(currentFrameNoLease, `"domain":`, `"domain":"poison","domain":`, 1)), bytes.Repeat([]byte{'x'}, 32769)} {
		if _, e := signComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentExecution), raw, currentFrameNow()); !errors.Is(e, ErrInvalid) {
			t.Fatal("malformed/duplicate/oversized body admitted")
		}
	}
}
func TestComplianceCurrentFramePurposeLaneAndDebtSeparation(t *testing.T) {
	bad := []struct {
		body   string
		p      ComplianceCurrentPurpose
		mutate func(map[string]any)
	}{
		{currentFrameFinish, ComplianceCurrentExecution, func(v map[string]any) { v["lane"] = "reconcile" }},
		{currentFrameCleanup, ComplianceCurrentCleanup, func(v map[string]any) { v["lane"] = "execute" }},
		{currentFrameCleanup, ComplianceCurrentCleanup, func(v map[string]any) { v["operation"] = "capture"; v["subaction"] = "capture" }},
		{currentFrameCleanup, ComplianceCurrentCleanup, func(v map[string]any) { v["operation"] = "prepare"; v["subaction"] = "read" }},
		{currentFrameCleanup, ComplianceCurrentCleanup, func(v map[string]any) { v["requester_decision"] = map[string]any{"allowed": true} }},
		{currentFrameFinish, ComplianceCurrentExecution, func(v map[string]any) { delete(v, "requester_decision"); v["debt_digest"] = strings.Repeat("6", 64) }},
		{currentFrameNoLease, ComplianceCurrentExecution, func(v map[string]any) { v["operation"] = "maintenance"; v["subaction"] = "maintain" }},
	}
	for _, c := range bad {
		raw := currentFrameChange(t, c.body, c.mutate)
		if _, e := signComplianceCurrentFrame(currentFrameKey(t, c.p), raw, currentFrameNow()); !errors.Is(e, ErrInvalid) {
			t.Fatal("lane/debt authority widened")
		}
	}
	// Explicit captured-only reconcile read is valid; it does not authorize PUT.
	rec := currentFrameChange(t, currentFrameCleanup, func(v map[string]any) { v["lane"] = "reconcile"; v["operation"] = "prepare"; v["subaction"] = "read" })
	if _, e := signComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentCleanup), rec, currentFrameNow()); e != nil {
		t.Fatal("captured-only reconcile prepared read refused")
	}
	write := currentFrameChange(t, string(rec), func(v map[string]any) { v["subaction"] = "write" })
	if _, e := signComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentCleanup), write, currentFrameNow()); !errors.Is(e, ErrInvalid) {
		t.Fatal("reconcile prepared write admitted")
	}
}
func TestComplianceCurrentFrameRequesterRevisionBinding(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"missing three checks": func(v map[string]any) { v["requester_decision"].(map[string]any)["checks"] = []any{} },
		"denied check": func(v map[string]any) {
			v["requester_decision"].(map[string]any)["checks"].([]any)[0].(map[string]any)["allowed"] = false
		},
		"model mismatch": func(v map[string]any) {
			v["requester_decision"].(map[string]any)["checks"].([]any)[0].(map[string]any)["model_id"] = "01K00000000000000000000009"
		},
		"pending revision": func(v map[string]any) {
			v["requester_decision"].(map[string]any)["revision"].(map[string]any)["applied"] = json.Number("0")
		},
		"service substitution": func(v map[string]any) {
			v["requester_decision"].(map[string]any)["checks"].([]any)[0].(map[string]any)["request"].(map[string]any)["principal_kind"] = "service"
		},
		"invented task": func(v map[string]any) {
			v["requester_decision"].(map[string]any)["checks"].([]any)[0].(map[string]any)["request"].(map[string]any)["task_id"] = "01K00000000000000000000009"
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw := currentFrameChange(t, currentFrameFinish, mutate)
			if _, e := signComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentExecution), raw, currentFrameNow()); !errors.Is(e, ErrInvalid) {
				t.Fatal("requester/revision binding widened")
			}
		})
	}
}
func TestComplianceCurrentFrameTimingAndIntegerPrecision(t *testing.T) {
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["expires_at"] = json.Number("1700000000000") },
		func(v map[string]any) { v["issued_at"] = json.Number("1700000005001") },
		func(v map[string]any) { v["expires_at"] = json.Number("1700000060001") },
		func(v map[string]any) { v["issued_at"] = true },
		func(v map[string]any) { v["issued_at"] = json.Number("1700000000000.5") },
	} {
		raw := currentFrameChange(t, currentFrameNoLease, change)
		if _, e := signComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentExecution), raw, currentFrameNow()); !errors.Is(e, ErrInvalid) {
			t.Fatal("expired/too-future/noninteger proof admitted")
		}
	}
	tooLate := currentFrameChange(t, currentFrameFinish, func(v map[string]any) { v["lease_expires_at"] = json.Number("1700000029999") })
	if _, e := signComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentExecution), tooLate, currentFrameNow()); !errors.Is(e, ErrInvalid) {
		t.Fatal("proof outlived actual held lease")
	}
	large := currentFrameChange(t, currentFrameFinish, func(v map[string]any) {
		r := v["requester_decision"].(map[string]any)["revision"].(map[string]any)
		r["desired"] = json.Number("9007199254740993")
		r["applied"] = json.Number("9007199254740993")
	})
	env, e := signComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentExecution), large, currentFrameNow())
	if e != nil {
		t.Fatal("valid int64 revision refused")
	}
	got, e := verifyComplianceCurrentFrame(currentFrameKey(t, ComplianceCurrentExecution), env, large, currentFrameNow())
	if e != nil || !bytes.Equal(got, large) {
		t.Fatal("int64 revision precision lost")
	}
}
func TestComplianceCurrentFrameMalformedEnvelopeAndSafeErrors(t *testing.T) {
	k := currentFrameKey(t, ComplianceCurrentExecution)
	valid := currentFrameEnvelope(t, currentFrameNoLease, currentFrameNoLeaseMAC, ComplianceCurrentExecution)
	var env map[string]any
	if e := json.Unmarshal(valid, &env); e != nil {
		t.Fatal(e)
	}
	candidates := [][]byte{[]byte(`null`), []byte(`{}`), []byte(`{"body":"not-base64","version":"x","mac":"x"}`), append(append([]byte(nil), valid...), []byte(`{}`)...), bytes.Repeat([]byte{'x'}, 65537)}
	for _, mutate := range []func(map[string]any){func(v map[string]any) { v["extra"] = "fixture-private-canary" }, func(v map[string]any) { v["mac"] = strings.ToUpper(currentFrameNoLeaseMAC) }, func(v map[string]any) { v["version"] = strings.Repeat("0", 64) }, func(v map[string]any) { v["body"] = nil }} {
		var v map[string]any
		_ = json.Unmarshal(valid, &v)
		mutate(v)
		r, _ := json.Marshal(v)
		candidates = append(candidates, r)
	}
	candidates = append(candidates, []byte(strings.Replace(string(valid), `"mac":`, `"mac":"poison","mac":`, 1)))
	for _, raw := range candidates {
		_, e := verifyComplianceCurrentFrame(k, raw, []byte(currentFrameNoLease), currentFrameNow())
		if !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid envelope admitted")
		}
		for _, format := range []string{"%v", "%#v", "%+#v"} {
			s := fmt.Sprintf(format, e)
			if strings.Contains(s, "fixture-private-canary") || strings.Contains(s, string(raw)) {
				t.Fatal("frame error disclosed raw content")
			}
		}
	}
}
func TestComplianceCurrentModuleClaimExactEightSlots(t *testing.T) {
	const claim = `{"arguments_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","decision_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","domain":"zasp-compliance-current-api-operation-v1","module_checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"grant","profile":"canonical61-temporal78-authorization79-80-compliance-current-v1","statement_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","subaction":"consume"}`
	if e := validateComplianceCurrentModuleClaim([]byte(claim)); e != nil {
		t.Fatal("valid exact8-field claim refused")
	}
	var slots map[string]json.RawMessage
	_ = json.Unmarshal([]byte(claim), &slots)
	if len(slots) != 8 {
		t.Fatal("claim fixture count drift")
	}
	for slot := range slots {
		raw := currentFrameChange(t, claim, func(v map[string]any) { delete(v, slot) })
		if e := validateComplianceCurrentModuleClaim(raw); !errors.Is(e, ErrInvalid) {
			t.Fatal("missing module claim slot admitted")
		}
	}
	for _, change := range []func(map[string]any){func(v map[string]any) { v["extra"] = true }, func(v map[string]any) { v["operation"] = "create" }, func(v map[string]any) { v["domain"] = "worker-forward" }, func(v map[string]any) { v["arguments_sha256"] = nil }} {
		raw := currentFrameChange(t, claim, change)
		if e := validateComplianceCurrentModuleClaim(raw); !errors.Is(e, ErrInvalid) {
			t.Fatal("wrong module claim admitted")
		}
	}
}
func TestComplianceCurrentArgumentDigestLiteralAndTypes(t *testing.T) {
	args := []any{"x", []byte{1, 2}, int64(9007199254740993), true, json.RawMessage(`{"x":1}`), nil}
	specs := []complianceCurrentArgumentSpec{{Kind: 1}, {Kind: 2}, {Kind: 3}, {Kind: 4}, {Kind: 5}, {Kind: 1, Nullable: true}}
	got, e := complianceCurrentArgumentsDigest(args, specs)
	if e != nil || got != currentArgumentLiteralSHA {
		t.Fatal("typed argument digest differs from independent byte-frame literal")
	}
	for _, a := range []any{int(1), float64(1), json.Number("1"), nil} {
		bad := append([]any(nil), args...)
		bad[2] = a
		if _, e := complianceCurrentArgumentsDigest(bad, specs); !errors.Is(e, ErrInvalid) {
			t.Fatal("argument numeric/null coercion admitted")
		}
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`{"x":1,"x":2}`), json.RawMessage(`{"x":{"y":1,"y":2}}`), json.RawMessage(`{} {}`)} {
		bad := append([]any(nil), args...)
		bad[4] = raw
		if _, e := complianceCurrentArgumentsDigest(bad, specs); !errors.Is(e, ErrInvalid) {
			t.Fatal("duplicate/malformed JSON argument admitted")
		}
	}
	if _, e := complianceCurrentArgumentsDigest(args, specs[:5]); !errors.Is(e, ErrInvalid) {
		t.Fatal("wrong arity admitted")
	}
	nonnull := append([]complianceCurrentArgumentSpec(nil), specs...)
	nonnull[5].Nullable = false
	if _, e := complianceCurrentArgumentsDigest(args, nonnull); !errors.Is(e, ErrInvalid) {
		t.Fatal("nonnullable null admitted")
	}
	badKind := append([]complianceCurrentArgumentSpec(nil), specs...)
	badKind[0].Kind = 99
	if _, e := complianceCurrentArgumentsDigest(args, badKind); !errors.Is(e, ErrInvalid) {
		t.Fatal("unknown type tag admitted")
	}
}

const currentFrameNoLease = `{"arguments_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","authority_kind":"no_lease","database_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","domain":"zasp-compliance-current-worker-frame-v1","expires_at":1700000030000,"global_head":"pid_10000000-0000-4000-8000-000000000004","issued_at":1700000000000,"key_version":"ac23efa46f80d01c19862b8063c035c234bb2abe68661bfb9432c291e137c681","lane":"execute","module_checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"candidates","profile":"canonical61-temporal78-authorization79-80-compliance-current-v1","purpose":"compliance-current-execution-v1","request_id":"pid_10000000-0000-4000-8000-000000000005","scope":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","workspace_id":"pid_10000000-0000-4000-8000-000000000002"},"session_user":"compliance_executor","subaction":"list"}`
const currentFrameNoLeaseMAC = "a77dafd6c01fe0d16a585e945ff9339194cb2daf123e107dbe5d7b40431e88a3"
const currentFrameAcquireExecute = `{"arguments_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","authority_kind":"acquire","database_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","domain":"zasp-compliance-current-worker-frame-v1","expires_at":1700000030000,"export_id":"pid_10000000-0000-4000-8000-000000000004","issued_at":1700000000000,"key_version":"ac23efa46f80d01c19862b8063c035c234bb2abe68661bfb9432c291e137c681","lane":"execute","module_checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"claim","origin_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","profile":"canonical61-temporal78-authorization79-80-compliance-current-v1","purpose":"compliance-current-execution-v1","request_id":"pid_10000000-0000-4000-8000-000000000005","requester_decision":{"checks":[{"allowed":true,"model_id":"01K00000000000000000000007","request":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","permission":"view","principal_id":"pid_10000000-0000-4000-8000-000000000008","principal_kind":"user","resource_id":"pid_10000000-0000-4000-8000-000000000003","resource_type":"environment","task_id":"","workspace_id":"pid_10000000-0000-4000-8000-000000000002"}},{"allowed":true,"model_id":"01K00000000000000000000007","request":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","permission":"view_audit","principal_id":"pid_10000000-0000-4000-8000-000000000008","principal_kind":"user","resource_id":"pid_10000000-0000-4000-8000-000000000003","resource_type":"environment","task_id":"","workspace_id":"pid_10000000-0000-4000-8000-000000000002"}},{"allowed":true,"model_id":"01K00000000000000000000007","request":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","permission":"view_compliance","principal_id":"pid_10000000-0000-4000-8000-000000000008","principal_kind":"user","resource_id":"pid_10000000-0000-4000-8000-000000000003","resource_type":"environment","task_id":"","workspace_id":"pid_10000000-0000-4000-8000-000000000002"}}],"credential_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","native_facts_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","requester_id":"pid_10000000-0000-4000-8000-000000000008","revision":{"applied":1,"desired":1,"generation":1,"model_id":"01K00000000000000000000007","organization_id":"pid_10000000-0000-4000-8000-000000000001","store_id":"01K00000000000000000000006"}},"scope":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","workspace_id":"pid_10000000-0000-4000-8000-000000000002"},"session_user":"compliance_executor","subaction":"acquire","worker_id":"compliance-worker-1"}`
const currentFrameAcquireExecuteMAC = "49cef89e28ca06d4d487a8dc820300e2098214fd79f505917eea661922aefe25"
const currentFramePreCapture = `{"arguments_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","attempt":1,"authority_kind":"execute_pre_capture_lease","database_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","domain":"zasp-compliance-current-worker-frame-v1","expires_at":1700000030000,"export_id":"pid_10000000-0000-4000-8000-000000000004","generation":1,"issued_at":1700000000000,"key_version":"ac23efa46f80d01c19862b8063c035c234bb2abe68661bfb9432c291e137c681","lane":"execute","lease_expires_at":1700000060000,"lease_token":"1111111111111111111111111111111111111111111111111111111111111111","module_checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"capture","origin_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","profile":"canonical61-temporal78-authorization79-80-compliance-current-v1","purpose":"compliance-current-execution-v1","request_id":"pid_10000000-0000-4000-8000-000000000005","requester_decision":{"checks":[{"allowed":true,"model_id":"01K00000000000000000000007","request":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","permission":"view","principal_id":"pid_10000000-0000-4000-8000-000000000008","principal_kind":"user","resource_id":"pid_10000000-0000-4000-8000-000000000003","resource_type":"environment","task_id":"","workspace_id":"pid_10000000-0000-4000-8000-000000000002"}},{"allowed":true,"model_id":"01K00000000000000000000007","request":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","permission":"view_audit","principal_id":"pid_10000000-0000-4000-8000-000000000008","principal_kind":"user","resource_id":"pid_10000000-0000-4000-8000-000000000003","resource_type":"environment","task_id":"","workspace_id":"pid_10000000-0000-4000-8000-000000000002"}},{"allowed":true,"model_id":"01K00000000000000000000007","request":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","permission":"view_compliance","principal_id":"pid_10000000-0000-4000-8000-000000000008","principal_kind":"user","resource_id":"pid_10000000-0000-4000-8000-000000000003","resource_type":"environment","task_id":"","workspace_id":"pid_10000000-0000-4000-8000-000000000002"}}],"credential_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","native_facts_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","requester_id":"pid_10000000-0000-4000-8000-000000000008","revision":{"applied":1,"desired":1,"generation":1,"model_id":"01K00000000000000000000007","organization_id":"pid_10000000-0000-4000-8000-000000000001","store_id":"01K00000000000000000000006"}},"scope":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","workspace_id":"pid_10000000-0000-4000-8000-000000000002"},"session_user":"compliance_executor","subaction":"capture","worker_id":"compliance-worker-1"}`
const currentFramePreCaptureMAC = "69b3a90583f1c51eeffdbd24fe3d49af684fe2fa765d38436ce9c3ae616f1a45"
const currentFrameFinish = `{"arguments_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","attempt":1,"authority_kind":"execute_lease","capture_digest":"2222222222222222222222222222222222222222222222222222222222222222","database_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","domain":"zasp-compliance-current-worker-frame-v1","expires_at":1700000030000,"export_id":"pid_10000000-0000-4000-8000-000000000004","generation":1,"issued_at":1700000000000,"key_version":"ac23efa46f80d01c19862b8063c035c234bb2abe68661bfb9432c291e137c681","lane":"execute","lease_expires_at":1700000060000,"lease_token":"1111111111111111111111111111111111111111111111111111111111111111","module_checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"finish","origin_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","package_digest":"3333333333333333333333333333333333333333333333333333333333333333","profile":"canonical61-temporal78-authorization79-80-compliance-current-v1","provider_coordinates":{"reference":"pid_10000000-0000-4000-8000-000000000004","sha256":"4444444444444444444444444444444444444444444444444444444444444444","size":128,"version_id":"fixture-version"},"purpose":"compliance-current-execution-v1","request_id":"pid_10000000-0000-4000-8000-000000000005","requester_decision":{"checks":[{"allowed":true,"model_id":"01K00000000000000000000007","request":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","permission":"view","principal_id":"pid_10000000-0000-4000-8000-000000000008","principal_kind":"user","resource_id":"pid_10000000-0000-4000-8000-000000000003","resource_type":"environment","task_id":"","workspace_id":"pid_10000000-0000-4000-8000-000000000002"}},{"allowed":true,"model_id":"01K00000000000000000000007","request":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","permission":"view_audit","principal_id":"pid_10000000-0000-4000-8000-000000000008","principal_kind":"user","resource_id":"pid_10000000-0000-4000-8000-000000000003","resource_type":"environment","task_id":"","workspace_id":"pid_10000000-0000-4000-8000-000000000002"}},{"allowed":true,"model_id":"01K00000000000000000000007","request":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","permission":"view_compliance","principal_id":"pid_10000000-0000-4000-8000-000000000008","principal_kind":"user","resource_id":"pid_10000000-0000-4000-8000-000000000003","resource_type":"environment","task_id":"","workspace_id":"pid_10000000-0000-4000-8000-000000000002"}}],"credential_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","native_facts_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","requester_id":"pid_10000000-0000-4000-8000-000000000008","revision":{"applied":1,"desired":1,"generation":1,"model_id":"01K00000000000000000000007","organization_id":"pid_10000000-0000-4000-8000-000000000001","store_id":"01K00000000000000000000006"}},"scope":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","workspace_id":"pid_10000000-0000-4000-8000-000000000002"},"session_user":"compliance_executor","subaction":"acknowledged","worker_id":"compliance-worker-1"}`
const currentFrameFinishMAC = "a606bce5e6adf5cb5b6d932214b039e3d625389612a63b0b181c23fc02ac140a"
const currentFrameCleanup = `{"arguments_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","attempt":1,"authority_kind":"debt_lease","captured_proof_digest":"5555555555555555555555555555555555555555555555555555555555555555","database_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","debt_digest":"6666666666666666666666666666666666666666666666666666666666666666","domain":"zasp-compliance-current-worker-frame-v1","expires_at":1700000030000,"export_id":"pid_10000000-0000-4000-8000-000000000004","generation":1,"issued_at":1700000000000,"key_version":"0f7021f915b6c65968912f1a764c789da863c74c3926d165fc56fe84cde635b7","lane":"cleanup","lease_expires_at":1700000060000,"lease_token":"1111111111111111111111111111111111111111111111111111111111111111","module_checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"cleanup","origin_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","package_digest":"3333333333333333333333333333333333333333333333333333333333333333","profile":"canonical61-temporal78-authorization79-80-compliance-current-v1","provider_coordinates":{"reference":"pid_10000000-0000-4000-8000-000000000004","sha256":"4444444444444444444444444444444444444444444444444444444444444444","size":128,"version_id":"fixture-version"},"purpose":"compliance-current-cleanup-v1","request_id":"pid_10000000-0000-4000-8000-000000000005","scope":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","workspace_id":"pid_10000000-0000-4000-8000-000000000002"},"session_user":"compliance_cleanup","subaction":"confirm_absent","worker_id":"compliance-worker-1"}`
const currentFrameCleanupMAC = "f7ced054a662a9ea64276ece963a2e7aa74944096e43446cc3c096cae9853aeb"
const currentFrameAcquireDebt = `{"arguments_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","authority_kind":"acquire","database_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","debt_digest":"6666666666666666666666666666666666666666666666666666666666666666","domain":"zasp-compliance-current-worker-frame-v1","expires_at":1700000030000,"export_id":"pid_10000000-0000-4000-8000-000000000004","issued_at":1700000000000,"key_version":"0f7021f915b6c65968912f1a764c789da863c74c3926d165fc56fe84cde635b7","lane":"reconcile","module_checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"claim","origin_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","profile":"canonical61-temporal78-authorization79-80-compliance-current-v1","purpose":"compliance-current-cleanup-v1","request_id":"pid_10000000-0000-4000-8000-000000000005","scope":{"environment_id":"pid_10000000-0000-4000-8000-000000000003","organization_id":"pid_10000000-0000-4000-8000-000000000001","workspace_id":"pid_10000000-0000-4000-8000-000000000002"},"session_user":"compliance_cleanup","subaction":"acquire","worker_id":"compliance-worker-1"}`
const currentFrameAcquireDebtMAC = "80b6edb2bc033e916190971dbcad14f34cc0d5a6021aab341e6320d55b31b7fc"
const currentArgumentLiteralSHA = "c2ca1668d18ef1162a33b3d8d6ac1b54d1f795aa7157c23b62e1786a90f8b7ed"

func TestComplianceCurrentFrameSourceIdentifierAndAttemptBounds(t *testing.T) {
	k := currentFrameKey(t, ComplianceCurrentExecution)
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["scope"].(map[string]any)["organization_id"] = "01K00000000000000000000001" },
		func(v map[string]any) { v["global_head"] = "01K00000000000000000000004" },
		func(v map[string]any) {
			v["scope"].(map[string]any)["workspace_id"] = "pid_10000000-0000-5000-8000-000000000002"
		},
		func(v map[string]any) {
			v["scope"].(map[string]any)["environment_id"] = "pid_ABCDEF00-0000-4000-8000-000000000003"
		},
		func(v map[string]any) {
			v["scope"].(map[string]any)["environment_id"] = "pid_00000000-0000-4000-8000-000000000000"
		},
	} {
		raw := currentFrameChange(t, currentFrameNoLease, mutate)
		if _, e := signComplianceCurrentFrame(k, raw, currentFrameNow()); !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid original product-ID grammar admitted")
		}
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["export_id"] = "01K00000000000000000000004" },
		func(v map[string]any) {
			v["requester_decision"].(map[string]any)["requester_id"] = "01K00000000000000000000008"
		},
		func(v map[string]any) { v["provider_coordinates"].(map[string]any)["reference"] = "owned/object" },
		func(v map[string]any) {
			v["provider_coordinates"].(map[string]any)["reference"] = "pid_10000000-0000-4000-8000-000000000010"
		},
		func(v map[string]any) {
			v["provider_coordinates"].(map[string]any)["reference"] = "01K00000000000000000000010"
		},
		func(v map[string]any) { v["attempt"] = json.Number("0") },
		func(v map[string]any) { v["attempt"] = json.Number("6") },
	} {
		raw := currentFrameChange(t, currentFrameFinish, mutate)
		if _, e := signComplianceCurrentFrame(k, raw, currentFrameNow()); !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid export/requester/reference/execute-attempt admitted")
		}
	}
	// Native SQL accepts these worker identities. Normal runtime configuration
	// additionally has its own original stricter selector; this codec is not it.
	for _, worker := range []string{"A", "A:B_1", "01K00000000000000000000009", strings.Repeat("a", 128)} {
		raw := currentFrameChange(t, currentFrameFinish, func(v map[string]any) { v["worker_id"] = worker })
		if _, e := signComplianceCurrentFrame(k, raw, currentFrameNow()); e != nil {
			t.Fatal("original bounded native worker ID refused")
		}
	}
	for _, worker := range []string{"", "has/slash", strings.Repeat("a", 129)} {
		raw := currentFrameChange(t, currentFrameFinish, func(v map[string]any) { v["worker_id"] = worker })
		if _, e := signComplianceCurrentFrame(k, raw, currentFrameNow()); !errors.Is(e, ErrInvalid) {
			t.Fatal("out-of-contract native worker ID admitted")
		}
	}
	cleanupKey := currentFrameKey(t, ComplianceCurrentCleanup)
	for _, attempt := range []int{0, 5} {
		raw := currentFrameChange(t, currentFrameCleanup, func(v map[string]any) { v["attempt"] = attempt })
		if _, e := signComplianceCurrentFrame(cleanupKey, raw, currentFrameNow()); e != nil {
			t.Fatal("original cleanup0..5 attempt refused")
		}
	}
	bad := currentFrameChange(t, currentFrameCleanup, func(v map[string]any) { v["attempt"] = 6 })
	if _, e := signComplianceCurrentFrame(cleanupKey, bad, currentFrameNow()); !errors.Is(e, ErrInvalid) {
		t.Fatal("cleanup attempt6 admitted")
	}
	rec := currentFrameChange(t, currentFrameCleanup, func(v map[string]any) {
		v["lane"] = "reconcile"
		v["operation"] = "prepare"
		v["subaction"] = "read"
		v["attempt"] = 0
	})
	if _, e := signComplianceCurrentFrame(cleanupKey, rec, currentFrameNow()); e != nil {
		t.Fatal("inherited reconcile zero-attempt refused")
	}
}
