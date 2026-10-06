from pathlib import Path
r=Path('/workspace/.zasp-cloud-owned/native379-v2-primary-replay-ci9zftl1');p=r/'source/services/platform/apiserver/authorization_worker_ordered_current_native379_v2_test.go'
t='''
func TestNative379V2PristineRecorderRejectsUnsafeSQLState(t *testing.T) {
 const secret = "SECRET-CANARY-PRIMARY-ERROR"
 recorder := &orderedCurrentNative379V2OperationRecorder{}
 err := &pgconn.PgError{Code: secret, Message: secret, Detail: secret}
 if recorder.observe("preflight-identity", err) != err { t.Fatal("actual error lost") }
 raw, marshalErr := json.Marshal(recorder.operations)
 if marshalErr != nil || bytes.Contains(raw, []byte(secret)) { t.Fatal("unsafe SQLSTATE leaked into operation prefix") }
 if !recorder.invalid { t.Fatal("invalid SQLSTATE recorded as valid") }
}
'''
p.write_text(p.read_text()+t);(r/'evidence/old-api-red-test.go.txt').write_text(t)
