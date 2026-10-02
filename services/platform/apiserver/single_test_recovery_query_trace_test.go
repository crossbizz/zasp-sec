package apiserver

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// This is a closed diagnostic wire, not trusted evidence. Only fixed labels
// from the two test-owned log sites survive; unknown fields discard the line.
var singleRecoveryQueryTracePattern = regexp.MustCompile(`(?m)^[ \t]*security_agent_temporal_single_recovery_(?:live|query_trace)_test\.go:[0-9]{1,4}: recovery-trace phase=(pending|settle) caller=(cleanup|step|finish) operation=(source-inspect|source-status|source-cleanup|source-state|proof|inspect|state|status|cleanup|load|observe|finish|other) error=(none|deadline|canceled|query) sqlstate=(none|22023|25001|23514|40001|40P01|42501|55P03|57014|other) ordinal=([0-8]|many) source_state=([0-8]|many) state_completed=([0-8]|many) elapsed=(lt1s|lt5s|lt10s|ge10s) result=(nil|pending|auth-conflict|auth-unavailable|auth-denied|auth-invalid|worker|conflict|unavailable|invalid|deadline|canceled|other)\r?$`)

var singleRecoveryContentionBoundaryPattern = regexp.MustCompile(`(?m)^[ \t]*security_agent_temporal_single_recovery_(?:live|query_trace)_test\.go:[0-9]{1,4}: recovery-contention phase=(pending|settle) wait=(ready|deadline|canceled|error) release=(ok|deadline|canceled|error) join=(complete|outer-deadline|outer-canceled|unjoined) elapsed=(lt5s|lt45s|ge45s)\r?$`)

func singleRecoveryQueryTraceSummary(output []byte) string {
	var summary strings.Builder
	seen := make(map[string]bool)
	for _, fields := range singleRecoveryQueryTracePattern.FindAllSubmatch(output, 6) {
		key := string(fields[1]) + "/" + string(fields[2])
		if seen[key] {
			continue
		}
		seen[key] = true
		summary.WriteString(" trace[" + key + "]=" + string(fields[3]) + "/" + string(fields[4]) + "/" + string(fields[5]) + "/" + string(fields[6]) + "/" + string(fields[7]) + "/" + string(fields[8]) + "/" + string(fields[9]) + "/" + string(fields[10]))
	}
	return summary.String()
}

func singleRecoveryContentionBoundarySummary(output []byte) string {
	var summary strings.Builder
	seen := make(map[string]bool)
	for _, fields := range singleRecoveryContentionBoundaryPattern.FindAllSubmatch(output, 2) {
		phase := string(fields[1])
		if seen[phase] {
			continue
		}
		seen[phase] = true
		summary.WriteString(" boundary[" + phase + "]=" + string(fields[2]) + "/" + string(fields[3]) + "/" + string(fields[4]) + "/" + string(fields[5]))
	}
	return summary.String()
}

func TestSingleRecoveryQueryTraceRedaction(t *testing.T) {
	const prefix = "    security_agent_temporal_single_recovery_query_trace_test.go:100: recovery-trace "
	const wire = "phase=pending caller=cleanup operation=source-state error=query sqlstate=40001 ordinal=4 source_state=2 state_completed=1 elapsed=lt1s result=auth-conflict"
	const want = " trace[pending/cleanup]=source-state/query/40001/4/2/1/lt1s/auth-conflict"
	classify := func(s string) string {
		return singleRecoveryWorkerFailure(context.Background(), []byte(s), errors.New("private secret")).Error()
	}
	if got := classify(prefix + wire + "\n"); !strings.Contains(got, want) || strings.Contains(got, "private") {
		t.Fatalf("trace not safely retained: %s", got)
	}
	for _, mutation := range []string{
		strings.Replace(prefix+wire, "query_trace_test.go", "secret_test.go", 1),
		prefix + strings.Replace(wire, "source-state", "SELECT secret", 1),
		prefix + strings.Replace(wire, "40001", "ZZ999", 1),
		prefix + strings.Replace(wire, "ordinal=4", "ordinal=9", 1),
		prefix + strings.Replace(wire, "source_state=2", "source_state=9", 1),
		prefix + strings.Replace(wire, "state_completed=1", "state_completed=9", 1),
		prefix + strings.Replace(wire, "lt1s", "1.34", 1),
		prefix + strings.Replace(wire, "auth-conflict", "postgres://secret", 1),
		prefix + wire + " private-secret",
	} {
		if got := classify(mutation + "\n"); strings.Contains(got, " trace[") || strings.Contains(got, "secret") {
			t.Fatalf("unbound trace escaped: %s", got)
		}
	}
	if got := classify(prefix + wire + "\n" + prefix + strings.Replace(wire, "source-state", "cleanup", 1) + "\n"); strings.Count(got, " trace[") != 1 || !strings.Contains(got, want) {
		t.Fatalf("first trace replaced: %s", got)
	}
	for _, result := range []string{"nil", "pending", "auth-conflict", "auth-unavailable", "auth-denied", "auth-invalid", "worker", "conflict", "unavailable", "invalid", "deadline", "canceled", "other"} {
		if got := classify(prefix + strings.Replace(wire, "auth-conflict", result, 1) + "\n"); !strings.Contains(got, "/"+result) || !strings.Contains(got, " trace[") {
			t.Fatalf("closed result missing: %s", got)
		}
	}
	var lines strings.Builder
	for _, phase := range []string{"pending", "settle"} {
		for _, caller := range []string{"cleanup", "step", "finish"} {
			lines.WriteString(prefix + strings.Replace(strings.Replace(wire, "phase=pending", "phase="+phase, 1), "caller=cleanup", "caller="+caller, 1) + "\n")
		}
	}
	if got := classify(lines.String() + lines.String()); strings.Count(got, " trace[") != 6 {
		t.Fatalf("trace bound: %s", got)
	}
}

func TestSingleRecoveryContentionBoundaryAndQueryOrdinals(t *testing.T) {
	const prefix = "    security_agent_temporal_single_recovery_query_trace_test.go:100: "
	const boundary = "recovery-contention phase=settle wait=ready release=ok join=outer-deadline elapsed=ge45s"
	output := []byte(prefix + boundary + "\n" +
		prefix + "recovery-trace phase=settle caller=cleanup operation=source-state error=deadline sqlstate=none ordinal=8 source_state=2 state_completed=1 elapsed=lt1s result=deadline\n")
	got := singleRecoveryWorkerFailure(context.Background(), output, errors.New("postgres" + "://private:secret@host/body")).Error()
	for _, want := range []string{
		" boundary[settle]=ready/ok/outer-deadline/ge45s",
		" trace[settle/cleanup]=source-state/deadline/none/8/2/1/lt1s/deadline",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing closed contention diagnostic %q: %s", want, got)
		}
	}
	if strings.Contains(got, "private") {
		t.Fatalf("private diagnostic input escaped: %s", got)
	}
	for _, mutation := range []string{
		strings.Replace(prefix+boundary, "query_trace_test.go", "private_test.go", 1),
		prefix + strings.Replace(boundary, "wait=ready", "wait=private", 1),
		prefix + strings.Replace(boundary, "release=ok", "release=private", 1),
		prefix + strings.Replace(boundary, "join=outer-deadline", "join=private", 1),
		prefix + strings.Replace(boundary, "elapsed=ge45s", "elapsed=45.1", 1),
		prefix + boundary + " private-secret",
	} {
		classified := singleRecoveryWorkerFailure(context.Background(), []byte(mutation+"\n"), errors.New("private-secret")).Error()
		if strings.Contains(classified, " boundary[") || strings.Contains(classified, "private") {
			t.Fatalf("unbound boundary escaped: %s", classified)
		}
	}
	duplicate := prefix + boundary + "\n" + prefix + strings.Replace(boundary, "join=outer-deadline", "join=complete", 1) + "\n"
	if classified := singleRecoveryWorkerFailure(context.Background(), []byte(duplicate), errors.New("private")).Error(); strings.Count(classified, " boundary[") != 1 || !strings.Contains(classified, "outer-deadline") {
		t.Fatalf("first boundary was replaced: %s", classified)
	}
}
